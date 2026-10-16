#!/usr/bin/env python3
"""
triage_columnar.py -- index COLUMNAR in memorie (logscan v44)

De ce exista (masurat pe un log de 2M linii, 440 MB, 2 core-uri):
  - sinteza panoului inferior pentru tara RO (57% din trafic) dura 13-19 s pe
    SQLite (9 interogari GROUP BY pe 1.1M randuri) si 3.5 s pe "cubul" v43.3,
    care pe date cu multe IP-uri x URL-uri avea 1.5M randuri la 2M evenimente;
  - histograma pentru aceeasi selectie: 2.1 s; filtrul "path contine": 1-2 s.

Aici fiecare camp folosit de filtre si agregari e o coloana numpy (cod intreg
dintr-un dictionar: IP, tara, metoda, URL, UA, severitate, actiune, zi), deci:
  - orice combinatie de filtre = o masca booleana (cateva ms pe milioane);
  - agregarile = bincount/unique pe selectie (zeci de ms), fara recitirea
    fisierului si fara a doua trecere prin SQLite.

Coloanele se colecteaza IN ACEEASI TRECERE de parsare (ChunkCollector, in
workerii din app._process_chunk), apoi se lipesc la finalizarea indexului.
SQLite ramane sursa randurilor complete (tabel, detalii, audit) -- accesate
DOAR prin cheia primara, pentru cele cateva zeci de randuri afisate.

Semantica filtrelor si a agregarilor e IDENTICA cu triage_engine (SQL) --
verificata automat in tests/test_logscan.py pe fiecare filtru acceptat.

numpy e optional: fara el AVAILABLE = False si aplicatia ramane pe calea
SQL din triage_engine (aceleasi rezultate, mai lent pe selectii mari).
"""
import calendar
import os
import pickle
import threading
from array import array

try:
    import numpy as np
except Exception:  # pragma: no cover - mediu fara numpy => calea SQL
    np = None

# LOGSCAN_NO_COLUMNAR=1 forteaza calea SQL (diagnostic / comparatie).
AVAILABLE = np is not None and os.environ.get("LOGSCAN_NO_COLUMNAR", "").strip() != "1"

# ordinea campurilor in tuplurile colectate de worker
_FIELDS = ("ts", "ip", "cc", "me", "fp", "st", "sz", "ua", "sev", "risk", "act", "lbl", "day", "off", "ln")
_DICT_FIELDS = ("ip", "cc", "me", "fp", "ua", "sev", "act", "lbl", "day")
_DTYPES = {"ts": "int64", "ip": "int32", "cc": "int16", "me": "int16", "fp": "int32", "st": "int16",
           "sz": "int64", "ua": "int32", "sev": "int8", "risk": "int16", "act": "int16", "lbl": "int16",
           "day": "int16", "off": "int64", "ln": "int32"}

# Categorii WordPress -- aceleasi definitii ca triage_engine.WP_CATEGORIES
# (si ca analiza v42): LIKE = subsir insensibil la majuscule ASCII pe URL-ul
# complet; GLOB = sufix sensibil la majuscule pe URL-ul fara query string.
WP_NAMES = ("wp_admin", "admin_ajax", "xmlrpc", "wp_json", "wp_cron", "wp_login_get", "wp_login_post")
WP_PRIORITY = ("admin_ajax", "wp_login_post", "wp_login_get", "xmlrpc", "wp_json", "wp_cron", "wp_admin")
_B_ADMIN, _B_AJAX, _B_XMLRPC, _B_JSON, _B_CRON, _B_LOGIN = 1, 2, 4, 8, 16, 32
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SESSION_GAP_SEC = 1800   # identic cu triage_engine.SESSION_GAP_SEC
_STATUS_CLASSES = {"1xx": 100, "2xx": 200, "3xx": 300, "4xx": 400, "5xx": 500}
_MON = {m: i + 1 for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"))}


def _day_utc_midnight(day):
    try:
        return calendar.timegm((int(day[7:11]), _MON[day[3:6]], int(day[0:2]), 0, 0, 0))
    except Exception:
        return None


def _lower_b(s):
    """Minuscule DOAR pe ASCII (exact semantica LIKE din SQLite)."""
    return s.encode("utf-8", "surrogatepass").lower()


# --------------------------------------------------------------------------
# Partea de worker (procesele din pool-ul de parsare)
# --------------------------------------------------------------------------
class ChunkCollector:
    """Colecteaza coloanele unui chunk, cu dictionare LOCALE (codurile se
    remapeaza global la lipire). Memorie plafonata: blocuri numpy de 64k.
    Hot-path (o apelare per linie): IP+tara si clasificarea (severitate,
    risc, actiune, eticheta) se codifica printr-o SINGURA cautare fiecare."""
    __slots__ = ("d_ip", "d_cc", "d_me", "d_fp", "d_sev", "d_act", "d_lbl", "d_day", "m_ipcc", "m_cls", "flat")

    def __init__(self):
        self.d_ip, self.d_cc, self.d_me, self.d_fp = {}, {}, {}, {}
        self.d_sev, self.d_act, self.d_lbl, self.d_day = {}, {}, {}, {}
        self.m_ipcc = {}   # ip -> (cod ip, cod tara)
        self.m_cls = {}    # (sev, risc, actiune, eticheta) -> (cod sev, risc, cod actiune, cod eticheta)
        # un singur buffer int64 contiguu (15 valori/linie): extend() e un apel
        # C, iar la final numpy il preia fara copiere -- de ~2x mai ieftin
        # decat o lista de tupluri convertita cu np.array.
        self.flat = array("q")

    @staticmethod
    def _code(d, v):
        k = d.get(v)
        if k is None:
            k = d[v] = len(d)
        return k

    def add(self, ts, ip, cc, me, fp, st, sz, ua_local, cls, day, off, ln):
        x = self.m_ipcc.get(ip)
        if x is None:
            x = self.m_ipcc[ip] = (self._code(self.d_ip, ip), self._code(self.d_cc, cc))
        c = self.m_cls.get(cls)
        if c is None:
            c = self.m_cls[cls] = (self._code(self.d_sev, cls[0]), cls[1], self._code(self.d_act, cls[2]),
                                   self._code(self.d_lbl, cls[3]))
        d = self.d_me; k_me = d.get(me)
        if k_me is None:
            k_me = d[me] = len(d)
        d = self.d_fp; k_fp = d.get(fp)
        if k_fp is None:
            k_fp = d[fp] = len(d)
        d = self.d_day; k_day = d.get(day)
        if k_day is None:
            k_day = d[day] = len(d)
        self.flat.extend((ts, x[0], x[1], k_me, k_fp, st, sz, ua_local, c[0], c[1], c[2], c[3], k_day, off, ln))

    def save(self, path, ua_list):
        arr = (np.frombuffer(self.flat, dtype=np.int64).reshape(-1, len(_FIELDS)) if len(self.flat)
               else np.zeros((0, len(_FIELDS)), np.int64))
        cols = {f: arr[:, i] for i, f in enumerate(_FIELDS)}
        payload = {"v": 1, "n": int(arr.shape[0]), "cols": cols, "ua": list(ua_list)}
        for k in _DICT_FIELDS:
            if k != "ua":
                payload[k] = list(getattr(self, "d_" + k))   # ordinea de insertie == codul local
        with open(path, "wb") as f:
            pickle.dump(payload, f, protocol=pickle.HIGHEST_PROTOCOL)
        self.flat = array("q")
        return path


# --------------------------------------------------------------------------
# Indexul global (procesul serverului)
# --------------------------------------------------------------------------
class ColStore:
    """Coloane globale + dictionare. Imutabil dupa build() (cu exceptia
    corelarii de login, facuta o singura data inainte de publicare)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._lut_cache = {}
        self._cache = {}

    # ---------------------------------------------------------------- build
    @classmethod
    def build(cls, chunk_paths, conn=None):
        self = cls()
        G = {k: {} for k in _DICT_FIELDS}
        parts = {f: [] for f in _FIELDS}
        for p in chunk_paths:
            with open(p, "rb") as fh:
                P = pickle.load(fh)
            for k in _DICT_FIELDS:
                g, L = G[k], P[k]
                col = P["cols"][k]
                if len(L):
                    remap = np.fromiter((g.setdefault(v, len(g)) for v in L), dtype=np.int64, count=len(L))
                    parts[k].append(remap[col])
                else:
                    parts[k].append(col)
            for f in _FIELDS:
                if f not in _DICT_FIELDS:
                    parts[f].append(P["cols"][f])
            del P
        for f in _FIELDS:
            arr = np.concatenate(parts[f]) if parts[f] else np.zeros(0, np.int64)
            dt = np.dtype(_DTYPES[f])
            if arr.size and (arr.max() > np.iinfo(dt).max or arr.min() < np.iinfo(dt).min):
                dt = np.dtype("int64")      # nu trunchiem niciodata (ex. >32k tari/zile imposibil, dar sigur)
            setattr(self, f, arr.astype(dt, copy=False))
            parts[f] = None
        for k in _DICT_FIELDS:
            setattr(self, "d_" + k, G[k])                 # valoare -> cod
            setattr(self, "v_" + k, list(G[k]))           # cod -> valoare
        self.n = int(self.ts.size)
        self._derive()
        self.rowid = None
        if conn is not None:
            self._align_rowids(conn)
        return self

    def _derive(self):
        # URL fara query string (acelasi split ca _PO din triage_engine)
        d_po = {}
        po_of_fp = np.fromiter((d_po.setdefault(p.split("?", 1)[0], len(d_po)) for p in self.v_fp),
                               dtype=np.int32, count=len(self.v_fp))
        self.d_po, self.v_po = d_po, list(d_po)
        self.po = po_of_fp[self.fp] if self.n else np.zeros(0, np.int32)
        # biti WordPress per URL distinct (vezi WP_NAMES)
        bits = np.zeros(len(self.v_fp), np.uint8)
        for i, p in enumerate(self.v_fp):
            lb = _lower_b(p)
            po = p.split("?", 1)[0]
            b = 0
            if b"/wp-admin/" in lb:
                b |= _B_ADMIN
            if b"admin-ajax.php" in lb:
                b |= _B_AJAX
            if b"xmlrpc.php" in lb:
                b |= _B_XMLRPC
            if b"/wp-json/" in lb:
                b |= _B_JSON
            if po.endswith("wp-cron.php"):
                b |= _B_CRON
            if po.endswith("wp-login.php") or "wp-login.php/" in po:   # v47.3: si cu PATH_INFO
                b |= _B_LOGIN
            if b:
                bits[i] = b
        self.wp = bits[self.fp] if self.n else np.zeros(0, np.uint8)
        # tara per IP (o adresa are o singura tara -- verificat, nu presupus)
        n_ip = len(self.v_ip)
        ip_cc = np.full(n_ip, -1, np.int32)
        if self.n:
            ip_cc[self.ip] = self.cc
        self.ip_cc = ip_cc
        self.ip_cc_functional = bool(self.n == 0 or np.array_equal(ip_cc[self.ip], self.cc.astype(np.int32)))
        self._order_asc = None

    def _align_rowids(self, conn):
        """Leaga randul i al coloanelor de id-ul din SQLite. Shard-urile se
        lipesc in ordinea chunk-urilor, deci id == i+1; verificat pe esantion
        (offset-ul liniei in fisier e unic), iar la orice nepotrivire se face
        alinierea completa dupa offset."""
        n = self.n
        mn, mx, cnt = conn.execute("SELECT MIN(id), MAX(id), COUNT(*) FROM events").fetchone()
        if cnt != n:
            raise RuntimeError(f"index columnar inconsistent cu SQLite ({n} vs {cnt} randuri)")
        if n == 0:
            return
        if mn == 1 and mx == n:
            sample = sorted(set([0, n - 1] + [int(x) for x in np.linspace(0, n - 1, 64)]))
            rows = conn.execute(
                "SELECT id, offset_start FROM events WHERE id IN (%s)" % ",".join(str(i + 1) for i in sample)).fetchall()
            if len(rows) == len(sample) and all(int(self.off[r[0] - 1]) == r[1] for r in rows):
                return
        pairs = np.array(conn.execute("SELECT id, offset_start FROM events").fetchall(), dtype=np.int64)
        o_sql = np.argsort(pairs[:, 1], kind="stable")
        o_me = np.argsort(self.off, kind="stable")
        if not np.array_equal(pairs[o_sql, 1], self.off[o_me]):
            raise RuntimeError("index columnar: offset-urile nu corespund cu SQLite")
        rid = np.empty(n, np.int64)
        rid[o_me] = pairs[o_sql, 0]
        self.rowid = rid

    def ids_of(self, idx):
        """index de rand -> id SQLite."""
        idx = np.asarray(idx, dtype=np.int64)
        return (idx + 1) if self.rowid is None else self.rowid[idx]

    def _rid_all(self):
        return np.arange(1, self.n + 1, dtype=np.int64) if self.rowid is None else self.rowid

    @property
    def order_asc(self):
        """ORDER BY ts ASC, id ASC (desc = exact inversul)."""
        if self._order_asc is None:
            o = np.lexsort((self._rid_all(), self.ts))
            self._order_asc = o.astype(np.int32 if self.n < 2 ** 31 else np.int64)
        return self._order_asc

    def memory_bytes(self):
        tot = 0
        for f in _FIELDS + ("po", "wp", "ip_cc"):
            a = getattr(self, f, None)
            if a is not None:
                tot += a.nbytes
        if self._order_asc is not None:
            tot += self._order_asc.nbytes
        return tot

    # ------------------------------------------------- corelare login reusit
    def correlate_logins(self, conn=None, window_sec=300, post_action="admin_login_post",
                         get_action="admin_get", success_action="admin_login_success"):
        """Aceeasi regula ca triage_engine.finalize_login_success (POST
        wp-login 302 urmat de un GET /wp-admin/ 200 de la ACELASI IP in max
        window_sec), vectorizata; actualizeaza si randurile din SQLite."""
        post = self.d_act.get(post_action)
        get = self.d_act.get(get_action)
        if post is None or get is None or not self.n:
            return 0
        cand = np.flatnonzero((self.act == post) & (self.st == 302))
        gets = np.flatnonzero(self.act == get)
        if not cand.size or not gets.size:
            return 0
        t0 = int(self.ts.min())
        span = int(self.ts.max()) - t0 + window_sec + 1
        gk = self.ip[gets].astype(np.int64) * span + (self.ts[gets] - t0)
        gk.sort()
        lo = self.ip[cand].astype(np.int64) * span + (self.ts[cand] - t0)
        pos = np.searchsorted(gk, lo, side="left")
        ok = pos < gk.size
        hit = np.zeros(cand.size, bool)
        hit[ok] = gk[pos[ok]] <= lo[ok] + window_sec
        hits = cand[hit]
        if not hits.size:
            return 0
        succ = self._code("act", success_action, add=True)
        crit = self._code("sev", "CRITICAL", add=True)
        info = self._code("sev", "INFO", add=True)
        lab_bad = "Login WP Admin reusit din IP non-RO -- posibil cont compromis"
        lab_ok = "Login WP Admin reusit"
        l_bad = self._code("lbl", lab_bad, add=True)
        l_ok = self._code("lbl", lab_ok, add=True)
        ro = self.d_cc.get("RO", -1)
        unk = self.d_cc.get("", -1)
        nonro = (self.cc[hits] != ro) & (self.cc[hits] != unk)
        self.act[hits] = succ
        self.sev[hits] = np.where(nonro, crit, info)
        self.risk[hits] = np.where(nonro, 100, 5)
        self.lbl[hits] = np.where(nonro, l_bad, l_ok)
        if conn is not None:
            ids = self.ids_of(hits)
            upd = [(success_action, "CRITICAL" if nr else "INFO", 100 if nr else 5, lab_bad if nr else lab_ok, int(i))
                   for nr, i in zip(nonro.tolist(), ids.tolist())]
            conn.executemany("UPDATE events SET action_type = ?, severity = ?, risk_score = ?, label = ? WHERE id = ?", upd)
            conn.commit()
        self._cache.clear()
        return int(hits.size)

    def _code(self, field, value, add=False):
        d = getattr(self, "d_" + field)
        c = d.get(value)
        if c is None and add:
            c = d[value] = len(d)
            getattr(self, "v_" + field).append(value)
            arr = getattr(self, field)
            if c > np.iinfo(arr.dtype).max:
                setattr(self, field, arr.astype(np.int64))
        return -1 if c is None else c

    # ---------------------------------------------------------------- filtre
    def _lut(self, field, needle):
        """Tabel de cautare: coduri ale caror valoare CONTINE needle (LIKE
        '%needle%' din SQLite: subsir literal, majuscule ASCII ignorate)."""
        key = (field, needle)
        hit = self._lut_cache.get(key)
        if hit is not None:
            return hit
        nb = _lower_b(needle)
        vals = getattr(self, "v_" + field)
        lut = np.fromiter((nb in _lower_b(v) for v in vals), dtype=bool, count=len(vals))
        if len(self._lut_cache) > 32:
            self._lut_cache.pop(next(iter(self._lut_cache)))
        self._lut_cache[key] = lut
        return lut

    def mask(self, f):
        """Masca booleana pentru filtre (aceleasi chei si aceeasi semantica ca
        triage_engine._build_where). None = fara filtre (toate randurile)."""
        f = f or {}
        m = None

        def AND(x):
            nonlocal m
            m = x if m is None else (m & x)

        if f.get("ts_from") is not None:
            AND(self.ts >= int(f["ts_from"]))
        if f.get("ts_to") is not None:
            AND(self.ts <= int(f["ts_to"]))
        countries = f.get("countries") or []
        if countries:
            sub = None
            for c in countries:
                if c == "__NON_RO__":
                    x = (self.cc != self.d_cc.get("", -1)) & (self.cc != self.d_cc.get("RO", -1))
                elif c in ("??", ""):
                    x = self.cc == self.d_cc.get("", -1)
                else:
                    x = self.cc == self.d_cc.get(c.upper()[:2], -1)
                sub = x if sub is None else (sub | x)
            AND(sub)
        for key, field, conv in (("severities", "sev", str), ("action_types", "act", str)):
            vals = f.get(key) or []
            if vals:
                d = getattr(self, "d_" + field)
                codes = [d[conv(v)] for v in vals if conv(v) in d]
                AND(np.isin(getattr(self, field), codes) if codes else np.zeros(self.n, bool))
        if f.get("statuses"):
            AND(np.isin(self.st, [int(v) for v in f["statuses"]]))
        if f.get("ip"):
            AND(self.ip == self.d_ip.get(f["ip"], -1))
        if f.get("method"):
            AND(self.me == self.d_me.get(f["method"].upper(), -1))
        if f.get("path_contains"):
            AND(self._lut("fp", f["path_contains"])[self.fp])
        if f.get("ua_contains"):
            AND(self._lut("ua", f["ua_contains"])[self.ua])
        if f.get("ua"):
            AND(self.ua == self.d_ua.get(f["ua"], -1))
        if f.get("ts_str_day"):
            day = f["ts_str_day"]
            base = _day_utc_midnight(day)
            if base is not None:
                AND((self.ts >= base - 14 * 3600) & (self.ts <= base + 86400 + 14 * 3600))
            nb = _lower_b(day)
            codes = [i for i, v in enumerate(self.v_day) if _lower_b(v) == nb]
            AND(np.isin(self.day, codes) if codes else np.zeros(self.n, bool))
        # ---- v45: filtre de entitate (explorer) + EXCLUDERI -- aceeasi
        # semantica exacta ca triage_engine._build_where (verificat in teste)
        if f.get("path_exact") not in (None, ""):
            AND(self.po == self.d_po.get(f["path_exact"], -1))
        sc = [c for c in (f.get("status_class") or []) if c in _STATUS_CLASSES]
        if sc:
            x = None
            for c in sc:
                lo = _STATUS_CLASSES[c]
                y = (self.st >= lo) & (self.st < lo + 100)
                x = y if x is None else (x | y)
            AND(x)
        if f.get("wp_cat"):
            AND(self._wp_cat_mask(f["wp_cat"]))
        if f.get("x_ips"):
            codes = [self.d_ip[v] for v in f["x_ips"] if v in self.d_ip]
            if codes:
                AND(~np.isin(self.ip, codes))
        for c in (f.get("x_countries") or []):
            unk, ro = self.d_cc.get("", -1), self.d_cc.get("RO", -1)
            if c == "__NON_RO__":
                AND((self.cc == unk) | (self.cc == ro))
            elif c in ("??", ""):
                AND(self.cc != unk)
            else:
                AND(self.cc != self.d_cc.get(c.upper()[:2], -1))
        if f.get("x_statuses"):
            AND(~np.isin(self.st, [int(v) for v in f["x_statuses"]]))
        for v in (f.get("x_paths") or []):
            AND(~self._lut("fp", v)[self.fp])
        for v in (f.get("x_uas") or []):
            AND(~self._lut("ua", v)[self.ua])
        for v in (f.get("_and_path_contains") or []):
            AND(self._lut("fp", v)[self.fp])
        for v in (f.get("_and_ua_contains") or []):
            AND(self._lut("ua", v)[self.ua])
        if f.get("_empty"):
            AND(np.zeros(self.n, bool))
        return m

    def _wp_cat_mask(self, name):
        get_c, post_c = self.d_me.get("GET", -1), self.d_me.get("POST", -1)
        w = self.wp
        if name == "wp_admin":
            return (w & _B_ADMIN) != 0
        if name == "admin_ajax":
            return (w & _B_AJAX) != 0
        if name == "xmlrpc":
            return (w & _B_XMLRPC) != 0
        if name == "wp_json":
            return (w & _B_JSON) != 0
        if name == "wp_cron":
            return (w & _B_CRON) != 0
        if name == "wp_login_get":
            return ((w & _B_LOGIN) != 0) & (self.me == get_c)
        if name == "wp_login_post":
            return ((w & _B_LOGIN) != 0) & (self.me == post_c)
        if name == "wp_any":
            return w != 0
        return np.zeros(self.n, bool)

    def count(self, f):
        m = self.mask(f)
        return self.n if m is None else int(np.count_nonzero(m))

    # ------------------------------------------------------------- agregari
    @staticmethod
    def _top(counts, names, k, extra_key=None):
        """Top-k coduri dupa (-numar, valoare) -- determinist la egalitate."""
        nz = np.flatnonzero(counts)
        if nz.size > 4 * k + 64:
            thr = np.partition(counts[nz], -k)[-k]
            nz = nz[counts[nz] >= thr]
        keyf = (lambda c: (-int(counts[c]), str(names[c]))) if extra_key is None else extra_key
        return sorted(nz.tolist(), key=keyf)[:k]

    def overview(self, f, top_n=15):
        """Aceeasi iesire ca triage_engine.overview_sql."""
        m = self.mask(f)
        idx = None if m is None else np.flatnonzero(m)
        S = (lambda a: a) if idx is None else (lambda a: a[idx])
        s_ip, s_po, s_st, s_ts = S(self.ip), S(self.po), S(self.st), S(self.ts)
        req = int(s_ip.size)
        n_ip, n_po, n_cc = len(self.v_ip), len(self.v_po), len(self.v_cc)
        ip_c = np.bincount(s_ip, minlength=n_ip) if n_ip else np.zeros(0, np.int64)
        po_c = np.bincount(s_po, minlength=n_po) if n_po else np.zeros(0, np.int64)
        none_if_empty = (lambda v: v) if req else (lambda v: None)
        out = {
            "requests": req,
            "unique_ips": int(np.count_nonzero(ip_c)),
            "unique_paths": int(np.count_nonzero(po_c)),
            "bandwidth": none_if_empty(int(S(self.sz).sum())) if req else None,
            "ts_min": int(s_ts.min()) if req else None,
            "ts_max": int(s_ts.max()) if req else None,
            "err_4xx": none_if_empty(int(np.count_nonzero((s_st >= 400) & (s_st < 500)))),
            "err_5xx": none_if_empty(int(np.count_nonzero(s_st >= 500))),
            "unknown_country": none_if_empty(int(np.count_nonzero(S(self.cc) == self.d_cc.get("", -1)))),
        }
        st_u, st_n = np.unique(s_st, return_counts=True)
        out["statuses"] = [{"status": int(s), "n": int(c)}
                           for s, c in sorted(zip(st_u.tolist(), st_n.tolist()), key=lambda x: (-x[1], x[0]))]
        me_c = np.bincount(S(self.me), minlength=len(self.v_me)) if self.v_me else np.zeros(0, np.int64)
        out["methods"] = [{"method": self.v_me[k], "n": int(me_c[k])}
                          for k in sorted(np.flatnonzero(me_c).tolist(), key=lambda k: (-int(me_c[k]), self.v_me[k]))]
        # top URL-uri (fara query string) + IP-uri distincte per URL
        tp = []
        for k in self._top(po_c, self.v_po, top_n):
            ips_k = s_ip[s_po == k]
            tp.append({"path": self.v_po[k], "n": int(po_c[k]), "ips": int(np.unique(ips_k).size)})
        out["top_paths"] = tp
        ti = []
        for k in self._top(ip_c, self.v_ip, top_n):
            t_k = s_ts[s_ip == k]
            cc = self.ip_cc[k]
            ti.append({"ip": self.v_ip[k], "country": self.v_cc[cc] if cc >= 0 else "", "n": int(ip_c[k]),
                       "first_ts": int(t_k.min()), "last_ts": int(t_k.max())})
        out["top_ips"] = ti
        s_cc = S(self.cc)
        cc_c = np.bincount(s_cc, minlength=n_cc) if n_cc else np.zeros(0, np.int64)
        if self.ip_cc_functional:
            seen = np.flatnonzero(ip_c)
            cc_ips = np.bincount(self.ip_cc[seen], minlength=n_cc) if seen.size else np.zeros(n_cc, np.int64)
        else:
            pairs = np.unique(s_cc.astype(np.int64) * max(1, n_ip) + s_ip)
            cc_ips = np.bincount(pairs // max(1, n_ip), minlength=n_cc)
        out["countries"] = [{"country": self.v_cc[k], "n": int(cc_c[k]), "ips": int(cc_ips[k])}
                            for k in self._top(cc_c, self.v_cc, 60)]
        sv_c = np.bincount(S(self.sev), minlength=len(self.v_sev)) if self.v_sev else np.zeros(0, np.int64)
        out["severities"] = [{"severity": self.v_sev[k], "n": int(sv_c[k])}
                             for k in sorted(np.flatnonzero(sv_c).tolist(), key=lambda k: self.v_sev[k])]
        out["wordpress"] = self._wp_block(S(self.wp), s_ip, S(self.me), s_st, s_ts)
        out["error_paths"] = self._error_block(s_st, s_po, s_ip, s_ts)
        out["source"] = "columnar"
        return out

    def _wp_cats(self, w_bits, w_me):
        get_c, post_c = self.d_me.get("GET", -1), self.d_me.get("POST", -1)
        login = (w_bits & _B_LOGIN) != 0
        return {
            "wp_admin": (w_bits & _B_ADMIN) != 0, "admin_ajax": (w_bits & _B_AJAX) != 0,
            "xmlrpc": (w_bits & _B_XMLRPC) != 0, "wp_json": (w_bits & _B_JSON) != 0,
            "wp_cron": (w_bits & _B_CRON) != 0,
            "wp_login_get": login & (w_me == get_c), "wp_login_post": login & (w_me == post_c),
        }

    def _wp_block(self, s_wp, s_ip, s_me, s_st, s_ts):
        widx = np.flatnonzero(s_wp)
        w_bits, w_ip, w_me, w_st, w_ts = s_wp[widx], s_ip[widx], s_me[widx], s_st[widx], s_ts[widx]
        cats = self._wp_cats(w_bits, w_me)
        out = {}
        for nm in WP_NAMES:
            c = cats[nm]
            out[nm] = int(np.count_nonzero(c))
            out[nm + "_ips"] = int(np.unique(w_ip[c]).size)
            out[nm + "_sessions"] = self._sessions(w_ip[c], w_ts[c])
        cat = np.full(widx.size, -1, np.int16)
        for i in range(len(WP_PRIORITY) - 1, -1, -1):
            cat[cats[WP_PRIORITY[i]]] = i
        sel = cat >= 0
        key = cat[sel].astype(np.int64) * 1000 + w_st[sel]
        u, c = np.unique(key, return_counts=True)
        rows = [{"cat": WP_PRIORITY[int(k) // 1000], "status": int(k) % 1000, "n": int(n)} for k, n in zip(u.tolist(), c.tolist())]
        rows.sort(key=lambda r: (-r["n"], r["cat"], r["status"]))
        out["status_by_category"] = rows
        return out

    @staticmethod
    def _sessions(ips, ts, gap=SESSION_GAP_SEC):
        """Sesiuni estimate: cererile aceluiasi IP fara pauza > gap secunde
        (aceeasi definitie ca triage_engine, cu LAG() in SQL)."""
        if not ips.size:
            return 0
        o = np.lexsort((ts, ips))
        a, t = ips[o], ts[o]
        new = (a[1:] != a[:-1]) | ((t[1:] - t[:-1]) > gap)
        return int(1 + np.count_nonzero(new))

    def _error_block(self, s_st, s_po, s_ip, s_ts, top_n=25):
        eidx = np.flatnonzero(s_st >= 400)
        if not eidx.size:
            return []
        n_po = max(1, len(self.v_po))
        key = s_st[eidx].astype(np.int64) * n_po + s_po[eidx]
        u, inv, cnt = np.unique(key, return_inverse=True, return_counts=True)
        order = sorted(range(u.size), key=lambda g: (-int(cnt[g]), int(u[g]) // n_po, self.v_po[int(u[g]) % n_po]))[:top_n]
        out = []
        for g in order:
            rows = eidx[inv == g]
            k = int(u[g])
            out.append({"status": k // n_po, "path": self.v_po[k % n_po], "n": int(cnt[g]),
                        "ips": int(np.unique(s_ip[rows]).size), "first_ts": int(s_ts[rows].min()),
                        "last_ts": int(s_ts[rows].max())})
        return out

    def histogram(self, ts_from, ts_to, bucket_seconds, filters=None):
        f = dict(filters or {})
        f["ts_from"], f["ts_to"] = ts_from, ts_to
        bucket_seconds = max(60, int(bucket_seconds))
        m = self.mask(f)
        idx = np.flatnonzero(m) if m is not None else None
        ts = self.ts if idx is None else self.ts[idx]
        sev = self.sev if idx is None else self.sev[idx]
        if not ts.size:
            return []
        q = ts // bucket_seconds
        q0 = int(q.min())
        nb = int(q.max()) - q0 + 1
        is_c = sev == self.d_sev.get("CRITICAL", -1)
        is_h = sev == self.d_sev.get("HIGH", -1)
        if nb <= 4_000_000:
            # bincount pe bucket-uri (O(n), fara sortare) -- 2M randuri: ~15 ms
            rel = q - q0
            cnt = np.bincount(rel, minlength=nb)
            crit = np.bincount(rel[is_c], minlength=nb)
            high = np.bincount(rel[is_h], minlength=nb)
            nz = np.flatnonzero(cnt)
            u = (nz + q0) * bucket_seconds
            cnt, crit, high = cnt[nz], crit[nz], high[nz]
        else:
            u, inv, cnt = np.unique(q * bucket_seconds, return_inverse=True, return_counts=True)
            crit = np.bincount(inv, weights=is_c, minlength=u.size)
            high = np.bincount(inv, weights=is_h, minlength=u.size)
        return [{"bucket": int(a), "total": int(c), "critical": int(x), "high": int(y)}
                for a, c, x, y in zip(u.tolist(), cnt.tolist(), crit.tolist(), high.tolist())]

    def page(self, f, limit=200, offset=0, sort="ts_desc"):
        """Indicii de rand pentru o pagina a tabelului (ordinea ca in SQL)."""
        limit = max(1, min(int(limit), 2000))
        offset = max(0, int(offset))
        if sort == "risk_desc":
            order = self._cache.get("order_risk")
            if order is None:
                order = np.lexsort((-self._rid_all(), -self.ts, -self.risk.astype(np.int64)))
                self._cache["order_risk"] = order
        elif sort == "ts_asc":
            order = self.order_asc
        else:
            order = self.order_asc[::-1]
        m = self.mask(f)
        if m is None:
            return order[offset:offset + limit]
        pos = np.flatnonzero(m[order])
        return order[pos[offset:offset + limit]]

    def offsets(self, f):
        """(start, end) in ordinea din fisier pentru liniile selectate, cu
        intervalele adiacente deja unite (citire secventiala)."""
        m = self.mask(f)
        idx = np.arange(self.n) if m is None else np.flatnonzero(m)
        if not idx.size:
            return []
        a = self.off[idx]
        b = a + self.ln[idx]
        o = np.argsort(a, kind="stable")
        a, b = a[o], b[o]
        brk = np.flatnonzero(a[1:] != b[:-1]) + 1
        starts = np.concatenate(([0], brk))
        ends = np.concatenate((brk, [a.size]))
        return list(zip(a[starts].tolist(), b[ends - 1].tolist()))

    def ip_profile(self, ip, filters=None, top_n=20):
        f = dict(filters or {})
        f["ip"] = ip
        ov = self.overview(f, top_n=top_n)
        m = self.mask(f)
        idx = np.flatnonzero(m)
        s_ua = self.ua[idx]
        ua_c = np.bincount(s_ua, minlength=len(self.v_ua)) if self.v_ua else np.zeros(0, np.int64)
        ov["user_agents"] = [{"ua": self.v_ua[k], "n": int(ua_c[k])} for k in self._top(ua_c, self.v_ua, 10)]
        acts = []
        if idx.size:
            key = self.act[idx].astype(np.int64) * 256 + self.sev[idx]
            u, inv, cnt = np.unique(key, return_inverse=True, return_counts=True)
            for g, k in enumerate(u.tolist()):
                lbls = np.unique(self.lbl[idx[inv == g]])
                acts.append({"action_type": self.v_act[k // 256], "severity": self.v_sev[k % 256],
                             "label": max(self.v_lbl[x] for x in lbls.tolist()), "n": int(cnt[g])})
        acts.sort(key=lambda a: (SEVERITY_RANK.get(a["severity"], 4), -a["n"]))
        ov["actions"] = acts
        span = (ov["ts_max"] - ov["ts_min"]) if ov.get("ts_min") is not None else 0
        ov["req_per_min"] = round(ov["requests"] / max(1.0, span / 60.0), 2) if ov["requests"] else 0
        if idx.size:
            mins = (self.ts[idx] // 60) * 60
            u, c = np.unique(mins, return_counts=True)
            j = int(np.argmax(c))
            ov["peak_minute"] = {"minute": int(u[j]), "n": int(c[j])}
        else:
            ov["peak_minute"] = None
        ov["ip"] = ip
        return ov

    def top_alerts(self, limit=30):
        cached = self._cache.get("alerts")
        if cached is None:
            cached = self._compute_alerts(60)
            self._cache["alerts"] = cached
        if limit <= len(cached) or len(cached) < 60:
            return cached[:limit]
        return self._compute_alerts(limit)

    def _compute_alerts(self, limit, base_mask=None):
        codes = [self.d_sev[s] for s in ("CRITICAL", "HIGH") if s in self.d_sev]
        if not codes:
            return []
        am = np.isin(self.sev, codes)
        if base_mask is not None:
            am &= base_mask
        idx = np.flatnonzero(am)
        if not idx.size:
            return []
        n_act = max(1, len(self.v_act))
        key = self.ip[idx].astype(np.int64) * n_act + self.act[idx]
        u, inv, cnt = np.unique(key, return_inverse=True, return_counts=True)
        o = np.argsort(inv, kind="stable")
        bounds = np.concatenate(([0], np.cumsum(cnt)))
        groups = []
        for g in range(u.size):
            rows = idx[o[bounds[g]:bounds[g + 1]]]
            r = self.risk[rows]
            jmax = int(np.argmax(r))
            groups.append((int(r[jmax]), int(self.ts[rows].max()), g, rows, jmax))
        groups.sort(key=lambda x: (-x[0], -x[1], x[2]))
        out = []
        for risk, last_ts, g, rows, jmax in groups[:limit]:
            k = int(u[g])
            ipc = k // n_act
            cc = self.ip_cc[ipc]
            ccs = self.v_cc[cc] if cc >= 0 else ""
            out.append({
                "ip": self.v_ip[ipc], "country": ccs, "is_non_ro": 1 if (ccs and ccs != "RO") else 0,
                "action_type": self.v_act[k % n_act], "severity": self.v_sev[int(self.sev[rows[jmax]])],
                "risk_score": risk, "last_ts": last_ts, "first_ts": int(self.ts[rows].min()),
                "sample_path": max(self.v_fp[x] for x in np.unique(self.fp[rows]).tolist()),
                "label": max(self.v_lbl[x] for x in np.unique(self.lbl[rows]).tolist()),
                "hits": int(rows.size),
            })
        return out

    # ------------------------------------------------------- v45: explorer
    def alerts_in(self, f, limit=30):
        """Alertele CRITICAL/HIGH DOAR din selectia data (perioada + filtre)."""
        m = self.mask(f)
        if m is None:
            return self.top_alerts(limit)
        return self._compute_alerts(limit, m)

    def _plugin_codes(self):
        """cod plugin/tema per URL distinct (-1 = nu e o ruta de plugin/tema)."""
        if getattr(self, "_plug", None) is None:
            import re
            rx = re.compile(r"/wp-content/(plugins|themes|mu-plugins)/([A-Za-z0-9_.\-]+)", re.I)
            d = {}
            codes = np.full(len(self.v_fp), -1, np.int32)
            for i, p in enumerate(self.v_fp):
                if "wp-content/" in p:
                    mm = rx.search(p.split("?", 1)[0])
                    if mm:
                        codes[i] = d.setdefault(mm.group(1).lower() + "/" + mm.group(2).lower(), len(d))
            self._plug = (codes, list(d))
        return self._plug

    def explore(self, f, top_n=15):
        """Tot ce trebuie panoului de explorare pentru o selectie (filtrele
        globale + entitatea): sinteza + UA-uri + IP-uri cu erori + rute de
        plugin/tema + alerte + varf + sesiuni estimate."""
        ov = self.overview(f, top_n=top_n)
        m = self.mask(f)
        idx = np.arange(self.n) if m is None else np.flatnonzero(m)
        s_ip, s_st, s_ts = self.ip[idx], self.st[idx], self.ts[idx]
        # UA-uri
        s_ua = self.ua[idx]
        ua_c = np.bincount(s_ua, minlength=len(self.v_ua)) if self.v_ua else np.zeros(0, np.int64)
        ov["user_agents"] = [{"ua": self.v_ua[k], "n": int(ua_c[k])} for k in self._top(ua_c, self.v_ua, 10)]
        ov["unique_uas"] = int(np.count_nonzero(ua_c))
        # IP-urile din top cu erori / rute distincte / pondere
        for t in ov["top_ips"]:
            k = self.d_ip.get(t["ip"], -1)
            sel = s_ip == k
            st_k = s_st[sel]
            t["err_4xx"] = int(np.count_nonzero((st_k >= 400) & (st_k < 500)))
            t["err_5xx"] = int(np.count_nonzero(st_k >= 500))
            t["paths"] = int(np.unique(self.po[idx[sel]]).size)
            span = max(60, t["last_ts"] - t["first_ts"])
            t["per_min"] = round(t["n"] * 60.0 / span, 2)
        # rute plugin / tema
        codes, names = self._plugin_codes()
        pc = codes[self.fp[idx]]
        has = pc >= 0
        plugs = []
        if has.any():
            pcs, ips_p, st_p = pc[has], s_ip[has], s_st[has]
            cnt = np.bincount(pcs, minlength=len(names))
            for k in self._top(cnt, names, 30):
                sel = pcs == k
                stk = st_p[sel]
                plugs.append({"route": names[k], "n": int(cnt[k]), "ips": int(np.unique(ips_p[sel]).size),
                              "ok_2xx": int(np.count_nonzero((stk >= 200) & (stk < 300))),
                              "err_4xx": int(np.count_nonzero((stk >= 400) & (stk < 500)))})
        ov["wp_routes"] = plugs
        ov["alerts"] = self._compute_alerts(30, m) if m is not None else self.top_alerts(30)
        ov["sessions_est"] = self._sessions(s_ip, s_ts)
        span = (ov["ts_max"] - ov["ts_min"]) if ov.get("ts_min") is not None else 0
        ov["req_per_min"] = round(ov["requests"] / max(1.0, span / 60.0), 2) if ov["requests"] else 0
        if idx.size:
            u, c = np.unique(s_ts // 60, return_counts=True)
            j = int(np.argmax(c))
            ov["peak_minute"] = {"minute": int(u[j]) * 60, "n": int(c[j])}
        else:
            ov["peak_minute"] = None
        ov["source"] = "columnar"
        return ov

    def timeline(self, f, ts_from, ts_to, bucket_seconds):
        """Seria temporala pe clase de cod (2xx..5xx) + CRITICAL/HIGH."""
        ff = dict(f or {})
        if ts_from is not None:
            ff["ts_from"] = ts_from if ff.get("ts_from") is None else max(int(ff["ts_from"]), int(ts_from))
        if ts_to is not None:
            ff["ts_to"] = ts_to if ff.get("ts_to") is None else min(int(ff["ts_to"]), int(ts_to))
        b = max(60, int(bucket_seconds))
        m = self.mask(ff)
        idx = np.arange(self.n) if m is None else np.flatnonzero(m)
        if not idx.size:
            return []
        q = self.ts[idx] // b
        q0 = int(q.min())
        nb = int(q.max()) - q0 + 1
        if nb > 200000:
            return []
        rel = q - q0
        st, sv = self.st[idx], self.sev[idx]
        cols = {"total": np.bincount(rel, minlength=nb)}
        for name, lo in (("c2", 200), ("c3", 300), ("c4", 400), ("c5", 500)):
            cols[name] = np.bincount(rel[(st >= lo) & (st < lo + 100)], minlength=nb)
        cols["critical"] = np.bincount(rel[sv == self.d_sev.get("CRITICAL", -1)], minlength=nb)
        cols["high"] = np.bincount(rel[sv == self.d_sev.get("HIGH", -1)], minlength=nb)
        cols["medium"] = np.bincount(rel[sv == self.d_sev.get("MEDIUM", -1)], minlength=nb)
        nz = np.flatnonzero(cols["total"])
        out = []
        lists = {k: v[nz].tolist() for k, v in cols.items()}
        for i, z in enumerate(nz.tolist()):
            row = {"bucket": (z + q0) * b}
            for k in lists:
                row[k] = lists[k][i]
            out.append(row)
        return out

    def security_groups(self, f, min_severity="MEDIUM", gap=600, limit=400):
        """Cronologia de securitate: evenimentele cu severitate >= prag din
        selectie, GRUPATE (acelasi IP + aceeasi actiune, fara pauza > gap s)."""
        rank_max = SEVERITY_RANK.get(min_severity, 2)
        codes = [c for v, c in self.d_sev.items() if SEVERITY_RANK.get(v, 4) <= rank_max]
        if not codes:
            return {"groups": [], "total_events": 0, "total_groups": 0, "by_severity": {}}
        sm = np.isin(self.sev, codes)
        m = self.mask(f)
        if m is not None:
            sm &= m
        idx = np.flatnonzero(sm)
        by_sev = {self.v_sev[k]: int(c) for k, c in enumerate(np.bincount(self.sev[idx], minlength=len(self.v_sev)).tolist()) if c}
        if not idx.size:
            return {"groups": [], "total_events": 0, "total_groups": 0, "by_severity": by_sev}
        o = np.lexsort((self.ts[idx], self.act[idx], self.ip[idx]))
        r = idx[o]
        ip, act, ts = self.ip[r], self.act[r], self.ts[r]
        brk = np.flatnonzero((ip[1:] != ip[:-1]) | (act[1:] != act[:-1]) | ((ts[1:] - ts[:-1]) > gap)) + 1
        starts = np.concatenate(([0], brk))
        ends = np.concatenate((brk, [r.size]))
        firsts = ts[starts]
        order = np.argsort(-firsts, kind="stable")
        groups = []
        for g in order[:limit].tolist():
            rows = r[starts[g]:ends[g]]
            sv = self.sev[rows]
            ranks = np.array([SEVERITY_RANK.get(self.v_sev[x], 4) for x in np.unique(sv).tolist()])
            worst = min(ranks.tolist())
            sev_name = next(k for k, v in SEVERITY_RANK.items() if v == worst)
            ipc = int(ip[starts[g]])
            cc = self.ip_cc[ipc]
            fps = np.bincount(self.fp[rows])
            stc = np.unique(self.st[rows], return_counts=True)
            groups.append({
                "ip": self.v_ip[ipc], "country": self.v_cc[cc] if cc >= 0 else "",
                "action_type": self.v_act[int(act[starts[g]])], "severity": sev_name,
                "label": max(self.v_lbl[x] for x in np.unique(self.lbl[rows]).tolist()),
                "n": int(rows.size), "first_ts": int(ts[starts[g]]), "last_ts": int(ts[ends[g] - 1]),
                "sample_path": self.v_fp[int(np.argmax(fps))], "paths": int(np.unique(self.po[rows]).size),
                "statuses": {int(a): int(b) for a, b in zip(stc[0].tolist(), stc[1].tolist())},
                "first_id": int(self.ids_of([rows[0]])[0]),
            })
        return {"groups": groups, "total_events": int(idx.size), "total_groups": int(starts.size),
                "by_severity": by_sev}

    # ------------------------------------------------- v47: fals pozitive
    FP_KEEP_ACTIONS = ("webshell_active", "admin_login_success")

    def suppress_verified_crawlers(self, ips):
        """Crawlere VERIFICATE prin DNS (PTR + forward-confirm): evenimentele
        lor CRITICAL/HIGH/MEDIUM/LOW devin INFO (fals pozitive: Googlebot sau
        facebookexternalhit urmeaza linkuri, nu ataca), cu exceptia dovezilor
        de compromitere (webshell servit, login reusit). Coloana se
        INLOCUIESTE (nu se modifica pe loc), deci cititorii concurenti vad fie
        vechea, fie noua versiune. Intoarce numarul de evenimente retrogradate."""
        codes = [self.d_ip[v] for v in ips if v in self.d_ip]
        if not codes or not self.n:
            return 0
        with self._lock:
            info = self._code("sev", "INFO", add=True)
            keep = [self.d_act[a] for a in self.FP_KEEP_ACTIONS if a in self.d_act]
            m = np.isin(self.ip, codes) & (self.sev != info)
            if keep:
                m &= ~np.isin(self.act, keep)
            n = int(np.count_nonzero(m))
            if n:
                sev = self.sev.copy()
                sev[m] = info
                self.sev = sev
                self._cache.clear()
            self.suppressed_ips = set(getattr(self, "suppressed_ips", set())) | set(ips)
            self.suppressed_events = getattr(self, "suppressed_events", 0) + n
        return n

    @staticmethod
    def wp_prefix(path):
        """Prefixul instalarii WordPress dintr-un URL de admin/login
        ('/blog/wp-admin/x' -> '/blog', '/wp-login.php' -> ''), sau None."""
        po = path.split("?", 1)[0].lower()
        for mk in ("/wp-admin", "/wp-login.php", "/xmlrpc.php"):
            i = po.find(mk)
            if i >= 0:
                return po[:i]
        return None

    FAKE_WP_ACTIONS = ("admin_get", "admin_login_post", "non_ro_admin_touch")

    def demote_fake_wp_paths(self):
        """v47.4: multe site-uri raspund 200 la ORICE URL (pagina generica /
        soft-404). Un scanner care cere /xml/wp-admin/ primeste 200 si arata ca
        un "acces in admin". WordPress exista doar la prefixele dovedite:
        radacina, prefixele cu login confirmat (admin_login_success) si cele unde
        >= 2 IP-uri distincte au primit 302 pe wp-admin/wp-login (redirectul
        real spre login). Evenimentele admin_get / admin_login_post /
        non_ro_admin_touch de pe alte prefixe devin 'wp_probe' (LOW)."""
        if getattr(self, "_fake_wp_done", False) or not self.n:
            return 0
        with self._lock:
            self._fake_wp_done = True
            pre = [self.wp_prefix(p) for p in self.v_fp]
            real = {""}
            ok_c = self.d_act.get("admin_login_success", -1)
            if ok_c >= 0:
                for f in np.unique(self.fp[self.act == ok_c]).tolist():
                    if pre[f] is not None:
                        real.add(pre[f])
            r302 = np.flatnonzero(self.st == 302)
            by = {}
            for f, ip in zip(self.fp[r302].tolist(), self.ip[r302].tolist()):
                if pre[f] is not None and pre[f] not in real:
                    by.setdefault(pre[f], set()).add(ip)
            real.update(k for k, v in by.items() if len(v) >= 2)
            fake_fp = np.fromiter((x is not None and x not in real for x in pre), dtype=bool, count=len(pre))
            acts = [self.d_act[a] for a in self.FAKE_WP_ACTIONS if a in self.d_act]
            if not acts or not fake_fp.any():
                self.wp_real_prefixes = sorted(real)
                return 0
            m = fake_fp[self.fp] & np.isin(self.act, acts)
            n = int(np.count_nonzero(m))
            if n:
                a = self._code("act", "wp_probe", add=True)
                sv = self._code("sev", "LOW", add=True)
                lb = self._code("lbl", "Sondare wp-admin/wp-login pe o cale fara WordPress (site-ul raspunde generic)", add=True)
                act, sev, lbl, risk = self.act.copy(), self.sev.copy(), self.lbl.copy(), self.risk.copy()
                act[m], sev[m], lbl[m], risk[m] = a, sv, lb, 5
                self.act, self.sev, self.lbl, self.risk = act, sev, lbl, risk
                self._cache.clear()
                self._lut_cache.clear()
            self.wp_real_prefixes = sorted(real)
            self.wp_fake_prefixes = sorted({pre[f] for f in np.unique(self.fp[m]).tolist()}) if n else []
            self.wp_probe_events = n
        return n

    def demote_rows(self, m, sev_name, label, risk=20):
        """v47.6: retrogradeaza randurile din masca (sev + eticheta + risc),
        pastrand action_type -- folosit pentru acces admin NECONFIRMAT."""
        n = int(np.count_nonzero(m))
        if not n:
            return 0
        with self._lock:
            sv = self._code("sev", sev_name, add=True)
            lb = self._code("lbl", label, add=True)
            sev, lbl, rk = self.sev.copy(), self.lbl.copy(), self.risk.copy()
            sev[m], lbl[m] = sv, lb
            rk[m] = np.minimum(rk[m], risk)
            self.sev, self.lbl, self.risk = sev, lbl, rk
            self._cache.clear()
            self._lut_cache.clear()
        return n

    def distinct(self, column, limit=300):
        field = {"country": "cc", "action_type": "act", "severity": "sev"}.get(column)
        if column == "http_status":
            u, c = np.unique(self.st, return_counts=True)
            rows = sorted(zip(u.tolist(), c.tolist()), key=lambda x: (-x[1], x[0]))
            return [{"value": int(v), "count": int(n)} for v, n in rows[:limit]]
        if field is None:
            raise ValueError("coloana neacceptata")
        vals = getattr(self, "v_" + field)
        c = np.bincount(getattr(self, field), minlength=len(vals)) if vals else np.zeros(0, np.int64)
        ks = sorted(np.flatnonzero(c).tolist(), key=lambda k: (-int(c[k]), str(vals[k])))
        return [{"value": vals[k], "count": int(c[k])} for k in ks[:limit]]

    def bounds(self):
        if not self.n:
            return {"ts_min": None, "ts_max": None, "total": 0}
        return {"ts_min": int(self.ts.min()), "ts_max": int(self.ts.max()), "total": self.n}

    def admin_session_rows(self, ip, around_ts=None, window_minutes=30):
        """Indicii (ordonati dupa timp) pentru audit trail -- ca
        triage_engine.admin_session. Intoarce (anchor_ts, idx)."""
        ipc = self.d_ip.get(ip, -1)
        if ipc < 0:
            return None, np.zeros(0, np.int64)
        mine = np.flatnonzero(self.ip == ipc)
        if around_ts is None:
            acts = [self.d_act[a] for a in ("admin_login_success", "admin_login_post") if a in self.d_act]
            cand = mine[np.isin(self.act[mine], acts)] if acts else mine[:0]
            if not cand.size:
                return None, np.zeros(0, np.int64)
            around_ts = int(self.ts[cand].max())
        span = window_minutes * 60
        sel = mine[(self.ts[mine] >= around_ts - span) & (self.ts[mine] <= around_ts + span)]
        o = np.lexsort((self.ids_of(sel), self.ts[sel]))
        return around_ts, sel[o]
