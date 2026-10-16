"""
workplace.py -- logscan v47: modulul WORKPLACE (filtrare combinata pe tot logul)

Un query = o lista de CONDITII, toate legate prin AND. Fiecare conditie:
    {"field": "ua", "op": "contains", "values": ["bot", "spider"], "not": false}
  - mai multe valori in aceeasi conditie = OR intre ele;
  - "not": true = excludere (NOT);
  - aceeasi coloana poate aparea in mai multe conditii (ex. UA contine "Mozilla"
    SI NU contine "bot").

Totul ruleaza pe indexul columnar (triage_columnar.ColStore): fiecare conditie
devine o masca booleana; potrivirile text (contine / regex / prefix) se
calculeaza O SINGURA DATA pe valorile UNICE (UA, URL, IP) si se aplica prin
tabel de cautare. Liniile brute se citesc direct din fisier dupa offset.
"""
import ipaddress
import re
import threading

import numpy as np

# ---------------------------------------------------------------- catalog
FIELDS = {
    # field: (eticheta, operatori acceptati)
    "ip":       ("IP", ("in", "cidr", "contains", "prefix")),
    "country":  ("Tara", ("in",)),
    "method":   ("Metoda", ("in",)),
    "status":   ("Cod HTTP", ("in",)),            # 404 sau clasa 4xx
    "path":     ("URL", ("contains", "regex", "prefix", "exact", "suffix")),
    "path_only": ("URL fara query", ("contains", "regex", "prefix", "exact", "suffix")),
    "ext":      ("Extensie", ("in",)),           # php, js, css, img, font, html, xml, json, txt, none
    "query":    ("Query string", ("has", "param")),
    "ua":       ("User-Agent", ("contains", "regex", "exact", "prefix", "empty")),
    "ua_cat":   ("Categorie UA", ("in",)),
    "crawler":  ("Crawler (DNS)", ("in",)),     # verified / fake / unverified / none
    "severity": ("Severitate", ("in",)),
    "action":   ("Actiune", ("in",)),
    "wp":       ("WordPress", ("in",)),
    "size":     ("Marime (B)", ("range",)),
    "hour":     ("Ora (fus orar log)", ("range",)),
    "weekday":  ("Zi din saptamana", ("in",)),
    "ip_hits":  ("Cereri / IP in selectie", ("range",)),
    "ip_paths": ("Path-uri unice / IP in selectie", ("range",)),
    # v50: comportament automat (boti, scanere, scraping) -- calculate tot pe selectie
    "asn":      ("Furnizor (ASN)", ("in", "contains")),
    "ip_rpm":   ("Varf cereri / minut / IP", ("range",)),
    "ip_err":   ("% erori 4xx / IP in selectie", ("range",)),
    "ip_uas":   ("User-Agent-uri diferite / IP", ("range",)),
    "subnet_hits": ("Cereri / subnet in selectie", ("range",)),
}
# conditiile calculate pe IP (sau subnet) in selectia de pana la ele
SEL_FIELDS = ("ip_hits", "ip_paths", "ip_rpm", "ip_err", "ip_uas", "subnet_hits")
UA_CATS = ("Human/Browser", "Legitimate crawler", "AI crawler", "SEO/monitoring", "Social media crawler",
           "Script/tool", "Other crawler/bot", "Suspicious automation", "Unknown/unidentified")
CRAWLER_STATES = ("verified", "fake", "unverified", "none")
EXT_GROUPS = {
    "php": (".php", ".phtml", ".php5", ".php7"),
    "js": (".js", ".mjs"),
    "css": (".css",),
    "img": (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".avif", ".bmp"),
    "font": (".woff", ".woff2", ".ttf", ".otf", ".eot"),
    "html": (".html", ".htm"),
    "xml": (".xml",),
    "json": (".json",),
    "txt": (".txt",),
    "arhiva": (".zip", ".gz", ".tar", ".rar", ".7z", ".sql", ".bak", ".old", ".tgz"),
    "media": (".mp4", ".webm", ".mp3", ".pdf"),
}
WEEKDAYS = ("Lu", "Ma", "Mi", "Jo", "Vi", "Sa", "Du")
MAX_CONDS = 40
MAX_REGEX_LEN = 300


class QueryError(ValueError):
    pass


def _c(field, op, values, not_=False):
    return {"field": field, "op": op, "values": list(values), "not": not_}


# v50: ACTIVITATE AUTOMATA (Security & Triaj) -- categorii de boti / scanari /
# scraping, definite O DATA aici si rulate cu acelasi motor ca Workplace (un
# click pe categorie deschide exact aceleasi conditii in Workplace).
_NOT_VERIFIED = _c("crawler", "in", ["verified"], True)
AUTOMATION = [
    ("vuln_scan", "Scanere de vulnerabilități",
     "Cereri către căi tipice exploit-urilor (phpunit, .env, .git, cgi-bin, vendor, actuator...).",
     [_c("path_only", "regex", [r"(phpunit|/cgi-bin/|/vendor/|/\.env|/\.git|actuator|/solr/|boaform|hnap1|eval-stdin|/\.aws|wp-config\.php\.|phpinfo)"])]),
    ("scan_tools", "Unelte de scanare și atac",
     "User-Agent-ul unei unelte cunoscute: sqlmap, nikto, nuclei, wpscan, zgrab, masscan, gobuster, ffuf...",
     [_c("ua", "regex", ["sqlmap|nikto|nuclei|zgrab|masscan|nmap|wpscan|acunetix|dirbuster|gobuster|ffuf|wfuzz|httpx|nessus|openvas"])]),
    ("auto_scan", "Scanare automată (majoritar erori 4xx)",
     "IP-uri cu cel puțin 30 de cereri, din care peste jumătate primesc 4xx: ghicesc fișiere și rute care nu există.",
     [_c("ip_err", "range", [50, None]), _c("ip_hits", "range", [30, None]), _NOT_VERIFIED]),
    ("brute_login", "Brute force pe autentificare",
     "POST pe wp-login.php / xmlrpc.php, de la IP-uri cu cel puțin 10 astfel de cereri.",
     [_c("method", "in", ["POST"]), _c("path_only", "suffix", ["wp-login.php", "xmlrpc.php"]), _c("ip_hits", "range", [10, None])]),
    ("wp_enum", "Enumerare utilizatori WordPress",
     "?author=N, /wp-json/wp/v2/users, /author/ -- colectarea numelor de cont înaintea unui brute force.",
     [_c("path", "regex", [r"[?&]author=\d|/wp-json/wp/v2/users|/author/"])]),
    ("wp_probe", "Scanare plugin-uri / teme WordPress",
     "Cereri cu 404 către /wp-content/plugins/ sau /themes/: cineva caută componente vulnerabile.",
     [_c("path_only", "regex", ["^/wp-content/(plugins|themes)/"]), _c("status", "in", ["404"])]),
    ("scraping", "Scraping (copiere de conținut)",
     "IP-uri care cer 150+ pagini diferite cu UA de browser, fără assets (img/js/css): un om nu navighează așa.",
     [_c("ext", "in", ["img", "js", "css", "font", "media"], True), _c("ip_paths", "range", [150, None]),
      _c("ua_cat", "in", ["Human/Browser"]), _NOT_VERIFIED]),
    ("bursts", "Rafale rapide (60+ cereri / minut)",
     "IP-uri care au depășit 60 de cereri într-un singur minut (crawlerele verificate DNS sunt excluse).",
     [_c("ip_rpm", "range", [60, None]), _NOT_VERIFIED]),
    ("ua_rotation", "Rotație de User-Agent",
     "Același IP trimite 5+ User-Agent-uri diferite -- tipic boților care încearcă să pară mai mulți vizitatori.",
     [_c("ip_uas", "range", [5, None]), _c("ip_hits", "range", [20, None])]),
    ("fake_bots", "Boți falși (UA de crawler, IP neconfirmat)",
     "Pretind că sunt Googlebot / Bingbot / etc., dar IP-ul nu aparține motorului (verificare DNS).",
     [_c("crawler", "in", ["fake"])]),
    ("scripts", "Scripturi și unelte HTTP",
     "curl, wget, python-requests, Go, Java etc. cu cel puțin 20 de cereri per IP.",
     [_c("ua_cat", "in", ["Script/tool", "Suspicious automation"]), _c("ip_hits", "range", [20, None])]),
]


def _lower(s):
    return s.lower() if isinstance(s, str) else str(s).lower()


class Workplace:
    """Cache-uri derivate pe un ColStore (UA categorii, extensii, ore)."""

    def __init__(self, store, classify_ua, classify_composition, classify_crawler_claim, tz_offset_sec=0):
        self.s = store
        self._lock = threading.Lock()
        self._lut = {}
        self.tz = int(tz_offset_sec)
        self._classify_ua = classify_ua
        self._classify_comp = classify_composition
        self._claim = classify_crawler_claim
        self._ua_cat = None
        self._ua_claim = None
        self._ext = None
        self._hour = None
        self._wd = None
        self._subnet = None
        self._asn = None
        self.asn_name_of = None      # setat de app: ip -> numele furnizorului ("" = necunoscut)

    # ------------------------------------------------------------ derivate
    def ua_cat_codes(self):
        if self._ua_cat is None:
            idx = {c: i for i, c in enumerate(UA_CATS)}
            cats = np.zeros(len(self.s.v_ua), np.int8)
            claim = np.zeros(len(self.s.v_ua), bool)
            for i, ua in enumerate(self.s.v_ua):
                ua = ua or ""
                comp = self._classify_comp(ua, self._classify_ua(ua))
                cats[i] = idx.get(comp, idx["Unknown/unidentified"])
                claim[i] = self._claim(ua) is not None
            self._ua_cat, self._ua_claim = cats, claim
        return self._ua_cat, self._ua_claim

    def ext_codes(self):
        if self._ext is None:
            names = list(EXT_GROUPS) + ["alta", "fara"]
            m = {}
            for g, exts in EXT_GROUPS.items():
                for e in exts:
                    m[e] = names.index(g)
            codes = np.zeros(len(self.s.v_po), np.int8)
            for i, p in enumerate(self.s.v_po):
                last = p.rsplit("/", 1)[-1].lower()
                dot = last.rfind(".")
                if dot <= 0 and not (dot == 0 and len(last) > 1):
                    codes[i] = names.index("fara")
                else:
                    codes[i] = m.get(last[dot:], names.index("alta"))
            self._ext = (codes, names)
        return self._ext

    def hours(self):
        if self._hour is None:
            local = self.s.ts + self.tz
            self._hour = ((local // 3600) % 24).astype(np.int8)
            # 1 ian 1970 = joi (3 in Lu=0)
            self._wd = (((local // 86400) + 3) % 7).astype(np.int8)
        return self._hour, self._wd

    def subnet_codes(self):
        """IP -> cod de subnet (/24 IPv4, /64 IPv6), calculat o data pe IP-urile unice."""
        if self._subnet is None:
            d = {}
            codes = np.zeros(len(self.s.v_ip), np.int64)
            for i, v in enumerate(self.s.v_ip):
                v = v or ""
                if ":" in v:
                    k = ":".join(v.split(":")[:4])
                else:
                    k = v.rsplit(".", 1)[0]
                c = d.get(k)
                if c is None:
                    c = d[k] = len(d)
                codes[i] = c
            self._subnet = (codes, len(d))
        return self._subnet

    def asn_names(self):
        """Numele furnizorului (ASN) pentru fiecare IP unic, calculat o data."""
        if self._asn is None:
            fn = self.asn_name_of
            if fn is None:
                raise QueryError("baza de furnizori (ASN) nu e disponibila")
            self._asn = [(fn(v) or "") for v in self.s.v_ip]
        return self._asn

    # ------------------------------------------------------------ LUT text
    def _text_lut(self, field, op, needle):
        key = (field, op, needle)
        hit = self._lut.get(key)
        if hit is not None:
            return hit
        vals = getattr(self.s, "v_" + field)
        if op == "regex":
            if len(needle) > MAX_REGEX_LEN:
                raise QueryError("regex prea lung")
            try:
                rx = re.compile(needle, re.I)
            except re.error as e:
                raise QueryError(f"regex invalid: {e}")
            fn = lambda v: rx.search(v or "") is not None
        else:
            nl = needle.lower()
            fn = {"contains": lambda v: nl in _lower(v or ""),
                  "prefix": lambda v: _lower(v or "").startswith(nl),
                  "suffix": lambda v: _lower(v or "").endswith(nl),
                  "exact": lambda v: (v or "") == needle}[op]
        lut = np.fromiter((fn(v) for v in vals), dtype=bool, count=len(vals))
        with self._lock:
            if len(self._lut) > 64:
                self._lut.pop(next(iter(self._lut)))
            self._lut[key] = lut
        return lut

    def _cidr_lut(self, nets):
        key = ("cidr", tuple(nets))
        hit = self._lut.get(key)
        if hit is not None:
            return hit
        parsed = []
        for n in nets:
            try:
                parsed.append(ipaddress.ip_network(n.strip(), strict=False))
            except ValueError:
                raise QueryError(f"CIDR invalid: {n}")
        out = np.zeros(len(self.s.v_ip), bool)
        for i, v in enumerate(self.s.v_ip):
            try:
                a = ipaddress.ip_address(v)
            except ValueError:
                continue
            out[i] = any(a.version == p.version and a in p for p in parsed)
        self._lut[key] = out
        return out

    # ------------------------------------------------------------ conditii
    def cond_mask(self, c, base, ctx):
        """Masca pentru O conditie (fara negatie). `base` = masca selectiei
        de pana acum (folosita doar de conditiile pe IP calculate in
        selectie: ip_hits / ip_paths)."""
        s = self.s
        field, op = c.get("field"), c.get("op") or "in"
        vals = [v for v in (c.get("values") or []) if str(v).strip() != ""]
        if field not in FIELDS:
            raise QueryError(f"camp necunoscut: {field}")
        if op not in FIELDS[field][1]:
            raise QueryError(f"operator {op} nu se aplica pe {field}")
        if not vals and op not in ("has", "empty", "range"):
            return None
        n = s.n

        def any_of(fn):
            m = np.zeros(n, bool)
            for v in vals:
                m |= fn(str(v))
            return m

        if field == "ip":
            if op == "in":
                codes = [s.d_ip[v.strip()] for v in map(str, vals) if v.strip() in s.d_ip]
                return np.isin(s.ip, codes)
            if op == "cidr":
                return self._cidr_lut([str(v) for v in vals])[s.ip]
            return any_of(lambda v: self._text_lut("ip", op, v)[s.ip])
        if field == "asn":
            names = self.asn_names()
            if op == "in":
                want = {"" if str(v).strip() == "__NONE__" else str(v).strip() for v in vals}   # __NONE__ = necunoscut
                lut = np.fromiter((x in want for x in names), dtype=bool, count=len(names))
            else:
                nl = [str(v).strip().lower() for v in vals]
                lut = np.fromiter((any(t in x.lower() for t in nl) for x in names), dtype=bool, count=len(names))
            return lut[s.ip]
        if field == "country":
            m = np.zeros(n, bool)
            for v in map(str, vals):
                v = v.strip().upper()
                if v == "__NON_RO__":
                    m |= (s.cc != s.d_cc.get("", -1)) & (s.cc != s.d_cc.get("RO", -1))
                elif v in ("??", ""):
                    m |= s.cc == s.d_cc.get("", -1)
                else:
                    m |= s.cc == s.d_cc.get(v[:2], -1)
            return m
        if field == "method":
            return np.isin(s.me, [s.d_me[v.upper()] for v in map(str, vals) if v.upper() in s.d_me])
        if field == "status":
            m = np.zeros(n, bool)
            for v in map(str, vals):
                v = v.strip().lower()
                if len(v) == 3 and v.endswith("xx") and v[0].isdigit():
                    lo = int(v[0]) * 100
                    m |= (s.st >= lo) & (s.st < lo + 100)
                elif v.isdigit():
                    m |= s.st == int(v)
                else:
                    raise QueryError(f"cod HTTP invalid: {v}")
            return m
        if field in ("path", "path_only"):
            col, src = ("fp", s.fp) if field == "path" else ("po", s.po)
            return any_of(lambda v: self._text_lut(col, op, v)[src])
        if field == "ext":
            codes, names = self.ext_codes()
            want = [names.index(v) for v in map(str, vals) if v in names]
            return np.isin(codes, want)[s.po]
        if field == "query":
            if op == "has":
                want = str(vals[0]).lower() not in ("0", "nu", "false", "no") if vals else True
                q = self._text_lut("fp", "contains", "?")[s.fp]
                return q if want else ~q
            return any_of(lambda v: self._text_lut("fp", "regex", r"[?&]" + re.escape(v) + r"(=|&|$)")[s.fp])
        if field == "ua":
            if op == "empty":
                return self._text_lut("ua", "regex", r"^\s*-?\s*$")[s.ua]
            return any_of(lambda v: self._text_lut("ua", op, v)[s.ua])
        if field == "ua_cat":
            cats, _ = self.ua_cat_codes()
            want = [UA_CATS.index(v) for v in map(str, vals) if v in UA_CATS]
            return np.isin(cats, want)[s.ua]
        if field == "crawler":
            _, claim = self.ua_cat_codes()
            cl = claim[s.ua]
            ver = ctx.get("verified") or set()
            fake = ctx.get("fake") or set()
            vm = np.isin(s.ip, [s.d_ip[i] for i in ver if i in s.d_ip])
            fm = np.isin(s.ip, [s.d_ip[i] for i in fake if i in s.d_ip])
            m = np.zeros(n, bool)
            for v in map(str, vals):
                if v == "verified":
                    m |= cl & vm
                elif v == "fake":
                    m |= cl & fm
                elif v == "unverified":
                    m |= cl & ~vm & ~fm
                elif v == "none":
                    m |= ~cl
            return m
        if field == "severity":
            return np.isin(s.sev, [s.d_sev[v.upper()] for v in map(str, vals) if v.upper() in s.d_sev])
        if field == "action":
            return np.isin(s.act, [s.d_act[v] for v in map(str, vals) if v in s.d_act])
        if field == "wp":
            m = np.zeros(n, bool)
            for v in map(str, vals):
                m |= s._wp_cat_mask(v)
            return m
        lo, hi = _range(c)
        if field == "size":
            return _in_range(s.sz, lo, hi)
        if field == "hour":
            h, _ = self.hours()
            if lo is not None and hi is not None and lo > hi:     # interval peste miezul noptii
                return (h >= lo) | (h <= hi)
            return _in_range(h, lo, hi)
        if field == "weekday":
            _, wd = self.hours()
            want = [WEEKDAYS.index(v) for v in map(str, vals) if v in WEEKDAYS]
            return np.isin(wd, want)
        if field in SEL_FIELDS:
            idx = np.arange(n) if base is None else np.flatnonzero(base)
            nip = len(s.v_ip)
            ipi = s.ip[idx].astype(np.int64)
            if field == "subnet_hits":
                sub, nsub = self.subnet_codes()
                per = np.bincount(sub[ipi], minlength=nsub)
                return _in_range(per, lo, hi)[sub[s.ip]]
            if field == "ip_hits":
                per = np.bincount(ipi, minlength=nip)
            elif field == "ip_paths":
                key = np.unique(ipi * (len(s.v_po) + 1) + s.po[idx])
                per = np.bincount((key // (len(s.v_po) + 1)).astype(np.int64), minlength=nip)
            elif field == "ip_uas":
                nua = len(s.v_ua) + 1
                key = np.unique(ipi * nua + s.ua[idx].astype(np.int64))
                per = np.bincount((key // nua).astype(np.int64), minlength=nip)
            elif field == "ip_rpm":
                if idx.size == 0:
                    return np.zeros(n, bool)
                mins = (s.ts[idx] // 60).astype(np.int64)
                mins -= int(mins.min())
                span = int(mins.max()) + 1
                key, cnt = np.unique(ipi * span + mins, return_counts=True)
                per = np.zeros(nip, np.int64)
                np.maximum.at(per, (key // span).astype(np.int64), cnt)
            else:   # ip_err: procentul de raspunsuri 4xx din cererile IP-ului
                tot = np.bincount(ipi, minlength=nip)
                e4 = np.bincount(ipi, weights=((s.st[idx] >= 400) & (s.st[idx] < 500)), minlength=nip)
                per = np.where(tot > 0, e4 * 100.0 / np.maximum(tot, 1), -1)
                ok = _in_range(per, lo, hi) & (tot > 0)
                return ok[s.ip]
            ok = _in_range(per, lo, hi)
            return ok[s.ip]
        raise QueryError(f"camp neimplementat: {field}")

    def build(self, q, ctx):
        """-> (masca finala sau None, funnel)."""
        s = self.s
        conds = list(q.get("conds") or [])[:MAX_CONDS]
        m = None
        if q.get("ts_from") is not None:
            m = s.ts >= int(q["ts_from"])
        if q.get("ts_to") is not None:
            x = s.ts <= int(q["ts_to"])
            m = x if m is None else (m & x)
        base_n = s.n if m is None else int(np.count_nonzero(m))
        funnel = []
        for i, c in enumerate(conds):
            if c.get("off"):
                continue
            cm = self.cond_mask(c, m, ctx)
            if cm is None:
                continue
            if c.get("not"):
                cm = ~cm
            alone = int(np.count_nonzero(cm if m is None or c.get("field") in SEL_FIELDS
                                         else cm & _period(s, q)))
            m = cm if m is None else (m & cm)
            funnel.append({"i": i, "alone": alone, "after": int(np.count_nonzero(m))})
        return m, base_n, funnel

    # ------------------------------------------------------------ raspuns
    def run(self, q, ctx, raw_path, limit=100, offset=0, sort="ts_desc", facet_n=12):
        s = self.s
        m, base_n, funnel = self.build(q, ctx)
        idx = np.arange(s.n) if m is None else np.flatnonzero(m)
        total = int(idx.size)
        res = {"total": total, "period_total": base_n, "dataset_total": s.n, "funnel": funnel}
        if total:
            res["unique_ips"] = int(np.unique(s.ip[idx]).size)
            res["unique_paths"] = int(np.unique(s.po[idx]).size)
            res["unique_uas"] = int(np.unique(s.ua[idx]).size)
            res["bytes"] = int(s.sz[idx].sum())
            res["ts_min"], res["ts_max"] = int(s.ts[idx].min()), int(s.ts[idx].max())
        else:
            res.update(unique_ips=0, unique_paths=0, unique_uas=0, bytes=0, ts_min=None, ts_max=None)
        res["facets"] = self.facets(idx, facet_n, ctx) if total else {}
        # pagina
        if sort == "ts_asc":
            order = idx[np.lexsort((idx, s.ts[idx]))]
        elif sort == "size_desc":
            order = idx[np.lexsort((idx, -s.sz[idx]))]
        else:
            order = idx[np.lexsort((-idx, -s.ts[idx]))]
        page = order[offset:offset + max(1, min(int(limit), 1000))]
        res["rows"] = self.rows(page, raw_path, ctx)
        res["limit"], res["offset"] = limit, offset
        return res

    def automation(self, ts_from, ts_to, ctx, top_n=5):
        """Categoriile AUTOMATION pe perioada data: cereri, IP-uri, top IP-uri."""
        s = self.s
        out = []
        for key, title, desc, conds in AUTOMATION:
            q = {"ts_from": ts_from, "ts_to": ts_to, "conds": conds}
            m, _, _ = self.build(q, ctx)
            idx = np.arange(s.n) if m is None else np.flatnonzero(m)
            item = {"key": key, "title": title, "desc": desc, "conds": conds,
                    "requests": int(idx.size), "ips": 0, "top": []}
            if idx.size:
                c = np.bincount(s.ip[idx], minlength=len(s.v_ip))
                nz = np.flatnonzero(c)
                item["ips"] = int(nz.size)
                nz = nz[np.argsort(-c[nz], kind="stable")][:top_n]
                cc_of = getattr(s, "ip_cc", None)
                item["top"] = [{"ip": s.v_ip[j], "n": int(c[j]),
                                "country": (s.v_cc[int(cc_of[j])] if cc_of is not None and cc_of[j] >= 0 else "") or "??"}
                               for j in nz.tolist()]
                item["ts_min"], item["ts_max"] = int(s.ts[idx].min()), int(s.ts[idx].max())
            out.append(item)
        return out

    def facets(self, idx, k, ctx):
        s = self.s
        out = {}

        def top(codes, names, minlength, label=lambda x: x):
            c = np.bincount(codes, minlength=minlength)
            nz = np.flatnonzero(c)
            nz = nz[np.argsort(-c[nz], kind="stable")][:k]
            return [{"value": label(names[j]), "n": int(c[j])} for j in nz.tolist()]

        out["ip"] = top(s.ip[idx], s.v_ip, len(s.v_ip))
        out["country"] = top(s.cc[idx], s.v_cc, len(s.v_cc), lambda x: x or "??")
        out["method"] = top(s.me[idx], s.v_me, len(s.v_me))
        u, c = np.unique(s.st[idx], return_counts=True)
        o = np.argsort(-c, kind="stable")[:k]
        out["status"] = [{"value": str(int(u[j])), "n": int(c[j])} for j in o.tolist()]
        out["path_only"] = top(s.po[idx], s.v_po, len(s.v_po))
        out["ua"] = top(s.ua[idx], s.v_ua, len(s.v_ua), lambda x: x or "")
        cats, claim = self.ua_cat_codes()
        out["ua_cat"] = top(cats[s.ua[idx]].astype(np.int64), UA_CATS, len(UA_CATS))
        ver, fake = ctx.get("verified") or set(), ctx.get("fake") or set()
        cl = claim[s.ua[idx]]
        vm = np.isin(s.ip[idx], [s.d_ip[i] for i in ver if i in s.d_ip])
        fm = np.isin(s.ip[idx], [s.d_ip[i] for i in fake if i in s.d_ip])
        cr = [("verified", int(np.count_nonzero(cl & vm))), ("fake", int(np.count_nonzero(cl & fm))),
              ("unverified", int(np.count_nonzero(cl & ~vm & ~fm))), ("none", int(np.count_nonzero(~cl)))]
        out["crawler"] = [{"value": a, "n": b} for a, b in cr if b]
        out["severity"] = top(s.sev[idx], s.v_sev, len(s.v_sev))
        out["action"] = top(s.act[idx], s.v_act, len(s.v_act))
        ext, names = self.ext_codes()
        out["ext"] = top(ext[s.po[idx]].astype(np.int64), names, len(names))
        h, wd = self.hours()
        hc = np.bincount(h[idx], minlength=24)
        out["hour"] = [{"value": i, "n": int(hc[i])} for i in range(24)]
        wc = np.bincount(wd[idx], minlength=7)
        out["weekday"] = [{"value": WEEKDAYS[i], "n": int(wc[i])} for i in range(7)]
        q = self._text_lut("fp", "contains", "?")[s.fp[idx]]
        out["query"] = [{"value": "da", "n": int(np.count_nonzero(q))}, {"value": "nu", "n": int(np.count_nonzero(~q))}]
        return out

    def rows(self, page, raw_path, ctx):
        s = self.s
        cats, claim = self.ua_cat_codes()
        ver, fake = ctx.get("verified") or set(), ctx.get("fake") or set()
        out = []
        f = None
        try:
            f = open(raw_path, "rb")
        except OSError:
            pass
        try:
            for i in page.tolist():
                ip = s.v_ip[int(s.ip[i])]
                raw = ""
                if f is not None:
                    a, ln = int(s.off[i]), int(s.ln[i])
                    if 0 <= ln <= 1 << 16:
                        f.seek(a)
                        raw = f.read(ln).decode("utf-8", errors="replace").rstrip("\r\n")
                cc = s.v_cc[int(s.cc[i])]
                uac = int(s.ua[i])
                crawler = "none"
                if claim[uac]:
                    crawler = "verified" if ip in ver else ("fake" if ip in fake else "unverified")
                out.append({
                    "ts": int(s.ts[i]), "ip": ip, "country": cc or "??", "method": s.v_me[int(s.me[i])],
                    "path": s.v_fp[int(s.fp[i])], "status": int(s.st[i]), "size": int(s.sz[i]),
                    "ua": s.v_ua[uac] or "", "ua_cat": UA_CATS[int(cats[uac])], "crawler": crawler,
                    "severity": s.v_sev[int(s.sev[i])], "action": s.v_act[int(s.act[i])],
                    "id": int(s.ids_of([i])[0]), "raw": raw,
                })
        finally:
            if f is not None:
                f.close()
        return out

    def raw_ranges(self, q, ctx, limit=None):
        """(start, end) contigue in fisier pentru liniile selectate (ordinea
        din fisier) + numarul de linii."""
        s = self.s
        m, _, _ = self.build(q, ctx)
        idx = np.arange(s.n) if m is None else np.flatnonzero(m)
        o = np.argsort(s.off[idx], kind="stable")
        idx = idx[o]
        if limit:
            idx = idx[:int(limit)]
        if not idx.size:
            return [], 0
        a = s.off[idx]
        b = a + s.ln[idx]
        brk = np.flatnonzero(a[1:] != b[:-1]) + 1
        st = np.concatenate(([0], brk))
        en = np.concatenate((brk, [a.size]))
        return list(zip(a[st].tolist(), b[en - 1].tolist())), int(idx.size)


def _range(c):
    v = c.get("values") or []
    def num(x):
        if x is None or str(x).strip() == "":
            return None
        try:
            return int(float(x))
        except ValueError:
            raise QueryError(f"valoare numerica invalida: {x}")
    lo = num(v[0]) if len(v) > 0 else None
    hi = num(v[1]) if len(v) > 1 else None
    return lo, hi


def _in_range(arr, lo, hi):
    m = np.ones(arr.shape[0], bool)
    if lo is not None:
        m &= arr >= lo
    if hi is not None:
        m &= arr <= hi
    return m


def _period(s, q):
    m = np.ones(s.n, bool)
    if q.get("ts_from") is not None:
        m &= s.ts >= int(q["ts_from"])
    if q.get("ts_to") is not None:
        m &= s.ts <= int(q["ts_to"])
    return m
