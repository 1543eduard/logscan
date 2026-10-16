#!/usr/bin/env python3
"""
triage_engine.py -- index SQLite per dataset (logscan v43.2)

Un rand in `events` pentru FIECARE linie valida din log, scris in ACEEASI
trecere cu motorul de agregare din app.py (_process_chunk cu shard), plus:
  - `uas`            : dictionar User-Agent (620 UA distincte la 2.65M linii
                       pe logul real -> 509 MB economisiti fata de a stoca
                       UA-ul inline pe fiecare rand);
  - `minute_rollup`  : totaluri pe minut, pentru histograme instantanee cand
                       singurul filtru e intervalul de timp;
  - `meta`           : rezultate precalculate o singura data la finalizare
                       (valorile pentru dropdown-uri, alertele critice).

Indexul are DOUA roluri:
  1. sursa directa pentru tabul Triaj (tabel, histograma, alerte, audit);
  2. INDEX in fisierul brut: offset_start/offset_end ale fiecarei linii, ca
     drill-down-urile si analiza filtrata sa citeasca doar liniile relevante
     in loc sa rescaneze tot fisierul (vezi app.py: api_raw, summary filtrat).

Fara dependinte de app.py (fara import circular). Fisierul .sqlite traieste
in workdir-ul datasetului si e sters automat de sweeper() la TTL.
"""
import calendar
import json
import os
import sqlite3
import threading

_MON = {m: i + 1 for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"))}


def _day_utc_midnight(day):
    """'05/Oct/2026' -> epoch 00:00 UTC al acelei zile (sau None)."""
    try:
        return calendar.timegm((int(day[7:11]), _MON[day[3:6]], int(day[0:2]), 0, 0, 0))
    except Exception:
        return None

DB_FILENAME = "triage_index.sqlite"

# Ordinea coloanelor in tuplurile produse de app.py (_process_chunk).
COLUMNS = (
    "ts", "ts_str", "ip", "country", "is_non_ro", "method", "path",
    "http_status", "size", "ua_id", "referer", "severity", "risk_score",
    "action_type", "label", "domain", "offset_start", "offset_end",
)

SCHEMA_TABLE = """
CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY,
    ts            INTEGER NOT NULL,
    ts_str        TEXT    NOT NULL,
    ip            TEXT    NOT NULL,
    country       TEXT    NOT NULL DEFAULT '',
    is_non_ro     INTEGER NOT NULL DEFAULT 0,
    method        TEXT    NOT NULL,
    path          TEXT    NOT NULL,
    http_status   INTEGER NOT NULL,
    size          INTEGER NOT NULL DEFAULT 0,
    ua_id         INTEGER NOT NULL DEFAULT 0,
    referer       TEXT    NOT NULL DEFAULT '',
    severity      TEXT    NOT NULL DEFAULT 'INFO',
    risk_score    INTEGER NOT NULL DEFAULT 0,
    action_type   TEXT    NOT NULL DEFAULT 'normal',
    label         TEXT    NOT NULL DEFAULT '',
    domain        TEXT    NOT NULL DEFAULT '',
    offset_start  INTEGER NOT NULL DEFAULT 0,
    offset_end    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS uas (
    id  INTEGER PRIMARY KEY,
    ua  TEXT NOT NULL
);
"""

# Indecsi alesi dupa interogarile reale ale UI-ului (filtru + ORDER BY ts),
# creati DUPA incarcarea in bloc (8 actualizari de B-tree per rand altfel):
# - (coloana, ts) compus => filtru + ordonare pe timp din acelasi index;
# - (country, ts) lipsea in v43.1 => filtrul Tara facea scan complet;
# - offset_start => drill-down pe liniile brute in ordinea din fisier.
SCHEMA_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_events_ts       ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_ip_ts    ON events(ip, ts);
CREATE INDEX IF NOT EXISTS idx_events_country  ON events(country, ts);
CREATE INDEX IF NOT EXISTS idx_events_status   ON events(http_status, ts);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity, ts);
CREATE INDEX IF NOT EXISTS idx_events_action   ON events(action_type, ts);
CREATE INDEX IF NOT EXISTS idx_events_ua       ON events(ua_id);
CREATE INDEX IF NOT EXISTS idx_uas_ua          ON uas(ua);
"""

SCHEMA_ROLLUPS = """
DROP TABLE IF EXISTS minute_rollup;
CREATE TABLE minute_rollup (
    minute    INTEGER PRIMARY KEY,
    total     INTEGER NOT NULL,
    critical  INTEGER NOT NULL,
    high      INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);
"""

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

_WRITE_LOCK = threading.Lock()  # o singura scriere (indexare) per proces la un moment dat

# SELECT folosit pentru orice rand trimis catre UI -- UA-ul reconstituit din
# dictionar, ca frontend-ul sa primeasca exact aceleasi campuri ca inainte.
_EVENT_COLS = ("e.id, e.ts, e.ts_str, e.ip, e.country, e.is_non_ro, e.method, e.path, "
               "e.http_status, e.size, COALESCE(u.ua, '') AS ua, e.referer, e.severity, "
               "e.risk_score, e.action_type, e.label, e.domain, e.offset_start, e.offset_end")


def db_path_for(workdir):
    return os.path.join(workdir, DB_FILENAME)


def connect(db_path, for_write=False):
    """Conexiune noua -- WAL permite multi cititori simultan; scrierile sunt
    serializate prin _WRITE_LOCK."""
    conn = sqlite3.connect(db_path, timeout=30, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.row_factory = sqlite3.Row
    if for_write:
        conn.executescript(SCHEMA_TABLE)
        conn.commit()
    return conn


def connect_shard(db_path):
    """Conexiune de SHARD, folosita DOAR intr-un worker de pool, pe un fisier
    propriu: fara jurnal si fara fsync (daca workerul moare, shardul se
    arunca si indexarea se reia -- nu exista date de pierdut)."""
    conn = sqlite3.connect(db_path, timeout=30)
    conn.execute("PRAGMA journal_mode=OFF")
    conn.execute("PRAGMA synchronous=OFF")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA page_size=16384")   # inainte de prima tabela; -30% la insert
    conn.execute("PRAGMA cache_size=-65536")
    conn.executescript(SCHEMA_TABLE)
    return conn


def adopt_first_shard(db_path, shard_paths):
    """Primul shard DEVINE indexul principal (redenumire, zero copiere); doar
    celelalte se lipesc cu merge_shards. Cu 1 worker nu se copiaza nimic."""
    shard_paths = [p for p in shard_paths if p and os.path.exists(p)]
    if not shard_paths:
        return []
    if os.path.exists(db_path):
        os.unlink(db_path)
    os.replace(shard_paths[0], db_path)
    return shard_paths[1:]


def merge_shards(conn, shard_paths):
    """ATTACH + INSERT...SELECT, integral in SQLite (C). Id-urile din `uas`
    sunt deja unice global (vezi app.py: baza per chunk), deci nu e nevoie
    de nicio remapare."""
    cols = ",".join(COLUMNS)
    total = 0
    with _WRITE_LOCK:
        for sp in shard_paths:
            if not sp or not os.path.exists(sp):
                continue
            conn.execute("ATTACH DATABASE ? AS shard", (sp,))
            try:
                cur = conn.execute(f"INSERT INTO main.events ({cols}) SELECT {cols} FROM shard.events")
                total += max(0, cur.rowcount or 0)
                conn.execute("INSERT OR IGNORE INTO main.uas (id, ua) SELECT id, ua FROM shard.uas")
                conn.commit()
            finally:
                conn.execute("DETACH DATABASE shard")
            try:
                os.unlink(sp)
            except OSError:
                pass
    return total


def create_indexes(conn):
    """Indecsii + ANALYZE (aproximativ, rapid): fara statistici, un filtru pe
    o valoare foarte frecventa (ex. status=200) putea alege indexul de status
    si sorta milioane de randuri in loc sa parcurga direct indexul pe timp."""
    with _WRITE_LOCK:
        conn.executescript(SCHEMA_INDEXES)
        conn.execute("PRAGMA analysis_limit=2000")
        conn.execute("ANALYZE")
        conn.commit()


def finalize_login_success(conn, post_action="admin_login_post", get_action="admin_get",
                             success_action="admin_login_success", window_sec=300):
    """Corelare POST login (302) -> GET /wp-admin/ (200) de la ACEEASI IP in
    max `window_sec` secunde -- oglindeste logica validata din build_summary
    (wp_successful_logins). Facuta in SQL, pe indecsi, pe tot datasetul,
    indiferent de chunk-ul paralel in care a picat fiecare linie.
    Non-RO => CRITICAL (posibil cont compromis); RO => INFO (login reusit)."""
    with _WRITE_LOCK:
        candidates = conn.execute(
            "SELECT id, ip, ts, is_non_ro FROM events WHERE action_type = ? AND http_status = 302",
            (post_action,),
        ).fetchall()
        updated = 0
        for row in candidates:
            hit = conn.execute(
                "SELECT 1 FROM events WHERE ip = ? AND ts >= ? AND ts <= ? AND action_type = ? LIMIT 1",
                (row["ip"], row["ts"], row["ts"] + window_sec, get_action),
            ).fetchone()
            if not hit:
                continue
            if row["is_non_ro"]:
                sev, risk, label = "CRITICAL", 100, "Login WP Admin reusit din IP non-RO -- posibil cont compromis"
            else:
                sev, risk, label = "INFO", 5, "Login WP Admin reusit"
            conn.execute(
                "UPDATE events SET action_type = ?, severity = ?, risk_score = ?, label = ? WHERE id = ?",
                (success_action, sev, risk, label, row["id"]),
            )
            updated += 1
        conn.commit()
    return updated


def build_rollups(conn):
    """Precalculari facute O SINGURA DATA, dupa indexare + corelare login:
    histograma pe minut, valorile dropdown-urilor si alertele critice. Fara
    ele, fiecare deschidere a tabului rescana milioane de randuri (masurat pe
    logul real: histograma 2.6s, filtre 1.2s, alerte 0.8s)."""
    with _WRITE_LOCK:
        conn.executescript(SCHEMA_ROLLUPS)
        conn.execute(
            "INSERT INTO minute_rollup (minute, total, critical, high) "
            "SELECT (ts / 60) * 60, COUNT(*), "
            "SUM(severity = 'CRITICAL'), SUM(severity = 'HIGH') "
            "FROM events GROUP BY 1"
        )
        meta = {
            "filters": {
                "countries": _distinct(conn, "country"),
                "action_types": _distinct(conn, "action_type"),
                "severities": _distinct(conn, "severity"),
                "statuses": _distinct(conn, "http_status"),
            },
            "alerts": _top_alerts_query(conn, 60),
            "wordpress_all": wordpress_block(conn, "", []),
            "error_paths_all": error_block(conn, "", []),
            "bounds": dict(conn.execute(
                "SELECT MIN(ts) AS ts_min, MAX(ts) AS ts_max, COUNT(*) AS total FROM events").fetchone()),
        }
        for k, v in meta.items():
            conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (k, json.dumps(v)))
        conn.commit()


def get_meta(conn, key):
    try:
        row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    except sqlite3.OperationalError:
        return None
    return json.loads(row["value"]) if row else None


def _build_where(filters, alias=""):
    """filters (dict, toate optionale):
       ts_from, ts_to            -- int epoch (UTC)
       countries   (list[str])   -- ISO-2; '__NON_RO__' = orice afara de RO;
                                    '??' sau '' = tara nedeterminata (GeoIP)
       severities  (list[str]), statuses (list[int]), action_types (list[str])
       ip (exact), method (exact), path_contains, ua_contains, ua (exact)
    -> (where_sql, params)"""
    a = (alias + ".") if alias else ""
    clauses = []
    params = []
    if filters.get("ts_from") is not None:
        clauses.append(f"{a}ts >= ?")
        params.append(int(filters["ts_from"]))
    if filters.get("ts_to") is not None:
        clauses.append(f"{a}ts <= ?")
        params.append(int(filters["ts_to"]))
    countries = filters.get("countries") or []
    if countries:
        sub = []
        for c in countries:
            if c == "__NON_RO__":
                sub.append(f"{a}is_non_ro = 1")
            elif c in ("??", ""):
                sub.append(f"{a}country = ''")
            else:
                sub.append(f"{a}country = ?")
                params.append(c.upper()[:2])
        clauses.append("(" + " OR ".join(sub) + ")")
    for key, col, conv in (("severities", "severity", str), ("statuses", "http_status", int),
                           ("action_types", "action_type", str)):
        vals = filters.get(key) or []
        if vals:
            clauses.append(f"{a}{col} IN (%s)" % ",".join(["?"] * len(vals)))
            params.extend(conv(v) for v in vals)
    if filters.get("ip"):
        clauses.append(f"{a}ip = ?")
        params.append(filters["ip"])
    if filters.get("method"):
        clauses.append(f"{a}method = ?")
        params.append(filters["method"].upper())
    if filters.get("path_contains"):
        clauses.append(f"{a}path LIKE ? ESCAPE '\\'")
        params.append("%" + _like_escape(filters["path_contains"]) + "%")
    if filters.get("ua_contains"):
        clauses.append(f"{a}ua_id IN (SELECT id FROM uas WHERE ua LIKE ? ESCAPE '\\')")
        params.append("%" + _like_escape(filters["ua_contains"]) + "%")
    if filters.get("ua"):
        clauses.append(f"{a}ua_id IN (SELECT id FROM uas WHERE ua = ?)")
        params.append(filters["ua"])
    if filters.get("ts_str_day"):
        # Ziua in formatul din log ('05/Oct/2026') -- potrivire EXACTA pe
        # ts_str (aceeasi semantica ca filtrul de zi din analiza v42), plus o
        # fereastra de timp +/-14h in jurul zilei (orice fus orar posibil) ca
        # sa foloseasca indexul pe ts: 335 ms -> 39 ms pe logul real.
        base = _day_utc_midnight(filters["ts_str_day"])
        if base is not None:
            clauses.append(f"{a}ts BETWEEN ? AND ?")
            params.extend([base - 14 * 3600, base + 86400 + 14 * 3600])
        clauses.append(f"{a}ts_str LIKE ? ESCAPE '\\'")
        params.append(_like_escape(filters["ts_str_day"]) + ":%")
    # ---- v45: filtre de entitate (explorer) + EXCLUDERI ------------------
    if filters.get("path_exact") is not None and filters.get("path_exact") != "":
        po = _PO.replace("path", f"{a}path")
        clauses.append(f"{po} = ?")
        params.append(filters["path_exact"])
    sc = [c for c in (filters.get("status_class") or []) if c in _STATUS_CLASSES]
    if sc:
        clauses.append("(" + " OR ".join(f"({a}http_status >= {_STATUS_CLASSES[c]} AND {a}http_status < "
                                          f"{_STATUS_CLASSES[c] + 100})" for c in sc) + ")")
    if filters.get("wp_cat"):
        cond = _WP_ANY if filters["wp_cat"] == "wp_any" else dict(WP_CATEGORIES).get(filters["wp_cat"])
        if cond is None:
            clauses.append("0")
        else:
            for col in ("path", "method"):
                cond = cond.replace(col, f"{a}{col}") if a else cond
            clauses.append(f"({cond})")
    if filters.get("x_ips"):
        clauses.append(f"{a}ip NOT IN (%s)" % ",".join(["?"] * len(filters["x_ips"])))
        params.extend(filters["x_ips"])
    for c in (filters.get("x_countries") or []):
        if c == "__NON_RO__":
            clauses.append(f"NOT ({a}country <> '' AND {a}country <> 'RO')")
        elif c in ("??", ""):
            clauses.append(f"{a}country <> ''")
        else:
            clauses.append(f"{a}country <> ?")
            params.append(c.upper()[:2])
    if filters.get("x_statuses"):
        clauses.append(f"{a}http_status NOT IN (%s)" % ",".join(["?"] * len(filters["x_statuses"])))
        params.extend(int(v) for v in filters["x_statuses"])
    for v in (filters.get("x_paths") or []):
        clauses.append(f"{a}path NOT LIKE ? ESCAPE '\\'")
        params.append("%" + _like_escape(v) + "%")
    for v in (filters.get("x_uas") or []):
        clauses.append(f"{a}ua_id NOT IN (SELECT id FROM uas WHERE ua LIKE ? ESCAPE '\\')")
        params.append("%" + _like_escape(v) + "%")
    for v in (filters.get("_and_path_contains") or []):
        clauses.append(f"{a}path LIKE ? ESCAPE '\\'")
        params.append("%" + _like_escape(v) + "%")
    for v in (filters.get("_and_ua_contains") or []):
        clauses.append(f"{a}ua_id IN (SELECT id FROM uas WHERE ua LIKE ? ESCAPE '\\')")
        params.append("%" + _like_escape(v) + "%")
    if filters.get("_empty"):
        clauses.append("0")
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, params


_STATUS_CLASSES = {"1xx": 100, "2xx": 200, "3xx": 300, "4xx": 400, "5xx": 500}
# chei de filtru noi (v45) -- niciuna nu se poate evalua pe rollup-ul pe minut
# sau pe cub, deci prezenta lor trimite interogarile pe calea generala.
EXTRA_FILTER_KEYS = ("path_exact", "status_class", "wp_cat", "x_ips", "x_countries", "x_statuses",
                     "x_paths", "x_uas", "_and_path_contains", "_and_ua_contains", "_empty")


def _like_escape(s):
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _only_time_filters(filters):
    f = filters or {}
    return not any(f.get(k) not in (None, "", [], ()) for k in (
        "countries", "severities", "statuses", "action_types", "ip", "method", "path_contains",
        "ua_contains", "ua", "ts_str_day") + EXTRA_FILTER_KEYS)


_SEL_MAX = 300000


def _narrow(conn, filters, alias=""):
    """Pentru filtrele de tip "contine" (LIKE '%x%' pe path/UA) -- care nu pot
    folosi un index -- materializam O SINGURA DATA id-urile potrivite intr-un
    tabel temporar al conexiunii, iar toate interogarile cererii (numarare,
    pagina de tabel, histograma, sinteza) ruleaza apoi doar pe acele id-uri.
    Inainte, fiecare interogare repeta scanarea, iar ORDER BY ts facea
    planner-ul sa parcurga indexul de timp cu cate o citire aleatoare per rand
    (masurat: tabel 2.0s, sinteza 7.8s pe logul real). Pentru selectii foarte
    mari (> _SEL_MAX) interogarile directe sunt deja eficiente."""
    where, params = _build_where(filters, alias)
    if not any(filters.get(k) for k in ("path_contains", "ua_contains")):
        return where, params
    # Selectie mare (stiuta exact din cub): materializarea id-urilor ar costa
    # secunde (milioane de INSERT-uri) fara niciun castig -- direct pe index.
    if cube_supports(filters) and cube_ready(conn):
        try:
            w, p = _cube_where(filters)
            if conn.execute(f"SELECT COALESCE(SUM(n), 0) FROM cube{w}", p).fetchone()[0] > _SEL_MAX:
                # "+" opreste folosirea indexului pe ua_id: pentru o selectie
                # mare e mult mai ieftin sa parcurgem indexul de timp si sa
                # filtram (prima pagina: ~0 ms) decat sa luam milioane de
                # randuri prin indexul de UA si sa le sortam (masurat: 1.4s).
                a = (alias + ".") if alias else ""
                return where.replace(f"{a}ua_id IN (SELECT", f"+{a}ua_id IN (SELECT"), params
        except sqlite3.OperationalError:
            pass
    key = json.dumps({k: v for k, v in filters.items() if v not in (None, [], "")}, sort_keys=True, default=str)
    conn.execute("CREATE TEMP TABLE IF NOT EXISTS _sel (id INTEGER PRIMARY KEY)")
    conn.execute("CREATE TEMP TABLE IF NOT EXISTS _selmeta (k TEXT, n INTEGER)")
    row = conn.execute("SELECT k, n FROM _selmeta").fetchone()
    if row is None or row[0] != key:
        w0, p0 = _build_where(filters)
        conn.execute("DELETE FROM _sel")
        conn.execute("DELETE FROM _selmeta")
        conn.execute(f"INSERT INTO _sel SELECT id FROM events{w0}", p0)
        n = conn.execute("SELECT COUNT(*) FROM _sel").fetchone()[0]
        conn.execute("INSERT INTO _selmeta VALUES (?, ?)", (key, n))
    else:
        n = row[1]
    if n > _SEL_MAX:
        return where, params
    a = (alias + ".") if alias else ""
    return f" WHERE {a}id IN (SELECT id FROM _sel)", []


def count_events(conn, filters):
    if any(v not in (None, [], "") for v in filters.values()) and cube_supports(filters) and cube_ready(conn):
        try:
            w, p = _cube_where(filters)
            return conn.execute(f"SELECT COALESCE(SUM(n), 0) FROM cube{w}", p).fetchone()[0]
        except sqlite3.OperationalError:
            pass
    where, params = _narrow(conn, filters)
    if not where:
        b = get_meta(conn, "bounds")
        if b:
            return b["total"]
    row = conn.execute(f"SELECT COUNT(*) AS n FROM events{where}", params).fetchone()
    return row["n"] if row else 0


def query_events(conn, filters, limit=200, offset=0, sort="ts_desc"):
    where, params = _narrow(conn, filters, alias="e")
    order = {
        "ts_desc": "e.ts DESC, e.id DESC",
        "ts_asc": "e.ts ASC, e.id ASC",
        "risk_desc": "e.risk_score DESC, e.ts DESC",
    }.get(sort, "e.ts DESC, e.id DESC")
    limit = max(1, min(int(limit), 2000))
    offset = max(0, int(offset))
    rows = conn.execute(
        f"SELECT {_EVENT_COLS} FROM events e LEFT JOIN uas u ON u.id = e.ua_id"
        f"{where} ORDER BY {order} LIMIT ? OFFSET ?",
        params + [limit, offset],
    ).fetchall()
    return [dict(r) for r in rows]


def build_histogram(conn, ts_from, ts_to, bucket_seconds, filters=None):
    """Histograma pe bucket-uri de timp, cu partea CRITICAL/HIGH separata.
    Cand singurul filtru e intervalul (cazul implicit), se citeste din
    minute_rollup (cateva mii de randuri) in loc de milioane de evenimente."""
    filters = dict(filters or {})
    bucket_seconds = max(60, int(bucket_seconds))
    if _only_time_filters(filters):
        try:
            rows = conn.execute(
                "SELECT (minute / ?) * ? AS bucket, SUM(total) AS total, SUM(critical) AS critical, "
                "SUM(high) AS high FROM minute_rollup WHERE minute >= ? AND minute <= ? "
                "GROUP BY bucket ORDER BY bucket ASC",
                (bucket_seconds, bucket_seconds, (int(ts_from) // 60) * 60, int(ts_to)),
            ).fetchall()
            return [dict(r) for r in rows]
        except sqlite3.OperationalError:
            pass  # index vechi fara rollup -- cadem pe varianta generala
    filters["ts_from"] = ts_from
    filters["ts_to"] = ts_to
    where, params = _narrow(conn, filters)
    rows = conn.execute(
        f"SELECT (ts / ?) * ? AS bucket, COUNT(*) AS total, "
        f"SUM(severity = 'CRITICAL') AS critical, SUM(severity = 'HIGH') AS high "
        f"FROM events{where} GROUP BY bucket ORDER BY bucket ASC",
        [bucket_seconds, bucket_seconds] + params,
    ).fetchall()
    return [dict(r) for r in rows]


def _top_alerts_query(conn, limit):
    rows = conn.execute(
        "SELECT ip, country, is_non_ro, action_type, severity, MAX(risk_score) AS risk_score, "
        "MAX(ts) AS last_ts, MIN(ts) AS first_ts, MAX(path) AS sample_path, MAX(label) AS label, "
        "COUNT(*) AS hits FROM events WHERE severity IN ('CRITICAL','HIGH') "
        "GROUP BY ip, action_type ORDER BY risk_score DESC, last_ts DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def top_alerts(conn, limit=30):
    """Alertele CRITICAL/HIGH, dedup pe (ip, action_type) cu contor -- din
    `meta` (precalculat) cand exista."""
    cached = get_meta(conn, "alerts")
    if cached is not None and len(cached) >= min(limit, len(cached)):
        return cached[:limit]
    return _top_alerts_query(conn, limit)


def admin_session(conn, ip, around_ts=None, window_minutes=30):
    """Audit trail: toate cererile IP-ului in jurul momentului de login
    (+/- window_minutes). Fara around_ts, ancora e ultimul login al IP-ului."""
    if around_ts is None:
        anchor = conn.execute(
            "SELECT ts FROM events WHERE ip = ? AND action_type IN "
            "('admin_login_success','admin_login_post') ORDER BY ts DESC LIMIT 1",
            (ip,),
        ).fetchone()
        around_ts = anchor["ts"] if anchor else None
    if around_ts is None:
        return {"ip": ip, "anchor_ts": None, "events": [], "duration_seconds": 0}
    span = window_minutes * 60
    rows = conn.execute(
        "SELECT e.ts, e.ts_str, e.method, e.path, e.http_status, e.size, COALESCE(u.ua,'') AS ua, "
        "e.referer, e.severity, e.action_type, e.label FROM events e LEFT JOIN uas u ON u.id = e.ua_id "
        "WHERE e.ip = ? AND e.ts BETWEEN ? AND ? ORDER BY e.ts ASC",
        (ip, around_ts - span, around_ts + span),
    ).fetchall()
    events = [dict(r) for r in rows]
    duration = (events[-1]["ts"] - events[0]["ts"]) if len(events) >= 2 else 0
    return {"ip": ip, "anchor_ts": around_ts, "events": events, "duration_seconds": duration}


def _distinct(conn, column, limit=300):
    rows = conn.execute(
        f"SELECT {column} AS v, COUNT(*) AS n FROM events GROUP BY {column} ORDER BY n DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [{"value": r["v"], "count": r["n"]} for r in rows]


def distinct_values(conn, column, limit=300):
    """Valorile REALE din dataset pentru dropdown-uri -- din `meta` cand exista."""
    if column not in ("country", "action_type", "severity", "http_status"):
        raise ValueError("coloana neacceptata")
    cached = get_meta(conn, "filters")
    key = {"country": "countries", "action_type": "action_types",
           "severity": "severities", "http_status": "statuses"}[column]
    if cached and key in cached:
        return cached[key][:limit]
    return _distinct(conn, column, limit)


# Categorii WordPress -- separate (spec §5), cu EXACT definitiile din analiza
# principala (app.py/_process_chunk, contoarele `wp`), ca sinteza filtrata
# (SQL) si cea completa (motorul v42) sa dea aceleasi numere:
#   - LIKE (insensibil la majuscule)  == "x in path.lower()"
#   - GLOB pe path fara query (sensibil) == path_only.endswith("x")
_PO = "(CASE WHEN instr(path,'?') > 0 THEN substr(path, 1, instr(path,'?') - 1) ELSE path END)"
WP_CATEGORIES = (
    ("wp_admin", "path LIKE '%/wp-admin/%'"),
    ("admin_ajax", "path LIKE '%admin-ajax.php%'"),
    ("xmlrpc", "path LIKE '%xmlrpc.php%'"),
    ("wp_json", "path LIKE '%/wp-json/%'"),
    ("wp_cron", f"{_PO} GLOB '*wp-cron.php'"),
    ("wp_login_get", f"({_PO} GLOB '*wp-login.php' OR {_PO} GLOB '*wp-login.php/*') AND method = 'GET'"),
    ("wp_login_post", f"({_PO} GLOB '*wp-login.php' OR {_PO} GLOB '*wp-login.php/*') AND method = 'POST'"),
)
# orice ruta WordPress de mai sus (wp-login.php cu orice metoda)
_WP_ANY = "(" + " OR ".join([c for n, c in WP_CATEGORIES if not n.startswith("wp_login")] +
                            [f"({_PO} GLOB '*wp-login.php' OR {_PO} GLOB '*wp-login.php/*')"]) + ")"
# pre-filtru: orice linie din categoriile de mai sus contine unul din acestea
_WP_PREFILTER = "(path LIKE '%wp-%' OR path LIKE '%xmlrpc.php%' OR path LIKE '%admin-ajax.php%')"


def _and(where, cond):
    return f"{where} AND {cond}" if where else f" WHERE {cond}"


SESSION_GAP_SEC = 1800   # pauza (secunde) dupa care o noua cerere a aceluiasi IP = sesiune noua


def wordpress_block(conn, where, params, sessions=False):
    """Cereri + IP-uri unice + coduri HTTP (+ sesiuni estimate) pe fiecare
    categorie WordPress."""
    sel = ", ".join(f"SUM({c}) AS {n}, COUNT(DISTINCT CASE WHEN {c} THEN ip END) AS {n}_ips"
                    for n, c in WP_CATEGORIES)
    row = conn.execute(f"SELECT {sel} FROM events{_and(where, _WP_PREFILTER)}", params).fetchone()
    out = {k: (row[k] or 0) for k in row.keys()}
    # o linie poate fi in doua categorii (admin-ajax e si sub /wp-admin/) --
    # pentru defalcarea pe coduri o atribuim celei mai specifice.
    order = ("admin_ajax", "wp_login_post", "wp_login_get", "xmlrpc", "wp_json", "wp_cron", "wp_admin")
    cats = dict(WP_CATEGORIES)
    case = " ".join(f"WHEN {cats[n]} THEN '{n}'" for n in order)
    codes = conn.execute(
        f"SELECT CASE {case} END AS cat, http_status AS status, COUNT(*) AS n "
        f"FROM events{_and(where, _WP_PREFILTER)} GROUP BY 1, 2 HAVING cat IS NOT NULL ORDER BY n DESC",
        params).fetchall()
    out["status_by_category"] = [dict(r) for r in codes]
    if sessions:
        # v44: sesiuni ESTIMATE per categorie -- cererile aceluiasi IP fara o
        # pauza mai mare de SESSION_GAP_SEC formeaza o sesiune (spec §5: cereri
        # != IP-uri unice != sesiuni). Estimare, nu sesiuni reale de aplicatie.
        for n, c in WP_CATEGORIES:
            out[n + "_sessions"] = conn.execute(
                f"SELECT COUNT(*) FROM (SELECT ts - LAG(ts) OVER (PARTITION BY ip ORDER BY ts) AS gap "
                f"FROM events{_and(_and(where, _WP_PREFILTER), c)}) WHERE gap IS NULL OR gap > ?",
                list(params) + [SESSION_GAP_SEC]).fetchone()[0]
    return out


def error_block(conn, where, params, top_n=25):
    """Erori 4xx/5xx corelate cu URL, IP-uri si interval (spec §5 -- un 404
    NU e interpretat automat ca atac, doar aratat)."""
    rows = conn.execute(
        f"SELECT http_status AS status, {_PO} AS path, COUNT(*) AS n, COUNT(DISTINCT ip) AS ips, "
        f"MIN(ts) AS first_ts, MAX(ts) AS last_ts FROM events{_and(where, 'http_status >= 400')} "
        f"GROUP BY 1, 2 ORDER BY n DESC LIMIT ?", list(params) + [top_n]).fetchall()
    return [dict(r) for r in rows]


# --------------------------------------------------------------------------
# v43.3 -- CUBUL de agregare (spec §4: "memorarea agregarilor reutilizabile",
# "filtrare pe indexuri, nu scanari complete repetate").
#
# Sinteza panoului de jos e formata EXCLUSIV din numaratori pe chei (IP, URL,
# tara, cod, metoda, severitate, categorie WP) + min/max de timp. Pe logul
# real, 2.65M evenimente se reduc la ~97k combinatii distincte de
# (zi, IP, URL, tara, cod, metoda, severitate, actiune, categorie WP). Cubul
# le precalculeaza O SINGURA DATA (in fundal, dupa indexare); orice selectie
# pe aceste dimensiuni se calculeaza apoi din <=97k randuri in loc de 2.65M --
# EXACT acelasi rezultat (numaratorile se insumeaza, IP-urile/URL-urile unice
# se reunesc, min/max raman min/max). Filtrele pe care cubul nu le poate
# exprima exact (URL/UA "contine", interval mai fin decat ziua) folosesc in
# continuare interogarea directa pe evenimente (overview_sql).
# --------------------------------------------------------------------------
_DAY_EXPR = "(CASE WHEN instr(ts_str, ':') > 0 THEN substr(ts_str, 1, instr(ts_str, ':') - 1) END)"
_CUBE_KEYS = {"countries", "severities", "statuses", "action_types", "ip", "method", "ts_str_day",
              "ua_contains", "ua"}


def build_cube(conn):
    """Construieste tabela `cube` (o data per dataset). Masca WP e calculata
    din ACELEASI conditii SQL ca wordpress_block (pe path-ul complet), deci
    categoriile din cub sunt identice cu cele calculate direct."""
    mask = " + ".join(f"(CASE WHEN {cond} THEN {1 << i} ELSE 0 END)"
                      for i, (_n, cond) in enumerate(WP_CATEGORIES))
    with _WRITE_LOCK:
        conn.executescript(
            "DROP TABLE IF EXISTS cube;"
            "CREATE TABLE cube (day TEXT, ip TEXT, path_only TEXT, country TEXT, "
            "http_status INTEGER, method TEXT, severity TEXT, action_type TEXT, wpmask INTEGER, "
            "ua_id INTEGER, n INTEGER, bytes INTEGER, ts_min INTEGER, ts_max INTEGER);")
        conn.execute(
            f"INSERT INTO cube SELECT {_DAY_EXPR}, ip, {_PO}, country, http_status, method, severity, "
            f"action_type, {mask}, ua_id, COUNT(*), SUM(size), MIN(ts), MAX(ts) FROM events "
            f"GROUP BY 1, 2, 3, 4, 5, 6, 7, 8, 9, 10")
        n = conn.execute("SELECT COUNT(*) FROM cube").fetchone()[0]
        conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
        conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('cube', ?)",
                     (json.dumps({"rows": n}),))
        conn.commit()
    return n


def cube_supports(filters):
    """True daca TOATE filtrele active se pot evalua exact pe cub."""
    for k, v in (filters or {}).items():
        if v in (None, [], "", ()):
            continue
        if k not in _CUBE_KEYS:
            return False
    return True


def _cube_where(filters):
    clauses, params = [], []
    countries = filters.get("countries") or []
    if countries:
        sub = []
        for c in countries:
            if c == "__NON_RO__":
                sub.append("(country <> '' AND country <> 'RO')")   # = is_non_ro din index
            elif c in ("??", ""):
                sub.append("country = ''")
            else:
                sub.append("country = ?")
                params.append(c.upper()[:2])
        clauses.append("(" + " OR ".join(sub) + ")")
    for key, col, conv in (("severities", "severity", str), ("statuses", "http_status", int),
                           ("action_types", "action_type", str)):
        vals = filters.get(key) or []
        if vals:
            clauses.append(f"{col} IN (%s)" % ",".join(["?"] * len(vals)))
            params.extend(conv(v) for v in vals)
    if filters.get("ip"):
        clauses.append("ip = ?")
        params.append(filters["ip"])
    if filters.get("method"):
        clauses.append("method = ?")
        params.append(filters["method"].upper())
    # UA: exact aceeasi subinterogare pe dictionarul `uas` ca in _build_where
    if filters.get("ua_contains"):
        clauses.append("ua_id IN (SELECT id FROM uas WHERE ua LIKE ? ESCAPE '\\')")
        params.append("%" + _like_escape(filters["ua_contains"]) + "%")
    if filters.get("ua"):
        clauses.append("ua_id IN (SELECT id FROM uas WHERE ua = ?)")
        params.append(filters["ua"])
    if filters.get("ts_str_day"):
        # LIKE din _build_where e case-insensitive pe ASCII -> NOCASE identic
        clauses.append("day = ? COLLATE NOCASE")
        params.append(filters["ts_str_day"])
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


def overview_cube(conn, filters, top_n=15):
    """Aceeasi iesire ca overview_sql, calculata din cub (vezi mai sus)."""
    where, params = _cube_where(filters)
    rows = conn.execute(
        f"SELECT ip, path_only, country, http_status, method, severity, wpmask, n, bytes, ts_min, ts_max "
        f"FROM cube{where}", params).fetchall()
    req = 0; bw = 0; tmin = tmax = None; e4 = e5 = unk = 0
    ip_n, ip_cc, ip_f, ip_l = {}, {}, {}, {}
    pa_n, pa_ips = {}, {}
    cc_n, cc_ips = {}, {}
    st_n, me_n, sv_n = {}, {}, {}
    wp_n = [0] * len(WP_CATEGORIES); wp_ips = [set() for _ in WP_CATEGORIES]
    wp_names = [nm for nm, _c in WP_CATEGORIES]
    prio = [wp_names.index(nm) for nm in ("admin_ajax", "wp_login_post", "wp_login_get", "xmlrpc",
                                           "wp_json", "wp_cron", "wp_admin")]
    wp_st = {}
    er = {}
    for ip, po, cc, st, me, sv, mask, n, b, t0, t1 in rows:
        req += n; bw += b or 0
        if tmin is None or t0 < tmin: tmin = t0
        if tmax is None or t1 > tmax: tmax = t1
        if 400 <= st < 500: e4 += n
        elif st >= 500: e5 += n
        if cc == "": unk += n
        ip_n[ip] = ip_n.get(ip, 0) + n
        if cc > ip_cc.get(ip, ""): ip_cc[ip] = cc
        elif ip not in ip_cc: ip_cc[ip] = cc
        if ip not in ip_f or t0 < ip_f[ip]: ip_f[ip] = t0
        if ip not in ip_l or t1 > ip_l[ip]: ip_l[ip] = t1
        pa_n[po] = pa_n.get(po, 0) + n
        pa_ips.setdefault(po, set()).add(ip)
        cc_n[cc] = cc_n.get(cc, 0) + n
        cc_ips.setdefault(cc, set()).add(ip)
        st_n[st] = st_n.get(st, 0) + n
        me_n[me] = me_n.get(me, 0) + n
        sv_n[sv] = sv_n.get(sv, 0) + n
        if mask:
            for i in range(len(WP_CATEGORIES)):
                if mask >> i & 1:
                    wp_n[i] += n
                    wp_ips[i].add(ip)
            for i in prio:
                if mask >> i & 1:
                    k = (wp_names[i], st)
                    wp_st[k] = wp_st.get(k, 0) + n
                    break
        if st >= 400:
            k = (st, po)
            e = er.get(k)
            if e is None:
                er[k] = [n, {ip}, t0, t1]
            else:
                e[0] += n; e[1].add(ip)
                if t0 < e[2]: e[2] = t0
                if t1 > e[3]: e[3] = t1
    none_if_empty = (lambda v: v) if req else (lambda v: None)
    top = lambda d: sorted(d.items(), key=lambda kv: (-kv[1], str(kv[0])))
    out = {
        "requests": req, "unique_ips": len(ip_n), "unique_paths": len(pa_n),
        "bandwidth": none_if_empty(bw), "ts_min": tmin, "ts_max": tmax,
        "err_4xx": none_if_empty(e4), "err_5xx": none_if_empty(e5), "unknown_country": none_if_empty(unk),
        "statuses": [{"status": k, "n": v} for k, v in top(st_n)],
        "methods": [{"method": k, "n": v} for k, v in top(me_n)],
        "top_paths": [{"path": k, "n": v, "ips": len(pa_ips[k])} for k, v in top(pa_n)[:top_n]],
        "top_ips": [{"ip": k, "country": ip_cc[k], "n": v, "first_ts": ip_f[k], "last_ts": ip_l[k]}
                    for k, v in top(ip_n)[:top_n]],
        "countries": [{"country": k, "n": v, "ips": len(cc_ips[k])} for k, v in top(cc_n)[:60]],
        "severities": [{"severity": k, "n": sv_n[k]} for k in sorted(sv_n)],
    }
    wp = {}
    for i, nm in enumerate(wp_names):
        wp[nm] = wp_n[i]
        wp[nm + "_ips"] = len(wp_ips[i])
    wp["status_by_category"] = [{"cat": c, "status": s_, "n": v}
                                for (c, s_), v in sorted(wp_st.items(), key=lambda kv: (-kv[1], kv[0]))]
    out["wordpress"] = wp
    out["error_paths"] = [{"status": s_, "path": po, "n": e[0], "ips": len(e[1]), "first_ts": e[2], "last_ts": e[3]}
                          for (s_, po), e in sorted(er.items(), key=lambda kv: (-kv[1][0], kv[0]))[:25]]
    out["source"] = "cube"
    return out


def cube_ready(conn):
    return get_meta(conn, "cube") is not None


def overview(conn, filters, top_n=15):
    """Dispecer: cubul cand toate filtrele se pot exprima exact pe el si e
    construit; altfel interogarea directa pe evenimente."""
    if cube_supports(filters) and cube_ready(conn):
        try:
            return overview_cube(conn, filters, top_n)
        except sqlite3.OperationalError:
            pass  # cub inca in constructie / index vechi -- varianta directa
    return overview_sql(conn, filters, top_n)


def overview_sql(conn, filters, top_n=15):
    """Sinteza pentru selectia curenta (orice combinatie de filtre): cereri,
    IP-uri unice, URL-uri distincte (fara query string, ca in analiza
    principala), erori, metode, top path-uri/IP-uri/tari, WordPress pe
    categorii. Totul din index, fara a reciti fisierul brut."""
    where, params = _narrow(conn, filters)
    q = lambda sql, extra=(): conn.execute(sql, list(params) + list(extra)).fetchall()
    head = q(f"SELECT COUNT(*) AS requests, COUNT(DISTINCT ip) AS unique_ips, "
             f"COUNT(DISTINCT {_PO}) AS unique_paths, SUM(size) AS bandwidth, "
             f"MIN(ts) AS ts_min, MAX(ts) AS ts_max, "
             f"SUM(http_status >= 400 AND http_status < 500) AS err_4xx, "
             f"SUM(http_status >= 500) AS err_5xx, "
             f"SUM(country = '') AS unknown_country FROM events{where}")[0]
    out = {k: head[k] for k in head.keys()}
    out["statuses"] = [dict(r) for r in q(
        f"SELECT http_status AS status, COUNT(*) AS n FROM events{where} GROUP BY http_status ORDER BY n DESC")]
    out["methods"] = [dict(r) for r in q(
        f"SELECT method, COUNT(*) AS n FROM events{where} GROUP BY method ORDER BY n DESC")]
    out["top_paths"] = [dict(r) for r in q(
        f"SELECT {_PO} AS path, COUNT(*) AS n, COUNT(DISTINCT ip) AS ips "
        f"FROM events{where} GROUP BY 1 ORDER BY n DESC LIMIT ?", (top_n,))]
    out["top_ips"] = [dict(r) for r in q(
        f"SELECT ip, MAX(country) AS country, COUNT(*) AS n, MIN(ts) AS first_ts, MAX(ts) AS last_ts "
        f"FROM events{where} GROUP BY ip ORDER BY n DESC LIMIT ?", (top_n,))]
    out["countries"] = [dict(r) for r in q(
        f"SELECT country, COUNT(*) AS n, COUNT(DISTINCT ip) AS ips FROM events{where} "
        f"GROUP BY country ORDER BY n DESC LIMIT 60")]
    out["severities"] = [dict(r) for r in q(
        f"SELECT severity, COUNT(*) AS n FROM events{where} GROUP BY severity")]
    out["wordpress"] = wordpress_block(conn, where, params, sessions=True)
    out["error_paths"] = error_block(conn, where, params)
    out["source"] = "index"
    return out


def ip_profile(conn, ip, filters=None, top_n=20):
    """Profilul unui IP (spec §5): totaluri, prima/ultima aparitie, URL-uri,
    coduri, metode, UA-uri, accesari WordPress, frecventa, clasificari."""
    f = dict(filters or {})
    f["ip"] = ip
    ov = overview(conn, f, top_n=top_n)
    where, params = _narrow(conn, f, alias="e")
    ov["user_agents"] = [dict(r) for r in conn.execute(
        f"SELECT COALESCE(u.ua,'') AS ua, COUNT(*) AS n FROM events e LEFT JOIN uas u ON u.id = e.ua_id"
        f"{where} GROUP BY e.ua_id ORDER BY n DESC LIMIT 10", params).fetchall()]
    ov["actions"] = [dict(r) for r in conn.execute(
        f"SELECT e.action_type, e.severity, MAX(e.label) AS label, COUNT(*) AS n FROM events e{where} "
        f"GROUP BY e.action_type, e.severity ORDER BY MIN(CASE e.severity WHEN 'CRITICAL' THEN 0 "
        f"WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END), n DESC", params).fetchall()]
    span = (ov["ts_max"] - ov["ts_min"]) if ov.get("ts_min") is not None else 0
    ov["req_per_min"] = round(ov["requests"] / max(1.0, span / 60.0), 2) if ov["requests"] else 0
    peak = conn.execute(
        f"SELECT (e.ts / 60) * 60 AS minute, COUNT(*) AS n FROM events e{where} GROUP BY 1 "
        f"ORDER BY n DESC LIMIT 1", params).fetchone()
    ov["peak_minute"] = dict(peak) if peak else None
    ov["ip"] = ip
    return ov


def candidate_offsets(conn, filters, batch=5000):
    """Generator de (offset_start, offset_end) in ordinea din fisier, pentru
    liniile care POT trece filtrele -- un SUPERSET (LIKE e case-insensitive,
    deci poate intoarce si linii pe care verificarea exacta din app.py le
    respinge). app.py aplica pe fiecare candidat EXACT predicatul original,
    deci rezultatul final e identic cu o scanare completa."""
    where, params = _narrow(conn, filters)
    # ORDER BY id == ordinea din fisier (shard-urile se adopta/lipesc in
    # ordinea chunk-urilor, iar in fiecare shard randurile sunt inserate in
    # ordinea liniilor) -- fara index pe offset si fara sortare: SQLite
    # poate parcurge in ordine si ne putem opri la plafonul de rezultate.
    cur = conn.execute(f"SELECT offset_start, offset_end FROM events{where} ORDER BY id", params)
    while True:
        rows = cur.fetchmany(batch)
        if not rows:
            return
        for r in rows:
            yield r[0], r[1]


# --------------------------------------------------------------------------
# v45 -- calea SQL (fara numpy) pentru panoul de explorare, seria temporala
# pe clase de cod si cronologia de securitate. Aceleasi chei de iesire ca
# triage_columnar.ColStore.explore / timeline / security_groups.
# --------------------------------------------------------------------------
import re as _re
_SEV_CH = "severity IN ('CRITICAL','HIGH')"
_WPC = "path LIKE '%wp-content/%'"
_PLUG_RX = _re.compile(r"/wp-content/(plugins|themes|mu-plugins)/([A-Za-z0-9_.\-]+)", _re.I)


def alerts_in_sql(conn, filters, limit=30):
    where, params = _build_where(filters)
    rows = conn.execute(
        "SELECT ip, country, (country <> '' AND country <> 'RO') AS is_non_ro, action_type, "
        "MIN(CASE severity WHEN 'CRITICAL' THEN 0 ELSE 1 END) AS sr, MAX(risk_score) AS risk_score, "
        "MAX(ts) AS last_ts, MIN(ts) AS first_ts, MAX(path) AS sample_path, MAX(label) AS label, COUNT(*) AS hits "
        f"FROM events{_and(where, _SEV_CH)} GROUP BY ip, action_type "
        "ORDER BY risk_score DESC, last_ts DESC LIMIT ?", list(params) + [limit]).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["severity"] = "CRITICAL" if d.pop("sr") == 0 else "HIGH"
        out.append(d)
    return out


def explore_sql(conn, filters, top_n=15):
    ov = overview_sql(conn, filters, top_n=top_n)
    where, params = _build_where(filters, "e")
    ov["user_agents"] = [dict(r) for r in conn.execute(
        f"SELECT COALESCE(u.ua,'') AS ua, COUNT(*) AS n FROM events e LEFT JOIN uas u ON u.id = e.ua_id"
        f"{where} GROUP BY COALESCE(u.ua,'') ORDER BY n DESC, ua ASC LIMIT 10", params).fetchall()]
    # pe TEXTUL UA (dupa unirea shard-urilor acelasi UA poate avea mai multe id-uri)
    ov["unique_uas"] = conn.execute(f"SELECT COUNT(DISTINCT COALESCE(u.ua,'')) FROM events e "
                                    f"LEFT JOIN uas u ON u.id = e.ua_id{where}", params).fetchone()[0]
    for t in ov["top_ips"]:
        ff = dict(filters); ff["ip"] = t["ip"]
        w2, p2 = _build_where(ff)
        r = conn.execute(f"SELECT SUM(http_status >= 400 AND http_status < 500), SUM(http_status >= 500), "
                         f"COUNT(DISTINCT {_PO}) FROM events{w2}", p2).fetchone()
        t["err_4xx"], t["err_5xx"], t["paths"] = int(r[0] or 0), int(r[1] or 0), int(r[2] or 0)
        span = max(60, t["last_ts"] - t["first_ts"])
        t["per_min"] = round(t["n"] * 60.0 / span, 2)
    w3, p3 = _build_where(filters)
    agg = {}
    for po, ip, st in conn.execute(f"SELECT {_PO}, ip, http_status FROM events{_and(w3, _WPC)}", p3):
        mm = _PLUG_RX.search(po)
        if not mm:
            continue
        k = mm.group(1).lower() + "/" + mm.group(2).lower()
        a = agg.setdefault(k, [0, set(), 0, 0])
        a[0] += 1; a[1].add(ip)
        if 200 <= st < 300: a[2] += 1
        elif 400 <= st < 500: a[3] += 1
    ov["wp_routes"] = [{"route": k, "n": v[0], "ips": len(v[1]), "ok_2xx": v[2], "err_4xx": v[3]}
                       for k, v in sorted(agg.items(), key=lambda kv: (-kv[1][0], kv[0]))[:30]]
    ov["alerts"] = alerts_in_sql(conn, filters, 30)
    ov["sessions_est"] = conn.execute(
        f"SELECT COUNT(*) FROM (SELECT ts - LAG(ts) OVER (PARTITION BY ip ORDER BY ts) AS gap FROM events{w3}) "
        f"WHERE gap IS NULL OR gap > ?", list(p3) + [SESSION_GAP_SEC]).fetchone()[0] if ov["requests"] else 0
    span = (ov["ts_max"] - ov["ts_min"]) if ov.get("ts_min") is not None else 0
    ov["req_per_min"] = round(ov["requests"] / max(1.0, span / 60.0), 2) if ov["requests"] else 0
    pk = conn.execute(f"SELECT (ts / 60) * 60 AS minute, COUNT(*) AS n FROM events{w3} GROUP BY 1 "
                      f"ORDER BY n DESC, minute ASC LIMIT 1", p3).fetchone()
    ov["peak_minute"] = dict(pk) if pk else None
    return ov


def timeline_sql(conn, filters, ts_from, ts_to, bucket_seconds):
    ff = dict(filters or {})
    if ts_from is not None:
        ff["ts_from"] = ts_from if ff.get("ts_from") is None else max(int(ff["ts_from"]), int(ts_from))
    if ts_to is not None:
        ff["ts_to"] = ts_to if ff.get("ts_to") is None else min(int(ff["ts_to"]), int(ts_to))
    b = max(60, int(bucket_seconds))
    where, params = _build_where(ff)
    rows = conn.execute(
        "SELECT (ts / ?) * ? AS bucket, COUNT(*) AS total, "
        "SUM(http_status >= 200 AND http_status < 300) AS c2, SUM(http_status >= 300 AND http_status < 400) AS c3, "
        "SUM(http_status >= 400 AND http_status < 500) AS c4, SUM(http_status >= 500 AND http_status < 600) AS c5, "
        "SUM(severity = 'CRITICAL') AS critical, SUM(severity = 'HIGH') AS high, SUM(severity = 'MEDIUM') AS medium "
        f"FROM events{where} GROUP BY bucket ORDER BY bucket", [b, b] + list(params)).fetchall()
    return [dict(r) for r in rows]


def security_groups_sql(conn, filters, min_severity="MEDIUM", gap=600, limit=400):
    rank_max = SEVERITY_RANK.get(min_severity, 2)
    sevs = [k for k, v in SEVERITY_RANK.items() if v <= rank_max]
    where, params = _build_where(filters)
    cond = "severity IN (%s)" % ",".join("'%s'" % x for x in sevs)
    by_sev = {r[0]: r[1] for r in conn.execute(
        f"SELECT severity, COUNT(*) FROM events{_and(where, cond)} GROUP BY 1", params)}
    rows = conn.execute(f"SELECT id, ip, country, action_type, severity, label, ts, path, http_status FROM events"
                        f"{_and(where, cond)} ORDER BY ip, action_type, ts, id LIMIT 300000", params).fetchall()
    groups, cur = [], None
    for r in rows:
        if cur is None or r["ip"] != cur["ip"] or r["action_type"] != cur["action_type"] or r["ts"] - cur["last_ts"] > gap:
            if cur is not None:
                groups.append(cur)
            cur = {"ip": r["ip"], "country": r["country"], "action_type": r["action_type"], "sr": 9, "label": "",
                   "n": 0, "first_ts": r["ts"], "last_ts": r["ts"], "_paths": {}, "statuses": {}, "first_id": r["id"]}
        cur["n"] += 1
        cur["last_ts"] = r["ts"]
        cur["sr"] = min(cur["sr"], SEVERITY_RANK.get(r["severity"], 4))
        cur["label"] = max(cur["label"], r["label"] or "")
        cur["_paths"][r["path"]] = cur["_paths"].get(r["path"], 0) + 1
        cur["statuses"][r["http_status"]] = cur["statuses"].get(r["http_status"], 0) + 1
    if cur is not None:
        groups.append(cur)
    total_groups = len(groups)
    groups.sort(key=lambda g: -g["first_ts"])
    out = []
    for g in groups[:limit]:
        paths = g.pop("_paths")
        g["sample_path"] = max(sorted(paths), key=lambda k: paths[k])
        g["paths"] = len({p.split("?", 1)[0] for p in paths})
        sr = g.pop("sr")
        g["severity"] = next(k for k, v in SEVERITY_RANK.items() if v == sr)
        out.append(g)
    return {"groups": out, "total_events": sum(by_sev.values()), "total_groups": total_groups, "by_severity": by_sev}
