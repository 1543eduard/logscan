#!/usr/bin/env python3
"""Teste automate logscan (spec §9): parser, agregari, clasificare, index si
filtre. Fara dependinte in plus -- ruleaza cu Python-ul aplicatiei:

    cd /opt/logscan && venv/bin/python3 tests/test_logscan.py

GeoIP e inlocuit cu o tabela fixa, ca rezultatele sa nu depinda de baza
GeoIP instalata pe server."""
import calendar
import inspect
import json
import os
import shutil
import sys
import tempfile
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
APP_DIR = os.path.dirname(HERE)
sys.path.insert(0, APP_DIR)
os.chdir(APP_DIR)
import importlib.util  # noqa: E402

_spec = importlib.util.spec_from_file_location("app", os.path.join(APP_DIR, "app.py"))
app = importlib.util.module_from_spec(_spec)
sys.modules["app"] = app
_spec.loader.exec_module(app)
import triage_engine as te  # noqa: E402
import triage_columnar as tc  # noqa: E402
import csv  # noqa: E402
import io  # noqa: E402
from datetime import datetime  # noqa: E402

GEO = {"8.8.4.4": "US", "220.181.38.148": "CN", "77.88.55.88": "RU", "86.120.5.5": "RO",
       "86.124.0.1": "RO", "86.124.0.2": "RO", "86.124.0.3": "RO", "2a02:2f0e::1": "RO"}
app.country_of = lambda ip: GEO.get(ip, "")


def L(ip, t, method, path, status, size=100, ref="-", ua="Mozilla/5.0"):
    return f'{ip} - - [{t} +0300] "{method} {path} HTTP/1.1" {status} {size} "{ref}" "{ua}"'


FIXTURE = [
    L("86.124.0.1", "05/Oct/2026:10:00:00", "GET", "/", 200),
    L("86.124.0.1", "05/Oct/2026:10:00:05", "GET", "/produs?id=1", 200),
    L("86.124.0.2", "05/Oct/2026:10:01:00", "GET", "/lipsa", 404),
    L("86.124.0.3", "06/Oct/2026:11:00:00", "GET", "/wp-cron.php", 200),
    # non-RO: login reusit (POST 302 + /wp-admin/ 200 in 60s) => CRITICAL
    L("8.8.4.4", "06/Oct/2026:12:00:00", "POST", "/wp-login.php", 302, ua="curl/8.0"),
    L("8.8.4.4", "06/Oct/2026:12:01:00", "GET", "/wp-admin/index.php", 200, ua="curl/8.0"),
    # RO: login reusit => INFO (verde)
    L("86.120.5.5", "06/Oct/2026:13:00:00", "POST", "/wp-login.php", 302),
    L("86.120.5.5", "06/Oct/2026:13:00:30", "GET", "/wp-admin/", 200),
    # RU: POST 302 dar acces wp-admin abia dupa 10 minute => NU e login confirmat
    L("77.88.55.88", "06/Oct/2026:14:00:00", "POST", "/wp-login.php", 302),
    L("77.88.55.88", "06/Oct/2026:14:10:00", "GET", "/wp-admin/", 200),
    # webshell servit (200) vs incercare (404)
    L("220.181.38.148", "07/Oct/2026:09:00:00", "GET", "/wp-content/uploads/2024/x.php", 200),
    L("220.181.38.148", "07/Oct/2026:09:00:05", "GET", "/wp-content/uploads/2024/y.php", 404),
    L("220.181.38.148", "07/Oct/2026:09:01:00", "GET", "/s?q=1%20UNION%20ALL%20SELECT%201,2", 200, ua="sqlmap/1.7"),
    L("220.181.38.148", "07/Oct/2026:09:02:00", "POST", "/xmlrpc.php", 200),
    L("2a02:2f0e::1", "07/Oct/2026:10:00:00", "GET", "/contact", 200),
    L("10.9.9.9", "07/Oct/2026:11:00:00", "GET", "/intern", 200),          # tara nedeterminata
    '86.124.0.1 - - [07/Oct/2026:12:00:00 +0300] "GET /q HTTP/2" 200 10 "-" "\\"Quoted UA\\""',
    '86.124.0.1 - - [07/Oct/2026:12:00:01 +0300] "GET /trunchiat',      # invalida
    'nu este o linie de log',                                             # invalida
    '',                                                                   # goala
    '86.124.0.1 - - [ieri la pranz] "GET /fara-timestamp HTTP/1.1" 200 5 "-" "-"',  # invalida (v44: timestamp)
]

RESULTS = []


def test(fn):
    try:
        fn()
        RESULTS.append((fn.__name__, None))
    except Exception:
        RESULTS.append((fn.__name__, traceback.format_exc()))
    return fn


def build_dataset(lines=FIXTURE, n_chunks=2):
    """Exact fluxul de productie: fisierul e impartit in chunk-uri (workerii
    pool-ului), fiecare scrie un shard SQLite + coloanele indexului columnar.
    Acelasi set de shard-uri e finalizat pe DOUA cai independente -- SQL
    (triage_engine, v43.3) si columnar (triage_columnar, v44) -- ca testele sa
    poata compara rezultatele intre ele."""
    d = tempfile.mkdtemp(prefix="logscan_test_")
    path = os.path.join(d, "plain.log")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    chunks = app.find_chunk_offsets(path, n_chunks)
    parts = [app._process_chunk((path, s, e, None, None, None, None, os.path.join(d, f"shard_{i}.sqlite")))
             for i, (s, e) in enumerate(chunks)]
    shards = [p.pop("_shard") for p in parts]
    part = parts[0] if len(parts) == 1 else app._merge_partials(parts)
    summary = app.build_summary(part)
    dcol = tempfile.mkdtemp(prefix="logscan_test_col_")
    copies = []
    for sp in shards:
        cp = os.path.join(dcol, os.path.basename(sp[0]))
        shutil.copyfile(sp[0], cp)
        copies.append(cp)
    # --- calea SQL (v43.3)
    db = te.db_path_for(d)
    rest = te.adopt_first_shard(db, [sp[0] for sp in shards])
    conn = te.connect(db, for_write=True)
    te.merge_shards(conn, rest)
    te.create_indexes(conn)
    te.finalize_login_success(conn)
    te.build_rollups(conn)
    conn.close()
    # --- calea columnara (v44), pe o copie a acelorasi shard-uri
    store = None
    dbc = te.db_path_for(dcol)
    rest = te.adopt_first_shard(dbc, copies)
    conn = te.connect(dbc, for_write=True)
    te.merge_shards(conn, rest)
    if tc.AVAILABLE:
        store = tc.ColStore.build([sp[2] for sp in shards], conn)
        store.correlate_logins(conn)
    conn.close()
    return d, path, part, summary, db, dcol, dbc, store


D, PATH, PART, SUMMARY, DB, DCOL, DBC, STORE = build_dataset()
N_VALID = len(FIXTURE) - 4   # 3 invalide (una cu timestamp nevalid) + 1 goala


def q(filters):
    c = te.connect(DB)
    try:
        return te.count_events(c, filters)
    finally:
        c.close()


# ---------------------------------------------------------------- parser
@test
def test_parser_linie_valida():
    r = app.parse_line_fast(FIXTURE[1])
    assert r[:4] == ("86.124.0.1", "GET", "/produs?id=1", 200), r
    assert r[6] == "05/Oct/2026:10:00:05 +0300" and r[7] == 100


@test
def test_parser_ipv6_si_ua_cu_ghilimele():
    assert app.parse_line_fast(FIXTURE[14])[0] == "2a02:2f0e::1"
    assert app.parse_line_fast(FIXTURE[16])[5] == '"Quoted UA"'


@test
def test_parser_linii_invalide():
    for bad in (FIXTURE[17], FIXTURE[18], FIXTURE[19],
                '1.2.3.4 - - [05/Oct/2026:10:00:00 +0300] "-" 408 0 "-" "-"'):
        assert app.parse_line_fast(bad) is None, bad


@test
def test_bilant_import():
    lines = SUMMARY["lines"]
    assert lines["processed"] == N_VALID and lines["invalid"] == 3 and lines["blank"] == 1, lines
    assert len(lines["invalid_samples"]) == 3


# ---------------------------------------------------------------- agregari
@test
def test_agregari_v42():
    assert SUMMARY["total"] == N_VALID
    assert SUMMARY["status"]["detail"].get("404") == 2, SUMMARY["status"]
    wp = SUMMARY["wp"]
    assert wp["wp_login_post"] == 3 and wp["xmlrpc"] == 1 and wp["wp_cron"] == 1, wp


@test
def test_sinteza_index_egala_cu_analiza_v42():
    c = te.connect(DB)
    ov = te.overview(c, {})
    c.close()
    assert ov["requests"] == SUMMARY["total"]
    assert ov["unique_ips"] == SUMMARY["unique_ips"]
    assert ov["unique_paths"] == SUMMARY["unique_paths"]
    for k in ("wp_login_post", "wp_login_get", "xmlrpc", "wp_admin", "admin_ajax", "wp_json", "wp_cron"):
        assert ov["wordpress"][k] == SUMMARY["wp"].get(k, 0), (k, ov["wordpress"][k], SUMMARY["wp"].get(k))


# ---------------------------------------------------------------- clasificare
@test
def test_clasificare():
    ce = app.classify_event
    assert ce("x", "GET", "/wp-content/uploads/a.php", 200, "", "-", "CN")[0] == "CRITICAL"
    assert ce("x", "GET", "/wp-content/uploads/a.php", 404, "", "-", "CN")[0] == "HIGH"
    assert ce("x", "GET", "/s?q=1%20UNION%20ALL%20SELECT%201", 200, "", "-", "RO")[0] == "CRITICAL"
    assert ce("x", "POST", "/wp-login.php", 200, "", "-", "US")[:3] == ("MEDIUM", 35, "admin_login_post")
    assert ce("x", "POST", "/wp-login.php", 200, "", "-", "RO")[0] == "LOW"
    # v47: fals pozitive LFI pe slug-uri trunchiate (facebookexternalhit, 301)
    assert ce("x", "GET", "/.../10-perfect-un-10-al.../", 301, "facebookexternalhit/1.1", "-", "US")[:3] == ("INFO", 1, "non_ro")
    assert ce("x", "GET", "/a/titlu.../", 200, "", "-", "RO")[0] == "INFO"
    # traversal real: 2xx -> HIGH, blocat (403) -> MEDIUM; sqli blocat -> HIGH
    assert ce("x", "GET", "/?f=../../etc/hosts", 200, "", "-", "RO")[0] == "CRITICAL"   # ../../ -> familia sqli
    assert ce("x", "GET", "/?f=../x", 200, "", "-", "RO")[:3] == ("HIGH", 65, "pattern_lfi_rfi")
    assert ce("x", "GET", "/?f=../x", 403, "", "-", "RO")[0] == "MEDIUM"
    assert ce("x", "GET", "/s?q=1%20UNION%20ALL%20SELECT%201", 403, "", "-", "RO")[0] == "HIGH"
    assert ce("x", "GET", "/", 200, "", "-", "")[2] == "normal"   # tara necunoscuta != non-RO


@test
def test_corelare_login_reusit():
    c = te.connect(DB)
    rows = {r["ip"]: (r["action_type"], r["severity"]) for r in c.execute(
        "SELECT ip, action_type, severity FROM events WHERE path LIKE '%wp-login%'")}
    c.close()
    assert rows["8.8.4.4"] == ("admin_login_success", "CRITICAL"), rows
    assert rows["86.120.5.5"] == ("admin_login_success", "INFO"), rows
    assert rows["77.88.55.88"][0] == "admin_login_post", rows   # in afara ferestrei de 5 min


# ---------------------------------------------------------------- filtre
@test
def test_filtre_individuale():
    assert q({}) == N_VALID
    assert q({"countries": ["RO"]}) == 8          # 86.124.* x5 (incl. UA citat) + 86.120.5.5 x2 + IPv6 RO
    assert q({"countries": ["??"]}) == 1          # doar 10.9.9.9 -- tara nedeterminata, neinventata
    assert q({"countries": ["__NON_RO__"]}) == 8  # US 2 + RU 2 + CN 4 (necunoscutul NU e non-RO)
    assert q({"ip": "220.181.38.148"}) == 4
    assert q({"statuses": [404]}) == 2
    assert q({"path_contains": "wp-login"}) == 3
    assert q({"ts_str_day": "05/Oct/2026"}) == 3


@test
def test_filtre_combinate_si_interval():
    assert q({"countries": ["CN"], "statuses": [200]}) == 3
    assert q({"path_contains": "wp-", "countries": ["RO"]}) == 3
    t0 = app._fast_epoch("06/Oct/2026:12:00:00 +0300")
    assert q({"ts_from": t0, "ts_to": t0 + 3600}) == 3   # capete incluse: 12:00, 12:01 si 13:00


@test
def test_histograma_si_tabel_coerente():
    c = te.connect(DB)
    for f in ({}, {"countries": ["RO"]}, {"path_contains": "wp-"}):
        h = te.build_histogram(c, 0, 2 ** 31, 3600, dict(f))
        assert sum(b["total"] for b in h) == te.count_events(c, f), f
    c.close()


@test
def test_drilldown_prin_index_identic_cu_scanarea():
    """/raw prin index (offset-uri) == scanarea completa veche."""
    size = os.path.getsize(PATH)
    base = (PATH, 0, size, "220.181.38.148", None, "", None, 100, None, None, None, None, None, None, None, None, None)
    full, _ = app._scan_chunk_raw(base)
    c = te.connect(DB)
    ranges = list(app._coalesce_ranges(te.candidate_offsets(c, {"ip": "220.181.38.148"})))
    c.close()
    via_idx, _ = app._scan_chunk_raw(base[:17] + (ranges,))
    assert [m["raw"] for m in full] == [m["raw"] for m in via_idx] and len(full) == 4


@test
def test_cub_agregare_identic_cu_sinteza_directa():
    """Sinteza din cubul precalculat == sinteza calculata direct pe evenimente,
    pe fiecare filtru pe care cubul il accepta (spec §4: memorare fara
    pierdere de acuratete)."""
    c = te.connect(DB, for_write=True)
    te.build_cube(c)
    def norm(o):
        o = dict(o); o.pop("source", None)
        for k in ("statuses", "methods", "top_paths", "top_ips", "countries", "severities", "error_paths"):
            o[k] = sorted(json.dumps(x, sort_keys=True) for x in o[k])
        w = {k: v for k, v in o["wordpress"].items() if not k.endswith("_sessions")}   # cubul nu are timpii per cerere
        w["status_by_category"] = sorted(json.dumps(x, sort_keys=True) for x in w["status_by_category"])
        o["wordpress"] = w
        return o
    cases = [{}, {"countries": ["RO"]}, {"countries": ["__NON_RO__"]}, {"countries": ["??"]},
             {"statuses": [200, 302]}, {"severities": ["CRITICAL"]}, {"ip": "220.181.38.148"},
             {"method": "post"}, {"ts_str_day": "06/oct/2026"}, {"action_types": ["admin_login_success"]},
             {"countries": ["RO"], "ts_str_day": "05/Oct/2026", "statuses": [404]}, {"ip": "1.1.1.1"},
             {"ua_contains": "curl"}, {"ua_contains": "QUOTED"}, {"ua": "sqlmap/1.7"}, {"ua_contains": "nimic"}]
    for f in cases:
        assert te.cube_supports(f), f
        a, b = te.overview_sql(c, f, top_n=10**6), te.overview_cube(c, f, top_n=10**6)
        assert norm(a) == norm(b), (f, {k for k in norm(a) if norm(a)[k] != norm(b).get(k)})
    # filtrele pe care cubul NU le poate exprima exact merg pe calea directa
    assert not te.cube_supports({"path_contains": "wp"})
    assert not te.cube_supports({"ts_from": 1, "ts_to": 2})
    assert te.overview(c, {"path_contains": "wp-login"})["source"] == "index"
    assert te.overview(c, {"countries": ["RO"]})["source"] == "cube"
    # totalul din cub == numararea directa
    for f in cases[1:]:
        assert te.count_events(c, f) == c.execute(
            "SELECT COUNT(*) FROM events" + te._build_where(f)[0], te._build_where(f)[1]).fetchone()[0], f
    c.close()


# ======================================================================
# v44 -- parser: timestamp, fus orar
# ======================================================================
@test
def test_parser_timestamp_invalid_si_fara_fus_orar():
    ok = '1.2.3.4 - - [05/Oct/2026:10:00:00 +0300] "GET / HTTP/1.1" 200 1 "-" "-"'
    assert app.parse_line_fast(ok) is not None
    for bad in ('1.2.3.4 - - [garbage] "GET / HTTP/1.1" 200 1 "-" "-"',
                '1.2.3.4 - - [] "GET / HTTP/1.1" 200 1 "-" "-"',
                '1.2.3.4 - - [05/Foo/2026:10:00:00 +0300] "GET / HTTP/1.1" 200 1 "-" "-"',
                '1.2.3.4 - - [05/Oct/2026:10:00 +0300] "GET / HTTP/1.1" 200 1 "-" "-"',
                '1.2.3.4 - - [05/Oct/2026:10:00:00 +0300] "GET / HTTP/1.1" 200 1 "\\"x" "y"'.replace('[05/Oct', '[5/Oct')):
        assert app.parse_line_fast(bad) is None, bad
    r = app.parse_line_fast('1.2.3.4 - - [05/Oct/2026:10:00:00] "GET /x HTTP/1.1" 200 1 "-" "-"')
    assert r is not None and app._fast_epoch(r[6]) == calendar.timegm((2026, 10, 5, 10, 0, 0))
    # acelasi moment in doua fusuri orare => acelasi epoch (DST +0300 / +0200)
    assert app._fast_epoch("25/Oct/2026:03:30:00 +0300") == app._fast_epoch("25/Oct/2026:02:30:00 +0200")
    # URL codificat + query + IPv6 pastrate exact (afisarea le escapeaza)
    r = app.parse_line_fast('2a02:2f0e::1 - - [05/Oct/2026:10:00:00 +0300] "GET /a%20b?x=<s>&y=1 HTTP/1.1" 404 0 "-" "-"')
    assert r[0] == "2a02:2f0e::1" and r[2] == "/a%20b?x=<s>&y=1" and r[3] == 404


@test
def test_linii_duplicate_nu_sunt_eliminate():
    """Doua cereri identice in aceeasi secunda sunt DOUA cereri (spec §8)."""
    line = '9.9.9.9 - - [05/Oct/2026:10:00:00 +0300] "GET /dup HTTP/1.1" 200 1 "-" "-"'
    _d, _p, part, summ, _db, _dc, _dbc, st = build_dataset([line, line, line], n_chunks=1)
    assert summ["total"] == 3
    if st is not None:
        assert st.count({"path_contains": "/dup"}) == 3


# ======================================================================
# v44 -- normalizarea tarii (spec §3)
# ======================================================================
@test
def test_normalizare_tara():
    n = app.normalize_country_value
    cases = {"ro": "RO", " RO ": "RO", "de": "DE", "??": "", "": "", "unknown": "", "N/A": "",
             "necunoscut": "", "-": "", "__non_ro__": "__NON_RO__", "__NON_RO__": "__NON_RO__",
             "NA": "NA"}   # NA = Namibia, NU "nedeterminat"
    for k, v in cases.items():
        assert n(k) == v, (k, n(k), v)
    for bad in ("Germany", "R0", "ROU", "ș1", "R"):
        assert n(bad) is None, bad
    f, err = app._gf_checked(country=["ro", "RO", "??"])
    assert err is None and f["countries"] == ["RO", ""], f
    f, err = app._gf_checked(country=["Germany"])
    assert f is None and err.status_code == 400 and b"Germany" in err.body


# ======================================================================
# v44 -- indexul columnar == indexul SQL (aceeasi semantica, alt motor)
# ======================================================================
T0 = app._fast_epoch("06/Oct/2026:12:00:00 +0300")
COL_CASES = [
    {}, {"countries": ["RO"]}, {"countries": ["__NON_RO__"]}, {"countries": ["??"]}, {"countries": [""]},
    {"countries": ["RO", "US"]}, {"countries": ["XX"]}, {"statuses": [200, 302]}, {"statuses": [999]},
    {"severities": ["CRITICAL"]}, {"severities": ["NOPE"]}, {"ip": "220.181.38.148"}, {"ip": "1.1.1.1"},
    {"method": "post"}, {"ts_str_day": "06/oct/2026"}, {"ts_str_day": "01/Jan/2020"},
    {"action_types": ["admin_login_success"]},
    {"countries": ["RO"], "ts_str_day": "05/Oct/2026", "statuses": [404]},
    {"ua_contains": "curl"}, {"ua_contains": "QUOTED"}, {"ua": "sqlmap/1.7"}, {"ua_contains": "nimic"},
    {"path_contains": "wp-login"}, {"path_contains": "WP-"}, {"path_contains": "%20"}, {"path_contains": "_"},
    {"path_contains": "wp-", "countries": ["RO"]},
    {"ts_from": T0, "ts_to": T0 + 3600}, {"ts_from": T0, "ts_to": T0 + 3600, "countries": ["RO"]},
    {"ts_from": T0 + 1}, {"ts_to": T0},
]


def _sqlc():
    return te.connect(DB)


def _norm_ov(o):
    o = dict(o)
    o.pop("source", None)
    o.pop("elapsed_ms", None)
    for k in ("statuses", "methods", "top_paths", "top_ips", "countries", "severities", "error_paths"):
        o[k] = sorted(json.dumps(x, sort_keys=True) for x in o[k])
    w = dict(o["wordpress"])
    w["status_by_category"] = sorted(json.dumps(x, sort_keys=True) for x in w["status_by_category"])
    o["wordpress"] = w
    return o


def _need_store():
    assert tc.AVAILABLE and STORE is not None, "numpy lipseste -- indexul columnar nu poate fi testat"


@test
def test_columnar_numarare_si_sinteza_identice_cu_sql():
    _need_store()
    c = _sqlc()
    try:
        for f in COL_CASES:
            w, p = te._build_where(f)
            exp = c.execute("SELECT COUNT(*) FROM events" + w, p).fetchone()[0]
            assert STORE.count(f) == exp, (f, STORE.count(f), exp)
            a = _norm_ov(te.overview_sql(c, f, top_n=10 ** 6))
            b = _norm_ov(STORE.overview(f, top_n=10 ** 6))
            assert a == b, (f, {k for k in a if a[k] != b.get(k)})
    finally:
        c.close()


@test
def test_columnar_histograma_tabel_offseturi_identice_cu_sql():
    _need_store()
    c = _sqlc()
    try:
        for f in COL_CASES:
            ff = dict(f)
            ff.setdefault("ts_from", 0)
            ff.setdefault("ts_to", 2 ** 31)
            w, p = te._build_where(ff)
            exp = [dict(bucket=r[0], total=r[1], critical=r[2], high=r[3]) for r in c.execute(
                "SELECT (ts / 3600) * 3600, COUNT(*), SUM(severity = 'CRITICAL'), SUM(severity = 'HIGH') "
                "FROM events" + w + " GROUP BY 1 ORDER BY 1", p)]
            got = STORE.histogram(ff["ts_from"], ff["ts_to"], 3600, f)
            assert got == exp, (f, got, exp)
            assert sum(b["total"] for b in got) == STORE.count(ff)
            for sort in ("ts_desc", "ts_asc"):
                ids = STORE.ids_of(STORE.page(f, 1000, 0, sort)).tolist()
                assert ids == [r["id"] for r in te.query_events(c, f, 1000, 0, sort)], (f, sort)
                ids = STORE.ids_of(STORE.page(f, 4, 3, sort)).tolist()
                assert ids == [r["id"] for r in te.query_events(c, f, 4, 3, sort)], (f, sort, "pag")
            got = STORE.offsets(f)
            exp = list(app._coalesce_ranges(te.candidate_offsets(c, f)))
            assert got == exp, (f, got, exp)
    finally:
        c.close()


@test
def test_columnar_corelare_login_identica_cu_sql():
    _need_store()
    a = te.connect(DB)
    b = te.connect(DBC)
    try:
        q = "SELECT id, ip, action_type, severity, risk_score, label, offset_start FROM events ORDER BY id"
        ra = [tuple(r) for r in a.execute(q)]
        rb = [tuple(r) for r in b.execute(q)]
        assert ra == rb
        assert STORE.rowid is None   # id == rand+1 (shard-uri lipite in ordine), verificat pe offset-uri
        for i in range(STORE.n):
            assert STORE.v_act[STORE.act[i]] == ra[i][2] and STORE.v_sev[STORE.sev[i]] == ra[i][3]
            assert int(STORE.risk[i]) == ra[i][4] and STORE.v_lbl[STORE.lbl[i]] == ra[i][5]
            assert int(STORE.off[i]) == ra[i][6]
    finally:
        a.close()
        b.close()


@test
def test_columnar_profil_ip_alerte_filtre_audit():
    _need_store()
    c = _sqlc()
    try:
        for ip in ("8.8.4.4", "220.181.38.148", "86.124.0.1", "10.9.9.9", "2a02:2f0e::1", "nu-exista"):
            for f in ({}, {"ts_from": T0, "ts_to": T0 + 7200}):
                a, b = te.ip_profile(c, ip, f), STORE.ip_profile(ip, f)
                for x in (a, b):
                    x["user_agents"] = sorted(json.dumps(u, sort_keys=True) for u in x["user_agents"])
                    x["actions"] = sorted(json.dumps(u, sort_keys=True) for u in x["actions"])
                    x["peak_n"] = (x.pop("peak_minute") or {}).get("n")
                    # profilul SQL poate veni din cub (fara timpii per cerere => fara sesiuni);
                    # sesiunile sunt comparate cu overview_sql in testul de sinteza
                    x["wordpress"] = {k: v for k, v in x["wordpress"].items() if not k.endswith("_sessions")}
                assert _norm_ov(a) == _norm_ov(b), (ip, f)
        key = lambda r: (r["ip"], r["action_type"], r["severity"], r["risk_score"], r["hits"], r["first_ts"],
                         r["last_ts"], r["sample_path"], r["label"], r["country"])
        assert sorted(map(key, te._top_alerts_query(c, 100))) == sorted(map(key, STORE.top_alerts(100)))
        for col in ("country", "action_type", "severity", "http_status"):
            assert sorted(map(json.dumps, te._distinct(c, col))) == sorted(map(json.dumps, STORE.distinct(col))), col
        for ip in ("8.8.4.4", "86.120.5.5", "77.88.55.88", "86.124.0.1"):
            s = te.admin_session(c, ip)
            anchor, idx = STORE.admin_session_rows(ip)
            assert anchor == s["anchor_ts"], ip
            assert STORE.ids_of(idx).tolist() == [r["id"] for r in c.execute(
                "SELECT id FROM events WHERE ip = ? AND ts BETWEEN ? AND ? ORDER BY ts, id",
                (ip, (anchor or 0) - 1800, (anchor or 0) + 1800))] if anchor else not idx.size, ip
    finally:
        c.close()


@test
def test_columnar_merge_mai_multe_chunkuri():
    """Dictionarele locale ale workerilor se remapeaza corect la lipire."""
    _need_store()
    lines = [FIXTURE[i % 17] for i in range(170) if FIXTURE[i % 17].count('"') >= 6]
    _d, _p, _part, summ, db, _dc, _dbc, st = build_dataset(lines, n_chunks=5)
    c = te.connect(db)
    try:
        assert st.n == summ["total"] == c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        for f in COL_CASES:
            w, p = te._build_where(f)
            assert st.count(f) == c.execute("SELECT COUNT(*) FROM events" + w, p).fetchone()[0], f
            assert _norm_ov(te.overview_sql(c, f, top_n=10 ** 6)) == _norm_ov(st.overview(f, top_n=10 ** 6)), f
    finally:
        c.close()


@test
def test_lipsa_datelor_geografice():
    """GeoIP indisponibil => nicio tara inventata: totul e "nedeterminat",
    filtrul pe o tara anume da 0 rezultate, iar statusul spune DE CE."""
    _need_store()
    real = app.country_of
    app.country_of = lambda ip: ""
    try:
        _d, _p, _part, _s, _db, _dc, _dbc, st = build_dataset(FIXTURE, n_chunks=1)
    finally:
        app.country_of = real
    assert st.distinct("country") == [{"value": "", "count": st.n}]
    ov = st.overview({})
    assert ov["unknown_country"] == ov["requests"] == st.n
    assert st.count({"countries": ["RO"]}) == 0 and st.count({"countries": ["__NON_RO__"]}) == 0
    saved = app._geoip
    app._geoip = None
    try:
        gs = app.geoip_status()
        assert gs["ipv4"] is False and gs["ipv6"] is False
    finally:
        app._geoip = saved


# ======================================================================
# v44 -- rutele HTTP (apelate direct, fara server) -- spec §6/§9
# ======================================================================
def call(fn, **kw):
    args = {}
    for name, p in inspect.signature(fn).parameters.items():
        args[name] = kw[name] if name in kw else getattr(p.default, "default", p.default)
    r = fn(**args)
    return r.status_code, json.loads(r.body)


def _register(store, workdir):
    did = "test_" + os.path.basename(workdir)
    app.DATASETS[did] = {"created": time.time(), "workdir": workdir, "plain_path": PATH, "filename": "t.log",
                         "source_files": ["t.log"], "days_available": SUMMARY["days_available"], "day_offsets": {},
                         "summary_cache": {"ALL": SUMMARY}, "triage_ready": True, "_col": store,
                         "engine": "columnar" if store is not None else "sql"}
    return did


@test
def test_api_tara_filtre_si_panou():
    _need_store()
    did = _register(STORE, DCOL)
    st, js = call(app.api_triage_status, dataset_id=did)
    assert st == 200 and js["engine"] == "columnar" and js["rows"] == N_VALID
    st, a = call(app.api_overview, dataset_id=did, country=["ro"])
    st2, b = call(app.api_overview, dataset_id=did, country=["RO"])
    assert st == st2 == 200 and a["requests"] == b["requests"] == 8
    st, js = call(app.api_overview, dataset_id=did, country=["Germany"])
    assert st == 400 and "ISO" in js["error"]
    st, js = call(app.api_triage_events, dataset_id=did, country=["??"], with_count=True)
    assert st == 200 and js["total"] == 1 and js["events"][0]["ip"] == "10.9.9.9" and js["events"][0]["country"] == ""
    st, js = call(app.api_triage_events, dataset_id=did, country=["__non_ro__"], with_count=True, limit=3)
    assert js["total"] == 8 and len(js["events"]) == 3 and all(e["country"] not in ("", "RO") for e in js["events"])
    st, h = call(app.api_triage_histogram, dataset_id=did, ts_from=0, ts_to=2 ** 31, bucket_seconds=3600, country=["RO"])
    assert sum(x["total"] for x in h["buckets"]) == 8
    st, js = call(app.api_triage_events, dataset_id=did, country=["RO"], status=[404], with_count=True)
    assert js["total"] == 1 and js["events"][0]["path"] == "/lipsa"
    # detaliu eveniment = linia ORIGINALA din fisier, octet cu octet
    st, ev = call(app.api_triage_event, dataset_id=did, id=js["events"][0]["id"])
    assert st == 200 and ev["raw_line"] == FIXTURE[2] and ev["path_only"] == "/lipsa"
    st, ev = call(app.api_triage_event, dataset_id=did, id=999999)
    assert st == 404
    # drill-down brut "non-RO" exclude tara nedeterminata (v44, ca indexul)
    st, js = call(app.api_raw, dataset_id=did, country="__non_ro__", limit=1000)
    assert st == 200 and len(js["matches"]) == 8, len(js["matches"])
    st, js = call(app.api_raw, dataset_id=did, country="Germany")
    assert st == 400
    # profil IP cu semnale justificate
    st, pr = call(app.api_ip_profile, dataset_id=did, ip="220.181.38.148")
    assert st == 200 and pr["requests"] == 4 and any(s["label"].startswith("Evenimente CRITICAL") for s in pr["signals"])
    # alerte + filtre
    st, al = call(app.api_triage_top_alerts, dataset_id=did, limit=5)
    assert st == 200 and al["alerts"] and al["alerts"][0]["severity"] == "CRITICAL"
    st, fl = call(app.api_triage_filters, dataset_id=did)
    assert {c["value"] for c in fl["countries"]} == {"RO", "US", "CN", "RU", ""} and "geoip" in fl
    # Prezentare respecta filtrele globale de continut
    st, ip_ov = call(app.api_ip_overview, dataset_id=did, country=["RO"])
    assert st == 200 and ip_ov["total_requests"] == 8 and ip_ov["global_filters"] == {"countries": ["RO"]}
    st, ip_ov = call(app.api_ip_overview, dataset_id=did)
    assert ip_ov["total_requests"] == N_VALID and ip_ov["global_filters"] == {}


@test
def test_api_cale_sql_fara_numpy_aceleasi_cifre():
    """Fara index columnar (numpy lipsa) rutele raspund identic din SQLite."""
    did_sql = _register(None, D)
    did_col = _register(STORE, DCOL) if STORE is not None else None
    for f in ({"country": ["RO"]}, {"country": ["??"]}, {"status": [404]}, {"path_contains": "wp-"},
              {"country": ["__non_ro__"], "status": [200]}):
        st, a = call(app.api_overview, dataset_id=did_sql, **f)
        assert st == 200
        st, e = call(app.api_triage_events, dataset_id=did_sql, with_count=True, **f)
        assert e["total"] == a["requests"], f
        if did_col:
            st, b = call(app.api_overview, dataset_id=did_col, **f)
            assert a["requests"] == b["requests"] and a["unique_ips"] == b["unique_ips"], f

# ======================================================================
# v45 -- perioada + filtrele globale in TOATE drilldown-urile (2s1.txt)
# Fiecare ruta e comparata cu un calcul direct pe liniile RAW din fixture
# (parsate aici, independent de aplicatie), nu doar cu alta ruta.
# ======================================================================
import re as _re  # noqa: E402
from datetime import datetime as _dt  # noqa: E402

_RAW_RX = _re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) (\d+|-)')


def _raw_rows():
    out = []
    for ln in FIXTURE:
        m = _RAW_RX.match(ln)
        if not m:
            continue
        try:
            ts = int(_dt.strptime(m.group(2), "%d/%b/%Y:%H:%M:%S %z").timestamp())
        except ValueError:
            continue
        out.append({"line": ln, "ip": m.group(1), "ts": ts, "method": m.group(3), "path": m.group(4),
                    "status": int(m.group(5)), "country": GEO.get(m.group(1), "")})
    return out


RAW = _raw_rows()


def EP(s):
    return int(_dt.strptime(s + " +0300", "%d/%b/%Y:%H:%M:%S %z").timestamp())


def _brute(f):
    """Liniile RAW care trec selectia f (doar cheile folosite in teste)."""
    r = RAW
    if f.get("ts_from") is not None:
        r = [x for x in r if x["ts"] >= f["ts_from"]]
    if f.get("ts_to") is not None:
        r = [x for x in r if x["ts"] <= f["ts_to"]]
    if f.get("countries"):
        cs = set(f["countries"])
        r = [x for x in r if x["country"] in cs or (x["country"] == "" and "??" in cs)]
    if f.get("ip"):
        r = [x for x in r if x["ip"] == f["ip"]]
    if f.get("statuses"):
        r = [x for x in r if x["status"] in set(map(int, f["statuses"]))]
    if f.get("x_ips"):
        r = [x for x in r if x["ip"] not in set(f["x_ips"])]
    if f.get("path_contains"):
        r = [x for x in r if f["path_contains"].lower() in x["path"].lower()]
    return r


# perioade si combinatii folosite peste tot
P_A = {"ts_from": EP("06/Oct/2026:12:00:00"), "ts_to": EP("06/Oct/2026:13:59:59")}     # US login + RO login
P_B = {"ts_from": EP("07/Oct/2026:09:00:00"), "ts_to": EP("07/Oct/2026:09:01:30")}     # CN, 3 cereri
P_EMPTY = {"ts_from": EP("05/Oct/2026:15:00:00"), "ts_to": EP("05/Oct/2026:16:00:00")}  # nimic
GF_CASES = [
    {}, P_A, P_B, P_EMPTY,
    dict(P_A, countries=["US"]), dict(P_A, countries=["RO"]), dict(P_A, countries=["??"]),
    dict(P_B, ip="220.181.38.148"), dict(P_B, statuses=[404]), dict(P_A, x_ips=["8.8.4.4"]),
    {"ts_from": EP("05/Oct/2026:00:00:00"), "ts_to": EP("06/Oct/2026:23:59:59"), "countries": ["RO"], "statuses": [200]},
    {"ts_from": EP("06/Oct/2026:12:00:00"), "ts_to": EP("06/Oct/2026:12:00:00")},       # granita exacta: 1 secunda
]


def _drain(resp):
    import asyncio

    async def go():
        out = []
        async for ch in resp.body_iterator:
            out.append(ch if isinstance(ch, bytes) else ch.encode())
        return b"".join(out)
    return asyncio.run(go())


def _gfj(f):
    return json.dumps(f) if f else ""


def _dids():
    out = [("sql", _register(None, D))]
    if STORE is not None:
        out.append(("columnar", _register(STORE, DCOL)))
    return out


@test
def test_gf_merge_entitate_si_selectie():
    m = app._gf_merge
    assert m({"countries": ["RO", "US"]}, {"countries": ["US"]})["countries"] == ["US"]
    assert m({"countries": ["RO"]}, {"countries": ["CN"]}).get("_empty")
    r = m({"ts_from": 10, "ts_to": 100}, {"ts_from": 50, "ts_to": 500})
    assert (r["ts_from"], r["ts_to"]) == (50, 100)
    assert m({"ts_from": 10, "ts_to": 20}, {"ts_from": 30, "ts_to": 40}).get("_empty") or \
        m({"ts_from": 10, "ts_to": 20}, {"ts_from": 30, "ts_to": 40})["ts_from"] > 20
    assert m({"ip": "1.1.1.1"}, {"ip": "2.2.2.2"}).get("_empty")
    assert not m({"ip": "1.1.1.1"}, {"ip": "1.1.1.1"}).get("_empty")
    assert sorted(m({"x_ips": ["a"]}, {"x_ips": ["b"]})["x_ips"]) == ["a", "b"]
    r = m({"path_contains": "wp-"}, {"path_contains": "login"})
    assert r["path_contains"] == "wp-" and r["_and_path_contains"] == ["login"]
    # o contradictie da 0 rezultate, NU tot logul
    c = _sqlc()
    try:
        assert te.count_events(c, m({"countries": ["RO"]}, {"countries": ["CN"]})) == 0
        assert te.count_events(c, r) == len(_brute({"path_contains": "wp-login"}))
    finally:
        c.close()
    if STORE is not None:
        assert STORE.count(m({"countries": ["RO"]}, {"countries": ["CN"]})) == 0
        assert STORE.count(r) == len(_brute({"path_contains": "wp-login"}))


NEW_KEY_CASES = [
    {"path_exact": "/wp-login.php"}, {"path_exact": "/produs"}, {"path_exact": "/nu-exista"},
    {"status_class": ["4xx"]}, {"status_class": ["2xx", "3xx"]}, {"status_class": ["5xx"]},
    {"wp_cat": "wp_login_post"}, {"wp_cat": "wp_admin"}, {"wp_cat": "xmlrpc"}, {"wp_cat": "wp_cron"}, {"wp_cat": "wp_any"},
    {"x_ips": ["86.124.0.1"]}, {"x_countries": ["RO"]}, {"x_countries": ["??"]}, {"x_countries": ["__NON_RO__"]},
    {"x_statuses": [200]}, {"x_paths": ["wp-"]}, {"x_uas": ["curl"]},
    {"path_contains": "wp-", "_and_path_contains": "login"}, {"ua_contains": "mozilla", "_and_ua_contains": "5.0"},
    {"_empty": True}, dict(P_A, status_class=["2xx"]), dict(P_A, x_countries=["RO"], wp_cat="wp_any"),
    {"countries": ["RO"], "x_ips": ["86.124.0.1", "86.124.0.2"], "x_statuses": [404]},
]


@test
def test_columnar_chei_noi_identice_cu_sql():
    """Filtrele noi (URL exact, clasa HTTP, categorie WordPress, excluderi,
    doua conditii "contine") dau aceleasi randuri pe ambele motoare, iar
    explore/timeline/cronologia/alertele sunt identice."""
    _need_store()
    # v47.6: corectiile de runtime (acces admin neconfirmat) se aplica identic
    # si in indexul SQL -- aici sincronizam DB-ul de test cu STORE.
    app._sync_sql_unconfirmed(DB, getattr(STORE, "unconf_demoted_ips", []))
    c = _sqlc()
    try:
        for f in NEW_KEY_CASES + GF_CASES:
            w, p = te._build_where(f)
            exp = c.execute("SELECT COUNT(*) FROM events" + w, p).fetchone()[0]
            assert STORE.count(f) == exp, (f, STORE.count(f), exp)
            a = te.explore_sql(c, f, top_n=10 ** 6)
            b = STORE.explore(f, top_n=10 ** 6)
            for k in ("requests", "unique_ips", "unique_paths", "unique_uas", "sessions_est", "err_4xx", "err_5xx",
                      "ts_min", "ts_max", "peak_minute", "req_per_min"):
                assert a.get(k) == b.get(k), (f, k, a.get(k), b.get(k))
            for k in ("top_ips", "user_agents", "wp_routes", "alerts", "top_paths", "statuses"):
                sa = sorted(json.dumps(x, sort_keys=True) for x in a.get(k) or [])
                sb = sorted(json.dumps(x, sort_keys=True) for x in b.get(k) or [])
                assert sa == sb, (f, k, sa[:3], sb[:3])
            t0, t1 = EP("05/Oct/2026:00:00:00"), EP("07/Oct/2026:23:59:59")
            assert te.timeline_sql(c, f, t0, t1, 3600) == STORE.timeline(f, t0, t1, 3600), f
            for ms in ("MEDIUM", "HIGH", "CRITICAL"):
                ga = te.security_groups_sql(c, f, ms, 600, 400)
                gb = STORE.security_groups(f, ms, 600, 400)
                assert ga == gb, (f, ms, ga, gb)
            assert sorted(json.dumps(x, sort_keys=True) for x in te.alerts_in_sql(c, f, 100)) == \
                sorted(json.dumps(x, sort_keys=True) for x in STORE.alerts_in(f, 100)), f
    finally:
        c.close()


@test
def test_drilldown_uri_respecta_perioada_si_filtrele():
    """Bugul raportat: un drilldown (ex. "Tara US") arata linii din afara
    perioadei selectate. Acum fiecare ruta de drilldown primeste selectia
    globala (gf) si raspunde DOAR din ea -- comparat cu calculul direct pe RAW,
    pe ambele motoare, pentru perioade succesive, perioada goala, granita de
    o secunda si combinatii perioada + tara / IP / cod / excludere."""
    for eng, did in _dids():
        for f in GF_CASES:
            g = _gfj(f)
            exp = _brute(f)
            tag = (eng, f)
            # /raw: drilldown pe tara + selectie (cazul din captura)
            for cc in ("US", "RO", "??"):
                st, js = call(app.api_raw, dataset_id=did, country=cc, gf=g, limit=1000)
                want = [x["line"] for x in exp if (x["country"] or "??") == cc]
                assert st == 200 and [mm["raw"] for mm in js["matches"]] == want, (tag, cc, len(js["matches"]), len(want))
            # /raw pe IP
            st, js = call(app.api_raw, dataset_id=did, ip="220.181.38.148", gf=g, limit=1000)
            assert [mm["raw"] for mm in js["matches"]] == [x["line"] for x in exp if x["ip"] == "220.181.38.148"], tag
            # detaliu IP / subrețele tara / path explorer / ferestre / extragere
            st, js = call(app.api_ip_detail, dataset_id=did, ip="8.8.4.4", gf=g)
            assert st == 200 and js["requests"] == sum(1 for x in exp if x["ip"] == "8.8.4.4"), (tag, js)
            st, js = call(app.api_country_subnets, dataset_id=did, country="RO", gf=g)
            assert st == 200 and js["total_requests"] == sum(1 for x in exp if x["country"] == "RO"), (tag, js)
            st, js = call(app.api_path_breakdown, dataset_id=did, prefix="/", gf=g)
            assert st == 200 and js["parent_total"] == len(exp), (tag, js.get("parent_total"))
            st, js = call(app.api_windows, dataset_id=did, gf=g)
            assert st == 200 and js["total_matching_requests"] == len(exp), (tag, js.get("total_matching_requests"))
            st, js = call(app.api_extract_raw, dataset_id=did, gf=g, limit=1000)
            assert st == 200 and js["total_matching_requests"] == len(exp), tag
            # Prezentare
            st, js = call(app.api_ip_overview, dataset_id=did, gf=g)
            assert st == 200 and js["total_requests"] == len(exp), (tag, js.get("total_requests"))
            # panoul de jos + panoul de explorare (entitate AND selectie)
            st, js = call(app.api_triage_events, dataset_id=did, gf=g, with_count=True, limit=1000, raw=True)
            assert st == 200 and js["total"] == len(exp), tag
            assert sorted(e["raw_line"] for e in js["events"]) == sorted(x["line"] for x in exp), tag
            for kind, val, pred in (("country", "US", lambda x: x["country"] == "US"),
                                    ("ip", "86.120.5.5", lambda x: x["ip"] == "86.120.5.5"),
                                    ("status", "404", lambda x: x["status"] == 404),
                                    ("sclass", "3xx", lambda x: 300 <= x["status"] < 400),
                                    ("path", "/wp-login.php", lambda x: x["path"] == "/wp-login.php"),
                                    ("country", "??", lambda x: x["country"] == "")):
                n = sum(1 for x in exp if pred(x))
                st, js = call(app.api_triage_events, dataset_id=did, gf=g, kind=kind, value=val, with_count=True)
                assert st == 200 and js["total"] == n, (tag, kind, val, js.get("total"), n)
                st, ex = call(app.api_explore, dataset_id=did, gf=g, kind=kind, value=val)
                assert st == 200 and ex["requests"] == n and ex["selection_requests"] == len(exp), (tag, kind, ex["requests"], n)
                if n == 0:
                    assert ex["empty_reason"], (tag, kind)       # mesaj explicit, nu tot logul
                st, tl = call(app.api_timeline, dataset_id=did, gf=g, kind=kind, value=val)
                assert st == 200 and sum(b["total"] for b in tl["buckets"]) == n, (tag, kind)
                if f.get("ts_from") is not None:
                    assert tl["range"][0] >= f["ts_from"] and tl["range"][1] <= f["ts_to"], (tag, tl["range"])
            # export: liniile ORIGINALE ale selectiei, nimic in plus
            r = app.api_export_events(dataset_id=did, gf=g, kind="sel", value="", format="log", limit=10 ** 6)
            body = _drain(r).decode()
            assert body.splitlines() == [x["line"] for x in sorted(exp, key=lambda x: x["ts"])] or \
                sorted(body.splitlines()) == sorted(x["line"] for x in exp), tag
            # alerte / cronologie / sesiune admin: nimic din afara perioadei
            st, al = call(app.api_triage_top_alerts, dataset_id=did, gf=g, limit=100)
            assert st == 200
            for a in al["alerts"]:
                assert any(x["ip"] == a["ip"] for x in exp), (tag, a)
                if f.get("ts_from") is not None:
                    assert f["ts_from"] <= a["first_ts"] <= a["last_ts"] <= f["ts_to"], (tag, a)
            st, sec = call(app.api_security_timeline, dataset_id=did, gf=g, min_severity="MEDIUM")
            assert st == 200
            for gr in sec["groups"]:
                if f.get("ts_from") is not None:
                    assert f["ts_from"] <= gr["first_ts"] <= gr["last_ts"] <= f["ts_to"], (tag, gr)
            st, ad = call(app.api_triage_admin_session, dataset_id=did, ip="8.8.4.4", gf=g)
            assert st == 200
            for e in ad.get("events") or []:
                if f.get("ts_from") is not None:
                    assert f["ts_from"] <= e["ts"] <= f["ts_to"], (tag, e["ts_str"])
            # profilul IP
            st, pr = call(app.api_ip_profile, dataset_id=did, ip="8.8.4.4", gf=g)
            assert st == 200 and pr["requests"] == sum(1 for x in exp if x["ip"] == "8.8.4.4"), tag


@test
def test_perioade_succesive_si_revenire():
    """Doua intervale succesive, apoi revenirea la primul: rezultatele
    depind DOAR de selectia trimisa (nu de cererea precedenta / cache)."""
    for eng, did in _dids():
        seen = []
        for f in (P_A, P_B, P_A, {}, P_EMPTY, P_A):
            st, js = call(app.api_raw, dataset_id=did, country="US", gf=_gfj(f), limit=1000)
            seen.append(len(js["matches"]))
            st, ex = call(app.api_explore, dataset_id=did, gf=_gfj(f), kind="sel", value="")
            assert ex["requests"] == len(_brute(f)), (eng, f)
        assert seen == [2, 0, 2, 2, 0, 2], (eng, seen)


@test
def test_comparatie_perioade_si_eticheta_fus_orar():
    for eng, did in _dids():
        st, ex = call(app.api_explore, dataset_id=did, gf=_gfj(P_A), kind="sel", value="",
                      cmp_from=P_B["ts_from"], cmp_to=P_B["ts_to"])
        assert st == 200 and ex["requests"] == len(_brute(P_A)) and ex["compare"]["requests"] == len(_brute(P_B))
        # eticheta perioadei e in fusul orar al LOGULUI (+0300), nu UTC
        assert "06 Oct 12:00:00" in ex["selection_label"], ex["selection_label"]
        st, ov = call(app.api_ip_overview, dataset_id=did, gf=_gfj(P_A))
        assert "06 Oct 12:00:00" in ov["label"], ov["label"]



# ---------------------------------------------------------------- v47 workplace
def _wp(did, conds, **kw):
    st, js = call(app.api_workplace, dataset_id=did, body={"q": {"conds": conds, **kw}, "limit": 500})
    assert st == 200, js
    return js


def _plines():
    out = []
    for ln in FIXTURE:
        r = app.parse_line_fast(ln)
        if r:
            out.append((r, ln))
    return out


@test
def test_workplace_conditii_identice_cu_scanarea():
    _need_store()
    did = _register(STORE, DCOL)
    P = _plines()
    js = _wp(did, [])
    assert js["total"] == N_VALID and js["rows"][0]["raw"]
    exp = sum(1 for r, _ in P if "curl" in r[5].lower())
    assert _wp(did, [{"field": "ua", "op": "contains", "values": ["CURL"]}])["total"] == exp
    exp = sum(1 for r, _ in P if "curl" not in r[5].lower() and r[3] >= 400)
    js = _wp(did, [{"field": "ua", "op": "contains", "values": ["curl"], "not": True},
                   {"field": "status", "values": ["4xx", "5xx"]}])
    assert js["total"] == exp, (js["total"], exp)
    assert js["funnel"][-1]["after"] == exp and len(js["funnel"]) == 2
    exp = sum(1 for r, _ in P if r[0].startswith("86.124."))
    assert _wp(did, [{"field": "ip", "op": "cidr", "values": ["86.124.0.0/16"]}])["total"] == exp
    exp = sum(1 for r, _ in P if r[1] == "POST")
    assert _wp(did, [{"field": "method", "values": ["post"]}])["total"] == exp
    exp = sum(1 for r, _ in P if r[2].split("?")[0].endswith(".php"))
    assert _wp(did, [{"field": "ext", "values": ["php"]}])["total"] == exp
    exp = sum(1 for r, _ in P if "?" in r[2])
    assert _wp(did, [{"field": "query", "op": "has", "values": ["da"]}])["total"] == exp
    js = _wp(did, [{"field": "ua", "op": "regex", "values": ["^mozilla"]}])
    assert js["total"] == sum(1 for r, _ in P if r[5].lower().startswith("mozilla"))
    st, e = call(app.api_workplace, dataset_id=did, body={"q": {"conds": [{"field": "ua", "op": "regex", "values": ["("]}]}})
    assert st == 400
    # cereri / IP in selectie
    from collections import Counter as _C
    c = _C(r[0] for r, _ in P)
    exp = sum(n for n in c.values() if n >= 2)
    assert _wp(did, [{"field": "ip_hits", "op": "range", "values": [2, None]}])["total"] == exp
    # liniile brute exportate = exact liniile din fisier
    r = app.api_workplace_raw(did, {"q": {"conds": [{"field": "ua", "op": "contains", "values": ["curl"]}]}})
    import asyncio
    async def _collect():
        return b"".join([c async for c in r.body_iterator])
    body = asyncio.run(_collect()).decode()
    assert body.splitlines() == [ln for rr, ln in P if "curl" in rr[5].lower()]


@test
def test_crawler_verificat_retrogradat():
    _need_store()
    d, path, part, summary, db, dcol, dbc, store = build_dataset()
    did = _register(store, dcol)
    app.DATASETS[did]["id"] = did
    hi = [i for i in range(store.n) if store.v_sev[store.sev[i]] in ("CRITICAL", "HIGH")]
    assert hi
    ip = store.v_ip[store.ip[hi[0]]]
    with app._CRAWLER_JOBS_LOCK:
        app._CRAWLER_JOBS[did] = {"results": {ip: {"verified": True, "identity": "Googlebot"}}, "pending": False}
    try:
        s2 = app._col_store(app.DATASETS[did])
        keep = set(tc.ColStore.FP_KEEP_ACTIONS)
        for i in range(s2.n):
            if s2.v_ip[s2.ip[i]] == ip and s2.v_act[s2.act[i]] not in keep:
                assert s2.v_sev[s2.sev[i]] == "INFO"
        st, js = call(app.api_triage_top_alerts, dataset_id=did)
        assert all(a["ip"] != ip or a["action_type"] in keep for a in js["alerts"])
    finally:
        app._CRAWLER_JOBS.pop(did, None)

@test
def test_incidente_si_traseu_ip():
    """v47.2: ip_trail = TOATE cererile IP-ului, crescator, cu linia bruta
    identica cu fisierul; /incidents contine IP-urile cu CRITICAL/HIGH."""
    _need_store()
    did = _register(STORE, DCOL)
    file_lines = open(PATH, encoding="utf-8").read().split("\n")
    hi_ips = sorted({STORE.v_ip[STORE.ip[i]] for i in range(STORE.n)
                     if STORE.v_sev[STORE.sev[i]] in ("CRITICAL", "HIGH")})
    assert hi_ips
    st, inc = call(app.api_incidents, dataset_id=did)
    assert st == 200, inc
    got = {x["ip"] for x in inc["incidents"]}
    # v47.6: IP-urile doar cu semnale de autentificare sunt in "Acces WP admin",
    # nu in Incidente; impreuna acopera TOT si nu se suprapun.
    st, adm = call(app.api_admin_access, dataset_id=did)
    cov = {x["ip"] for k in ("successes", "unconfirmed", "attempts") for x in adm[k]}
    assert set(hi_ips) <= got | cov, (hi_ips, got, cov)
    assert inc["total"] == len(inc["incidents"]) and inc["total"] + inc["admin_only_total"] == inc["candidates_total"]
    assert all(x["is_attack"] for x in inc["incidents"])
    for x in inc["incidents"]:
        assert x["before"] + x["after"] + (1 if x["first_significant"] else 0) == x["requests"]
    for ip in {STORE.v_ip[c] for c in STORE.ip.tolist()}:
        st, tr = call(app.api_ip_trail, dataset_id=did, ip=ip)
        assert st == 200, tr
        n = sum(1 for i in range(STORE.n) if STORE.v_ip[STORE.ip[i]] == ip)
        ev = tr["events"]
        assert tr["total"] == n == len(ev), (ip, n, len(ev))
        assert [e["ts"] for e in ev] == sorted(e["ts"] for e in ev)
        for e in ev:
            assert e["raw"] in file_lines and e["raw"].split(" ", 1)[0] == ip, e["raw"]
        exp = sorted(l for l in file_lines if l.split(" ", 1)[0] == ip and l in {e["raw"] for e in ev})
        assert sorted(e["raw"] for e in ev) == exp
        if ip in hi_ips:
            k = tr["first_significant_index"]
            assert k is not None and ev[k]["severity"] in ("CRITICAL", "HIGH") and ev[k]["first_significant"]
            assert all(e["phase"] == "inainte" for e in ev[:k]) and all(e["phase"] == "dupa" for e in ev[k:])
            assert all(e["severity"] not in ("CRITICAL", "HIGH") for e in ev[:k])
        st, sg = call(app.api_ip_trail, dataset_id=did, ip=ip, only="significant")
        assert all(e["severity"] in ("CRITICAL", "HIGH", "MEDIUM") or e["method"] == "POST" for e in sg["events"])
    st, none = call(app.api_ip_trail, dataset_id=did, ip="1.2.3.4")
    assert st == 200 and none["total"] == 0 and none["events"] == []


@test
def test_acces_admin_reusit_si_incercari():
    """v47.3: secventa reala (login prin /wp-login.php/ cu PATH_INFO, apoi
    upload de plugin blocat 403) -> IP in "acces reusit" cu actiunile
    clasificate; IP-ul care doar incearca parole -> "incercari"."""
    _need_store()
    A, B, C = "104.28.245.128", "203.0.113.9", "149.36.51.165"
    GEO[A] = "ID"; GEO[B] = "VN"; GEO[C] = "DE"
    ch = "Mozilla/5.0 Chrome/120.0.0.0"
    lines = [
        L(A, "09/Oct/2026:21:22:05", "POST", "/wp-json/batch/v1", 207, ua="Mozilla/5.0 Chrome/131.0.0.0"),
        L(A, "09/Oct/2026:21:23:07", "GET", "/wp-login.php/", 200, ua=ch),
        L(A, "09/Oct/2026:21:23:09", "POST", "/wp-login.php/", 302, ua=ch),
        L(A, "09/Oct/2026:21:23:25", "GET", "/wp-admin/", 200, ua=ch),
        L(A, "09/Oct/2026:21:24:45", "GET", "/wp-admin/plugin-install.php?tab=upload", 200, ua=ch),
        L(A, "09/Oct/2026:21:25:10", "GET", "/wp-admin/theme-editor.php", 200, ua=ch),
        L(A, "09/Oct/2026:21:25:22", "POST", "/wp-admin/update.php?action=upload-plugin", 403, ua=ch),
        L(A, "09/Oct/2026:21:25:28", "POST", "/wp-admin/update.php?action=upload-plugin", 403, ua=ch),
        L(A, "09/Oct/2026:21:25:30", "GET", "/wp-admin/plugins.php?action=activate&plugin=x%2Fx.php", 302, ua=ch),
    ] + [L(B, f"09/Oct/2026:22:00:{i:02d}", "POST", "/wp-login.php", 200) for i in range(12)] + [
        # scanner pe o cale fara WordPress: site-ul raspunde 200 la orice URL
        L(C, "12/Oct/2026:11:35:08", "GET", "/xml/wp-admin/", 200),
        L(C, "12/Oct/2026:11:35:09", "POST", "/xml/wp-admin/index.php", 200),
        L(C, "12/Oct/2026:11:35:09", "POST", "/xml/wp-login.php", 403),
        # v47.5: 1 pagina admin + load-styles, fara login -> neconfirmat
        L("180.243.0.174", "11/Oct/2026:03:45:19", "GET", "/wp-admin/", 200),
        L("180.243.0.174", "11/Oct/2026:03:45:20", "GET", "/wp-admin/load-styles.php?c=0", 200),
    ]
    try:
        d, path, part, summary, db, dcol, dbc, store = build_dataset(FIXTURE + lines)
        global PATH
        old = PATH
        PATH = path
        did = _register(store, dcol)
        app.DATASETS[did]["summary_cache"] = {"ALL": summary}
        st, js = call(app.api_admin_access, dataset_id=did)
        PATH = old
        assert st == 200, js
        ok = {x["ip"]: x for x in js["successes"]}
        assert A in ok, list(ok)
        assert "180.243.0.174" not in ok
        unc = {x["ip"]: x for x in js["unconfirmed"]}
        assert "180.243.0.174" in unc and unc["180.243.0.174"]["distinct_admin_pages"] == 1
        assert all("load-styles" not in gg["label"] for gg in unc["180.243.0.174"]["groups"])
        a = ok[A]
        assert a["session_mode"] == "login" and len(a["login_ts"]) == 1, a["login_ts"]
        g = {x["key"]: x for x in a["groups"]}
        assert g["plugin_upload"]["n"] == 2 and g["plugin_upload"]["results"] == {"blocat": 2}
        assert not g["theme_editor"]["critical"] and g["theme_editor"]["sensitive"]
        assert g["plugin_activate"]["results"] == {"redirect": 1} and g["plugin_activate"]["confirmed"] == 0
        assert "plugin_upload_page" in g and "CU SUCCES" in a["narrative"] and "BLOCAT" in a["narrative"]
        assert [e["ts"] for e in a["timeline"]] == sorted(e["ts"] for e in a["timeline"])
        assert all("/wp-json/batch" not in e["url"] for e in a["timeline"])
        tr = {x["ip"]: x for x in js["attempts"]}
        assert B in tr and tr[B]["attempts"] == 12 and tr[B]["n_302"] == 0 and B not in ok
        assert A not in tr
        # v47.4: /xml/wp-admin/ cu 200 = sondare (raspuns generic), nu acces admin
        assert C not in ok and "" in js["wp_real_prefixes"] and "/xml" in js["wp_fake_prefixes"]
        acts_c = {store.v_act[store.act[i]] for i in range(store.n) if store.v_ip[store.ip[i]] == C}
        assert "admin_get" not in acts_c and "wp_probe" in acts_c, acts_c
        # v47.4: POST wp-login cu 200 = parola respinsa -> "login_attempt", nu activitate admin
        t = {x["ip"]: x for x in summary["compromise_trail"]}
        if B in t:
            assert t[B]["dominant_category"] != "confirmed_admin_activity", t[B]["dominant_category"]
            assert all(e["category"] != "confirmed_admin_activity" for e in t[B]["events"]
                       if "login post" in (e.get("label") or "").lower())
    finally:
        GEO.pop(A, None); GEO.pop(B, None); GEO.pop(C, None)


@test
def test_v476_coerenta_intre_sectiuni():
    """v47.6: (1) un 200 pe /wp-json/wp/v2/users/me cu dimensiunea paginii
    generice NU e dovada de autentificare -> acces neconfirmat, demotat si in
    alerte; (2) operatiile admin sunt CONFIRMATE doar de pagina de succes a
    WordPress (?update=del&delete_count=N); (3) un singur card de alerta per
    IP; (4) findingul 'login reusit dupa brute force' fara login real devine LOW;
    (5) Incidente nu numara IP-urile care sunt doar in 'Acces WP admin'."""
    _need_store()
    A, U, R, X = "45.1.1.1", "45.2.2.2", "86.125.9.9", "45.3.3.3"
    GEO[A] = "ID"; GEO[U] = "ID"; GEO[R] = "RO"; GEO[X] = "DE"
    GEN = 158177
    pub = [L(f"86.126.0.{i}", "08/Oct/2026:10:00:%02d" % i, "GET", f"/pagina-{i}/", 200, size=GEN) for i in range(12)]
    lines = pub + [
        # A: login confirmat + upload blocat + /wp-admin/ (doua alerte -> un card)
        L(A, "09/Oct/2026:21:23:09", "POST", "/wp-login.php", 302),
        L(A, "09/Oct/2026:21:23:25", "GET", "/wp-admin/", 200, size=320000),
        L(A, "09/Oct/2026:21:24:00", "GET", "/wp-admin/plugins.php", 200, size=90000),
        L(A, "09/Oct/2026:21:25:22", "POST", "/wp-admin/update.php?action=upload-plugin", 403),
        # U: o pagina admin + REST users/me cu continutul generic -> NECONFIRMAT
        L(U, "11/Oct/2026:04:12:01", "GET", "/wp-admin/", 200, size=99078),
        L(U, "11/Oct/2026:04:12:05", "GET", "/wp-json/wp/v2/users/me?context=edit", 200, size=GEN),
        # R: login RO + stergere confirmata de WordPress
        L(R, "12/Oct/2026:13:07:18", "POST", "/wp-login.php", 302),
        L(R, "12/Oct/2026:13:07:19", "GET", "/wp-admin/", 200, size=102213),
        L(R, "12/Oct/2026:13:10:30", "GET", "/wp-admin/users.php?action=delete&user=12&_wpnonce=a", 200, size=50000),
        L(R, "12/Oct/2026:13:10:33", "POST", "/wp-admin/users.php?action=delete&user=12&_wpnonce=a", 302),
        L(R, "12/Oct/2026:13:10:33", "GET", "/wp-admin/users.php?delete_count=1&update=del", 200, size=50000),
        L(R, "12/Oct/2026:13:46:13", "POST", "/wp-admin/options.php", 302),
        L(R, "12/Oct/2026:13:46:13", "GET", "/wp-admin/options-reading.php?settings-updated=true", 200, size=40000),
    ] + [L(X, "12/Oct/2026:11:29:%02d" % i, "POST", "/xmlrpc.php", 403) for i in range(9)] + [
        L(X, "12/Oct/2026:11:29:58", "POST", "/xmlrpc.php", 200),
        L(X, "12/Oct/2026:11:29:59", "POST", "/xmlrpc.php", 200),
    ]
    try:
        d, path, part, summary, db, dcol, dbc, store = build_dataset(FIXTURE + lines)
        did = _register(store, dcol)
        app.DATASETS[did]["summary_cache"] = {"ALL": summary}
        store = app._col_store(app.DATASETS[did])
        st, js = call(app.api_admin_access, dataset_id=did)
        assert st == 200, js
        ok = {x["ip"]: x for x in js["successes"]}
        unc = {x["ip"]: x for x in js["unconfirmed"]}
        assert U in unc and U not in ok, (list(ok), list(unc))
        assert not unc[U]["auth_proof"] and any("generic" in h for h in unc[U]["hints"])
        assert ok[A]["session_mode"] == "login" and ok[R]["session_mode"] == "login"
        g = {x["key"]: x for x in ok[R]["groups"]}
        assert g["users_action"]["n"] == 1 and g["users_action"]["confirmed_units"] == 1
        assert g["users_confirm_page"]["critical"] is False      # pagina de confirmare nu e stergere
        assert g["options_save"]["confirmed_units"] == 1 and "options-reading.php" in g["options_save"]["targets"]
        assert "1 utilizator sters" in ok[R]["narrative"]
        ga = {x["key"]: x for x in ok[A]["groups"]}
        assert ga["plugin_upload"]["results"] == {"blocat": 1} and ga["plugin_upload"]["confirmed_units"] == 0
        # alerte: un card per IP, U nu mai e HIGH
        st, al = call(app.api_triage_top_alerts, dataset_id=did)
        ips = [a["ip"] for a in al["alerts"]]
        assert len(ips) == len(set(ips)), ips
        assert U not in ips
        a = next(x for x in al["alerts"] if x["ip"] == A)
        assert a["severity"] == "CRITICAL" and any(r["action_type"] == "admin_get" for r in a["related"])
        u_sev = {store.v_sev[store.sev[i]] for i in range(store.n) if store.v_ip[store.ip[i]] == U}
        assert not (u_sev & {"CRITICAL", "HIGH"}), u_sev
        # incidente: numarul din antet = randurile; IP-urile doar-admin raportate separat
        st, inc = call(app.api_incidents, dataset_id=did)
        assert inc["total"] == len(inc["incidents"])
        assert not ({A, U, R} & {x["ip"] for x in inc["incidents"]})
        assert inc["total"] + inc["admin_only_total"] == inc["candidates_total"]
        # sumarul reconciliat: login dupa brute force fara login real -> LOW; login numarat o data
        rs = app._summary_without_fp(did, summary)
        for f in rs["findings"]:
            if f.get("ip") == X:
                assert f["severity"] != "CRITICAL", f
        tr = {t["ip"]: t for t in rs["compromise_trail"]}
        if A in tr:
            assert any(l.startswith("Login CONFIRMAT in WP-Admin (1x)") for l in tr[A]["summary"]), tr[A]["summary"]
            keys = [(e.get("time"), e.get("label")) for e in tr[A]["events"]]
            assert sum(1 for e in tr[A]["events"] if "login" in (e.get("label") or "").lower()) == 1, keys
        aa = {x["ip"]: x for x in rs["admin_activity"]}
        if A in aa:
            assert "Login reusit (302)" not in aa[A]["actions"]
    finally:
        for k in (A, U, R, X):
            GEO.pop(k, None)


@test
def test_v48_brief_signal_first():
    """v48: /brief = incidente unice (nu semnale), stari din setul definit,
    accesul neconfirmat nu e promovat, evenimente grupate pe secventa,
    findings din aceeasi secventa grupate fara pierderea cererilor."""
    _need_store()
    A, U, R = "45.1.1.1", "45.2.2.2", "86.125.9.9"
    GEO[A] = "ID"; GEO[U] = "ID"; GEO[R] = "RO"
    lines = [L(f"86.126.0.{i}", "08/Oct/2026:10:00:%02d" % i, "GET", f"/pagina-{i}/", 200, size=158177) for i in range(12)] + [
        L(A, "09/Oct/2026:21:23:09", "POST", "/wp-login.php", 302),
        L(A, "09/Oct/2026:21:23:25", "GET", "/wp-admin/", 200, size=320000),
        L(A, "09/Oct/2026:21:24:45", "GET", "/wp-admin/plugin-install.php?tab=upload", 200, size=90000),
        L(A, "09/Oct/2026:21:25:20", "GET", "/wp-admin/plugin-install.php?tab=upload", 200, size=90000),
        L(A, "09/Oct/2026:21:25:22", "POST", "/wp-admin/update.php?action=upload-plugin", 403),
        L(A, "09/Oct/2026:21:25:28", "POST", "/wp-admin/update.php?action=upload-plugin", 403),
        L(U, "11/Oct/2026:04:12:01", "GET", "/wp-admin/", 200, size=99078),
        L(R, "12/Oct/2026:13:07:18", "POST", "/wp-login.php", 302),
        L(R, "12/Oct/2026:13:07:19", "GET", "/wp-admin/", 200, size=102213),
        L(R, "12/Oct/2026:13:10:33", "POST", "/wp-admin/users.php?action=delete&user=12&_wpnonce=a", 302),
        L(R, "12/Oct/2026:13:10:33", "GET", "/wp-admin/users.php?delete_count=1&update=del", 200, size=50000),
    ]
    try:
        d, path, part, summary, db, dcol, dbc, store = build_dataset(FIXTURE + lines)
        did = _register(store, dcol)
        app.DATASETS[did]["summary_cache"] = {"ALL": summary}
        app._col_store(app.DATASETS[did])
        st, b = call(app.api_brief, dataset_id=did)
        assert st == 200, b
        st, adm = call(app.api_admin_access, dataset_id=did)
        st, inc = call(app.api_incidents, dataset_id=did)
        ids = [x["id"] for x in b["incidents"]]
        assert len(ids) == len(set(ids))
        assert len(ids) == len(adm["successes"]) + len(adm["unconfirmed"]) + len(inc["incidents"])
        assert b["exec"]["incidents"] == len(ids)
        allowed = set(b["definitions"])
        assert all(set(x["status"]) <= allowed for x in b["incidents"])
        by = {x["ip"]: x for x in b["incidents"]}
        assert app.ST_CONF not in by[U]["status"] and app.ST_UNC in by[U]["status"]
        assert by[A]["severity"] == "CRITICAL" and app.ST_BLOCK in by[A]["status"]
        assert app.ST_CONF in by[R]["status"] and any("1 utilizator sters" in o for o in by[R]["observed"])
        assert b["incidents"][0]["severity"] == "CRITICAL"
        # evenimente pe secventa: upload x2 = UN eveniment, nu doua
        ev_a = [e for e in b["events"] if e["ip"] == A]
        assert sum(1 for e in ev_a if "Upload plugin" in e["text"]) == 1, ev_a
        assert b["exec"]["blocked_admin_actions"] == sum(x["critical_blocked"] for x in adm["successes"] + adm["unconfirmed"])
        assert b["exec"]["requests"] == store.n and b["exec"]["admin_ops_confirmed"] == 1
        # findings din aceeasi secventa -> un rand, cu toate cererile in evidence
        rs = app._summary_without_fp(did, summary)
        fa = [f for f in rs["findings"] if f.get("ip") == A and f["rule"].startswith("Acces admin sensibil")]
        raw = [f for f in summary["findings"] if f.get("ip") == A and f["rule"].startswith("Acces admin sensibil")]
        assert sum(int(f.get("occurrences") or 1) for f in fa) == len(raw) and len(fa) < len(raw), (len(fa), len(raw))
        assert rs["findings_signals"] >= rs["findings_count"]
    finally:
        for k in (A, U, R):
            GEO.pop(k, None)



@test
def test_v49_perioada_pura():
    """compute_period: zi, ora, 30/10 min, minut, moment +-N, interval peste
    miezul noptii si pe mai multe zile, capete incluse, intrari invalide si
    log cu doua offseturi (ora de vara -> ora de iarna)."""
    seg = [(10800, 0, 2 ** 40, 1)]
    E = lambda s: int(datetime.strptime(s + " +0300", "%d/%b/%Y:%H:%M:%S %z").timestamp())
    cp = app.compute_period
    p = cp(seg, "day", "09/Oct/2026")
    assert (p["ts_from"], p["ts_to"]) == (E("09/Oct/2026:00:00:00"), E("09/Oct/2026:23:59:59"))
    p = cp(seg, "hour", "09/Oct/2026", 21)
    assert (p["ts_from"], p["ts_to"]) == (E("09/Oct/2026:21:00:00"), E("09/Oct/2026:21:59:59"))
    p = cp(seg, "min30", "09/Oct/2026", 21, 47)
    assert (p["ts_from"], p["ts_to"]) == (E("09/Oct/2026:21:30:00"), E("09/Oct/2026:21:59:59"))
    p = cp(seg, "min10", "09/Oct/2026", 21, 47)
    assert (p["ts_from"], p["ts_to"]) == (E("09/Oct/2026:21:40:00"), E("09/Oct/2026:21:49:59"))
    p = cp(seg, "minute", "09/Oct/2026", 21, 47)
    assert p["ts_to"] - p["ts_from"] == 59
    p = cp(seg, "moment", "12/Oct/2026", 13, 10, 33, win=30)
    assert (p["ts_from"], p["ts_to"]) == (E("12/Oct/2026:13:10:03"), E("12/Oct/2026:13:11:03"))
    p = cp(seg, "custom", "10/Oct/2026", 23, 30, 0, "11/Oct/2026", 0, 29, 59)
    assert p["ts_to"] - p["ts_from"] == 3599                       # traverseaza miezul noptii
    p = cp(seg, "custom", "09/Oct/2026", 12, 0, 0, "12/Oct/2026", 12, 0, 0)
    assert p["ts_to"] - p["ts_from"] == 3 * 86400
    for bad in (lambda: cp(seg, "hour", "09/Oct/2026", 24), lambda: cp(seg, "minute", "09/Oct/2026", 1, 60),
                lambda: cp(seg, "custom", "12/Oct/2026", 0, 0, 0, "11/Oct/2026", 0, 0, 0),
                lambda: cp(seg, "day", "32/Oct/2026"), lambda: cp(seg, "day", "2026-10-09"), lambda: cp(seg, "bogus", "09/Oct/2026"),
                lambda: cp(seg, "moment", "09/Oct/2026", 1, 1, 1, win=-5)):
        try:
            bad(); raise AssertionError("trebuia ValueError")
        except ValueError:
            pass
    # log cu doua offseturi: 25 Oct 2026, 04:00 +0300 -> 03:00 +0200
    sw = E("25/Oct/2026:04:00:00")
    seg2 = [(10800, 0, sw - 1, 10), (7200, sw, 2 ** 40, 10)]
    assert app.offset_at(seg2, sw - 1) == 10800 and app.offset_at(seg2, sw) == 7200
    day = cp(seg2, "day", "25/Oct/2026")
    assert day["ts_to"] - day["ts_from"] == 25 * 3600 - 1          # ziua schimbarii are 25 de ore
    h = cp(seg2, "hour", "25/Oct/2026", 10)
    assert h["ts_from"] == int(datetime.strptime("25/Oct/2026:10:00:00 +0200", "%d/%b/%Y:%H:%M:%S %z").timestamp())
    w = app.epoch_to_wall(seg2, h["ts_from"])
    assert (w["h"], w["offset"]) == (10, "+0200")


@test
def test_v49_filtre_timp_export_sincron():
    """Selectorul de perioada (API), filtrele combinate (timp AND IP AND cod,
    OR in acelasi filtru), resetarea, ziua veche (ts_str_day) vs perioada si
    exporturile (.log / CSV / sumar) -- aceeasi baza de filtrare, toate
    cererile (nu doar pagina), nimic din afara selectiei."""
    _need_store()
    I1, I2 = "45.9.9.1", "45.9.9.2"
    GEO[I1] = "DE"; GEO[I2] = "DE"
    lines = [
        L(I1, "10/Oct/2026:20:59:59", "GET", "/inainte", 200),
        L(I1, "10/Oct/2026:21:00:00", "GET", "/capat-start", 200),     # exact la inceputul orei
        L(I1, "10/Oct/2026:21:30:00", "POST", "/wp-login.php", 200),
        L(I2, "10/Oct/2026:21:30:01", "GET", "/lipsa", 404),
        L(I1, "10/Oct/2026:21:59:59", "GET", "/capat-sfarsit", 404),   # exact la sfarsitul orei
        L(I1, "10/Oct/2026:22:00:00", "GET", "/dupa", 200),
        L(I2, "10/Oct/2026:23:59:30", "GET", "/noapte-1", 200),
        L(I2, "11/Oct/2026:00:00:10", "GET", "/noapte-2", 200),
    ]
    try:
        d, path, part, summary, db, dcol, dbc, store = build_dataset(FIXTURE + lines)
        did = _register(store, dcol)
        app.DATASETS[did]["summary_cache"] = {"ALL": summary}
        app.DATASETS[did]["plain_path"] = path
        app._col_store(app.DATASETS[did])
        st, ti = call(app.api_time_info, dataset_id=did)
        assert st == 200 and "10/Oct/2026" in ti["days"] and ti["segments"][0]["offset_sec"] == 10800
        st, p = call(app.api_period, dataset_id=did, mode="hour", day="10/Oct/2026", h=21)
        assert st == 200 and p["requests"] == 4, p                     # 21:00:00 si 21:59:59 incluse, 20:59:59/22:00:00 nu
        st, p2 = call(app.api_period, dataset_id=did, mode="custom", day="10/Oct/2026", h=23, m=59, s=0,
                      day2="11/Oct/2026", h2=0, m2=1, s2=0)
        assert p2["requests"] == 2                                     # peste miezul noptii
        st, bad = call(app.api_period, dataset_id=did, mode="hour", day="10/Oct/2026", h=24)
        assert st == 400
        st, mo = call(app.api_period, dataset_id=did, mode="moment", day="10/Oct/2026", h=21, m=30, s=0, win=1)
        assert mo["requests"] == 2
        ff = {"ts_from": p["ts_from"], "ts_to": p["ts_to"]}
        # timp AND ip AND cod; OR intre doua coduri
        g = json.dumps(dict(ff, ip=I1, statuses=[404]))
        st, ev = call(app.api_triage_events, dataset_id=did, gf=g, with_count=True)
        assert ev["total"] == 1 and ev["events"][0]["path"] == "/capat-sfarsit"
        g_or = json.dumps(dict(ff, statuses=[200, 404]))
        st, ev = call(app.api_triage_events, dataset_id=did, gf=g_or, with_count=True)
        assert ev["total"] == 4
        st, p3 = call(app.api_period, dataset_id=did, mode="hour", day="10/Oct/2026", h=21, gf=json.dumps({"ip": I2}))
        assert p3["requests"] == 1                                     # perioada AND celelalte filtre active
        # resetarea unui filtru = filtrul lipseste; restul ramane
        g_noip = json.dumps(dict(ff, statuses=[404]))
        st, ev = call(app.api_triage_events, dataset_id=did, gf=g_noip, with_count=True)
        assert ev["total"] == 2
        # ziua veche (ts_str_day) si perioada "o zi" dau exact aceleasi cereri
        st, pd = call(app.api_period, dataset_id=did, mode="day", day="10/Oct/2026")
        st, a = call(app.api_triage_events, dataset_id=did, gf=json.dumps({"ts_str_day": "10/Oct/2026"}), with_count=True)
        st, b = call(app.api_triage_events, dataset_id=did, gf=json.dumps({"ts_from": pd["ts_from"], "ts_to": pd["ts_to"]}), with_count=True)
        assert a["total"] == b["total"] == pd["requests"], (a["total"], b["total"], pd["requests"])
        # export: TOATE cererile filtrate (si peste limita de afisare), nimic din afara
        g = json.dumps(ff)
        r = app.api_export_events(dataset_id=did, gf=g, kind="sel", value="", format="log", limit=10 ** 6)
        body = _drain(r).decode().splitlines()
        want = [l for l in lines if l.split("[", 1)[1][:20] >= "10/Oct/2026:21:00:00" and l.split("[", 1)[1][:20] <= "10/Oct/2026:21:59:59"]
        assert sorted(body) == sorted(want), body
        assert r.headers["X-Total-Matched"] == "4" and "_4cereri" in r.headers["Content-Disposition"]
        r = app.api_export_events(dataset_id=did, gf=g, kind="sel", value="", format="csv", limit=10 ** 6)
        rows = list(csv.reader(io.StringIO(_drain(r).decode("utf-8-sig"))))
        assert len(rows) - 1 == 4 and {x[0][:20] for x in rows[1:]} <= {l.split("[", 1)[1][:20] for l in want}
        r = app.api_export_events(dataset_id=did, gf=g, kind="sel", value="", format="log", limit=2)
        assert len(_drain(r).decode().splitlines()) == 2 and "PRIMELE_din_4" in r.headers["Content-Disposition"]
        # exportul sumarului = aceleasi findings ca interfata (reconciliate)
        r = app.api_export_csv(dataset_id=did, day="ALL", type="findings", gf="")
        exp_rows = list(csv.reader(io.StringIO(r.body.decode())))
        ui = app._summary_without_fp(did, summary)
        assert len(exp_rows) - 1 == len(ui["findings"]) and "sumar" in r.headers["Content-Disposition"]
    finally:
        GEO.pop(I1, None); GEO.pop(I2, None)


@test
def test_v49_performanta_mask_timp():
    """Filtrul de timp + IP + cod pe ~500k randuri (index columnar) ramane
    interactiv (< 0.5 s), fara a reconstrui indexul."""
    _need_store()
    import numpy as np
    n = 500_000
    big = tc.ColStore.__new__(tc.ColStore)
    for k, v in STORE.__dict__.items():
        big.__dict__[k] = v
    rng = np.random.default_rng(1)
    idx = rng.integers(0, STORE.n, n)
    for fld in ("ts", "ip", "cc", "me", "fp", "st", "sz", "ua", "sev", "risk", "act", "lbl"):
        if hasattr(STORE, fld) and isinstance(getattr(STORE, fld), np.ndarray) and getattr(STORE, fld).shape[0] == STORE.n:
            setattr(big, fld, getattr(STORE, fld)[idx])
    big.n = n
    big._cache = {}; big._lut_cache = {}
    for k in list(big.__dict__):
        if "order" in k:
            big.__dict__.pop(k, None)
    t0 = int(big.ts.min()); t1 = int(big.ts.max())
    f = dict(app._gf_from_params(t0 + (t1 - t0) // 4, t0 + (t1 - t0) // 2, [], [], [200, 404], [], "86.124.0.1", "", "", "", ""))
    import time as _t
    a = _t.perf_counter()
    for _ in range(5):
        c = big.count(f)
    dt = (_t.perf_counter() - a) / 5
    exp = int(np.count_nonzero((big.ts >= f["ts_from"]) & (big.ts <= f["ts_to"]) & np.isin(big.st, [200, 404])
                               & (big.ip == STORE.d_ip.get("86.124.0.1", -1))))
    assert c == exp, (c, exp)
    print(f"    perf: count pe {n} randuri = {dt * 1000:.1f} ms")
    assert dt < 0.5, dt



@test
def test_v491_atac_pe_filtre():
    """Atac pe filtre: detectat dupa regulile explicite, IP totale (cereri) vs
    IP unice corecte in ambele moduri de afisare, filtrele listei (tinta,
    parametru, cod, min cereri/IP, IP) si selectia globala (timp) respectate;
    fara atac -> nedetectat."""
    _need_store()
    att = []
    for i in range(250):
        ip = f"34.10.{i // 200}.{i % 200 + 1}"            # 250 de IP-uri unice
        st = 503 if i % 10 == 0 else 200
        att.append(L(ip, "13/Oct/2026:03:%02d:%02d" % (i // 60, i % 60), "GET",
                     f"/magazin/?filter_culoare=c{i}&filter_marime=m{i % 3}", st))
    for i in range(10):                                   # acelasi IP de 10 ori -> 10 aparitii, 1 IP unic
        att.append(L("5.6.7.8", "13/Oct/2026:05:00:%02d" % i, "GET", f"/magazin/?orderby=price&min_price={i}", 200))
    try:
        d, path, part, summary, db, dcol, dbc, store = build_dataset(FIXTURE + att)
        did = _register(store, dcol)
        app.DATASETS[did]["summary_cache"] = {"ALL": summary}
        st, fa = call(app.api_filter_attacks, dataset_id=did)
        assert st == 200 and fa["detected"] and "distribuit" in fa["kinds"][0], fa.get("verdict")
        assert fa["filter_requests"] == 260 and fa["unique_ips"] == 251
        assert fa["status"]["5xx"] == 25
        t = {x["target"]: x for x in fa["targets"]}
        assert t["/magazin/"]["requests"] == 260 and t["/magazin/"]["unique_ips"] == 251
        st, u = call(app.api_filter_attack_requests, dataset_id=did, mode="unique", limit=5000)
        assert u["unique_ips"] == 251 and u["total_requests"] == 260 and sum(x["requests"] for x in u["items"]) == 260
        assert u["items"][0]["ip"] == "5.6.7.8" and u["items"][0]["requests"] == 10
        st, a = call(app.api_filter_attack_requests, dataset_id=did, mode="all", limit=5000)
        assert a["total"] == 260 and len(a["items"]) == 260 and a["unique_ips"] == 251
        st, x = call(app.api_filter_attack_requests, dataset_id=did, mode="unique", min_requests=2)
        assert x["unique_ips"] == 1
        st, x = call(app.api_filter_attack_requests, dataset_id=did, mode="all", status_class="5xx")
        assert x["total"] == 25
        st, x = call(app.api_filter_attack_requests, dataset_id=did, mode="all", param="orderby")
        assert x["total"] == 10 and x["unique_ips"] == 1
        st, x = call(app.api_filter_attack_requests, dataset_id=did, mode="all", ip="5.6.7.8", limit=3)
        assert x["total"] == 10 and len(x["items"]) == 3
        # selectia globala: doar ora 05 -> 10 cereri, 1 IP, sub praguri
        E = lambda s: int(datetime.strptime(s + " +0300", "%d/%b/%Y:%H:%M:%S %z").timestamp())
        g = json.dumps({"ts_from": E("13/Oct/2026:05:00:00"), "ts_to": E("13/Oct/2026:05:59:59")})
        st, fa2 = call(app.api_filter_attacks, dataset_id=did, gf=g)
        assert fa2["filter_requests"] == 10 and fa2["unique_ips"] == 1 and not fa2["detected"]
        st, b = call(app.api_brief, dataset_id=did)
        assert b["exec"]["filter_attack"] and any(i["kind"] == "filter_attack" for i in b["incidents"])
    finally:
        pass
    # logul de baza nu are atac pe filtre
    did0 = _register(STORE, DCOL)
    st, fa0 = call(app.api_filter_attacks, dataset_id=did0)
    assert st == 200 and not fa0["detected"]


@test
def test_v50_comportament_automat():
    """Conditiile noi din Workplace (varf/minut, % 4xx, UA-uri/IP, cereri/subnet)
    calculate exact pe selectie + categoriile 'Activitate automata' (aceleasi
    conditii, aceleasi cifre ca Workplace) + upload gzip in bucati."""
    _need_store()
    ex = []
    for i in range(70):                                   # 70 de cereri in acelasi minut, un IP
        ex.append(L("45.9.1.10", "13/Oct/2026:04:10:%02d" % (i % 60), "GET", f"/produs/p{i}/", 200))
    for i in range(40):                                   # scanner: 40 cereri, 36 x 404
        ex.append(L("45.9.1.20", "13/Oct/2026:04:20:%02d" % i, "GET", f"/x{i}.php", 404 if i < 36 else 200))
    for i in range(25):                                   # rotatie de UA: 25 cereri, 5 UA-uri
        ex.append(L("45.9.1.30", "13/Oct/2026:04:30:%02d" % i, "GET", "/", 200, ua=f"Mozilla/5.0 v{i % 5}"))
    for i in range(30):                                   # acelasi /24, 30 de IP-uri cu o cerere
        ex.append(L(f"45.9.2.{i + 1}", "13/Oct/2026:04:40:%02d" % i, "GET", "/", 200))
    ex.append(L("45.9.1.40", "13/Oct/2026:04:50:00", "GET", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", 404))
    d, path, part, summary, db, dcol, dbc, store = build_dataset(FIXTURE + ex)
    did = _register(store, dcol)
    app.DATASETS[did]["summary_cache"] = {"ALL": summary}

    def wk(conds):
        st, r = call(app.api_workplace, dataset_id=did, body={"q": {"conds": conds}, "limit": 500})
        assert st == 200, r
        return r["total"], {x["ip"] for x in r["rows"]}
    R = lambda f, lo=None, hi=None: {"field": f, "op": "range", "values": [lo, hi]}
    n, ips = wk([R("ip_rpm", 60)])
    assert n == 70 and ips == {"45.9.1.10"}, (n, ips)
    n, ips = wk([R("ip_err", 90), R("ip_hits", 30)])
    assert n == 40 and ips == {"45.9.1.20"}, (n, ips)
    n, _ = wk([R("ip_err", 100, 100), {"field": "ip", "op": "in", "values": ["45.9.1.40"]}])
    assert n == 1
    n, ips = wk([R("ip_uas", 5)])
    assert ips == {"45.9.1.30"} and n == 25, (n, ips)
    n, ips = wk([{"field": "ip", "op": "cidr", "values": ["45.9.2.0/24"]}, R("subnet_hits", 30, 30)])
    assert n == 30 and len(ips) == 30
    n, _ = wk([{"field": "ip", "op": "cidr", "values": ["45.9.2.0/24"]}, R("subnet_hits", 31)])
    assert n == 0
    # conditia se calculeaza pe selectia de PANA la ea: dupa URL /x -> scannerul are 40/40 = 100% 4xx? nu, 36/40
    n, _ = wk([{"field": "path_only", "op": "prefix", "values": ["/x"]}, R("ip_err", 91)])
    assert n == 0
    st, au = call(app.api_automation, dataset_id=did)
    assert st == 200, au
    cat = {c["key"]: c for c in au["categories"]}
    assert cat["bursts"]["requests"] == 70 and cat["bursts"]["top"][0]["ip"] == "45.9.1.10"
    assert cat["auto_scan"]["ips"] >= 1 and any(t["ip"] == "45.9.1.20" for t in cat["auto_scan"]["top"])
    assert cat["ua_rotation"]["top"][0]["ip"] == "45.9.1.30"
    assert cat["vuln_scan"]["requests"] >= 1
    for c in au["categories"]:                            # aceleasi conditii -> aceleasi cifre in Workplace
        assert wk(c["conds"])[0] == c["requests"], c["key"]
    # selectia globala (timp) se respecta
    E = lambda s: int(datetime.strptime(s + " +0300", "%d/%b/%Y:%H:%M:%S %z").timestamp())
    g = json.dumps({"ts_from": E("13/Oct/2026:04:20:00"), "ts_to": E("13/Oct/2026:04:59:59")})
    st, au2 = call(app.api_automation, dataset_id=did, gf=g)
    assert {c["key"]: c for c in au2["categories"]}["bursts"]["requests"] == 0
    # upload gzip in bucati (gzip multi-membru) == acelasi continut
    import gzip as _gz
    st, ini = call(app.api_upload2_init, payload={"filename": "x.log", "total_size": 10, "encoding": "gzip"})
    up = app.UPLOADS[ini["upload_id"]]
    assert up["raw_path"].endswith(".gz")
    raw = ("\n".join(FIXTURE) + "\n").encode()
    with open(up["raw_path"], "wb") as f:
        f.write(_gz.compress(raw[:200]) + _gz.compress(raw[200:]))
    plain = app.decompress_to_plain(up["raw_path"], up["workdir"])
    assert open(plain, "rb").read() == raw
    app.UPLOADS.pop(ini["upload_id"], None); shutil.rmtree(up["workdir"], ignore_errors=True)
    st, v = call(app.api_version)
    assert v["upload_gzip"] is True


if __name__ == "__main__":
    bad = [r for r in RESULTS if r[1]]
    for name, err in RESULTS:
        print(("OK   " if not err else "FAIL ") + name)
        if err:
            print(err)
    print(f"\n{len(RESULTS) - len(bad)}/{len(RESULTS)} teste trecute")
    sys.exit(1 if bad else 0)
