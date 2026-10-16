#!/usr/bin/env python3
"""Benchmark end-to-end pe server (HTTP real): import + interactiunile pe
care le face UI-ul la o selectie (tabel + total, histograma, sinteza) pentru
tara majoritara, o tara straina, tara nedeterminata, 404, URL, IP, zi, ora,
plus re-analiza completa a taburilor pentru o tara.
Uz: [BENCH_CC=US] bench.py BASE_URL LOGFILE [eticheta]  -> JSON pe stdout."""
import json
import os
import sys
import time
import urllib.parse
import urllib.request

BASE, LOG = sys.argv[1], sys.argv[2]
LABEL = sys.argv[3] if len(sys.argv) > 3 else ""
OUT = {"label": LABEL, "file": os.path.basename(LOG), "bytes": os.path.getsize(LOG)}


def req(method, path, data=None, headers=None, timeout=900):
    r = urllib.request.Request(BASE + path, data=data, method=method, headers=headers or {})
    t = time.time()
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            body = resp.read()
            code = resp.status
    except urllib.error.HTTPError as e:
        body = e.read(); code = e.code
    dt = time.time() - t
    try:
        js = json.loads(body)
    except Exception:
        js = None
    return code, js, dt, len(body)


def get(path, **params):
    q = []
    for k, v in params.items():
        if isinstance(v, (list, tuple)):
            q += [(k, x) for x in v]
        elif v is not None:
            q.append((k, v))
    return req("GET", path + ("?" + urllib.parse.urlencode(q) if q else ""))


# ---------------- import
t0 = time.time()
code, js, _, _ = req("POST", "/api/upload2/init", json.dumps({"filename": os.path.basename(LOG),
                     "total_size": os.path.getsize(LOG)}).encode(), {"Content-Type": "application/json"})
uid = js["upload_id"]
CH = 8 * 1024 * 1024
with open(LOG, "rb") as f:
    i = 0
    while True:
        b = f.read(CH)
        if not b:
            break
        req("POST", f"/api/upload2/chunk/{uid}?index={i}", b)
        i += 1
t_up = time.time()
code, js, _, _ = req("POST", f"/api/upload2/complete/{uid}")
job = js["job_id"]
while True:
    code, js, _, _ = req("GET", f"/api/jobs/{job}")
    if js.get("status") in ("done", "error"):
        break
    time.sleep(0.25)
t_done = time.time()
assert js["status"] == "done", js
DS = js["dataset_id"]
OUT["upload_s"] = round(t_up - t0, 2)
OUT["parse_to_dashboard_s"] = round(t_done - t_up, 2)
while True:
    code, st, _, _ = get(f"/api/dataset/{DS}/triage_status")
    if st.get("ready") or st.get("error"):
        break
    time.sleep(0.25)
t_ready = time.time()
OUT["index_ready_after_dashboard_s"] = round(t_ready - t_done, 2)
OUT["total_import_s"] = round(t_ready - t_up, 2)
OUT["geoip"] = st.get("geoip")
OUT["dataset"] = DS

# filtre disponibile
code, flt, dt, _ = get(f"/api/dataset/{DS}/filters")
countries = [c["value"] for c in flt.get("countries", [])]
OUT["countries_top"] = flt.get("countries", [])[:8]
c_foreign = os.environ.get("BENCH_CC") or next((c for c in countries if c not in ("RO", "")), None)
code, al, _, _ = get(f"/api/dataset/{DS}/alerts/top", limit=5)
top_ip = (al.get("alerts") or [{}])[0].get("ip")


def timed(name, path, **params):
    code, js, dt, n = get(path, **params)
    OUT.setdefault("api", {})[name] = {"ms": round(dt * 1000), "code": code, "bytes": n}
    return js


def interaction(name, filt):
    """Ce face UI-ul la o selectie: tabel (pagina 1 + total), histograma, sinteza."""
    tf = {"ts_from": BOUNDS[0], "ts_to": BOUNDS[1]}
    t = time.time()
    timed(name + ".events", f"/api/dataset/{DS}/events", limit=150, offset=0, sort="ts_desc", with_count="true", **tf, **filt)
    timed(name + ".histogram", f"/api/dataset/{DS}/histogram", bucket_seconds=3600, **tf, **filt)
    ov = timed(name + ".overview", f"/api/dataset/{DS}/overview", **filt)
    OUT["api"][name + ".TOTAL"] = {"ms": round((time.time() - t) * 1000)}
    return ov


# limite de timp (ca UI-ul)
_, a, _, _ = get(f"/api/dataset/{DS}/events", sort="ts_asc", limit=1)
_, b, _, _ = get(f"/api/dataset/{DS}/events", sort="ts_desc", limit=1)
BOUNDS = (a["events"][0]["ts"], b["events"][0]["ts"])

time.sleep(0.5)
interaction("all", {})
ov = interaction("country_RO", {"country": ["RO"]})
OUT["country_RO_requests"] = ov and ov.get("requests")
if c_foreign:
    ov = interaction("country_" + c_foreign, {"country": [c_foreign]})
    OUT["country_foreign_requests"] = ov and ov.get("requests")
ov = interaction("country_unknown", {"country": [""]})
OUT["country_unknown_requests"] = ov and ov.get("requests")
interaction("status_404", {"status": ["404"]})
interaction("path_wp_login", {"path_contains": "wp-login"})
interaction("country_RO+status_200", {"country": ["RO"], "status": ["200"]})
if top_ip:
    interaction("ip", {"ip": top_ip})
    timed("ip_profile", f"/api/dataset/{DS}/ip_profile", ip=top_ip)
interaction("day", {"day": "08/Oct/2026"})
mid = (BOUNDS[0] + BOUNDS[1]) // 2
interaction("time_1h", {"ts_from": mid, "ts_to": mid + 3600}) if False else None
t = time.time()
timed("time_1h.events", f"/api/dataset/{DS}/events", limit=150, ts_from=mid, ts_to=mid + 3600, with_count="true")
timed("time_1h.overview", f"/api/dataset/{DS}/overview", ts_from=mid, ts_to=mid + 3600)
OUT["api"]["time_1h.TOTAL"] = {"ms": round((time.time() - t) * 1000)}

# re-analiza completa a taburilor v42 pentru o selectie (country foreign)
if c_foreign:
    t = time.time()
    while True:
        code, js, _, _ = get(f"/api/dataset/{DS}/summary_filtered", country=[c_foreign])
        if js.get("status") in ("done", "error"):
            break
        time.sleep(0.3)
    OUT["summary_filtered_country_s"] = round(time.time() - t, 2)
    OUT["summary_filtered_status"] = js.get("status")
    if js.get("summary"):
        OUT["summary_filtered_total"] = js["summary"].get("total")

print(json.dumps(OUT, indent=1))
