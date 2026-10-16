#!/usr/bin/env python3
"""v45 -- timpii drilldown-urilor CU selectia globala (perioada + filtre),
ai panoului de explorare, cronologiei, comparatiei si exportului.
Uz: bench_v45.py BASE_URL LOGFILE [eticheta]  -> JSON pe stdout."""
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


import json as _j
_, a, _, _ = get(f"/api/dataset/{DS}/events", sort="ts_asc", limit=1)
_, b, _, _ = get(f"/api/dataset/{DS}/events", sort="ts_desc", limit=1)
B0, B1 = a["events"][0]["ts"], b["events"][0]["ts"]
MID = (B0 + B1) // 2
H1 = {"ts_from": MID - 3600, "ts_to": MID - 1}
D1 = {"ts_from": MID - 86400, "ts_to": MID - 1}
CC = os.environ.get("BENCH_CC", "US")
OUT["api"] = {}


def timed(name, path, **params):
    code, js, dt, n = get(path, **params)
    OUT["api"][name] = {"ms": round(dt * 1000), "code": code}
    return js


for lbl, g in (("1h", H1), ("24h", D1), ("1h+RO+404", dict(H1, countries=["RO"], statuses=[404]))):
    gj = _j.dumps(g)
    js = timed(f"raw country={CC} [{lbl}] prima", f"/api/dataset/{DS}/raw", country=CC, gf=gj)
    OUT["api"][f"raw country={CC} [{lbl}] prima"]["lines"] = len(js["matches"])
    timed(f"raw country={CC} [{lbl}] repetat", f"/api/dataset/{DS}/raw", country=CC, gf=gj)
    js = timed(f"explore sel [{lbl}]", f"/api/dataset/{DS}/explore", kind="sel", value="", gf=gj)
    ip = js["top_ips"][0]["ip"] if js.get("top_ips") else "1.1.1.1"
    timed(f"explore country={CC} [{lbl}]", f"/api/dataset/{DS}/explore", kind="country", value=CC, gf=gj)
    timed(f"explore ip [{lbl}]", f"/api/dataset/{DS}/explore", kind="ip", value=ip, gf=gj)
    timed(f"explore path /wp-login.php [{lbl}]", f"/api/dataset/{DS}/explore", kind="path", value="/wp-login.php", gf=gj)
    timed(f"explore wp_any [{lbl}]", f"/api/dataset/{DS}/explore", kind="wp", value="wp_any", gf=gj)
    timed(f"explore ip + comparatie perioada [{lbl}]", f"/api/dataset/{DS}/explore", kind="ip", value=ip, gf=gj,
          cmp_from=g["ts_from"] - 86400, cmp_to=g["ts_to"] - 86400)
    timed(f"timeline country [{lbl}]", f"/api/dataset/{DS}/timeline", kind="country", value=CC, gf=gj)
    timed(f"security_timeline HIGH [{lbl}]", f"/api/dataset/{DS}/security_timeline", min_severity="HIGH", gf=gj)
    timed(f"events country (pagina+total) [{lbl}]", f"/api/dataset/{DS}/events", kind="country", value=CC, gf=gj,
          limit=100, with_count="true", raw="true")
    timed(f"alerts/top [{lbl}]", f"/api/dataset/{DS}/alerts/top", gf=gj)
    timed(f"ip_detail (rescanare) [{lbl}]", f"/api/dataset/{DS}/ip_detail", ip=ip, gf=gj)
    timed(f"country_subnets RO (rescanare) [{lbl}]", f"/api/dataset/{DS}/country_subnets", country="RO", gf=gj)
    timed(f"path_breakdown / (rescanare) [{lbl}]", f"/api/dataset/{DS}/path_breakdown", prefix="/", gf=gj)
    t = time.time()
    code, _, dt, n = req("GET", f"/api/dataset/{DS}/export_events?" + urllib.parse.urlencode({"gf": gj, "format": "log"}))
    OUT["api"][f"export .log [{lbl}]"] = {"ms": round(dt * 1000), "bytes": n}
# fara selectie (tot logul) -- referinta
timed("raw country=US [tot logul]", f"/api/dataset/{DS}/raw", country=CC)
timed("explore sel [tot logul]", f"/api/dataset/{DS}/explore", kind="sel", value="")
timed("timeline sel [tot logul]", f"/api/dataset/{DS}/timeline", kind="sel", value="")
timed("security_timeline HIGH [tot logul]", f"/api/dataset/{DS}/security_timeline", min_severity="HIGH")
print(json.dumps(OUT, indent=1))
