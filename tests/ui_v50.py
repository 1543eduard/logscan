"""v50 -- teste end-to-end: Raw Logs (linii originale + copiere), Workplace
(preseturi noi + ghid), Security & Triaj (incidente compacte, activitate
automata), steaguri, upload comprimat in browser.

    python3 app.py --port 8092 &
    python3 tests/ui_v50.py http://127.0.0.1:8092 /cale/log.log [/cale/screenshots]

Cifrele din interfata sunt comparate cu API-ul pentru aceeasi selectie."""
import json
import os
import sys
import time
import urllib.request

from playwright.sync_api import sync_playwright

BASE = sys.argv[1].rstrip("/")
LOG = sys.argv[2]
SHOTS = sys.argv[3] if len(sys.argv) > 3 else None
RESULTS, CONSOLE = [], []


def api(path, body=None):
    req = urllib.request.Request(BASE + path, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json"} if body is not None else {})
    with urllib.request.urlopen(req, timeout=300) as r:
        return json.loads(r.read())


def check(name, fn, page):
    t = time.time()
    try:
        info = fn() or ""
        RESULTS.append((name, True, f"{info} ({time.time() - t:.1f}s)"))
    except Exception as e:  # noqa: BLE001
        RESULTS.append((name, False, f"{type(e).__name__}: {e}"))
    if SHOTS:
        page.screenshot(path=os.path.join(SHOTS, f"v50_{len(RESULTS):02d}.png"))


def goto(page, mod):
    page.click(f'.pageTabBtn[data-page="{mod}"]')
    page.wait_for_timeout(1500)


with sync_playwright() as pw:
    browser = pw.chromium.launch()
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    page.on("console", lambda m: m.type == "error" and CONSOLE.append(m.text))
    page.on("pageerror", lambda e: CONSOLE.append(str(e)))
    page.goto(BASE + "/")
    t0 = time.time()
    page.set_input_files("#fileInput", LOG)
    page.wait_for_selector("#pageTabs", state="visible", timeout=900000)
    page.wait_for_function("() => TRIAGE.ready", timeout=900000)
    did = page.evaluate("DATASET_ID")
    total = api(f"/api/dataset/{did}/workplace", {"q": {"conds": []}, "limit": 1})["total"]

    def t_upload():
        msg = page.evaluate("document.querySelector('#uploadMsg').textContent")
        n = page.evaluate("GF.overview ? GF.overview.requests : null") or total
        assert n == total, (n, total)
        return f"{total} cereri dupa upload (comprimat in browser: {'comprimat' in msg or 'n/a'}), {time.time() - t0:.1f}s"
    check("upload (comprimat in browser) -> aceleasi cereri ca API", t_upload, page)

    def t_raw_lines():
        goto(page, "raw")
        page.click('[data-rawview="lines"]')
        page.wait_for_function("() => document.querySelectorAll('.rawLn').length > 0")
        first = page.evaluate("document.querySelector('.rawLn .rawTx').textContent")
        ev = page.evaluate("TRIAGE.rows[0]")
        assert first == ev["raw_line"], (first, ev.get("raw_line"))
        assert ev["ua"] in first, "UA-ul nu apare intreg in linia afisata"
        n0 = page.evaluate("document.querySelectorAll('.rawLn').length")
        page.evaluate("const b = document.querySelector('#rawLinesBox'); b.scrollTop = b.scrollHeight")
        page.wait_for_timeout(1500)
        n1 = page.evaluate("document.querySelectorAll('.rawLn').length")
        assert n1 > n0 or page.evaluate("TRIAGE.allLoaded"), (n0, n1)
        exp = page.evaluate("fetch(rawExportUrl(50000)).then(async r => [r.headers.get('X-Exported'), (await r.text()).split('\\n').filter(Boolean).length])")
        assert int(exp[0]) == exp[1] == min(total, 50000), exp
        page.click('[data-rawview="table"]')
        sig = page.evaluate("[...document.querySelectorAll('.triageRow')].filter(r => r.style.display !== 'none').map(r => r.children[5].textContent.trim())")
        assert not any(s in ("INFO normal", "INFO non_ro") for s in sig), sig[:5]
        return f"linie completa cu UA, {n0}->{n1} randuri la derulare, copiere selectie = {exp[1]} linii"
    check("Raw: linii originale complete, derulare, copiere toata selectia", t_raw_lines, page)

    def t_workplace():
        goto(page, "workplace")
        page.wait_for_selector("#wkGuide")
        n_ex = page.evaluate("document.querySelectorAll('[data-wkex]').length")
        assert n_ex >= 30, n_ex
        btn = page.locator('[data-wkp]', has_text="Rafale rapide").first
        btn.click()
        page.wait_for_function("() => WK.res && !WK.busy && WK.conds.some(c => c.field === 'ip_rpm')")
        page.locator('[data-wkex]').first.click()
        page.wait_for_function("() => WK.res && !WK.busy && WK.conds.length === 1 && WK.conds[0].field === 'ip'")
        return f"{n_ex} exemple in ghid; preset nou + exemplu aplicate"
    check("Workplace: preseturi boti/scraping + ghid cu exemple aplicabile", t_workplace, page)

    def t_security():
        goto(page, "security")
        page.wait_for_function("() => SF.data && AUTO.data", timeout=60000)
        n_inc = page.evaluate("SF.data.incidents.length")
        shown = page.evaluate("document.querySelectorAll('#sfIncs .sfInc').length")
        assert shown == min(n_inc, 10), (shown, n_inc)
        assert page.evaluate("[...document.querySelectorAll('#sfIncs .sfIncBody')].every(b => b.hidden)")
        if n_inc:
            page.locator("#sfIncs [data-sf-inctoggle]").first.click()
            assert page.evaluate("!document.querySelector('#sfIncs .sfIncBody').hidden")
        h = page.evaluate("document.querySelector('#sfBrief').offsetHeight")
        assert h < 3000, h
        cats = api(f"/api/dataset/{did}/automation")["categories"]
        for c in cats:
            if c["requests"]:
                cell = page.evaluate(f"(() => {{ const b = document.querySelector('[data-auto-wk=\"{c['key']}\"]'); return b ? b.closest('tr').children[1].firstChild.textContent : null; }})()")
                assert cell and int(cell.replace(".", "")) == c["requests"], (c["key"], cell, c["requests"])
        page.evaluate("document.querySelector('[data-auto-wk]') && document.querySelector('[data-auto-wk]').click()")
        page.wait_for_timeout(1500)
        assert page.evaluate("CURRENT_PAGE") == "workplace" or not any(c["requests"] for c in cats)
        return f"{shown}/{n_inc} incidente compacte (card {h}px), {sum(1 for c in cats if c['requests'])} categorii automate = API"
    check("Security: incidente compacte + activitate automata = API", t_security, page)

    def t_networks():
        goto(page, "ip")
        page.wait_for_function("() => NET.data && NET.data.group === 'asn'", timeout=120000)
        d = page.evaluate("NET.data")
        rows = page.evaluate("document.querySelectorAll('#netBody tbody tr').length")
        assert rows == min(50, len(d["groups"])), (rows, len(d["groups"]))
        api_d = api(f"/api/dataset/{did}/networks?group=asn&max_hits=1&top=500")
        assert api_d["matched_ips"] == d["matched_ips"] and api_d["n_groups"] == d["n_groups"]
        page.select_option("#netGroup", "s24")
        page.wait_for_function("() => NET.data && NET.data.group === 's24'", timeout=60000)
        if d["groups"]:
            page.select_option("#netGroup", "asn")
            page.wait_for_function("() => NET.data && NET.data.group === 'asn'", timeout=60000)
            page.locator("[data-net-wk]").first.click()
            page.wait_for_function("() => CURRENT_PAGE === 'workplace' && WK.res && !WK.busy", timeout=60000)
            got = page.evaluate("WK.res.unique_ips")
            assert got == d["groups"][0]["ips"], (got, d["groups"][0])
        return f"{d['n_groups']} furnizori, {d['matched_ips']} IP-uri cu o cerere; Workplace = {d['groups'][0]['ips'] if d['groups'] else 0} IP"
    check("IP Explorer: retele (ASN / subnet) + Workplace cu aceleasi IP-uri", t_networks, page)

    def t_flags():
        goto(page, "countries")
        page.wait_for_function("() => document.querySelectorAll('#ctyMod img.flag').length > 0")
        page.wait_for_timeout(800)
        ok = page.evaluate("[...document.querySelectorAll('#ctyMod img.flag')].filter(i => i.complete && i.naturalWidth > 0).length")
        assert ok > 0, ok
        return f"{ok} steaguri incarcate"
    check("Countries: steaguri", t_flags, page)

    def t_console():
        assert not CONSOLE, CONSOLE[:5]
        return "0 erori JS"
    check("consola fara erori", t_console, page)
    browser.close()

bad = [r for r in RESULTS if not r[1]]
for name, ok, info in RESULTS:
    print(("PASS " if ok else "FAIL ") + name + " -- " + info)
print(f"{len(RESULTS) - len(bad)}/{len(RESULTS)} scenarii v50 trecute")
sys.exit(1 if bad else 0)
