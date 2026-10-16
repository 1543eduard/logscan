"""v51 -- teste end-to-end: "Ce s-a intamplat", reguli de blocare, profilul IP
din panoul lateral, bara compacta (mini-grafic + filtre), link care reproduce
ecranul, comparatia de perioade, tabelele uniforme.

    python3 app.py --port 8092 &
    python3 tests/ui_v51.py http://127.0.0.1:8092 /cale/log.log [/cale/screenshots]

Cifrele din interfata sunt comparate cu API-ul pentru aceeasi selectie."""
import json
import os
import sys
import time
import urllib.parse
import urllib.request

from playwright.sync_api import sync_playwright

BASE = sys.argv[1].rstrip("/")
LOG = sys.argv[2]
SHOTS = sys.argv[3] if len(sys.argv) > 3 else None
RESULTS, CONSOLE = [], []


def api(path, body=None, **q):
    url = BASE + path + ("?" + urllib.parse.urlencode(q) if q else "")
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
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
        page.screenshot(path=os.path.join(SHOTS, f"v51_{len(RESULTS):02d}.png"))
    page.keyboard.press("Escape")


def goto(page, mod):
    page.click(f'.pageTabBtn[data-page="{mod}"]')
    page.wait_for_timeout(1500)


def rule_modal(page):
    page.wait_for_function("() => document.querySelector('#ruleOverlay.open') && RULES.cur && !document.querySelector('#rlBody .xpBusy')", timeout=60000)
    return page.evaluate("RULES.cur")


with sync_playwright() as pw:
    browser = pw.chromium.launch()
    ctx = browser.new_context(viewport={"width": 1440, "height": 900})
    page = ctx.new_page()
    page.on("console", lambda m: m.type == "error" and CONSOLE.append(m.text))
    page.on("pageerror", lambda e: CONSOLE.append(str(e)))
    page.goto(BASE + "/")
    page.set_input_files("#fileInput", LOG)
    page.wait_for_function("() => TRIAGE.ready", timeout=900000)
    did = page.evaluate("DATASET_ID")

    def t_findings():
        goto(page, "overview")
        page.wait_for_function("() => document.querySelector('#ovFind .ovF')", timeout=90000)
        titles = page.evaluate("[...document.querySelectorAll('#ovFind .ovFT')].map(x => x.textContent)")
        assert 1 <= len(titles) <= 5, titles
        br = api(f"/api/dataset/{did}/brief")
        if br["exec"].get("filter_attack"):
            assert any("filtrele" in t for t in titles), titles
        btn = page.locator("#ovFind [data-rule]").first
        if btn.count():
            btn.click()
            d = rule_modal(page)
            assert d["options"] and d["strategy"] in ("ip", "subnet", "pattern", "ratelimit"), d
            if br["exec"].get("filter_attack") and "filtre" in d["label"]:
                assert d["strategy"] == "pattern" and "args.names" in d["options"][0]["text"], d["options"][0]
            page.locator("[data-rl-copy]").first.click()
        return f"{len(titles)} concluzii: {titles[0][:50]}…"
    check("Overview: 'Ce s-a intamplat' + regula de blocare", t_findings, page)

    def t_ip_profile():
        top = api(f"/api/dataset/{did}/explore", kind="sel", value="", top_n=5)["top_ips"][0]["ip"]
        page.evaluate(f"XP.open('ip', {json.dumps(top)})")
        page.wait_for_function("() => document.querySelector('#xpIdent .xpVerd')", timeout=60000)
        idn = api(f"/api/dataset/{did}/ip_identity", ip=top)
        txt = page.inner_text("#xpIdent")
        assert (idn["asn"] or "necunoscut") in txt and (idn["subnet"] in txt if idn["subnet"] else True), txt[:200]
        page.click("#xpActions .xpRuleBtn")
        d = rule_modal(page)
        assert d["strategy"] == "ip" and d["ips"] == 1, d
        page.keyboard.press("Escape")
        page.evaluate("XP.close()")
        # panoul se suprapune peste pagina, nu o ingusteaza (sub 1800px)
        return f"{top}: {idn['asn']} ({idn['kind']}), {idn.get('subnet_ips')} IP-uri in {idn['subnet']}"
    check("Panou IP: furnizor, retea, verdict, regula", t_ip_profile, page)

    def t_ctxbar():
        goto(page, "countries")
        page.evaluate("window.scrollTo(0, 1600)")
        page.wait_for_function("() => !document.querySelector('#ctxBar').hidden && CBAR.buckets.length", timeout=10000)
        B0, B1 = page.evaluate("() => [TRIAGE.boundsFrom, TRIAGE.boundsTo]")
        box = page.locator("#ctxHist").bounding_box()
        y = box["y"] + box["height"] / 2
        page.mouse.move(box["x"] + box["width"] * 0.30, y)
        page.mouse.down()
        page.mouse.move(box["x"] + box["width"] * 0.45, y, steps=6)
        page.mouse.up()
        page.wait_for_function("() => gfTimeNarrowed()", timeout=10000)
        a, b = page.evaluate("[TRIAGE.tsFrom, TRIAGE.tsTo]")
        span = B1 - B0
        assert abs((a - B0) / span - 0.30) < 0.03 and abs((b - B0) / span - 0.45) < 0.03, (a, b)
        page.wait_for_function("() => document.querySelectorAll('#ctxChips .filterChip').length === 1", timeout=10000)
        page.click("#ctxChips .filterChip .x")
        page.wait_for_function("() => !gfTimeNarrowed()", timeout=10000)
        return f"tragere 30%-45% -> {round(100 * (a - B0) / span)}%-{round(100 * (b - B0) / span)}%, x pe eticheta -> tot logul"
    check("Bara compacta: tragere pe mini-grafic + eticheta stearsa", t_ctxbar, page)

    def t_link():
        page.evaluate("triageSetSingleFilter('status', '200')")
        page.wait_for_timeout(800)
        goto(page, "endpoints")
        page.wait_for_timeout(500)
        url = page.evaluate("linkUrl()")
        assert f"d={did}" in url and "v=" in url and url.endswith("#endpoints"), url
        assert page.evaluate("location.href") == url, (page.evaluate("location.href"), url)
        p2 = ctx.new_page()
        p2.goto(url)
        p2.wait_for_function("() => TRIAGE.ready && (TRIAGE.filters.statuses || []).length === 1", timeout=120000)
        got = p2.evaluate("[TRIAGE.filters.statuses, CURRENT_PAGE, DATASET_ID]")
        p2.close()
        assert got == [["200"], "endpoints", did], got
        page.click("#triageResetBtn")
        return "link -> aceeasi analiza, pagina si filtre, fara reincarcare"
    check("Link care reproduce ecranul", t_link, page)

    def t_compare():
        page.evaluate("window.scrollTo(0, 0)")
        page.evaluate("cmpOpen()")
        page.wait_for_function("() => document.querySelector('#cmpOut .cmpTot')", timeout=90000)
        a0, a1, b0, b1 = page.evaluate("CMP.range")
        d = api(f"/api/dataset/{did}/diff", a_from=a0, a_to=a1, b_from=b0, b_to=b1, top=10)
        cells = page.evaluate("[...document.querySelectorAll('#cmpOut .cmpTot tbody tr:first-child td')].map(x => x.textContent.trim())")
        assert int(cells[1].replace(".", "")) == d["a"]["requests"] and int(cells[2].replace(".", "")) == d["b"]["requests"], (cells, d["a"], d["b"])
        page.click("#cmpUseB")
        page.wait_for_function("() => gfTimeNarrowed()", timeout=10000)
        assert page.evaluate("[TRIAGE.tsFrom, TRIAGE.tsTo]") == [b0, b1]
        page.click("#triageResetBtn")
        return f"A {d['a']['requests']} / B {d['b']['requests']} cereri = API; 'aplica B' -> perioada globala"
    check("Compara perioade = API", t_compare, page)

    def t_tables():
        goto(page, "countries")
        page.wait_for_function("() => document.querySelector('#ctyMod .tblx')", timeout=30000)
        t = "document.querySelector('#ctyMod table.tblxT')"
        n0 = page.evaluate(f"{t}.tBodies[0].rows.length")
        page.fill("#ctyMod .tblx input[type=search]", "Rom")
        page.wait_for_timeout(400)
        vis = page.evaluate(f"[...{t}.tBodies[0].rows].filter(r => r.style.display !== 'none').length")
        assert 1 <= vis < n0, (vis, n0)
        page.fill("#ctyMod .tblx input[type=search]", "")
        page.wait_for_timeout(400)
        hdr = page.evaluate(f"[...{t}.querySelectorAll('thead th')].findIndex(h => /IP/.test(h.textContent))")
        page.evaluate(f"{t}.querySelectorAll('thead th')[{hdr}].click()")
        vals = page.evaluate(f"[...{t}.tBodies[0].rows].map(r => parseInt(r.cells[{hdr}].textContent.replace(/\\D/g, '')) || 0)")
        assert vals == sorted(vals, reverse=True), vals[:8]
        return f"cautare {vis}/{n0} randuri, sortare descrescatoare pe IP-uri"
    check("Tabele: cautare + sortare", t_tables, page)

    def t_workplace_rule():
        goto(page, "workplace")
        page.locator('[data-wkp]', has_text="Rafale rapide").first.click()
        page.wait_for_timeout(1500)
        page.wait_for_function("() => WK.res && !WK.busy && WK.conds.some(c => c.field === 'ip_rpm')", timeout=60000)
        total = page.evaluate("WK.res.total")
        if not total:
            assert not page.query_selector(".wkRuleBtn")
            return "presetul nu are cereri in acest log -- butonul lipseste corect"
        page.click(".wkRuleBtn")
        d = rule_modal(page)
        assert d["requests"] == total, (d["requests"], total)
        return f"regula pentru {d['requests']} cereri / {d['ips']} IP-uri ({d['strategy']})"
    check("Workplace: regula de blocare pe rezultat", t_workplace_rule, page)

    def t_console():
        assert not CONSOLE, CONSOLE[:5]
        return "0 erori JS"
    check("consola fara erori", t_console, page)
    browser.close()

bad = [r for r in RESULTS if not r[1]]
for name, ok, info in RESULTS:
    print(("PASS " if ok else "FAIL ") + name + " -- " + info)
print(f"{len(RESULTS) - len(bad)}/{len(RESULTS)} scenarii v51 trecute")
sys.exit(1 if bad else 0)
