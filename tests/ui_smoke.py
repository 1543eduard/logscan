#!/usr/bin/env python3
"""Test end-to-end al interfetei (spec §9) -- Playwright + Chromium, pe un
server logscan PORNIT. Nu face parte din testele unitare (cere browser):

    python3 app.py --port 8092 &
    python3 tests/ui_smoke.py http://127.0.0.1:8092 /cale/log.log [/cale/screenshots]

Fiecare scenariu verifica DATE, nu doar ca pagina porneste: valorile din UI
sunt comparate cu raspunsurile API-ului pentru aceeasi selectie. Orice eroare
JavaScript / promisiune respinsa / console.error pica testul."""
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
RESULTS = []
CONSOLE = []


def api(path, **params):
    q = []
    for k, v in params.items():
        for x in (v if isinstance(v, list) else [v]):
            q.append((k, x))
    with urllib.request.urlopen(BASE + path + ("?" + urllib.parse.urlencode(q) if q else ""), timeout=120) as r:
        return json.loads(r.read())


def check(name, fn, page):
    t = time.time()
    try:
        info = fn() or ""
        RESULTS.append((name, True, f"{info} ({time.time() - t:.1f}s)"))
    except Exception as e:  # noqa: BLE001
        RESULTS.append((name, False, f"{type(e).__name__}: {e}"))
    if SHOTS:
        page.screenshot(path=os.path.join(SHOTS, f"{len(RESULTS):02d}_{name.split()[0]}.png"))


def settle(page, timeout=60000):
    """Asteapta ca tabelul, sinteza si histograma sa fi raspuns pentru selectia curenta."""
    page.wait_for_function(
        "() => TRIAGE.ready && !TRIAGE.loading && !TRIAGE.histLoading && !document.querySelector('#spKpis .skel') "
        "&& !document.querySelector('#triageRowCount').classList.contains('busy')", timeout=timeout)
    page.wait_for_timeout(250)


def ui_state(page):
    return page.evaluate("""() => {
      const vp = document.querySelector('#triageViewport');
      const vr = vp.getBoundingClientRect();
      const vis = [...vp.querySelectorAll('.triageRow')].filter(r => r.style.display !== 'none' && r.getBoundingClientRect().top < vr.bottom && r.getBoundingClientRect().bottom > vr.top);
      return {
        rowsLoaded: TRIAGE.rows.length, total: TRIAGE.total, visibleRows: vis.length,
        firstRowOffset: vis.length ? Math.round(vis[0].getBoundingClientRect().top - vr.top) : null,
        overview: GF.overview ? GF.overview.requests : null,
        histTotal: TRIAGE.histBuckets.reduce((a, b) => a + b.total, 0),
        scope: document.querySelector('#spScope').textContent,
        rowCount: document.querySelector('#triageRowCount').textContent,
        chips: [...document.querySelectorAll('#triageActiveFilters .filterChip')].map(c => c.textContent.replace('×', '').trim()),
        countries: [...new Set(TRIAGE.rows.map(r => r.country || '??'))],
        statuses: [...new Set(TRIAGE.rows.map(r => r.http_status))],
        ips: [...new Set(TRIAGE.rows.map(r => r.ip))],
      };
    }""")


def ds_params(page):
    return page.evaluate("() => Object.fromEntries([...gfParams().keys()].map(k => [k, gfParams().getAll(k)]))")


def coherent(page, s):
    """Tabel == sinteza == histograma == API, pentru selectia curenta."""
    p = ds_params(page)
    did = page.evaluate("() => DATASET_ID")
    ov = api(f"/api/dataset/{did}/overview", **p)
    assert s["total"] == s["overview"] == ov["requests"], (s["total"], s["overview"], ov["requests"])
    assert s["histTotal"] == s["total"], ("histograma", s["histTotal"], s["total"])
    if s["total"]:
        assert s["visibleRows"] > 0 and s["firstRowOffset"] is not None and s["firstRowOffset"] < 60, \
            ("panoul inferior nu arata randurile", s["visibleRows"], s["firstRowOffset"])
    return ov


with sync_playwright() as pw:
    browser = pw.chromium.launch()
    page = browser.new_page(viewport={"width": 1440, "height": 950})
    page.on("pageerror", lambda e: CONSOLE.append("pageerror: " + str(e)))
    page.on("console", lambda m: m.type == "error" and CONSOLE.append("console.error: " + m.text))
    page.add_init_script("""window.__lt = []; try { new PerformanceObserver(l => l.getEntries().forEach(e => window.__lt.push(e.duration))).observe({entryTypes: ['longtask']}); } catch (e) {}""")
    page.goto(BASE)

    # 1 + 2 + 14: import (fisier valid; mare daca LOG e mare), fara blocarea UI
    def t_import():
        t0 = time.time()
        page.set_input_files("#fileInput", LOG)
        page.wait_for_selector("#pageTabs", state="visible", timeout=900000)
        t_dash = time.time() - t0
        page.wait_for_function("() => TRIAGE.ready", timeout=900000)
        page.click('.pageTabBtn[data-page="raw"]')
        settle(page)
        lt = page.evaluate("() => window.__lt.splice(0)")
        s = ui_state(page)
        assert s["rowsLoaded"] > 0 and s["total"] > 0, s
        coherent(page, s)
        assert max(lt or [0]) < 1500, ("UI blocat", max(lt))
        return (f"dashboard {t_dash:.1f}s, index gata {time.time() - t0:.1f}s; {s['total']} cereri; "
                f"cel mai lung task UI {round(max(lt or [0]))} ms")
    check("import fisier + panou inferior populat", t_import, page)
    page.click('.pageTabBtn[data-page="raw"]')   # v46: inregistrarile selectiei sunt in modulul Raw Logs
    settle(page)
    DID = page.evaluate("() => DATASET_ID")
    summ_all = api(f"/api/dataset/{DID}/overview")

    # 3: linii invalide raportate
    def t_invalid():
        txt = page.inner_text("#gfImportInfo")
        assert "linii procesate" in txt, txt
        return txt
    check("bilant import (linii procesate / invalide)", t_invalid, page)

    # 4: selectarea unei tari din dropdown (cu cautare)
    def t_country():
        flt = api(f"/api/dataset/{DID}/filters")
        cc = next(c["value"] for c in flt["countries"] if c["value"] not in ("", "RO"))
        page.click("#msCountry .msBtn")
        page.fill("#msCountry .msSearch", cc)
        page.check(f'#msCountry .msOption input[value="{cc}"]')
        settle(page)
        assert page.is_visible("#msCountry .msPanel"), "panoul de tari s-a inchis dupa bifare"
        s = ui_state(page)
        assert s["countries"] == [cc], s["countries"]
        ov = coherent(page, s)
        assert ov["requests"] == next(c["count"] for c in flt["countries"] if c["value"] == cc)
        assert cc in s["scope"], s["scope"]
        page.keyboard.press("Escape")
        return f"{cc}: {s['total']} cereri, {ov['unique_ips']} IP-uri, {ov['unique_paths']} URL-uri, 4xx={ov['err_4xx']}"
    check("filtru TARA -> tabel/sinteza/histograma", t_country, page)

    # 5: selectarea unui IP (click pe celula IP -> popover -> filtru)
    def t_ip():
        page.click("#triageResetBtn"); settle(page)
        page.locator("#triageViewport .triageRow .colIp").first.click()
        page.locator("#ctxMenu.open .ctxItem", has_text="Filtreaza dupa aceasta valoare").click()
        settle(page)
        s = ui_state(page)
        assert len(s["ips"]) == 1 and s["total"] > 0, s
        coherent(page, s)
        return f"IP {s['ips'][0]}: {s['total']} cereri"
    check("selectare IP din tabel", t_ip, page)

    # profil IP + detaliul unei cereri (linia originala)
    def t_detail():
        try:
            page.locator("#triageViewport .triageRow [data-detail]").first.click()
            page.wait_for_selector("#xpDrawer.open .evRaw")
            page.wait_for_function("() => !document.querySelector('#xpBody .evRaw .spBusy')")
            raw = page.inner_text("#xpBody .evRaw")
            ev = page.evaluate("() => TRIAGE.rows.find(r => r.id === TRIAGE.selId) || null")
            assert ev and ev["ip"] in raw and (" %s " % ev["http_status"]) in raw, ("linie/rand diferite", raw[:200], ev and ev["ip"])
            page.keyboard.press("Escape")
            ip = ev["ip"]
            page.evaluate(f"() => openIpProfile({json.dumps(ip)})")
            page.wait_for_function("() => document.querySelector('#xpBody .ipProfGrid')")
            assert "comportament" in page.inner_text("#xpBody").lower()
            return "linie bruta: " + raw[:70] + "..."
        finally:
            page.keyboard.press("Escape")
            page.evaluate("() => { closeAuditDrawer(); XP.close(); }")
    check("detaliu cerere (linia RAW originala) + profil IP", t_detail, page)

    # 6: URL (camp "Path contine", cu debounce)
    def t_url():
        page.click("#triageResetBtn"); settle(page)
        page.fill("#triagePathFilter", "wp-login")
        page.wait_for_timeout(600)
        settle(page)
        s = ui_state(page)
        assert s["total"] > 0 and all("wp-login" in r.lower() for r in page.evaluate("() => TRIAGE.rows.map(r => r.path)")), s
        coherent(page, s)
        return f"{s['total']} cereri cu 'wp-login'"
    check("filtru URL (path contine)", t_url, page)

    # 7: cod HTTP
    def t_status():
        page.click("#triageResetBtn"); settle(page)
        page.click("#msStatus .msBtn")
        page.check('#msStatus .msOption input[value="404"]')
        settle(page)
        page.keyboard.press("Escape")
        s = ui_state(page)
        assert s["statuses"] == [404], s["statuses"]
        coherent(page, s)
        return f"{s['total']} cereri 404"
    check("filtru cod HTTP", t_status, page)

    # 11: combinare + eliminare individuala + Inapoi
    def t_combine():
        page.click("#msCountry .msBtn")
        page.check('#msCountry .msOption input[value="RO"]')
        settle(page)
        page.keyboard.press("Escape")
        s = ui_state(page)
        assert s["statuses"] == [404] and s["countries"] == ["RO"], s
        coherent(page, s)
        both = s["total"]
        # elimina doar chip-ul de status
        page.locator("#triageActiveFilters .filterChip", has_text="Status").locator(".x").click()
        settle(page)
        s2 = ui_state(page)
        assert s2["countries"] == ["RO"] and len(s2["statuses"]) > 1 and s2["total"] > both, s2
        coherent(page, s2)
        page.click("#gfBackBtn")
        settle(page)
        s3 = ui_state(page)
        assert s3["total"] == both, (s3["total"], both)
        page.click("#triageResetBtn"); settle(page)
        s4 = ui_state(page)
        assert s4["total"] == summ_all["requests"] and not s4["chips"], s4
        return f"RO+404={both}, RO={s2['total']}, Inapoi->{s3['total']}, Reset->{s4['total']}"
    check("combinare, eliminare individuala, Inapoi, Reset", t_combine, page)

    # 8: interval de timp (click pe histograma)
    def t_time():
        page.wait_for_function("() => TRIAGE.histBuckets.length > 2")
        page.evaluate("() => { const r = document.querySelector('#triageHistChart').getBoundingClientRect(); window.scrollBy(0, r.top - 180); }")
        page.wait_for_timeout(200)
        box = page.locator("#triageHistChart").bounding_box()
        page.mouse.click(box["x"] + box["width"] * 0.5, box["y"] + box["height"] * 0.8)
        settle(page)
        s = ui_state(page)
        assert any(c.startswith("Interval") for c in s["chips"]), s["chips"]
        coherent(page, s)
        ts = page.evaluate("() => [TRIAGE.tsFrom, TRIAGE.tsTo, Math.min(...TRIAGE.rows.map(r => r.ts)), Math.max(...TRIAGE.rows.map(r => r.ts))]")
        assert ts[0] <= ts[2] and ts[3] <= ts[1], ts
        page.click("#triageResetBtn"); settle(page)
        return f"interval {s['chips'][0]} -> {s['total']} cereri"
    check("interval de timp din histograma", t_time, page)

    # 9 + 12: taburile panoului inferior (IP/URL/Tari/WordPress/Erori)
    def t_tabs():
        out = []
        for tab in ("ips", "paths", "countries", "wp", "errors"):
            page.click(f'#spTabs .spTab[data-sp="{tab}"]')
            pane = page.locator(f'.spPane[data-sp-pane="{tab}"]')
            if tab == "wp":
                page.wait_for_function("() => !document.querySelector('#spWpSources .spBusy')", timeout=60000)
            txt = pane.inner_text()
            assert len(txt) > 40 and "Sinteza se incarca" not in txt, (tab, txt[:200])
            out.append(f"{tab}:{pane.locator('tr').count()} randuri")
        # click pe o tara din tab-ul Tari -> filtru global
        page.click('#spTabs .spTab[data-sp="countries"]')
        page.locator('.spPane[data-sp-pane="countries"] .spLink').nth(1).click()
        settle(page)
        s = ui_state(page)
        assert len(s["countries"]) == 1, s["countries"]
        coherent(page, s)
        page.click("#triageResetBtn"); settle(page)
        return ", ".join(out)
    check("panou inferior: IP-uri / URL-uri / Tari / WordPress / Erori", t_tabs, page)

    # 12: WordPress -- categorie -> filtru (path + metoda)
    def t_wp():
        page.click('#spTabs .spTab[data-sp="wp"]')
        link = page.locator('[data-wpcat="wp_login_post"]')
        if not link.count():
            return "fara POST wp-login in acest log"
        exp = api(f"/api/dataset/{DID}/overview")["wordpress"]["wp_login_post"]
        link.click()
        settle(page)
        s = ui_state(page)
        meth = page.evaluate("() => [...new Set(TRIAGE.rows.map(r => r.method))]")
        assert meth == ["POST"] and s["total"] >= exp, (meth, s["total"], exp)
        coherent(page, s)
        page.click("#triageResetBtn"); settle(page)
        return f"POST wp-login: {s['total']} (sinteza WP: {exp})"
    check("WordPress: categorie -> cereri reale", t_wp, page)

    # 13: tara nedeterminata
    def t_unknown():
        flt = api(f"/api/dataset/{DID}/filters")
        n_unk = next((c["count"] for c in flt["countries"] if c["value"] == ""), 0)
        page.evaluate("() => triageSetSingleFilter('country', '??')")
        settle(page)
        s = ui_state(page)
        assert s["total"] == n_unk, (s["total"], n_unk)
        if n_unk:
            assert s["countries"] == ["??"], s["countries"]
            coherent(page, s)
        else:
            assert "Nicio cerere" in s["rowCount"], s["rowCount"]
        page.click("#triageResetBtn"); settle(page)
        return f"{n_unk} cereri fara tara (nu sunt atribuite niciunei tari)"
    check("tara nedeterminata (??)", t_unknown, page)

    # 10: corelare cu Prezentare si cu taburile detaliate
    def t_pages():
        flt = api(f"/api/dataset/{DID}/filters")
        cc = next(c["value"] for c in flt["countries"] if c["value"] not in ("", "RO"))
        page.evaluate(f"() => triageSetSingleFilter('country', '{cc}')")
        settle(page)
        page.click('.pageTabBtn[data-page="ip"]')
        page.wait_for_function("() => IPOV && IPOV_GF_KEY.includes('countries')", timeout=300000)
        tot = page.evaluate("() => IPOV.total_requests")
        exp = page.evaluate("() => GF.overview.requests")
        assert tot == exp, (tot, exp)
        assert page.is_visible("#ipovGfBanner")
        page.click('.pageTabBtn[data-page="security"]')
        page.wait_for_function("() => GF.detailKey === gfParams().toString()", timeout=600000)
        assert not page.is_visible("#dashStale")
        tot2 = page.evaluate("() => CURRENT_SUMMARY.total")
        assert tot2 == exp, (tot2, exp)
        # meniu pe un IP din tabelele detaliate -> filtru global
        cell = page.locator("#dash [data-ip]:visible").first
        if cell.count():
            ip = cell.get_attribute("data-ip")
            cell.click()
            page.locator("#ctxMenu.open .ctxItem", has_text="Filtreaza dupa aceasta valoare").click()
            settle(page)
            assert page.evaluate("() => TRIAGE.filters.ip") == ip
        page.click("#triageResetBtn"); settle(page)
        page.click('.pageTabBtn[data-page="raw"]')
        return f"{cc}: Prezentare={tot}, taburi detaliate={tot2}, panou={exp}"
    check("corelare Prezentare + taburi detaliate + meniu entitate", t_pages, page)

    # 15: fara erori in consola
    def t_console():
        assert not CONSOLE, CONSOLE[:5]
        return "0 erori JS"
    check("consola fara erori", t_console, page)
    browser.close()

ok = sum(1 for r in RESULTS if r[1])
for name, passed, info in RESULTS:
    print(("PASS " if passed else "FAIL ") + name + " -- " + info)
print(f"\n{ok}/{len(RESULTS)} scenarii UI trecute")
sys.exit(0 if ok == len(RESULTS) else 1)
