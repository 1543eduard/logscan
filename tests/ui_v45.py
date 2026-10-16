#!/usr/bin/env python3
"""v45 -- teste end-to-end (Playwright) pentru propagarea perioadei si a
filtrelor globale in TOATE drilldown-urile si pentru interactivitatea noua
(panoul de explorare, meniul contextual, paleta, investigatia).

    python3 app.py --port 8092 &
    python3 tests/ui_v45.py http://127.0.0.1:8092 /cale/log.log [/cale/screenshots]

Fiecare verificare compara ce se vede in UI cu API-ul interogat INDEPENDENT
pentru aceeasi selectie, si (pentru liniile RAW) timestamp-ul fiecarei linii
afisate cu perioada selectata. Orice eroare JavaScript pica testul."""
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime

from playwright.sync_api import sync_playwright

BASE = sys.argv[1].rstrip("/")
LOG = sys.argv[2]
SHOTS = sys.argv[3] if len(sys.argv) > 3 else None
RESULTS, CONSOLE = [], []
TS_RX = re.compile(r"\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]")


def api(path, **params):
    q = []
    for k, v in params.items():
        for x in (v if isinstance(v, list) else [v]):
            q.append((k, x))
    with urllib.request.urlopen(BASE + path + ("?" + urllib.parse.urlencode(q) if q else ""), timeout=300) as r:
        return json.loads(r.read())


def line_ts(line):
    m = TS_RX.search(line)
    return int(datetime.strptime(m.group(1), "%d/%b/%Y:%H:%M:%S %z").timestamp()) if m else None


def check(name, fn, page):
    t = time.time()
    try:
        info = fn() or ""
        RESULTS.append((name, True, f"{info} ({time.time() - t:.1f}s)"))
    except Exception as e:  # noqa: BLE001
        RESULTS.append((name, False, f"{type(e).__name__}: {e}"))
    if SHOTS:
        page.screenshot(path=os.path.join(SHOTS, f"v45_{len(RESULTS):02d}.png"))


def settle(page, timeout=90000):
    page.wait_for_function(
        "() => TRIAGE.ready && !TRIAGE.loading && !TRIAGE.histLoading && !document.querySelector('#spKpis .skel') "
        "&& !document.querySelector('#triageRowCount').classList.contains('busy')", timeout=timeout)
    page.wait_for_timeout(200)


def xp_settle(page, timeout=90000):
    """Panoul de explorare a terminat de randat vederea curenta."""
    page.wait_for_function(
        "() => XP.isOpen() && !document.querySelector('#xpBody .xpBusy') && !document.querySelector('#xpBody .evRaw .spBusy')",
        timeout=timeout)
    page.wait_for_timeout(150)


def modal_settle(page, timeout=90000):
    page.wait_for_function(
        "() => modalIsOpen() && !document.querySelector('#modalBody .spinner')", timeout=timeout)
    page.wait_for_timeout(150)


def gf(page):
    return page.evaluate("() => gfJSON()")


def sel_range(page):
    return page.evaluate("() => [TRIAGE.tsFrom, TRIAGE.tsTo]")


def set_range(page, a, b):
    page.evaluate(f"() => triageSetRange({int(a)}, {int(b)})")
    settle(page)


def modal_lines(page):
    return page.evaluate("() => [...document.querySelectorAll('#modalBody pre')].map(p => p.textContent)")


def reset(page):
    page.evaluate("() => { XP.close(); document.querySelector('#modalClose').click(); }")
    page.click("#triageResetBtn")
    settle(page)


with sync_playwright() as pw:
    browser = pw.chromium.launch()
    page = browser.new_page(viewport={"width": 1500, "height": 950})
    page.on("pageerror", lambda e: CONSOLE.append("pageerror: " + str(e)))
    page.on("console", lambda m: m.type == "error" and CONSOLE.append("console.error: " + m.text))
    page.on("dialog", lambda d: d.accept())
    page.add_init_script("""window.__lt = []; try { new PerformanceObserver(l => l.getEntries().forEach(e => window.__lt.push(e.duration))).observe({entryTypes: ['longtask']}); } catch (e) {}""")
    page.goto(BASE)
    page.set_input_files("#fileInput", LOG)
    page.wait_for_function("() => TRIAGE.ready", timeout=900000)
    settle(page)
    page.evaluate("() => window.__lt.splice(0)")     # importul e masurat in ui_smoke
    page.evaluate("() => showPage('raw')")           # v46: tabelul selectiei e in modulul Raw Logs
    settle(page)
    DID = page.evaluate("() => DATASET_ID")
    B0, B1 = page.evaluate("() => [TRIAGE.boundsFrom, TRIAGE.boundsTo]")
    MID = (B0 + B1) // 2
    H1 = (MID - 3600, MID - 1)            # prima ora
    H2 = (MID + 7200, MID + 10799)        # alt interval, mai tarziu
    flt = api(f"/api/dataset/{DID}/filters")
    CC = next(c["value"] for c in flt["countries"] if c["value"] not in ("", "RO"))

    # 1: cazul din captura -- perioada restransa, apoi "Drill-down: Tara X"
    def t_modal_period():
        set_range(page, *H1)
        g = gf(page)
        page.evaluate(f"() => drillDown({{ country: {json.dumps(CC)} }}, 'Tara {CC}')")
        modal_settle(page)
        lines = modal_lines(page)
        ts = [line_ts(x) for x in lines]
        exp = api(f"/api/dataset/{DID}/events", gf=g, kind="country", value=CC, with_count="true", limit=1)["total"]
        assert all(H1[0] <= t <= H1[1] for t in ts), ("linii din afara perioadei", [x for x, t in zip(lines, ts) if not H1[0] <= t <= H1[1]][:2])
        assert len(lines) == min(exp, 2000), (len(lines), exp)
        assert "Doar in selectia globala" in page.inner_text("#modalScope"), page.inner_text("#modalScope")
        return f"{CC} in {H1}: {len(lines)} linii, toate in perioada (API: {exp})"
    check("drilldown Tara (fereastra) respecta perioada selectata", t_modal_period, page)

    # 2: doua intervale succesive cu fereastra DESCHISA + revenire (Inapoi)
    def t_modal_successive():
        set_range(page, *H2)
        modal_settle(page)
        lines = modal_lines(page)
        ts = [line_ts(x) for x in lines]
        exp = api(f"/api/dataset/{DID}/events", gf=gf(page), kind="country", value=CC, with_count="true", limit=1)["total"]
        assert all(H2[0] <= t <= H2[1] for t in ts) and len(lines) == min(exp, 2000), (len(lines), exp)
        page.click("#gfBackBtn")
        settle(page)
        modal_settle(page)
        assert sel_range(page) == list(H1), sel_range(page)
        lines1 = modal_lines(page)
        assert all(H1[0] <= line_ts(x) <= H1[1] for x in lines1), "dupa Inapoi fereastra nu a revenit la prima perioada"
        page.click("#modalClose")
        return f"H2: {len(lines)} linii (API {exp}); Inapoi -> H1: {len(lines1)} linii"
    check("doua intervale succesive + Inapoi, cu fereastra deschisa", t_modal_successive, page)

    # 3: panoul de explorare pe tara: RAW in perioada; schimbarea perioadei il actualizeaza
    def t_xp_country():
        set_range(page, *H1)
        page.evaluate(f"() => XP.open('country', {json.dumps(CC)}, 'raw')")
        xp_settle(page)
        page.wait_for_function("() => /din/.test(document.querySelector('#xpRawCount').textContent)")
        out = []
        for rng in (H1, H2):
            if rng is H2:
                set_range(page, *H2)
                xp_settle(page)
                page.wait_for_function("() => /din/.test(document.querySelector('#xpRawCount').textContent)")
            g = gf(page)
            exp = api(f"/api/dataset/{DID}/events", gf=g, kind="country", value=CC, with_count="true", limit=1)["total"]
            st = page.evaluate("() => ({ total: XP.cur().list.total, ts: XP.cur().list.rows.map(r => r.ts), cc: [...new Set(XP.cur().list.rows.map(r => r.country))], scope: document.querySelector('#xpScope').textContent })")
            assert st["total"] == exp, (rng, st["total"], exp)
            assert all(rng[0] <= t <= rng[1] for t in st["ts"]), ("cereri din afara perioadei", rng)
            assert st["cc"] in ([CC], []), st["cc"]
            out.append(f"{exp}")
        return f"{CC}: H1={out[0]}, H2={out[1]} cereri; panoul s-a actualizat singur"
    check("panou explorare (tara) urmeaza perioada, si cand e deja deschis", t_xp_country, page)

    # 4: cronologia unui IP in perioada
    def t_ip_timeline():
        g = gf(page)
        top = api(f"/api/dataset/{DID}/explore", gf=g, kind="sel", value="")["top_ips"][0]
        page.evaluate(f"() => XP.open('ip', {json.dumps(top['ip'])}, 'time')")
        xp_settle(page)
        page.wait_for_function("() => !document.querySelector('#xpTimeNote .xpBusy')")
        tot = page.evaluate("() => { const c = XP.charts[0]; return c ? c.data.datasets.reduce((a, d) => a + d.data.reduce((x, y) => x + y, 0), 0) : -1; }")
        tl = api(f"/api/dataset/{DID}/timeline", gf=g, kind="ip", value=top["ip"])
        assert tot == top["n"] == sum(b["total"] for b in tl["buckets"]), (tot, top["n"])
        assert H2[0] <= tl["range"][0] and tl["range"][1] <= H2[1], tl["range"]
        # comparatie cu perioada precedenta (aceeasi durata)
        page.click('[data-cmpp="prev"]')
        page.wait_for_selector("#xpCmpOut .cmpTbl", timeout=60000)
        n_prev = api(f"/api/dataset/{DID}/explore", gf=g, kind="ip", value=top["ip"],
                     cmp_from=H2[0] - (H2[1] - H2[0] + 1), cmp_to=H2[0] - 1)["compare"]["requests"]
        cell = page.inner_text("#xpCmpOut .cmpTbl tbody tr:first-child td:nth-child(3)").replace(".", "").strip()
        assert int(cell) == n_prev, (cell, n_prev)
        return f"IP {top['ip']}: {tot} cereri pe grafic = API; perioada precedenta: {n_prev}"
    check("cronologia unui IP (+ comparatie cu perioada precedenta)", t_ip_timeline, page)

    # 5: alerta -> dovezile RAW (doar din perioada)
    def t_alert_raw():
        reset(page)
        al = api(f"/api/dataset/{DID}/alerts/top", limit=30)["alerts"]
        if not al:
            return "nicio alerta in log"
        a0 = al[0]
        page.evaluate("() => showPage('security')")
        set_range(page, a0["first_ts"] - 1800, a0["last_ts"] + 60)
        page.wait_for_function("() => document.querySelector('#triageAlertsRow .alertCard')", timeout=60000)
        g = gf(page)
        al2 = api(f"/api/dataset/{DID}/alerts/top", gf=g, limit=30)["alerts"]
        r0, r1 = sel_range(page)
        assert all(r0 <= x["first_ts"] <= x["last_ts"] <= r1 for x in al2), "alerte din afara perioadei"
        ui_n = page.locator("#triageAlertsRow .alertCard").count()
        assert ui_n == min(len(al2), 12), (ui_n, len(al2))   # Triajul afiseaza primele 12
        card = page.locator("#triageAlertsRow .alertCard").first
        ip, act = card.get_attribute("data-alert-ip"), card.get_attribute("data-action")
        card.click()
        xp_settle(page)
        page.wait_for_function("() => /din/.test(document.querySelector('#xpRawCount').textContent)")
        st = page.evaluate("() => ({ total: XP.cur().list.total, rows: XP.cur().list.rows.map(r => [r.ip, r.action_type, r.ts]) })")
        exp = api(f"/api/dataset/{DID}/events", gf=g, kind="alert", value=f"{ip}|{act}", with_count="true", limit=1)["total"]
        assert st["total"] == exp and exp > 0, (st["total"], exp)
        assert all(r[0] == ip and r[1] == act and r0 <= r[2] <= r1 for r in st["rows"]), st["rows"][:3]
        page.check("#xpRawLines")
        raw = page.locator("#xpRawList .xpRawLine").first.inner_text()
        assert raw.startswith(ip + " ") and r0 <= line_ts(raw) <= r1, raw
        return f"{len(al2)} alerte in perioada; {ip} {act}: {exp} cereri dovada, linia bruta: {raw[:60]}..."
    check("alerta din Triaj -> dovezi RAW din perioada", t_alert_raw, page)

    # 6: perioada / combinatie fara evenimente: mesaj explicit, NU tot logul
    def t_empty():
        reset(page)
        page.evaluate("() => showPage('raw')")
        # o secunda fara nicio cerere
        sec = None
        for start in range(MID, MID + 86400, 600):
            evs = api(f"/api/dataset/{DID}/events", ts_from=start, ts_to=start + 599, sort="ts_asc", limit=5000)["events"]
            busy = {e["ts"] for e in evs}
            sec = next((t for t in range(start, start + 600) if t not in busy), None)
            if sec is not None and len(evs) < 5000:
                break
        assert sec is not None, "nicio secunda libera in log"
        set_range(page, sec, sec)
        assert page.evaluate("() => TRIAGE.total") == 0, (sec, page.evaluate("() => TRIAGE.total"))
        assert "Nicio cerere" in page.inner_text("#triageRowCount") or page.is_visible("#triageEmptyMsg.on")
        page.evaluate("() => XP.open('sel', '')")
        xp_settle(page)
        assert page.locator("#xpBody .xpEmpty").count() == 1, page.inner_text("#xpBody")[:200]
        page.evaluate(f"() => drillDown({{ country: {json.dumps(CC)} }}, 'Tara {CC}')")
        modal_settle(page)
        txt = page.inner_text("#modalBody")
        assert "Nicio linie" in txt and "selectia curenta" in txt and not modal_lines(page), txt
        page.click("#modalClose")
        # combinatie: perioada normala + IP inexistent
        reset(page)
        set_range(page, *H1)
        page.evaluate("() => triageSetSingleFilter('ip', '203.0.113.254')")
        settle(page)
        page.evaluate("() => XP.open('ip', '203.0.113.254')")
        xp_settle(page)
        assert page.locator("#xpBody .xpEmpty").count() == 1
        return f"secunda {sec} fara cereri + IP inexistent: mesaj explicit in panou, explorer si fereastra"
    check("perioada fara evenimente: mesaj explicit, fara revenire la tot logul", t_empty, page)

    # 7: timp + tara + cod + severitate + IP, verificat pe toate componentele
    def t_combined():
        reset(page)
        set_range(page, B0, MID)
        page.evaluate("() => { TRIAGE.filters.countries = ['RO']; TRIAGE.filters.statuses = ['404']; triageRenderMultiSelects(); triageRenderActiveChips(); triageReloadAll(); }")
        settle(page)
        g = gf(page)
        ov = api(f"/api/dataset/{DID}/overview", gf=g)
        page.evaluate("() => XP.open('sel', '')")
        xp_settle(page)
        xp_n = page.evaluate("async () => (await xpExploreData('sel', '')).requests")
        assert page.evaluate("() => TRIAGE.total") == ov["requests"] == xp_n, (page.evaluate("() => TRIAGE.total"), ov["requests"], xp_n)
        ip = ov["top_ips"][0]["ip"] if ov["top_ips"] else None
        out = f"RO+404 in prima jumatate: {ov['requests']}"
        if ip:
            page.evaluate(f"() => triageSetSingleFilter('ip', {json.dumps(ip)})")
            settle(page)
            g2 = gf(page)
            n = api(f"/api/dataset/{DID}/overview", gf=g2)["requests"]
            d = api(f"/api/dataset/{DID}/ip_detail", ip=ip, gf=g2)
            assert d["requests"] == n == page.evaluate("() => TRIAGE.total"), (d["requests"], n)
            page.evaluate("() => { TRIAGE.filters.severities = ['INFO']; triageRenderMultiSelects(); triageRenderActiveChips(); triageReloadAll(); }")
            settle(page)
            n3 = api(f"/api/dataset/{DID}/overview", gf=gf(page))["requests"]
            assert page.evaluate("() => TRIAGE.total") == n3 <= n
            out += f"; + IP {ip}: {n} (= detaliu IP rescanat); + severitate INFO: {n3}"
        return out
    check("combinatie timp + tara + cod + IP + severitate", t_combined, page)

    # 8: schimbari rapide -- niciun rezultat depasit nu suprascrie selectia finala
    def t_rapid():
        reset(page)
        page.evaluate(f"() => XP.open('country', {json.dumps(CC)}, 'raw')")
        xp_settle(page)
        page.evaluate(f"() => drillDown({{ country: {json.dumps(CC)} }}, 'Tara {CC}')")
        modal_settle(page)
        steps = [(B0, B1), H2, (MID - 7200, MID), H1, (B0, MID), H2, H1]
        page.evaluate("(st) => st.forEach(([a, b]) => triageSetRange(a, b))", [list(x) for x in steps])
        settle(page)
        xp_settle(page)
        modal_settle(page)
        page.wait_for_function("() => /din/.test(document.querySelector('#xpRawCount').textContent)")
        page.wait_for_timeout(1500)
        xp_settle(page)
        modal_settle(page)
        assert sel_range(page) == list(H1)
        g = gf(page)
        exp = api(f"/api/dataset/{DID}/events", gf=g, kind="country", value=CC, with_count="true", limit=1)["total"]
        xp = page.evaluate("() => XP.cur().list.total")
        lines = modal_lines(page)
        assert xp == exp, (xp, exp)
        assert len(lines) == min(exp, 2000) and all(H1[0] <= line_ts(x) <= H1[1] for x in lines), (len(lines), exp)
        assert page.evaluate("() => TRIAGE.total") == api(f"/api/dataset/{DID}/overview", gf=g)["requests"]
        page.click("#modalClose")
        return f"7 perioade in rafala -> panou, explorer si fereastra arata ultima ({exp} cereri {CC})"
    check("schimbari rapide de perioada: fara rezultate depasite", t_rapid, page)

    # 9: meniu contextual -> exclude IP din selectie
    def t_ctx_exclude():
        reset(page)
        page.evaluate("() => showPage('raw')")
        page.click('#spTabs .spTab[data-sp="ips"]')
        page.wait_for_selector('.spPane[data-sp-pane="ips"] [data-ek="ip"]')
        link = page.locator('.spPane[data-sp-pane="ips"] a[data-ek="ip"]').first
        ip = link.get_attribute("data-ev")
        link.click(button="right")
        page.wait_for_selector("#ctxMenu.open")
        items = page.locator("#ctxMenu .ctxItem").all_inner_texts()
        page.locator("#ctxMenu .ctxItem", has_text="Exclude din selectie").click()
        settle(page)
        assert ip in page.evaluate("() => TRIAGE.filters.x.ips")
        assert page.locator("#triageActiveFilters .filterChip.neg").count() >= 1
        g = gf(page)
        ov = api(f"/api/dataset/{DID}/overview", gf=g)
        full = api(f"/api/dataset/{DID}/overview")["requests"]
        n_ip = api(f"/api/dataset/{DID}/events", kind="ip", value=ip, with_count="true", limit=1)["total"]
        assert page.evaluate("() => TRIAGE.total") == ov["requests"] == full - n_ip
        assert ip not in page.evaluate("() => TRIAGE.rows.map(r => r.ip)")
        page.click('#spTabs .spTab[data-sp="raw"]')
        return f"exclus {ip}: {full} -> {ov['requests']} cereri; meniul are {len(items)} actiuni"
    check("meniu contextual: exclude un IP din selectie", t_ctx_exclude, page)

    # 10: paleta de comenzi + navigare eveniment cu eveniment
    def t_palette_nav():
        reset(page)
        ip = api(f"/api/dataset/{DID}/explore", kind="sel", value="")["top_ips"][1]["ip"]
        page.keyboard.press("Control+k")
        page.wait_for_selector("#cmdk.open")
        page.keyboard.type(ip)
        page.keyboard.press("Enter")
        xp_settle(page)
        assert page.evaluate("() => XP.cur().kind + ':' + XP.cur().value") == "ip:" + ip
        page.click('#xpTabs [data-xtab="raw"]')
        xp_settle(page)
        page.wait_for_function("() => /din/.test(document.querySelector('#xpRawCount').textContent)")
        page.locator("#xpRawList .xpEvRow").first.click()
        xp_settle(page)
        r1 = page.inner_text("#xpBody .evRaw")
        page.keyboard.press("]")
        page.wait_for_function("() => XP.cur().index === 1")
        xp_settle(page)
        r2 = page.inner_text("#xpBody .evRaw")
        page.keyboard.press("[")
        page.wait_for_function("() => XP.cur().index === 0")
        assert r1 != r2 and r1.startswith(ip) and r2.startswith(ip), (r1[:60], r2[:60])
        page.keyboard.press("Alt+ArrowLeft")
        page.wait_for_function("() => XP.cur().type === 'ent'")
        return f"Ctrl+K '{ip}' -> explorer; cererea 1 -> 2 -> 1 cu ] [; Alt+<- inapoi la lista"
    check("paleta de comenzi + navigare intre cereri + inapoi", t_palette_nav, page)

    # 11: investigatie (salvata local, export)
    def t_workspace():
        ip = page.evaluate("() => XP.cur().value")
        page.evaluate(f"() => WS.addEntity('ip', {json.dumps(ip)})")
        page.evaluate("() => XP.openWorkspace()")
        page.wait_for_selector("#invBody #wsNotes")
        page.fill("#wsNotes", "verificat brute force")
        page.wait_for_timeout(700)
        saved = page.evaluate("() => JSON.parse(localStorage.getItem(WS.key))")
        assert saved["notes"] == "verificat brute force" and any(i["value"] == ip for i in saved["items"]), saved
        md = page.evaluate("() => WS.md()")
        assert ip in md and "verificat brute force" in md
        assert "DOAR in acest browser" in page.inner_text("#invBody")
        return f"{len(saved['items'])} element(e), notite salvate in localStorage ({page.evaluate('() => WS.key')[:40]}...)"
    check("spatiul de investigatie: elemente, notite, export", t_workspace, page)

    # 12: cronologia de securitate (card Triaj) urmeaza perioada; drag pe grafic = perioada
    def t_security():
        reset(page)
        page.click('.pageTabBtn[data-page="security"]')
        set_range(page, B0, MID)
        # regresie: randari suprapuse ale aceluiasi card (intrare in modul + schimbare de perioada)
        page.evaluate("() => { secCardRefresh(); secCardRefresh(); secCardRefresh(); }")
        page.wait_for_function("() => document.querySelector('#secCardBody .secRows, #secCardBody .xpEmpty')", timeout=60000)
        page.wait_for_function("() => !document.querySelector('#secCardBody .xpBusy')")
        g = gf(page)
        d = api(f"/api/dataset/{DID}/security_timeline", gf=g, min_severity="HIGH", gap=600, limit=300)
        r0, r1 = sel_range(page)
        assert all(r0 <= x["first_ts"] <= x["last_ts"] <= r1 for x in d["groups"])
        n_ui = page.locator("#secCardBody .secRow").count()
        assert n_ui == len(d["groups"]), (n_ui, len(d["groups"]))
        # tragere pe graficul de severitate -> perioada globala
        page.evaluate("() => { const c = document.querySelector('#secCardBody canvas'); c.scrollIntoView({ block: 'start' }); window.scrollBy(0, -260); }")
        page.wait_for_timeout(300)
        box = page.locator("#secCardBody canvas").bounding_box()
        page.mouse.move(box["x"] + box["width"] * 0.3, box["y"] + box["height"] * 0.5)
        page.mouse.down()
        page.mouse.move(box["x"] + box["width"] * 0.5, box["y"] + box["height"] * 0.5, steps=5)
        page.mouse.up()
        settle(page)
        n0, n1 = sel_range(page)
        assert r0 <= n0 < n1 <= r1 and (n1 - n0) < (r1 - r0) * 0.6, ((r0, r1), (n0, n1))
        return f"{d['total_groups']} grupuri HIGH+ in perioada (UI {n_ui}); tragere pe grafic -> {n1 - n0 + 1}s"
    check("cronologia de securitate + selectie de interval pe grafic", t_security, page)

    # 13: graficele vechi din taburile detaliate -> perioada / explorer
    def t_legacy_charts():
        reset(page)
        page.click('.pageTabBtn[data-page="traffic"]')
        page.wait_for_function("() => typeof timelineChart !== 'undefined' && timelineChart && timelineChart.options.onClick", timeout=600000)
        lbl = page.evaluate("() => { timelineChart.options.onClick({}, [{ index: 1 }]); return timelineChart.data.labels[1]; }")
        settle(page)
        assert page.evaluate("() => gfTimeNarrowed()"), lbl
        page.click("#triageResetBtn"); settle(page)
        return f"click pe '{lbl}' in 'Trafic in timp' -> perioada globala"
    check("graficele din taburile detaliate seteaza perioada", t_legacy_charts, page)

    def t_longtasks():
        lt = page.evaluate("() => window.__lt.slice()")
        assert max(lt or [0]) < 1000, ("UI blocat", sorted(lt)[-5:])
        return f"{len(lt)} task-uri > 50 ms in toate scenariile; cel mai lung {round(max(lt or [0]))} ms"
    check("UI fara blocaje in timpul interactiunilor", t_longtasks, page)

    def t_console():
        assert not CONSOLE, CONSOLE[:5]
        return "0 erori JS"
    check("consola fara erori", t_console, page)
    browser.close()

ok = sum(1 for r in RESULTS if r[1])
for name, passed, info in RESULTS:
    print(("PASS " if passed else "FAIL ") + name + " -- " + info, flush=True)
print(f"\n{ok}/{len(RESULTS)} scenarii v45 trecute")
sys.exit(0 if ok == len(RESULTS) else 1)
