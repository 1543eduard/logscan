#!/usr/bin/env python3
"""Datele din log sunt NEINCREDERE (spec §8): un log cu payload-uri HTML/JS in
URL, referer si User-Agent nu trebuie sa execute nimic in UI -- pe niciun tab,
in panoul inferior, in detaliul cererii sau in profilul IP.
Uz: ui_xss.py BASE LOG"""
import sys
from playwright.sync_api import sync_playwright

BASE, LOG = sys.argv[1], sys.argv[2]
errs = []
with sync_playwright() as pw:
    b = pw.chromium.launch()
    page = b.new_page(viewport={"width": 1440, "height": 950})
    page.on("pageerror", lambda e: errs.append(str(e)))
    page.on("dialog", lambda d: (errs.append("dialog: " + d.message), d.dismiss()))
    page.goto(BASE)
    page.set_input_files("#fileInput", LOG)
    page.wait_for_function("() => TRIAGE.ready && TRIAGE.rows.length > 0", timeout=300000)
    page.wait_for_timeout(800)
    for tab in ("overview", "traffic", "countries", "endpoints", "errors", "security", "wordpress", "ip", "investigations", "raw"):
        page.click(f'.pageTabBtn[data-page="{tab}"]')
        page.wait_for_timeout(700)
    for sp in ("ips", "paths", "countries", "wp", "errors", "raw"):
        page.click(f'#spTabs .spTab[data-sp="{sp}"]')
        page.wait_for_timeout(300)
    # v50: vederea "Linii originale" afiseaza textul brut al liniilor
    page.evaluate("() => rawSetView('lines')")
    page.wait_for_timeout(700)
    assert page.evaluate("() => document.querySelectorAll('#rawLinesBox script, #rawLinesBox img, #rawLinesBox svg, #rawLinesBox iframe').length") == 0
    page.evaluate("() => rawSetView('table')")
    page.wait_for_timeout(300)
    page.locator("#triageViewport .triageRow [data-detail]").first.click()
    page.wait_for_function("() => !document.querySelector('.evRaw .spBusy')")
    page.wait_for_timeout(300)
    raw = page.inner_text(".evRaw")
    page.keyboard.press("Escape")
    page.evaluate("() => openIpProfile('203.0.113.1')")
    page.wait_for_timeout(800)
    # v45: panoul de explorare (toate taburile), meniul contextual, paleta,
    # investigatia si cronologia -- pe entitatile cu payload
    ents = page.evaluate("""() => TRIAGE.rows.filter(r => r.ip === '203.0.113.1').slice(0, 3)
        .flatMap(r => [['path', r.path.split('?')[0]], ['ua', r.ua], ['prefix', r.path.slice(0, 12)]])""")
    for kind, val in [["ip", "203.0.113.1"]] + ents:
        for tab in ("sum", "time", "raw", "rel", "alerts"):
            page.evaluate("([k, v, t]) => XP.open(k, v, t)", [kind, val, tab])
            page.wait_for_timeout(350)
        page.evaluate("([k, v]) => { openEntityMenu(100, 100, k, v); WS.addEntity(k, v); }", [kind, val])
        page.wait_for_timeout(150)
    page.evaluate("() => { XP.open('ip', '203.0.113.1', 'raw'); }")
    page.wait_for_timeout(700)
    page.check("#xpRawLines")
    page.wait_for_timeout(200)
    page.locator("#xpRawList [data-xev]").first.click()
    page.wait_for_timeout(600)
    page.evaluate("() => { WS.addEvent(XP.cur().list.rows[0]); XP.openWorkspace(); }")
    page.wait_for_timeout(400)
    page.evaluate("() => XP.openSecurity()")
    page.wait_for_timeout(800)
    page.keyboard.press("Control+k")
    page.keyboard.type("/<img src=x onerror=window.__xss=1>")
    page.wait_for_timeout(300)
    page.keyboard.press("Escape")
    xss = page.evaluate("() => window.__xss || 0")
    b.close()
assert "window.__xss" in raw, raw[:200]   # payload-ul apare ca TEXT
assert not xss, "payload executat!"
assert not errs, errs
print("PASS date neincredere: payload-urile HTML/JS din URL/referer/UA sunt afisate ca text, nimic executat pe 10 module + panou + detaliu + profil + panoul de explorare (5 taburi) + meniu contextual + investigatie + cronologie + paleta")
