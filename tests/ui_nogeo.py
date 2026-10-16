#!/usr/bin/env python3
"""Scenariul "lipsa datelor geografice" in UI (spec §9.13): server pornit
dintr-o copie FARA geoip/geoip2fast.py si geoip2fast.dat.gz.
Uz: ui_nogeo.py BASE LOG [screenshot.png]"""
import sys
from playwright.sync_api import sync_playwright

BASE, LOG = sys.argv[1], sys.argv[2]
SHOT = sys.argv[3] if len(sys.argv) > 3 else None
errs = []
with sync_playwright() as pw:
    b = pw.chromium.launch()
    page = b.new_page(viewport={"width": 1440, "height": 950})
    page.on("pageerror", lambda e: errs.append(str(e)))
    page.on("console", lambda m: m.type == "error" and errs.append(m.text))
    page.goto(BASE)
    page.set_input_files("#fileInput", LOG)
    page.wait_for_function("() => TRIAGE.ready && GF.overview", timeout=900000)
    warn = page.inner_text("#gfGeoWarn")
    assert page.is_visible("#gfGeoWarn") and "GeoIP indisponibil" in warn, warn
    page.click("#msCountry .msBtn")
    opts = page.eval_on_selector_all("#msCountry .msOption input", "els => els.map(e => e.value)")
    note = page.inner_text("#msCountry .msPanel")
    assert opts == ["??"], opts
    assert "GeoIP indisponibil" in note, note
    ov = page.evaluate("() => GF.overview")
    assert ov["unknown_country"] == ov["requests"] > 0, ov
    page.keyboard.press("Escape")
    page.evaluate("() => triageSetSingleFilter('country', 'RO')")
    page.wait_for_function("() => !TRIAGE.loading && !document.querySelector('#spKpis .skel') && TRIAGE.total === 0", timeout=60000)
    msg = page.inner_text("#triageRowCount")
    assert "GeoIP" in msg, msg
    if SHOT:
        page.screenshot(path=SHOT)
    b.close()
assert not errs, errs
print("PASS lipsa GeoIP: avertisment vizibil, doar '??' in filtru, 0 tari inventate, mesaj explicit la filtrare:", msg[:140])
