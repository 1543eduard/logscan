#!/usr/bin/env python3
"""v46 -- teste end-to-end pentru noua structura (meniu lateral + module),
tema luminoasa si eliminarea barii de jos din ecranul initial.

    python3 app.py --port 8092 &
    python3 tests/ui_v46.py http://127.0.0.1:8092 /cale/log.log [/cale/screenshots]

Cifrele din fiecare modul sunt comparate cu API-ul interogat independent
pentru aceeasi selectie (perioada + filtre)."""
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
MODULES = ["overview", "traffic", "countries", "endpoints", "errors", "security", "wordpress", "ip", "raw", "investigations"]


def api(path, **params):
    q = [(k, x) for k, v in params.items() for x in (v if isinstance(v, list) else [v])]
    with urllib.request.urlopen(BASE + path + ("?" + urllib.parse.urlencode(q) if q else ""), timeout=300) as r:
        return json.loads(r.read())


def check(name, fn, page):
    t = time.time()
    try:
        info = fn() or ""
        RESULTS.append((name, True, f"{info} ({time.time() - t:.1f}s)"))
    except Exception as e:  # noqa: BLE001
        RESULTS.append((name, False, f"{type(e).__name__}: {e}"))
    if SHOTS:
        page.screenshot(path=os.path.join(SHOTS, f"v46_{len(RESULTS):02d}.png"))


def mod_settle(page, timeout=120000):
    page.wait_for_function(
        "() => TRIAGE.ready && ![...document.querySelectorAll('.modPage')].some(p => p.style.display !== 'none' && p.querySelector('.xpBusy'))",
        timeout=timeout)
    page.wait_for_timeout(200)


def settle(page, timeout=90000):
    page.wait_for_function(
        "() => TRIAGE.ready && !TRIAGE.loading && !TRIAGE.histLoading && !document.querySelector('#spKpis .skel') "
        "&& !document.querySelector('#triageRowCount').classList.contains('busy')", timeout=timeout)
    page.wait_for_timeout(200)


def luminance(rgb):
    nums = [int(x) for x in rgb[rgb.index("(") + 1:rgb.index(")")].split(",")[:3]]
    return sum(nums) / (3 * 255)


BOTTOM_JS = """() => {
  // ce se afla pe ultimii 6 px ai ecranului, pe toata latimea?
  const hits = new Set();
  for (let x = 260; x < innerWidth - 10; x += 120) {
    const el = document.elementFromPoint(x, innerHeight - 6);
    if (el) hits.add((el.closest('#selectionPanel') ? 'PANOU-JOS ' : '') + (getComputedStyle(el).position) + ':' + (el.id || el.className || el.tagName));
  }
  const fixedBottom = [...document.querySelectorAll('body *')].filter(e => {
    const cs = getComputedStyle(e); if (cs.position !== 'fixed' || cs.display === 'none' || cs.visibility === 'hidden') return false;
    const r = e.getBoundingClientRect(); return r.height > 30 && r.width > innerWidth * 0.5 && Math.abs(r.bottom - innerHeight) < 2;
  }).map(e => e.id || e.className);
  return { hits: [...hits], fixedBottom, panelVisible: !!document.querySelector('#selectionPanel') && document.querySelector('#selectionPanel').offsetParent !== null };
}"""

with sync_playwright() as pw:
    browser = pw.chromium.launch()
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    page.on("pageerror", lambda e: CONSOLE.append("pageerror: " + str(e)))
    page.on("console", lambda m: m.type == "error" and CONSOLE.append("console.error: " + m.text))
    page.goto(BASE)
    page.wait_for_timeout(500)

    def t_start():
        st = page.evaluate(BOTTOM_JS)
        assert not st["panelVisible"] and not st["fixedBottom"], st
        assert page.is_visible("#dropzone") and page.is_visible("#sidebar")
        bg = page.evaluate("() => getComputedStyle(document.body).backgroundColor")
        assert luminance(bg) > 0.85, bg
        return f"ecran initial: zona de incarcare + meniu lateral, fundal {bg}, nimic fixat jos"
    check("ecran initial (inainte de import): fara bara de jos, tema luminoasa", t_start, page)

    page.set_input_files("#fileInput", LOG)
    page.wait_for_function("() => TRIAGE.ready", timeout=900000)
    mod_settle(page)
    DID = page.evaluate("() => DATASET_ID")
    B0, B1 = page.evaluate("() => [TRIAGE.boundsFrom, TRIAGE.boundsTo]")
    MID = (B0 + B1) // 2

    def t_after_import():
        cur = page.evaluate("() => CURRENT_PAGE")
        assert cur == "overview", cur
        st = page.evaluate(BOTTOM_JS)
        assert not st["panelVisible"] and not st["fixedBottom"] and not any(h.startswith("PANOU-JOS") for h in st["hits"]), st
        page.wait_for_function("() => /cereri/.test(document.querySelector('#ovLeadText').textContent)", timeout=60000)
        lead = page.inner_text("#ovLeadText")
        assert "cereri" in lead, lead
        return f"modul implicit Overview; marginea de jos: {', '.join(st['hits'][:3])}"
    check("dupa import: Overview curat, fara panoul de jos", t_after_import, page)

    def t_theme():
        st = page.evaluate("""() => ({ body: getComputedStyle(document.body).backgroundColor,
          card: getComputedStyle(document.querySelector('.card')).backgroundColor,
          side: getComputedStyle(document.querySelector('#sidebar')).backgroundColor,
          text: getComputedStyle(document.body).color, font: getComputedStyle(document.body).fontFamily,
          plex: document.fonts.check('14px "IBM Plex Sans"') && [...document.fonts].some(f => f.family.includes('IBM Plex Sans') && f.status === 'loaded') })""")
        assert luminance(st["body"]) > .85 and luminance(st["card"]) > .97 and luminance(st["side"]) > .9 and luminance(st["text"]) < .2, st
        assert "IBM Plex Sans" in st["font"] and st["plex"], st
        return f"fundal {st['body']}, carduri {st['card']}, text {st['text']}, font IBM Plex Sans incarcat"
    check("tema luminoasa + fonturile noi aplicate", t_theme, page)

    def t_nav():
        out = []
        for m in MODULES:
            page.click(f'.pageTabBtn[data-page="{m}"]')
            mod_settle(page)
            st = page.evaluate("""(m) => ({ cur: CURRENT_PAGE, hash: location.hash, title: document.querySelector('#modTitle').textContent,
              active: document.querySelector('.pageTabBtn.active').dataset.page,
              visible: [...document.querySelectorAll('.modPage')].filter(p => p.style.display !== 'none').map(p => p.id),
              dash: [...document.querySelector('#dash').children].filter(c => c.style.display !== 'none' && c.id !== 'dashStale').length })""", m)
            assert st["cur"] == m and st["hash"] == "#" + m and st["active"] == m and len(st["visible"]) == 1, st
            out.append(f"{m}:{st['visible'][0]}+{st['dash']}")
            if SHOTS:
                page.screenshot(path=os.path.join(SHOTS, f"v46_mod_{m}.png"), full_page=True)
        page.evaluate("() => { location.hash = 'errors'; }")
        page.wait_for_function("() => CURRENT_PAGE === 'errors'")
        page.keyboard.press("o")
        page.wait_for_function("() => CURRENT_PAGE === 'overview'")
        page.keyboard.press("r")
        page.wait_for_function("() => CURRENT_PAGE === 'raw'")
        page.go_back()
        page.wait_for_function("() => CURRENT_PAGE === 'overview'")
        return "; ".join(out) + " | link #errors, tastele O / R si butonul Inapoi al browserului functioneaza"
    check("meniul lateral: toate cele 10 module, titlu, link, tastatura", t_nav, page)

    def numbers_match(label):
        g = page.evaluate("() => gfJSON()")
        sel = api(f"/api/dataset/{DID}/explore", kind="sel", value="", gf=g, top_n=60)
        # Overview
        page.evaluate("() => showPage('overview')"); mod_settle(page)
        tiles = page.evaluate("() => [...document.querySelectorAll('#ovKpis .tileV')].map(t => t.textContent)")
        fmt = lambda n: f"{n:,}".replace(",", ".")
        if sel["requests"]:
            assert tiles[0] == fmt(sel["requests"]) and tiles[1] == fmt(sel["unique_ips"]) and tiles[2] == fmt(sel["unique_paths"]), (tiles, sel["requests"])
        # Countries: fiecare rand = API
        page.evaluate("() => showPage('countries')"); mod_settle(page)
        rows = page.evaluate("""() => [...document.querySelectorAll('#ctyMod table tbody tr')].map(r => [r.querySelector('[data-ev]').dataset.ev, r.children[1].textContent])""")
        exp = [[c["country"] or "??", fmt(c["n"])] for c in sel["countries"]]
        assert rows == exp, (label, rows[:3], exp[:3])
        # Errors
        page.evaluate("() => showPage('errors')"); mod_settle(page)
        if sel["requests"]:
            et = page.evaluate("() => [...document.querySelectorAll('#errMod .tileV')].map(t => t.textContent)")
            assert et[1] == fmt(sel["err_4xx"]) and et[2] == fmt(sel["err_5xx"]), (et, sel["err_4xx"], sel["err_5xx"])
        # WordPress
        wp = api(f"/api/dataset/{DID}/explore", kind="wp", value="wp_any", gf=g)
        page.evaluate("() => showPage('wordpress')"); mod_settle(page)
        if wp["requests"]:
            wt = page.evaluate("() => [...document.querySelectorAll('#wpMod .tileV')].map(t => t.textContent)")
            assert wt[0] == fmt(wp["requests"]) and wt[1] == fmt(wp["wordpress"].get("wp_login_post", 0)), (wt, wp["requests"])
        # Endpoints
        page.evaluate("() => showPage('endpoints')"); mod_settle(page)
        if sel["requests"]:
            first = page.evaluate("() => document.querySelector('#epMod [data-ek=\"path\"]').dataset.ev")
            assert first == sel["top_paths"][0]["path"], (first, sel["top_paths"][0])
        # Raw Logs
        page.evaluate("() => showPage('raw')"); settle(page)
        assert page.evaluate("() => TRIAGE.total") == sel["requests"]
        # banda perioadei
        txt = page.inner_text("#gfRibStats")
        assert fmt(sel["requests"]) in txt, (txt, sel["requests"])
        return sel["requests"]

    def t_numbers_full():
        n = numbers_match("tot logul")
        return f"Overview / Countries / Errors / WordPress / Endpoints / Raw Logs = API pe tot logul ({n} cereri)"
    check("cifrele fiecarui modul = API (tot logul)", t_numbers_full, page)

    def t_numbers_period():
        page.evaluate(f"() => triageSetRange({MID - 3600}, {MID - 1})")
        settle(page)
        page.evaluate("() => { TRIAGE.filters.countries = ['RO']; triageRenderMultiSelects(); triageRenderActiveChips(); triageReloadAll(); }")
        settle(page)
        n = numbers_match("1h + RO")
        assert "Ro" in page.inner_text("#triageActiveFilters") or "RO" in page.inner_text("#triageActiveFilters")
        tb = page.inner_text("#tbSel")
        assert f"{n:,}".replace(",", ".") in tb, tb
        return f"o ora + tara RO: {n} cereri, aceleasi in toate modulele si in bara de sus"
    check("perioada + filtru propagate in toate modulele", t_numbers_period, page)

    def t_period_while_open():
        page.evaluate("() => showPage('countries')"); mod_settle(page)
        page.evaluate(f"() => triageSetRange({MID}, {MID + 1799})")
        settle(page); mod_settle(page)
        g = page.evaluate("() => gfJSON()")
        sel = api(f"/api/dataset/{DID}/explore", kind="sel", value="", gf=g, top_n=60)
        rows = page.evaluate("""() => [...document.querySelectorAll('#ctyMod table tbody tr')].map(r => r.children[1].textContent)""")
        assert rows == [f"{c['n']:,}".replace(",", ".") for c in sel["countries"]], rows[:3]
        return f"modulul deschis s-a actualizat singur: {sel['requests']} cereri RO in 30 min"
    check("modul deschis se actualizeaza la schimbarea perioadei", t_period_while_open, page)

    def t_empty():
        page.evaluate("() => triageSetSingleFilter('ip', '203.0.113.254')")
        settle(page)
        out = []
        for m in ("overview", "countries", "errors", "endpoints", "traffic"):
            page.evaluate(f"() => showPage('{m}')"); mod_settle(page)
            txt = page.inner_text(".modPage:not([style*='none'])")
            assert "Nicio cerere" in txt or "nu conține nicio cerere" in txt, (m, txt[:200])
            out.append(m)
        page.click("#triageResetBtn"); settle(page)
        return "mesaj explicit (fara revenire la tot logul) in: " + ", ".join(out)
    check("selectie fara rezultate: mesaj explicit in fiecare modul", t_empty, page)

    def t_drill_from_module():
        page.evaluate("() => showPage('countries')"); mod_settle(page)
        link = page.locator('#ctyMod a[data-ek="country"]').nth(1)
        cc = link.get_attribute("data-ev")
        link.click()
        page.wait_for_function("() => XP.isOpen() && !document.querySelector('#xpBody .xpBusy')")
        n = page.evaluate("async () => (await xpExploreData(XP.cur().kind, XP.cur().value)).requests")
        exp = api(f"/api/dataset/{DID}/explore", kind="country", value=cc, gf=page.evaluate("() => gfJSON()"))["requests"]
        assert n == exp, (n, exp)
        page.evaluate("() => XP.close()")
        page.evaluate("() => showPage('overview')"); mod_settle(page)
        page.locator('#ovKpis .tile[data-goto="errors"]').first.click()
        page.wait_for_function("() => CURRENT_PAGE === 'errors'")
        return f"tara {cc} din Countries -> panoul de explorare ({n} cereri = API); tile Overview -> HTTP Errors"
    check("legaturi intre module si panoul de explorare", t_drill_from_module, page)

    def t_console():
        assert not CONSOLE, CONSOLE[:5]
        return "0 erori JS"
    check("consola fara erori", t_console, page)
    browser.close()

ok = sum(1 for r in RESULTS if r[1])
for name, passed, info in RESULTS:
    print(("PASS " if passed else "FAIL ") + name + " -- " + info, flush=True)
print(f"\n{ok}/{len(RESULTS)} scenarii v46 trecute")
sys.exit(0 if ok == len(RESULTS) else 1)
