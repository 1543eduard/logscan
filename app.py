#!/usr/bin/env python3
"""
logscan - Security / Traffic Analytics Dashboard pentru loguri cPanel Raw
Access (Apache/LiteSpeed combined format).

Single-file FastAPI backend + dashboard.html (frontend static, Chart.js
inclus direct in pagina -- fara dependinte externe). Upload un log
(.log/.txt/.gz/.zip), motorul il parseaza o singura data
pe toate core-urile disponibile si tine un "dataset" in memorie (cu TTL) pe
care dashboard-ul il interogheaza interactiv: filtrare pe zi, drill-down pe
IP/URL/subnet, export CSV/JSON.

Fisierul decomprimat (plain text) e pastrat temporar cat timp dataset-ul e
activ, ca sa poata servi vizualizarea de linii brute la drill-down -- se
sterge automat la expirarea TTL-ului sau la oprirea aplicatiei.

v44: filtrele globale, panoul inferior, histograma si pagina Prezentare
raspund dintr-un index COLUMNAR in memorie (triage_columnar.py, necesita
numpy -- optional: fara el se foloseste indexul SQLite, cu aceleasi cifre).
Dependinte: fastapi, uvicorn, python-multipart; optional numpy.
"""
import argparse
import calendar
import csv
import gzip
import hashlib
import html
import io
import ipaddress
import json
import functools
import signal
import sqlite3
import multiprocessing as mp
import os
import re
import shutil
import socket
import sys
import tempfile
import threading
import time
import urllib.request
import uuid
import zipfile
from collections import Counter, defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import unquote

from typing import Any, Dict, List, Optional, Set, Tuple

from fastapi import FastAPI, UploadFile, File, Form, Query, Request, Body
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse, Response, FileResponse, StreamingResponse
import uvicorn

import triage_engine
import triage_columnar
import workplace
import blockrules
np = triage_columnar.np   # None fara numpy -- folosit doar pe calea columnara

APP_DIR = os.path.dirname(os.path.abspath(__file__))

# --------------------------------------------------------------------------
# GeoIP (optional, complet offline) -- foloseste geoip2fast (MIT), vendorizat
# in geoip/geoip2fast.py + geoip/geoip2fast.dat.gz. Nu face NICIUN apel de
# retea; daca fisierele lipsesc, tara pur si simplu nu se afiseaza.
# --------------------------------------------------------------------------
_GEOIP_DIR = os.path.join(APP_DIR, "geoip")
_geoip = None
if os.path.isdir(_GEOIP_DIR):
    if _GEOIP_DIR not in sys.path:
        sys.path.insert(0, _GEOIP_DIR)
    try:
        from geoip2fast import GeoIP2Fast
        _geoip = GeoIP2Fast(verbose=False)
    except Exception:
        _geoip = None

# Baza IPv6 (optionala): geoip2fast.dat.gz (implicita) acopera doar IPv4, deci
# orice IP IPv6 iesea "tara nedeterminata" (207 linii in logul real). Daca in
# geoip/ exista si geoip2fast-ipv6.dat.gz (din acelasi pachet geoip2fast), o
# folosim DOAR pentru adresele IPv6 -- rezultatele IPv4 raman neschimbate.
# Incarcare lenesa: ~0.2s si ~48 MB, platite doar daca apare un IPv6.
_GEOIP6_FILE = os.path.join(_GEOIP_DIR, "geoip2fast-ipv6.dat.gz")
_geoip6 = None
_geoip6_tried = False


def _geoip_isolated(tag):
    """Clasa GeoIP2Fast dintr-o copie SEPARATA a modulului. geoip2fast tine
    baza incarcata in variabile globale de modul: un al doilea GeoIP2Fast(...)
    (IPv6, furnizori ASN) in acelasi modul o suprascria pe prima, iar ~3% din
    IP-urile IPv4 primeau apoi alta tara. Fiecare baza are deci modulul ei."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(f"geoip2fast_{tag}", os.path.join(_GEOIP_DIR, "geoip2fast.py"))
    if spec is None or spec.loader is None:
        raise ImportError("geoip2fast.py lipseste")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.GeoIP2Fast


def geoip_status():
    """Ce poate rezolva GeoIP pe acest server -- afisat in UI (spec §3: nu
    inventam tari; explicam de ce un IP nu are tara). IPv6 e raportat
    disponibil doar daca baza chiar se incarca (nu doar daca fisierul exista)."""
    ipv6 = False
    if _geoip and os.path.exists(_GEOIP6_FILE):
        if not _geoip6_tried:
            _lookup6("2001:4860:4860::8888")
        ipv6 = _geoip6 is not None
    missing = []
    if not _geoip:
        for fn in ("geoip2fast.py", "geoip2fast.dat.gz"):
            if not os.path.exists(os.path.join(_GEOIP_DIR, fn)):
                missing.append("geoip/" + fn)
    return {"ipv4": bool(_geoip), "ipv6": ipv6, "missing": missing}


def _lookup6(ip):
    global _geoip6, _geoip6_tried
    if not _geoip6_tried:
        _geoip6_tried = True
        if _geoip and os.path.exists(_GEOIP6_FILE):
            try:
                _geoip6 = _geoip_isolated("ipv6")(geoip2fast_data_file=_GEOIP6_FILE, verbose=False)
            except (Exception, SystemExit):
                # versiune de geoip2fast.py incompatibila cu fisierul IPv6 ->
                # IPv6 ramane "tara nedeterminata" (explicat in UI), nimic nu cade
                _geoip6 = None
    return _geoip6.lookup(ip) if _geoip6 else None


def country_of(ip):
    """Cod de tara (ex: 'RO') pentru un IP, sau '' daca GeoIP nu e
    disponibil / IP-ul nu e gasit in baza de date. Lookup local, offline,
    ~microsecunde. '' inseamna NEDETERMINAT -- nu se ghiceste niciodata."""
    if not _geoip or not ip:
        return ""
    try:
        r = _lookup6(ip) if ":" in ip else _geoip.lookup(ip)
        if r is None:
            return ""
        cc = getattr(r, "country_code", "") or ""
        return "" if cc in ("--", "") else cc
    except Exception:
        return ""

# v44 (spec §3): valorile de tara venite din UI/URL se normalizeaza INTR-UN
# SINGUR loc. Rezultat: "" = tara nedeterminata (GeoIP nu a rezolvat IP-ul --
# niciodata ghicita), "__NON_RO__" = orice tara CUNOSCUTA diferita de RO, sau
# un cod ISO-3166 alpha-2 cu majuscule. None = valoare nerecunoscuta (apelantul
# raspunde cu o eroare explicita, nu cu o lista goala fara motiv). Inainte,
# "Germany".upper()[:2] devenea "GE" (Georgia) fara niciun avertisment.
_UNKNOWN_CC_ALIASES = frozenset(("", "??", "?", "-", "--", "n/a", "unknown", "necunoscut", "necunoscuta",
                                 "nedeterminat", "nedeterminata", "__unknown__", "none", "null"))


def normalize_country_value(v):
    s = (v or "").strip()
    low = s.lower()
    if low in _UNKNOWN_CC_ALIASES:
        return ""
    if low == "__non_ro__":
        return "__NON_RO__"
    if len(s) == 2 and s.isascii() and s.isalpha():
        return s.upper()
    return None


# --------------------------------------------------------------------------
# Wordfence Intelligence -- cross-referentiere OPTIONALA, BEST-EFFORT, cu
# baza publica de vulnerabilitati WordPress a Wordfence
# (https://www.wordfence.com/threat-intel/vulnerabilities/). SINGURUL loc
# din aplicatie care face un apel de retea catre altcineva decat clientul
# din browser -- tot restul (GeoIP, parsare) e 100% offline.
#
# Ce face: descarca (o data pe zi, in fundal, fara sa blocheze nimic)
# feed-ul public JSON al Wordfence, extrage slug-urile de plugin-uri/teme
# WordPress cu vulnerabilitati cunoscute, si le compara cu path-urile
# vazute in log (wp-content/plugins/<slug>/, wp-content/themes/<slug>/).
#
# Ce NU face si nu poate face: access log-ul NU arata versiunea instalata
# a unui plugin, deci un "match" NU inseamna exploatare confirmata -- doar
# ca acel plugin/tema (indiferent de versiune) ARE vulnerabilitati
# cunoscute in baza Wordfence, deci merita verificat manual daca versiunea
# instalata e printre cele afectate.
#
# Best-effort explicit: daca feed-ul nu poate fi descarcat (fara net,
# schimbare de termeni de acces, schema JSON diferita de cea asteptata),
# functia esueaza silentios -- restul aplicatiei functioneaza normal,
# doar sectiunea Wordfence din dashboard arata "indisponibil".
# --------------------------------------------------------------------------
WORDFENCE_FEED_URL = "https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production"
WORDFENCE_CACHE_PATH = os.path.join(APP_DIR, "wordfence_cache.json")
WORDFENCE_REFRESH_SECONDS = 24 * 3600
WORDFENCE_FETCH_TIMEOUT = 90
WORDFENCE_MAX_FEED_BYTES = 250 * 1024 * 1024  # plafon siguranta (feed-ul real e ~100-150MB)

_wordfence_lock = threading.Lock()
_wordfence_state = {
    "slugs": {},          # slug -> {"type": "plugin"|"theme", "count": n, "titles": [...]}
    "last_attempt": 0.0,
    "last_success": 0.0,
    "last_error": None,
    "source": None,       # "cache_disk" | "network"
}

_WP_PLUGIN_THEME_RE = re.compile(
    r"wp-content/(plugins|themes)/([a-zA-Z0-9_.-]+)/", re.IGNORECASE
)


def _wordfence_extract_slugs(data):
    """Parcurge JSON-ul feed-ului (dict cheie=uuid vulnerabilitate, sau
    lista, in functie de versiunea API-ului) si extrage, pentru fiecare
    intrare cu un bloc "software" continand plugin-uri/teme WordPress,
    slug-ul + titlul vulnerabilitatii. Scris defensiv (izoleaza fiecare
    intrare in try/except) ca sa nu esueze complet daca o mica parte din
    schema difera de ce ne asteptam."""
    slugs = {}
    if isinstance(data, dict):
        entries = data.values()
    elif isinstance(data, list):
        entries = data
    else:
        return {}
    for entry in entries:
        try:
            if not isinstance(entry, dict):
                continue
            title = entry.get("title") or entry.get("name") or ""
            software_list = entry.get("software")
            if not isinstance(software_list, list):
                continue
            for sw in software_list:
                if not isinstance(sw, dict):
                    continue
                slug = (sw.get("slug") or "").strip().lower()
                sw_type = (sw.get("type") or "").strip().lower()
                if not slug or sw_type not in ("plugin", "theme"):
                    continue
                rec = slugs.setdefault(slug, {"type": sw_type, "count": 0, "titles": set()})
                rec["count"] += 1
                if title and len(rec["titles"]) < 5:
                    rec["titles"].add(title)
        except Exception:
            continue
    return {s: {"type": r["type"], "count": r["count"], "titles": sorted(r["titles"])} for s, r in slugs.items()}


def _wordfence_load_disk_cache():
    try:
        with open(WORDFENCE_CACHE_PATH, "r", encoding="utf-8") as f:
            cached = json.load(f)
        slugs = cached.get("slugs") or {}
        if slugs:
            with _wordfence_lock:
                _wordfence_state["slugs"] = slugs
                _wordfence_state["last_success"] = cached.get("saved_at", 0.0)
                _wordfence_state["source"] = "cache_disk"
    except Exception:
        pass  # fara cache pe disc inca (prima rulare) -- normal, nu e o eroare


def wordfence_refresh(force=False):
    """Descarca si (re)incarca feed-ul, daca a trecut TTL-ul sau daca
    force=True. Ruleaza pe un thread separat, nu blocheaza niciodata
    cererile HTTP normale. Sigura de apelat oricand -- orice eroare e
    prinsa si stocata in _wordfence_state['last_error'], nimic nu crapa."""
    now = time.time()
    with _wordfence_lock:
        if not force and (now - _wordfence_state["last_attempt"]) < WORDFENCE_REFRESH_SECONDS:
            return
        _wordfence_state["last_attempt"] = now
    try:
        req = urllib.request.Request(
            WORDFENCE_FEED_URL,
            headers={"User-Agent": "logscan-selfhosted-dashboard/1.0 (+best-effort vulnerability cross-check)"},
        )
        with urllib.request.urlopen(req, timeout=WORDFENCE_FETCH_TIMEOUT) as resp:
            raw = resp.read(WORDFENCE_MAX_FEED_BYTES)
        data = json.loads(raw)
        slugs = _wordfence_extract_slugs(data)
        if not slugs:
            raise ValueError("Feed descarcat, dar 0 slug-uri extrase -- posibil schema JSON schimbata")
        with _wordfence_lock:
            _wordfence_state["slugs"] = slugs
            _wordfence_state["last_success"] = time.time()
            _wordfence_state["last_error"] = None
            _wordfence_state["source"] = "network"
        try:
            with open(WORDFENCE_CACHE_PATH, "w", encoding="utf-8") as f:
                json.dump({"slugs": slugs, "saved_at": _wordfence_state["last_success"]}, f)
        except Exception:
            pass  # cache-ul pe disc e doar o optimizare, nu esential
    except Exception as e:
        with _wordfence_lock:
            _wordfence_state["last_error"] = f"{type(e).__name__}: {e}"


def wordfence_status():
    with _wordfence_lock:
        return {
            "available": bool(_wordfence_state["slugs"]),
            "slug_count": len(_wordfence_state["slugs"]),
            "last_success": _wordfence_state["last_success"],
            "last_error": _wordfence_state["last_error"],
            "source": _wordfence_state["source"],
        }


def wordfence_match_paths(top_paths_counter, path_ips):
    """Compara path-urile vazute in log cu slug-urile Wordfence cunoscute.
    Intoarce o lista goala instant daca feed-ul nu e (inca) disponibil --
    restul dashboard-ului nu asteapta niciodata dupa asta."""
    with _wordfence_lock:
        slugs_snapshot = _wordfence_state["slugs"]
    if not slugs_snapshot:
        return []
    hits = defaultdict(lambda: {"requests": 0, "paths": set(), "ips": set()})
    for p, c in top_paths_counter.items():
        m = _WP_PLUGIN_THEME_RE.search(p)
        if not m:
            continue
        kind_plural, slug_raw = m.group(1).lower(), m.group(2).lower()
        wf = slugs_snapshot.get(slug_raw)
        if not wf or wf["type"] != kind_plural[:-1]:
            continue
        rec = hits[slug_raw]
        rec["requests"] += c
        if len(rec["paths"]) < 15:
            rec["paths"].add(p)
        for ip in path_ips.get(p, ()):
            if len(rec["ips"]) < MAX_IPS_PER_BUCKET:
                rec["ips"].add(ip)
    out = []
    for slug, rec in hits.items():
        wf = slugs_snapshot[slug]
        out.append({
            "slug": slug, "type": wf["type"], "requests": rec["requests"],
            "unique_ips": len(rec["ips"]), "sample_paths": sorted(rec["paths"]),
            "known_vuln_titles": wf["titles"], "known_vuln_count": wf["count"],
        })
    out.sort(key=lambda x: -x["requests"])
    return out


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------
MAX_UPLOAD_BYTES = 8 * 1024 * 1024 * 1024  # 8 GB decompressed safety cap
DATASET_TTL_SECONDS = 2 * 3600  # dataset-ul (inclusiv fisierul plain de pe disc) tinut 2h
DATASETS: Dict[str, Dict[str, Any]] = {}  # dataset_id -> Dataset dict
DATASETS_LOCK = threading.Lock()

MAX_IPS_PER_BUCKET = 300_000     # plafon IP-uri unice retinute per path/subnet/pattern
MAX_LOGIN_ATTEMPTS_PER_IP = 5000
MAX_ADMIN_EVENTS_PER_IP = 200     # cate evenimente admin/WP (login, plugin etc.) tinem per IP pentru afisare
MAX_FINDINGS_PER_RULE_PER_CHUNK = 500
MAX_RAW_MATCHES = 2000           # default cate linii brute intorci la un drill-down
                                  # (poate fi ridicat pana la RAW_MATCHES_HARD_CAP prin
                                  # parametrul ?limit= -- vezi api_raw/api_burst_raw)

BURST_KPI_MIN_REQUESTS = 50       # prag folosit DOAR pentru KPI-ul "Bursturi" (cate ferestre de
                                   # 30s ating/depasesc acest volum) -- top_bursts (top 3) ramane
                                   # neschimbat, neconditionat de acest prag.

# --------------------------------------------------------------------------
# Verificare identitate crawler (Tier 2, DNS) -- vezi CRAWLER_IDENTITY_CATALOG
# si _verify_one_ip mai jos pentru detalii.
# --------------------------------------------------------------------------
DNS_LOOKUP_TIMEOUT_SEC = 2.0      # per lookup (PTR sau forward-confirm), nu per IP total
DNS_VERIFY_MAX_WORKERS = 20       # concurenta maxima de IP-uri verificate simultan
CRAWLER_VERIFY_CACHE_MAX = 50_000  # plafon simplu pe cache-ul in memorie (viata procesului, fara persistenta)
RAW_MATCHES_HARD_CAP = 20000     # plafon absolut server-side, indiferent ce cere clientul
                                  # (protectie impotriva unui "Tot" accidental pe un log uriaș)

# --------------------------------------------------------------------------
# Parsing (regex pastrat doar ca fallback/referinta pentru teste)
# --------------------------------------------------------------------------
LOG_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+\S+)?"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)


# --------------------------------------------------------------------------
# SQL injection (Eduard, atv-de-vanzare.atvrom.ro -- un atac sqlmap real,
# 100% vizibil in log, care NU aparea deloc in findings). Semnatura veche
# ("sqli": union\s+select|base64_decode\(|/etc/passwd|\.\./\.\./|<\?php) rata
# aproape tot traficul real de sqlmap din acel log, din doua motive:
#   1) union\s+select cere DOAR spatiu intre cuvinte -- payload-urile reale
#      erau "UNION+ALL+SELECT" (cuvantul ALL intre ele, "+" in loc de spatiu
#      dupa unquote() -- vezi mai jos, "+" NU e decodat de unquote standard).
#   2) marea majoritate a request-urilor din acel atac erau blind SQLi
#      error-based/time-based prin sqlmap (INFORMATION_SCHEMA.PLUGINS,
#      CONCAT(0x..), FLOOR(RAND(0)*2), extractvalue()/updatexml(), SLEEP(),
#      BENCHMARK()) -- tehnici care nu contin deloc cuvintele "union"/"select"
#      si nu erau acoperite de NICIO semnatura existenta.
# "+SP+" de mai jos = separator tolerant intre cuvinte-cheie: spatiu real SAU
# "+" literal (unquote() standard NU converteste "+" in spatiu, doar %XX --
# pastrat asa intentionat, ca sa nu schimbe comportamentul existent pe restul
# path-ului) SAU un comentariu SQL inline gen /**/ (tehnica uzuala de sqlmap
# ca sa ocoleasca filtre naive pe spatiu).
_SP = r"(?:[\s+]|/\*\*/|%20|%2b)*"
SUSPICIOUS_PATTERNS = [
    ("sqli_union", re.compile(r"union" + _SP + r"(?:all" + _SP + r")?select", re.I)),
    # Blind error-based (sqlmap): INFORMATION_SCHEMA/CONCAT(0x.../FLOOR(RAND(/
    # EXTRACTVALUE(/UPDATEXML( -- niciunul dintre acestea n-ar trebui sa
    # apara VREODATA intr-un query string legitim.
    ("sqli_error_blind", re.compile(
        r"information_schema|extractvalue\s*\(|updatexml\s*\(|floor\s*\(\s*rand\s*\("
        r"|concat\s*\(\s*0x", re.I)),
    # Blind time-based (sqlmap/manual): SLEEP()/BENCHMARK()/WAITFOR DELAY/
    # PG_SLEEP() -- tehnica clasica de deducere bit-cu-bit prin intarzierea
    # raspunsului serverului.
    ("sqli_time_blind", re.compile(
        r"sleep\s*\(\s*\d|benchmark\s*\(|waitfor" + _SP + r"delay|pg_sleep\s*\(", re.I)),
    # Exfiltrare/RCE prin SQL: xp_cmdshell (MSSQL), LOAD_FILE()/INTO OUTFILE
    # (MySQL, citire/scriere fisiere pe server), @@version (fingerprinting).
    ("sqli_exfil", re.compile(
        r"xp_cmdshell|load_file\s*\(|into" + _SP + r"(?:outfile|dumpfile)|@@version", re.I)),
    # v47: traversal DOAR ca segment complet ("/../../" sau "=../../"), nu
    # orice "../" -- slug-urile trunchiate in log ("/.../titlu-al.../")
    # contineau "../" literal si dadeau CRITICAL/HIGH fals.
    ("sqli", re.compile(r"base64_decode\(|/etc/passwd|(?:^|[/\\=])\.\.[/\\]\.\.[/\\]|<\?php", re.I)),
    ("lfi_rfi", re.compile(r"(?:^|[/\\=])\.\.[/\\]|php://|data://|expect://|=(?:https?|ftp)://[^&]*\.(?:txt|php)\?", re.I)),
    ("webshell_name", re.compile(r"(shell|cmd|wso|c99|r57|b374k|pantek|vqmod)\.php", re.I)),
    # --------------------------------------------------------------------
    # XSS (Eduard: "cauta mai multe xss") -- inainte, zero detectie dedicata.
    # Doua familii principale, verificate real (scannere XSS/sqlmap tag-along
    # payloads trimit de obicei ambele variante pe rand ca sa ocoleasca WAF-uri
    # naive):
    #   xss_tag    -- injectare de tag HTML executabil: <script>, <svg>,
    #                 <iframe>, <img>/<body>/<input> etc. cu handler de
    #                 eveniment (onerror/onload/onmouseover/...), sau URI
    #                 scheme javascript:/vbscript: (in href/src/action).
    #   xss_payload -- "payload-ul" propriu-zis, chiar fara tag HTML vizibil
    #                 in path (poate fi injectat intr-un atribut existent):
    #                 alert(/confirm(/prompt( cu argument tipic de PoC,
    #                 document.cookie/document.location (exfiltrare/redirect),
    #                 String.fromCharCode( (obfuscare uzuala anti-filtru).
    # Entitati HTML (&#x3c;script sau &#60;script) NU sunt decodate de
    # unquote() (asta e decodare HTML, nu URL) -- verificate separat mai jos.
    ("xss_tag", re.compile(
        r"<\s*(?:script|svg|iframe)\b"
        r"|<\s*(?:img|body|input|marquee|details|video|audio)\b[^>]*\bon\w+\s*="
        r"|\bon(?:error|load|mouseover|focus|click|mouseenter)\s*="
        r"|(?:href|src|action)\s*=\s*[\"']?\s*(?:javascript|vbscript):", re.I)),
    ("xss_payload", re.compile(
        r"(?:alert|confirm|prompt)\s*\((?:['\"\d]|String\.fromCharCode)"
        r"|document\.(?:cookie|location|write)"
        r"|String\.fromCharCode\s*\(", re.I)),
    ("xss_html_entity", re.compile(
        r"&#x0*3c;?\s*script|&#0*60;?\s*script", re.I)),
]
SUSPICIOUS_QUICK_HINTS = (
    "union", "select", "base64_decode", "/etc/passwd", "<?php", "../",
    "php://", "data://", "expect://", "shell.php", "cmd.php", "wso.php",
    "c99.php", "r57.php", "b374k.php", "pantek.php", "vqmod.php",
    "%75nion", "%2e%2e",
    # sqli_error_blind / sqli_time_blind / sqli_exfil (vezi SUSPICIOUS_PATTERNS
    # mai sus) -- cuvinte-cheie SQL care nu sunt caractere rezervate URL, deci
    # apar identic in path_low chiar inainte de unquote().
    "information_schema", "extractvalue(", "updatexml(", "floor(rand(",
    "concat(0x", "sleep(", "benchmark(", "waitfor", "pg_sleep(",
    "xp_cmdshell", "load_file(", "outfile", "dumpfile", "@@version",
    # xss_tag / xss_payload / xss_html_entity -- litere/simboluri obisnuite,
    # deci vizibile in path_low chiar inainte de unquote() (doar "<" si ">"
    # apar de obicei %-encoded -- de-aia includem si variantele %3c/%3cscript).
    "<script", "%3cscript", "<svg", "<iframe", "onerror=", "onload=",
    "onmouseover=", "onfocus=", "onclick=", "javascript:", "vbscript:",
    "alert(", "confirm(", "prompt(", "document.cookie", "document.location",
    "fromcharcode(", "&#x3c", "&#60;",
)

FILE_MGR_ACTIONS = re.compile(r"action=(connectormanager|upload|fileManagerUpload|elementor_upload|duplicator_download)", re.I)

PLUGIN_PAGE_RE = re.compile(r"admin\.php\?page=([a-zA-Z0-9_-]+)", re.IGNORECASE)


def _narrate_compromise(events):
    """Genereaza un rezumat scurt, in limba romana, din evenimentele
    cronologice ale unui IP din traseul de compromitere -- raspunde direct
    la "s-a logat, a adaugat plugin X, a modificat Y" fara sa mai citesti
    evenimentele brute unul cate unul. Eristica simpla, bazata pe
    label/detail-urile deja generate de _process_chunk/build_summary, nu
    pe reguli noi de detectie."""
    login_success = 0
    last_login_time = ""
    plugin_pages = []
    plugin_activated = False
    admin_sensitive = 0
    webshell = 0
    enum_hits_n = 0
    bruteforce = 0
    for e in events:
        lbl = e.get("label", "") or ""
        detail = e.get("detail", "") or ""
        if lbl == "Login reusit (302)" or e.get("type") == "login":
            login_success += 1
            if e.get("time"):
                last_login_time = e["time"]
        m = PLUGIN_PAGE_RE.search(detail)
        if m and m.group(1) not in plugin_pages:
            plugin_pages.append(m.group(1))
        if "activate=true" in detail.lower() and "plugin" in detail.lower():
            plugin_activated = True
        if e.get("type") == "finding":
            rule_low = lbl.lower()
            if "webshell" in rule_low or "pattern suspect" in rule_low:
                webshell += 1
            elif "admin sensibil" in rule_low:
                admin_sensitive += 1
            elif "enumerare" in rule_low:
                enum_hits_n += 1
            elif "brute force" in rule_low:
                bruteforce += 1

    lines = []
    if login_success:
        lines.append(f"S-a logat cu succes in WP-Admin ({login_success}x" +
                      (f", ultima la {last_login_time}" if last_login_time else "") + ").")
    if bruteforce:
        lines.append("A facut brute-force pe wp-login/xmlrpc inainte de login.")
    if plugin_pages:
        lines.append("A accesat panouri posibil de plugin: " + ", ".join(plugin_pages[:8]) + ".")
    if plugin_activated:
        lines.append("A activat un plugin din lista de plugin-uri instalate.")
    if admin_sensitive:
        lines.append(f"A accesat editor de plugin-uri/teme sau upload de plugin ({admin_sensitive}x).")
    if webshell:
        lines.append(f"Semnal de webshell/fisier suspect ({webshell}x) -- verifica manual, e cel mai serios semnal.")
    if enum_hits_n:
        lines.append("A facut enumerare de utilizatori WordPress.")
    if not lines:
        lines.append("Activitate inregistrata, fara un tipar clar -- verifica evenimentele de mai jos.")
    return lines


# --- Reclasificare evenimente din Traseul de compromitere (Faza 3) ---
# Principiul cerut explicit: "compromitere" e un cuvant prea puternic pentru
# majoritatea semnalelor din access log -- un scan/probe NU e o dovada de
# compromitere, iar un 302 izolat NU e o dovada de login reusit (vezi nota
# deja existenta la wp_successful_logins). Functia de mai jos NU introduce
# nicio regula de detectie noua -- doar RE-ETICHETEAZA evenimentele deja
# calculate (findings/login/admin) intr-una din 5 categorii, pe baza a ce e
# deja stiut despre eveniment (rule/label/status), plus o explicatie scurta
# per eveniment:
#   suspicious_request     -- semnal slab/ambiguu, merita o privire
#   attack_attempt          -- cerere care se potriveste cu o semnatura de
#                               atac/exploatare cunoscuta, sau incearca ceva
#                               (ex: fisier posibil webshell cerut, dar
#                               serverul NU a raspuns cu succes)
#   successful_login         -- DOAR semnalul combinat deja existent (302 +
#                               acces GET 200 confirmat ulterior in /wp-admin/
#                               de la aceeasi IP), niciodata un 302 izolat
#   confirmed_admin_activity -- dovada clara de folosire a zonei de admin
#                               (autentificat sau nu -- doar CE s-a accesat)
#   confirmed_compromise     -- rezervat: un fisier de tip webshell a fost
#                               EFECTIV servit cu succes (status 2xx), nu doar
#                               cerut/scanat
_TRAIL_CATEGORY_LABELS = {
    "suspicious_request": "Cerere suspecta",
    "attack_attempt": "Incercare de atac",
    "successful_login": "Login reusit (confirmat)",
    "confirmed_admin_activity": "Activitate admin confirmata",
    "confirmed_compromise": "Compromitere confirmata",
    "login_attempt": "Incercare de autentificare",
}


def _classify_trail_event(ev):
    """Intoarce (categorie, eticheta, motiv) pentru un eveniment din
    traseul de compromitere -- vezi comentariul de mai sus pentru principii.
    `ev` e dict-ul deja construit (type/label/detail/status), fara nimic nou
    scanat din log."""
    etype = ev.get("type", "")
    label_low = (ev.get("label") or "").lower()
    status = ev.get("status")
    try:
        status = int(status) if status not in (None, "") else None
    except (TypeError, ValueError):
        status = None
    is_2xx = status is not None and 200 <= status < 300

    if etype == "login":
        if "high" in label_low:
            cat = "successful_login"
            reason = ("POST wp-login.php cu 302, urmat in max. 5 minute de un acces GET 200 real in "
                      "/wp-admin/ de la aceeasi IP -- semnal combinat, nu doar un cod de redirect izolat.")
        else:
            cat = "suspicious_request"
            reason = ("Doar un raspuns 302 dupa POST wp-login.php, FARA acces ulterior confirmat in "
                      "/wp-admin/ -- un redirect izolat nu e o dovada de login reusit (poate fi 2FA, "
                      "plugin de securitate sau redirect canonic).")
        return cat, reason

    if etype == "admin":
        if "webshell" in label_low:
            if is_2xx:
                cat = "confirmed_compromise"
                reason = (f"Un fisier .php dintr-o locatie care nu ar trebui sa contina cod a fost "
                          f"EFECTIV servit cu succes (status {status}) -- dovada puternica de webshell "
                          f"activ, nu doar o cerere/scanare.")
            else:
                cat = "attack_attempt"
                reason = (f"Cerere catre un fisier .php suspect (posibil webshell), dar serverul nu a "
                          f"raspuns cu succes (status {status if status is not None else 'necunoscut'}) -- "
                          f"incercare, fara confirmare ca fisierul a fost efectiv executat.")
        elif "admin-ajax" in label_low:
            cat = "suspicious_request"
            reason = ("Actiune admin-ajax cu potential de upload/file manager -- normala daca vine de la "
                      "administratorul autentificat, altfel doar un semnal de urmarit.")
        elif "login post" in label_low or "login reusit (302)" in label_low:
            # v47.4: un POST pe wp-login NU e activitate in admin. 200 = parola
            # respinsa (WordPress reafiseaza formularul); 302 izolat = redirect
            # fara acces confirmat in /wp-admin/ (loginul confirmat vine separat,
            # ca eveniment "login" -> successful_login).
            cat = "login_attempt"
            reason = ("POST pe wp-login.php: cu 200 parola a fost respinsa; cu 302 fara acces confirmat "
                      "ulterior in /wp-admin/ nu e dovada de login reusit.")
        elif "acces /wp-admin/" in label_low:
            cat = "suspicious_request"
            reason = ("Raspuns 200 pe o cale /wp-admin/ fara login confirmat in log -- poate fi o sesiune "
                      "deja deschisa sau raspunsul generic al site-ului la o cale inexistenta.")
        else:
            cat = "confirmed_admin_activity"
            reason = "Pagina de administrare (plugin/tema) incarcata in zona de administrare WordPress."
        return cat, reason

    if etype == "finding":
        if "webshell" in label_low:
            if is_2xx:
                cat = "confirmed_compromise"
                reason = (f"Fisier .php suspect servit cu succes (status {status}) dintr-o locatie care "
                          f"nu ar trebui sa contina cod -- dovada puternica, nu doar o cerere.")
            else:
                cat = "attack_attempt"
                reason = (f"Fisier .php suspect cerut, dar fara raspuns de succes confirmat "
                          f"(status {status if status is not None else 'necunoscut'}) -- incercare, "
                          f"nu confirmare de executie.")
        elif "pattern suspect" in label_low or "brute force" in label_low:
            cat = "attack_attempt"
            reason = "Cerere care se potriveste cu o semnatura cunoscuta de atac/exploatare sau brute force."
        elif "admin sensibil" in label_low:
            if is_2xx:
                cat = "confirmed_admin_activity"
                reason = f"Pagina de admin sensibila (editor plugin/tema, upload) incarcata cu succes (status {status})."
            else:
                cat = "attack_attempt"
                reason = (f"Cerere catre un endpoint admin sensibil, fara raspuns de succes confirmat "
                          f"(status {status if status is not None else 'necunoscut'}).")
        elif "enumerare" in label_low:
            cat = "suspicious_request"
            reason = "Tehnica de recunoastere/enumerare (nu un exploit direct) -- de obicei pasul dinaintea unui brute force tintit."
        elif "posibil login reusit" in label_low:
            cat = "suspicious_request"
            reason = "Semnal statistic (302 dupa un sir de esecuri) -- fara acces ulterior confirmat, ramane suspiciune, nu certitudine."
        else:
            cat = "suspicious_request"
            reason = "Semnal marcat automat (finding) -- vezi detaliul evenimentului pentru context complet."
        return cat, reason

    return "suspicious_request", "Eveniment fara categorie specifica -- vezi detaliul."


# Fisier .php ascuns intr-un folder WordPress care in mod normal contine
# DOAR assets statice (css/js/imagini/fonturi) -- tehnica frecventa de
# deghizare a unui webshell (ex: wp-admin/css/colors/nume-oarecare.php),
# independenta de folderul wp-content/uploads/cache deja acoperit mai jos
# (asta acopera wp-admin/, wp-includes/, wp-content/themes|plugins/.../
# css|js|images/ etc.).
# IMPORTANT: ancorat STRICT in structura WordPress (wp-admin/wp-includes/
# wp-content) -- varianta veche cauta orice /css|js|images|.../*.php din
# TOT site-ul, ceea ce da fals-pozitive masive pe orice aplicatie PHP
# non-WordPress care are legitim un script generator (ex: un tire-shop
# custom cu /css/dims.css.php care genereaza CSS dinamic -- fiecare
# vizitator care incarca pagina ajungea marcat HIGH ca "posibil webshell").
STATIC_ASSET_PHP_DISGUISE_RE = re.compile(
    r"/wp-(?:admin|includes|content)/(?:[^?]*/)?(?:css|js|images?|img|fonts?|assets)/[^?]*\.php(?:$|\?)",
    re.IGNORECASE,
)
# Aceeasi expresie, fara IGNORECASE -- de aplicat DOAR pe path deja lowercase
# (vezi classify_event_pre). Semantic identic, fara costul case-folding.
STATIC_ASSET_PHP_DISGUISE_RE_LOW = re.compile(
    r"/wp-(?:admin|includes|content)/(?:[^?]*/)?(?:css|js|images?|img|fonts?|assets)/[^?]*\.php(?:$|\?)"
)

SCAN_SIGNATURES = [
    ("WordPress", ("wp-config", "xmlrpc.php", "wp-content/debug.log", "wlwmanifest.xml")),
    ("Joomla", ("/administrator/", "configuration.php.bak", "joomla.xml")),
    ("Drupal", ("/user/register", "changelog.txt", "core/install.php")),
    ("phpMyAdmin", ("phpmyadmin", "pma/", "/pma_")),
    ("Sensitive files", (".env", ".git/config", ".git/head", "id_rsa", "docker-compose.yml")),
    ("Backup files", (".sql.gz", ".sql.zip", "backup.zip", "backup.tar", ".bak")),
]

# Regex de PRE-FILTRARE (un singur .search() in loc de N "any(needle in x)")
# pentru cele doua verificari cele mai scumpe din bucla per-linie: semnaturile
# de scanare CMS si pattern-urile suspecte. Pe trafic normal (marea majoritate
# a liniilor), niciuna din ele nu se potriveste -- inainte, fiecare linie
# platea costul complet al buclei "any" indiferent de rezultat. Verificat cu
# profiler pe log sintetic de 500k linii: acestea erau, de departe, cele mai
# costisitoare doua puncte din _process_chunk (vezi audit v11 in README).
_SCAN_SIG_NEEDLES = [n for _sig, needles in SCAN_SIGNATURES for n in needles]
SCAN_SIG_QUICK_RE = re.compile("|".join(re.escape(n) for n in _SCAN_SIG_NEEDLES))
SUSPICIOUS_QUICK_RE = re.compile("|".join(re.escape(h) for h in SUSPICIOUS_QUICK_HINTS))


def decompress_to_plain(src_path, workdir):
    lower = src_path.lower()
    if lower.endswith(".gz"):
        plain_path = os.path.join(workdir, "plain.log")
        with gzip.open(src_path, "rb") as fin, open(plain_path, "wb") as fout:
            shutil.copyfileobj(fin, fout, length=4 * 1024 * 1024)
        return plain_path
    if lower.endswith(".zip"):
        plain_path = os.path.join(workdir, "plain.log")
        with zipfile.ZipFile(src_path) as zf, open(plain_path, "wb") as fout:
            names = [n for n in zf.namelist() if not n.endswith("/")]
            if not names:
                raise ValueError("Arhiva zip e goala")
            for name in names:
                info = zf.getinfo(name)
                if info.file_size > MAX_UPLOAD_BYTES:
                    raise ValueError(f"Fisier prea mare in zip (posibil zip bomb): {name}")
                with zf.open(name) as f:
                    if name.lower().endswith(".gz"):
                        f = gzip.GzipFile(fileobj=f)
                    shutil.copyfileobj(f, fout, length=4 * 1024 * 1024)
        return plain_path
    return src_path


# --------------------------------------------------------------------------
# Detectie domeniu din numele fisierului, pentru upload multi-arhiva.
# cPanel numeste log-urile de acces dupa domeniu, ex:
#   accesslog_piatradesign.ro_9_20_2026.gz
#   domain.tld-Sep-2026.gz
#   www.domeniu.ro-ssl_log-2026-09-20.gz
# Extragem cel mai lung token care arata ca un domeniu (label.label.tld) si
# normalizam (lowercase, fara "www."). E o eristica, nu o certitudine -- daca
# un fisier redenumit manual nu contine domeniul, pur si simplu nu detectam
# nimic pentru el (nu blocam upload-ul).
# --------------------------------------------------------------------------
_DOMAIN_IN_NAME_RE = re.compile(
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}", re.IGNORECASE
)


def extract_domain_from_filename(filename):
    if not filename:
        return None
    base = os.path.basename(filename)
    # scoatem extensiile de arhiva/log ca sa nu fie confundate cu un TLD
    base = re.sub(r"\.(gz|zip|log|txt)$", "", base, flags=re.IGNORECASE)
    candidates = _DOMAIN_IN_NAME_RE.findall(base)
    if not candidates:
        return None
    # preferam cel mai lung candidat (cel mai probabil sa fie domeniul intreg,
    # nu o data gen "9.20.2026" -- care oricum nu are litere la TLD si nu
    # matcheaza regexul de mai sus)
    best = max(candidates, key=len)
    best = best.lower()
    if best.startswith("www."):
        best = best[4:]
    return best or None


def _pool_worker_init():
    """Worker-ii Pool sunt facuti prin fork din procesul uvicorn si mostenesc
    handler-ul lui de SIGTERM (care doar seteaza un flag de "should_exit" in
    loc sa opreasca procesul). Pool.terminate() foloseste exact SIGTERM --
    un worker blocat pe lock-ul cozii nu mai murea niciodata si request-ul
    atarna la infinit (reprodus pe /ip_compare, py-spy: join() blocat in
    _terminate_pool). Aici refacem comportamentul implicit al semnalelor."""
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def _pool_worker_init_low():
    """Ca _pool_worker_init, plus prioritate CPU scazuta (nice +10): folosit
    pentru re-analiza v42 a unei selectii (vezi _FSUM_EXECUTOR), ca sa nu
    concureze cu interogarile interactive (tabel, sinteza) sau cu un upload."""
    _pool_worker_init()
    try:
        os.nice(10)
    except OSError:
        pass


def _pool_map(fn, args, n_procs):
    """pool.map + inchidere GRACEFUL (close/join, nu terminate) -- vezi
    _pool_worker_init pentru bug-ul de hang pe care il evita."""
    low = threading.current_thread().name.startswith("fsum")
    pool = mp.Pool(processes=n_procs, initializer=_pool_worker_init_low if low else _pool_worker_init)
    try:
        result = pool.map(fn, args)
        pool.close()
        pool.join()
        return result
    except BaseException:
        pool.terminate()
        raise


def find_chunk_offsets(path, n_chunks, region_start=0, region_end=None):
    """Imparte [region_start, region_end) in n_chunks byte-range-uri aliniate
    la inceput de linie. Fara argumente de regiune, imparte tot fisierul
    (comportament original)."""
    full_size = os.path.getsize(path)
    region_end = full_size if region_end is None else min(region_end, full_size)
    region_start = max(0, min(region_start, region_end))
    size = region_end - region_start
    if size <= 0:
        return []
    if n_chunks <= 1:
        return [(region_start, region_end)]
    offsets = [region_start]
    with open(path, "rb") as f:
        for i in range(1, n_chunks):
            approx = region_start + size * i // n_chunks
            f.seek(approx)
            f.readline()
            pos = f.tell()
            if region_start < pos < region_end:
                offsets.append(pos)
    offsets.append(region_end)
    chunks = []
    for i in range(len(offsets) - 1):
        if offsets[i] < offsets[i + 1]:
            chunks.append((offsets[i], offsets[i + 1]))
    return chunks


def _find_quote(line, start):
    """Prima ghilimea NE-scapata (nu precedata de un numar impar de \\)."""
    i = line.find('"', start)
    while i != -1:
        k = i - 1
        n = 0
        while k >= 0 and line[k] == "\\":
            n += 1
            k -= 1
        if n % 2 == 0:
            return i
        i = line.find('"', i + 1)
    return -1


def _unescape_field(v):
    return v.replace('\\"', '"').replace("\\\\", "\\") if "\\" in v else v


# v44 (spec §8): o linie fara timestamp valid NU mai intra in analiza cu data
# 1970 (epoch 0 strica histograma, limitele intervalului si statisticile pe
# zi) -- e numarata ca invalida si apare in exemplele de linii respinse.
# Acceptat: formatul cPanel/Apache "05/Oct/2026:10:00:00 +0300" si varianta
# fara fus orar "05/Oct/2026:10:00:00" (interpretata ca UTC).
_TS_SHAPE_RE = re.compile(
    r"\d\d/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4}:\d\d:\d\d:\d\d(?: [+-]\d{4})?")


def _parse_line_escaped(line):
    """Aceeasi iesire ca parse_line_fast, pentru liniile cu \" in campuri."""
    q1 = _find_quote(line, 0)
    if q1 == -1:
        return None
    pre = line[:q1]
    sp = pre.find(" ")
    ip = pre[:sp] if sp != -1 else pre
    if not ip:
        return None
    b1 = pre.find("[")
    b2 = pre.find("]", b1 + 1) if b1 != -1 else -1
    time_str = pre[b1 + 1:b2] if b1 != -1 and b2 != -1 else ""
    if not _TS_SHAPE_RE.fullmatch(time_str):
        return None
    q2 = _find_quote(line, q1 + 1)
    if q2 == -1:
        return None
    req_parts = _unescape_field(line[q1 + 1:q2]).split(" ", 2)
    if len(req_parts) < 2:
        return None
    method, path = req_parts[0], req_parts[1]
    if not method.isalpha():
        return None
    rest_tokens = line[q2 + 1:].split(None, 2)
    if not rest_tokens:
        return None
    try:
        status = int(rest_tokens[0])
    except ValueError:
        return None
    size = 0
    if len(rest_tokens) >= 2 and rest_tokens[1] != "-":
        try:
            size = int(rest_tokens[1])
        except ValueError:
            size = 0
    referer, ua = "-", "-"
    q3 = _find_quote(line, q2 + 1)
    if q3 != -1:
        q4 = _find_quote(line, q3 + 1)
        if q4 != -1:
            referer = _unescape_field(line[q3 + 1:q4])
            q5 = _find_quote(line, q4 + 1)
            last = line.rfind('"')
            if q5 != -1 and last > q5:
                ua = _unescape_field(line[q5 + 1:last])
    return ip, method, path, status, referer, ua, time_str, size


def parse_line_fast(line):
    """Parser bazat pe str.find()/split() (cod C), fara regex pe hot-path.
    Returneaza (ip, method, path_raw, status:int, referer, ua, time_str) sau
    None. time_str e in formatul cPanel: "18/Sep/2026:15:02:05 +0300"."""
    line = line.rstrip("\r\n")
    if not line:
        return None
    if '\\"' in line:
        # Apache scapa ghilimelele din campuri ca \" (ex. un UA trimis de
        # client chiar cu ghilimele: "\"Mozilla/5.0 ...\"") -- 6 linii in
        # logul real ariesul.ro. Varianta rapida de mai jos taia UA-ul la
        # prima ghilimea scapata; aici citim campurile tinand cont de escape.
        return _parse_line_escaped(line)
    q1 = line.find('"')
    if q1 == -1:
        return None
    pre = line[:q1]
    sp = pre.find(" ")
    ip = pre[:sp] if sp != -1 else pre
    if not ip:
        return None
    b1 = pre.find("[")
    b2 = pre.find("]", b1 + 1) if b1 != -1 else -1
    time_str = pre[b1 + 1:b2] if b1 != -1 and b2 != -1 else ""
    if not _TS_SHAPE_RE.fullmatch(time_str):
        return None

    q2 = line.find('"', q1 + 1)
    if q2 == -1:
        return None
    request = line[q1 + 1:q2]
    req_parts = request.split(" ", 2)
    if len(req_parts) < 2:
        return None
    method, path = req_parts[0], req_parts[1]
    if not method.isalpha():
        return None

    rest = line[q2 + 1:]
    rest_tokens = rest.split(None, 2)
    if not rest_tokens:
        return None
    try:
        status = int(rest_tokens[0])
    except ValueError:
        return None

    size = 0
    if len(rest_tokens) >= 2:
        size_tok = rest_tokens[1]
        if size_tok != "-":
            try:
                size = int(size_tok)
            except ValueError:
                size = 0

    referer, ua = "-", "-"
    q3 = line.find('"', q2 + 1)
    if q3 != -1:
        q4 = line.find('"', q3 + 1)
        if q4 != -1:
            referer = line[q3 + 1:q4]
            q5 = line.find('"', q4 + 1)
            if q5 != -1:
                q6 = line.find('"', q5 + 1)
                if q6 != -1:
                    ua = line[q5 + 1:q6]

    return ip, method, path, status, referer, ua, time_str, size


def day_of(time_str):
    """'18/Sep/2026:15:02:05 +0300' -> '18/Sep/2026'"""
    return time_str[:11] if len(time_str) >= 11 else ""


def hour_of(time_str):
    """-> '15' (ora, doua cifre) sau '' daca nu poate fi extrasa."""
    if len(time_str) >= 14:
        return time_str[12:14]
    return ""


def parse_apache_time(time_str):
    """'18/Sep/2026:15:02:05 +0300' -> datetime cu offset, sau None."""
    try:
        return datetime.strptime(time_str, "%d/%b/%Y:%H:%M:%S %z")
    except Exception:
        return None


def subnet24_of(ip):
    if ":" in ip:
        return None  # IPv6 -- gruparea /24 (IPv4) nu se aplica, vezi ipv6_subnet64_of
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    return ".".join(parts[:3]) + ".0/24"


def subnet16_of(ip):
    """Grupare /16 (IPv4) -- mai LARGA decat subnet24_of, ceruta separat
    (Eduard: 'de la ce subneturi /16 in principal') pentru rubricile de
    procentaj din Explorator de loguri si din pagina 'Prezentare IP'. Un /16
    arata mai clar provenienta la nivel de furnizor/retea cand cereri vin
    dintr-un range mare (multe IP-uri diferite din acelasi /16), lucru pe
    care un /24 il fragmenteaza prea mult ca sa se observe cu ochiul liber.
    IPv6 nu se grupeaza /16 (nu are sens) -- apelantul trateaza None ca o
    categorie separata ('IPv6')."""
    if ":" in ip:
        return None
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    return ".".join(parts[:2]) + ".0.0/16"


def ipv6_subnet64_of(ip):
    """Echivalentul IPv6 al subnet24_of -- grupeaza pe /64 (dimensiunea
    STANDARD alocata unui singur "site"/retea in IPv6, la fel cum /24 e
    conventia folosita pentru IPv4 in restul aplicatiei). Folosit de
    country_subnets ca sa NU piarda liniile IPv6 (majoritatea bucketului
    "??" geoip-neresolvat e IPv6 -- vezi bug raportat de Eduard: fara asta,
    subnet24_of() intorcea None pentru orice IPv6 si acele linii disparea
    complet din raspuns, desi country_totals le numara corect)."""
    if ":" not in ip:
        return None
    try:
        net = ipaddress.ip_network(ip + "/64", strict=False)
        return str(net)
    except ValueError:
        return None


def subnet_key_of(ip):
    """Cheia de subnet folosita pentru gruparea generica (IPv4 /24 SAU
    IPv6 /64), impreuna cu tipul ei -- vezi subnet_matches() pentru cum se
    potriveste inapoi cu un filtru primit din query string."""
    s = subnet24_of(ip)
    if s:
        return s
    return ipv6_subnet64_of(ip)


@functools.lru_cache(maxsize=256)
def _cached_network(cidr):
    try:
        return ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None


def ipv6_subnet48_of(ip):
    """Echivalentul IPv6 al subnet16_of -- /48 (alocarea tipica pentru o
    organizatie/un client al unui ISP), folosit in rubrica "Subnete /16"."""
    if ":" not in ip:
        return None
    try:
        return str(ipaddress.ip_network(ip + "/48", strict=False))
    except ValueError:
        return None


def normalize_subnet_filter(subnet):
    """Transforma orice forma de subnet primita din UI intr-un filtru pentru
    subnet_matches: IPv4 /8, /16, /24 -> prefix de octeti ('82.76') (match
    rapid cu startswith); alt CIDR IPv4 sau orice retea IPv6 -> CIDR complet
    (match prin ipaddress). Inainte doar '.0/24' era inteles, deci un click
    pe un /16 nu filtra nimic."""
    if not subnet:
        return None
    s = subnet.strip()
    if not s:
        return None
    if ":" in s:
        return s
    if "/" in s:
        base, _, bits = s.partition("/")
        try:
            bits_i = int(bits)
        except ValueError:
            return None
        octs = base.split(".")
        if len(octs) == 4 and bits_i in (8, 16, 24):
            return ".".join(octs[:bits_i // 8])
        return s
    return s.rstrip(".")


def subnet_matches(rip, subnet_prefix):
    """Potriveste un IP cu un filtru de subnet care poate fi fie un prefix
    IPv4 /24 (format istoric: doar primele 3 octeti, ex. '1.2.3', vezi
    api_raw) fie o retea IPv6 /64 completa (ex. '2001:4860:7:626::/64').
    Extras separat ca sa fie folosit identic in _scan_chunk_raw si in
    orice alt loc care are nevoie de acelasi filtru de subnet."""
    if not subnet_prefix:
        return True
    if ":" in subnet_prefix or "/" in subnet_prefix:
        net = _cached_network(subnet_prefix)
        if net is None:
            return False
        try:
            return ipaddress.ip_address(rip) in net
        except ValueError:
            return False
    return rip.startswith(subnet_prefix + ".")


STATIC_EXTS = (
    ".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".map", ".webp", ".avif",
    ".json", ".txt", ".xml", ".webmanifest",
)
STATIC_EXACT = ("/favicon.ico", "/robots.txt", "/apple-touch-icon.png", "/apple-touch-icon-precomposed.png")


def is_static_path(path_only):
    """True daca path-ul e cu foarte mare probabilitate un asset static
    (favicon, css/js/imagini/fonturi) -- fara risc de atac real, folosit
    doar ca sa nu aglomereze tabelele de path-uri cu zgomot."""
    pl = path_only.lower()
    if pl in STATIC_EXACT:
        return True
    if pl.endswith(STATIC_EXTS):
        return True
    return False


def scan_signature_of(path_low):
    """Daca path-ul (lowercase) se potriveste cu o semnatura de scanare CMS/
    fisiere sensibile cunoscuta (vezi SCAN_SIGNATURES), intoarce numele
    semnaturii -- altfel None. Extras ca functie separata ca sa fie folosit
    identic si la agregare (_process_chunk) si la drill-down (_scan_chunk_raw),
    ca sa nu poata aparea discrepante intre ce arata tabelul si ce iti da
    click-ul pe el.
    PERF: filtru rapid intai (acelasi SCAN_SIG_QUICK_RE folosit deja in
    _process_chunk) -- pe majoritatea path-urilor (fara nicio semnatura de
    scanare), un singur .search() e mult mai ieftin decat 6x any(needle in
    path_low). Apelata acum si per PATH UNIC din build_summary (is_risk_path,
    pentru top_paths_risk) -- pe cataloage cu foarte multe URL-uri distincte,
    fara acest filtru devine masurabil (vezi audit v12/profiling)."""
    if not SCAN_SIG_QUICK_RE.search(path_low):
        return None
    for sig_name, needles in SCAN_SIGNATURES:
        if any(n in path_low for n in needles):
            return sig_name
    return None


# Path-uri care reprezinta un semnal de risc REAL (tinta cunoscuta de atac/
# scanare), nu doar "path fara extensie statica". Orice pagina de business
# normala (contact, oferta, produs etc.) NU intra aici doar pentru ca are
# trafic mare -- asta era problema din versiunea anterioara.
RISK_NEEDLES = (
    "wp-login.php", "xmlrpc.php", "wp-json/wp/v2/users",
    "plugin-install.php", "theme-editor.php", "plugin-editor.php",
    "update.php",
)
# Filtru rapid (acelasi truc ca SCAN_SIG_QUICK_RE) -- folosit de is_risk_path,
# apelata acum si per PATH UNIC in build_summary (nu doar per linie), deci pe
# cataloage cu foarte multe URL-uri distincte costul needle-by-needle devine
# masurabil (vezi audit v12/profiling).
RISK_QUICK_RE = re.compile("|".join(re.escape(n) for n in RISK_NEEDLES) + r"|wp-content/(?:uploads|cache)")
# Combinatia celor doua filtre rapide de mai sus (scanare CMS + risc WP),
# verificata cu UN SINGUR .search() la inceputul is_risk_path() -- apelata
# acum si per PATH UNIC (nu doar per linie), deci pe cataloage cu foarte
# multe URL-uri distincte, a evita un al doilea .search() separat pentru
# path-urile care nu se potrivesc cu NICIUNA din cele doua categorii (marea
# majoritate) reduce la jumatate costul de regex per path (vezi audit
# v12/profiling -- is_risk_path era printre cele mai costisitoare functii
# din build_summary pe un catalog cu >150k URL-uri unice).
_RISK_OR_SCAN_QUICK_RE = re.compile(SCAN_SIG_QUICK_RE.pattern + "|" + RISK_QUICK_RE.pattern)


def is_risk_path(path_only):
    """True doar daca path-ul se potriveste cu un semnal de risc CONCRET:
    o semnatura de scanare cunoscuta (SCAN_SIGNATURES: .env, .git, backup-uri,
    phpMyAdmin etc.), un endpoint WordPress vizat frecvent in atacuri
    (wp-login/xmlrpc/enumerare useri/editor de plugin-uri-teme), sau un
    fisier .php ajuns intr-un director de upload/cache (posibil webshell).
    NU se bazeaza pe volumul de cereri -- un path cu trafic mare dar fara
    niciun semnal concret (ex. o pagina de produs populara) NU e "risc"."""
    pl = path_only.lower()
    if not _RISK_OR_SCAN_QUICK_RE.search(pl):
        return False
    if scan_signature_of(pl):
        return True
    if any(n in pl for n in RISK_NEEDLES):
        return True
    path_clean = pl.split("?", 1)[0]
    if ("wp-content/uploads" in pl or "wp-content/cache" in pl) and path_clean.endswith(".php"):
        return True
    return False


# Path-uri dinamice / API -- endpoint-uri care raspund cu continut generat
# (nu fisiere statice), tipic tinte de abuz de rate/enumerare mai degraba
# decat de "scanare de fisier cunoscut" (vezi RISK_NEEDLES mai sus, care e
# despre semnaturi de ATAC). Categoria e utila separat de static/risc/popular
# -- raspunde la "ce parte din trafic loveste cod care ruleaza efectiv pe
# server (PHP/DB), nu doar fisiere servite direct". NU e mutual-exclusiva cu
# is_risk_path (ex: xmlrpc.php e si risc si dinamic) -- e o vedere
# transversala, calculata din ACELASI Counter top_paths deja agregat (fara
# nicio trecere suplimentara prin log, vezi build_summary).
# IMPORTANT (perf): NU regex -- apelata o data per PATH UNIC (nu per linie),
# dar pe loguri cu foarte multe path-uri distincte (cataloage mari, sute de
# mii de URL-uri unice) un .search() de regex per path devine masurabil
# (vezi audit v12 din README/profiling). Substring-uri simple, la fel ca
# is_risk_path/RISK_NEEDLES de mai sus, sunt de ordinul de marime mai
# ieftine si byte-identice ca rezultat pentru needle-urile de mai jos.
DYNAMIC_PATH_NEEDLES = ("wp-json/", "admin-ajax.php", "xmlrpc.php", "/wc-ajax",
                        "rest_route=", "add-to-cart", "/api/")
DYNAMIC_PATH_SUFFIXES = ("/cart", "/checkout", "/my-account")


def is_dynamic_path(path_only):
    """True daca path-ul e cu mare probabilitate un endpoint dinamic/API
    (wp-json, admin-ajax, REST-like, cart/checkout/cont) -- vezi comentariul
    de mai sus. Fara cost suplimentar de scanare: apelata doar in bucla deja
    existenta din build_summary care iterate top_paths."""
    pl = path_only.lower()
    if any(n in pl for n in DYNAMIC_PATH_NEEDLES):
        return True
    path_clean = pl.split("?", 1)[0].rstrip("/")
    return path_clean.endswith(DYNAMIC_PATH_SUFFIXES)


def burst_key_of(time_str):
    """'18/Sep/2026:15:02:37 +0300' -> ('18/Sep/2026','15','02',1) -- cheie
    de fereastra de 30 secunde, calculata DOAR cu slicing pe string (fara
    strptime) ca sa ramana ieftina in bucla per-linie. A doua jumatate a
    minutului (secunda >=30) e half=1, prima half=0."""
    if len(time_str) < 20:
        return None
    day = time_str[0:11]
    hour = time_str[12:14]
    minute = time_str[15:17]
    sec_tok = time_str[18:20]
    if not sec_tok.isdigit():
        return None
    half = 0 if int(sec_tok) < 30 else 1
    return (day, hour, minute, half)


def burst_window_label(bkey):
    day, hour, minute, half = bkey
    s0 = "00" if half == 0 else "30"
    s1 = "29" if half == 0 else "59"
    return f"{day} {hour}:{minute}:{s0} - {hour}:{minute}:{s1}"


# --------------------------------------------------------------------------
# Clasificare User-Agent -> categorie de bot/vizitator. Aplicata DOAR la
# constructia rezumatului (build_summary), pe fiecare User-Agent UNIC (nu pe
# fiecare linie -- de obicei sute pana la cateva mii de UA-uri distincte per
# log, deci cost neglijabil, ZERO impact asupra vitezei de parsare). Lista nu
# e exhaustiva -- e o eticheta orientativa ca sa raspunda rapid la intrebarea
# "asta e legit sau il blochez?", nu o sursa de adevar (vezi nota din raspuns:
# verificarea DEFINITIVA a unui bot se face dupa IP-ul publicat de furnizor,
# nu doar dupa User-Agent, care poate fi falsificat).
BOT_CATALOG = [
    ("Motor de cautare (legit)", (
        "googlebot", "googleother", "bingbot", "yandexbot", "baiduspider",
        "duckduckbot", "applebot",
    )),
    ("AI crawler (legit)", (
        "claudebot", "claude-searchbot", "claude-user", "gptbot", "chatgpt-user",
        "oai-searchbot", "perplexitybot", "perplexity-user", "amazonbot",
        "bytespider", "ccbot", "google-extended", "meta-externalagent",
    )),
    ("SEO / monitorizare", (
        "ahrefsbot", "semrushbot", "mj12bot", "dotbot", "seznambot",
        "sitebulb", "screaming frog", "uptimerobot", "pingdom", "gtmetrix",
    )),
    ("Social media preview", (
        "facebookexternalhit", "facebot", "twitterbot", "linkedinbot",
        "whatsapp", "telegrambot", "slackbot", "discordbot",
    )),
    ("Script / tool (necunoscut ca provenienta)", (
        "curl/", "wget/", "python-requests", "python-urllib", "go-http-client",
        "libwww-perl", "java/", "okhttp", "scrapy", "node-fetch", "axios/",
        "postmanruntime", "powershell",
    )),
    ("Alt bot / crawler", (
        "bot", "spider", "crawl", "slurp", "archiver",
    )),
]


def classify_ua(ua):
    """Intoarce categoria (vezi BOT_CATALOG) sau 'Browser / necunoscut' daca
    UA-ul nu se potriveste cu niciun semnal cunoscut de bot. Verificare in
    ordine (prima potrivire castiga), pe User-Agent lowercase."""
    ual = ua.lower()
    for category, needles in BOT_CATALOG:
        if any(n in ual for n in needles):
            return category
    return "Browser / necunoscut"


# --------------------------------------------------------------------------
# Verificare identitate crawler -- Tier 1 (User-Agent) + Tier 2 (DNS async)
# --------------------------------------------------------------------------
# Tier 1: care UA-uri PRETIND ca sunt un crawler cunoscut anume (nu doar
# "bot generic" ca in BOT_CATALOG) -- doar identitatile astea sunt candidate
# pentru verificarea DNS din Tier 2 (vezi _verify_one_ip). needles = text de
# cautat in UA lowercase; ptr_suffixes = sufixe de hostname ACCEPTATE la
# reverse-DNS pentru identitatea respectiva.
#
# SIMPLIFICARE cunoscuta: sufixele de mai jos sunt o lista rezonabila,
# suficienta pt. cazul comun de spoofing (UA fals + PTR lipsa/gresit), NU
# lista oficiala completa de range-uri IP publicate de fiecare furnizor (ex:
# Google publica un API JSON dedicat cu range-urile exacte -- vezi
# developers.google.com/search/apis/ipranges-overview). Pentru verificare
# 100% oficiala ar trebui consumat acel API, nu doar suffix-matching pe PTR.
CRAWLER_IDENTITY_CATALOG = [
    # (identitate, needles-in-UA-lowercase, ptr-suffixes-acceptate)
    ("AdsBot-Google", ("adsbot-google",), (".googlebot.com", ".google.com")),
    ("Storebot-Google", ("storebot-google",), (".googlebot.com", ".google.com")),
    ("Googlebot", ("googlebot",), (".googlebot.com", ".google.com")),
    ("Bingbot", ("bingbot",), (".search.msn.com",)),
    ("Meta crawler", ("meta-externalagent", "facebookexternalhit"), (".fbsv.net", ".facebook.com")),
    ("Yandex", ("yandexbot",), (".yandex.com", ".yandex.net", ".yandex.ru")),
    ("DuckDuckBot", ("duckduckbot",), (".duckduckgo.com",)),
    ("ClaudeBot", ("claudebot",), (".anthropic.com",)),
    ("GPTBot", ("gptbot",), (".openai.com",)),
]
CRAWLER_PTR_SUFFIXES = {identity: suffixes for identity, _needles, suffixes in CRAWLER_IDENTITY_CATALOG}
# Identitati pentru care furnizorul DOCUMENTEAZA oficial verificarea prin
# reverse DNS + forward-confirm (Google, Bing, Yandex). Doar pentru ele un
# PTR lipsa/gresit inseamna "fals". Restul (Meta, ClaudeBot, GPTBot,
# DuckDuckBot) publica liste de IP/ASN, nu PTR -- vezi _verify_one_ip.
CRAWLER_DNS_VERIFIABLE = {"Googlebot", "AdsBot-Google", "Storebot-Google", "Bingbot", "Yandex"}
# Retele alocate Meta/Facebook (AS32934) -- cele mai folosite de crawlerul lor.
_CRAWLER_KNOWN_NETS = {
    "Meta crawler": tuple(ipaddress.ip_network(n) for n in (
        "2a03:2880::/32", "31.13.64.0/18", "57.141.0.0/16", "66.220.144.0/20", "69.63.176.0/20",
        "69.171.224.0/19", "157.240.0.0/16", "173.252.64.0/18")),
}
# Filtru rapid (acelasi truc ca SCAN_SIG_QUICK_RE/SUSPICIOUS_QUICK_RE) -- un
# singur .search() pe UA ca sa evitam bucla de needles pe fiecare linie cand
# UA-ul evident nu revendica nicio identitate cunoscuta (marea majoritate a
# traficului).
_CRAWLER_CLAIM_NEEDLES = [n for _i, needles, _p in CRAWLER_IDENTITY_CATALOG for n in needles]
CRAWLER_CLAIM_QUICK_RE = re.compile("|".join(re.escape(n) for n in _CRAWLER_CLAIM_NEEDLES), re.IGNORECASE)
# PERF (v43.2, masurat pe logul real ariesul.ro, 300k linii): un regex
# re.IGNORECASE peste o alternanta de literali e de ~5.5x mai lent decat
# acelasi regex case-sensitive aplicat pe UA deja lowercase (5.38s vs 0.97s).
# Semantica identica: needles sunt ASCII, deci lower() pe ambele parti
# echivaleaza cu IGNORECASE. Folosit in bucla per-linie (vezi _process_chunk).
CRAWLER_CLAIM_QUICK_RE_LOW = re.compile("|".join(re.escape(n.lower()) for n in _CRAWLER_CLAIM_NEEDLES))


def classify_crawler_claim(ua):
    """Tier 1: ce identitate de crawler CUNOSCUTA revendica acest UA (sau
    None). Doar text-matching pe User-Agent -- poate fi falsificat trivial,
    de-asta exista Tier 2 (verificare DNS, vezi _verify_one_ip)."""
    ual = ua.lower()
    for identity, needles, _suffixes in CRAWLER_IDENTITY_CATALOG:
        if any(n in ual for n in needles):
            return identity
    return None


# --------------------------------------------------------------------------
# Traffic Composition -- reconciliaza schema VECHE de categorii (BOT_CATALOG/
# classify_ua, folosita de mult in "Boti & crawlere") cu schema NOUA ceruta
# (9 categorii) intr-un SINGUR sistem de clasificare, nu doua paralele.
# Majoritatea categoriilor vechi se mapeaza direct 1:1; doar catch-all-ul
# vechi "Browser / necunoscut" (orice UA care nu se potriveste cu niciun
# semnal de bot) se imparte in continuare, tot pe baza de text-matching pe
# UA, in 3 categorii noi: Human/Browser (arata a browser real), Suspicious
# automation (UA gol sau semne clare de headless/automation), si
# Unknown/unidentified (nu e nici bot cunoscut, nici arata a browser real).
# Ruleaza o singura data PER USER-AGENT UNIC (in bucla care agrega
# bot_breakdown/traffic_composition), niciodata per cerere.
_OLD_TO_NEW_CATEGORY = {
    "Motor de cautare (legit)": "Legitimate crawler",
    "AI crawler (legit)": "AI crawler",
    "SEO / monitorizare": "SEO/monitoring",
    "Social media preview": "Social media crawler",
    "Script / tool (necunoscut ca provenienta)": "Script/tool",
    "Alt bot / crawler": "Other crawler/bot",
}
_SUSPICIOUS_AUTOMATION_NEEDLES = ("headlesschrome", "phantomjs", "selenium", "puppeteer", "playwright")
_BROWSER_NEEDLES = ("mozilla", "chrome", "safari", "firefox", "edg/", "opr/", "applewebkit", "gecko", "trident")


def classify_composition(ua, old_category):
    """Vezi comentariul de mai sus. `old_category` = rezultatul deja calculat
    de classify_ua(ua) (evitam sa il recalculam)."""
    mapped = _OLD_TO_NEW_CATEGORY.get(old_category)
    if mapped:
        return mapped
    # old_category == "Browser / necunoscut" -> mai departajam
    ual = ua.lower().strip()
    if not ual:
        return "Unknown/unidentified"
    if any(n in ual for n in _SUSPICIOUS_AUTOMATION_NEEDLES):
        return "Suspicious automation"
    if any(n in ual for n in _BROWSER_NEEDLES):
        return "Human/Browser"
    return "Unknown/unidentified"


def normalize_pattern(path_only, query):
    """/product?id=1&sort=asc -> /product?id=*&sort=*  (grupeaza variantele
    de valori sub aceeasi "forma", pentru detectia de abuz de parametri)."""
    if not query:
        return None
    names = set()
    for tok in query.split("&"):
        if not tok:
            continue
        name = tok.split("=", 1)[0]
        if name:
            names.add(name)
    if not names:
        return None
    return path_only + "?" + "&".join(f"{n}=*" for n in sorted(names))


# --------------------------------------------------------------------------
# Worker de procesare paralela (multiprocessing) -- un chunk = un byte range
# --------------------------------------------------------------------------
def _new_pattern_stat():
    """Factory picklabila pentru defaultdict (lambda nu poate fi trimisa
    intre procese de multiprocessing)."""
    return {"count": 0, "ips": set(), "params": Counter()}


def _new_partial():
    return {
        "total": 0, "bad": 0, "blank": 0, "bad_samples": [],
        "ip_counter": Counter(),
        "ua_counter": Counter(),
        "status_counter": Counter(),
        "top_paths": Counter(),
        "method_counter": Counter(),
        "filter_ip_hits": Counter(),
        "dist_path_ips": defaultdict(set),
        "dist_path_count": Counter(),
        "path_prefix_counter": Counter(),   # prefix (primul segment de path, ex: /bijuterii) -> nr cereri
        "path_prefix_ips": defaultdict(set),  # acelasi prefix -> IP-uri unice
        "path_prefix_bandwidth": Counter(),  # acelasi prefix -> total bytes (cine consuma trafic pe categorie)
        "path_facet_count": Counter(),      # prefix -> nr cereri cu marcaj de navigare fatetata (&/* in path)
        "path_facet_ips": defaultdict(set),   # acelasi prefix -> IP-uri unice (pt. enumerare distribuita pe path)
        "login_attempts": defaultdict(list),
        "enum_hits": Counter(),
        "enum_hits_last_time": {},  # ip -> ultimul timestamp la care a fost vazuta o cerere de enumerare (pt. findings/trail)
        "enum_hits_last_domain": {},  # ip -> domeniul acelui ultim timestamp (doar la upload multi-fisier)
        "findings": [],
        "findings_cap_hit": defaultdict(int),
        "day_counter": Counter(),
        "day_hour_counter": Counter(),
        "subnet_counter": Counter(),
        "subnet_ips": defaultdict(set),
        "wp": Counter(),
        "wp_login_ips": defaultdict(int),
        "pattern_stats": defaultdict(_new_pattern_stat),
        "scan_hits": Counter(),  # semnatura -> nr cereri
        "bandwidth": 0,
        "path_ips": defaultdict(set),   # path -> IP-uri unice (pentru coloana "IP unice")
        "ua_ips": defaultdict(set),     # user-agent -> IP-uri unice
        "wp_admin_hits": defaultdict(list),  # ip -> [time,...] acces GET reusit in /wp-admin/ (fara login/ajax)
        "burst_counter": Counter(),     # (day,hour,minute,half) -> nr cereri in acea fereastra de 30s
        "burst_ips": defaultdict(set),  # (day,hour,minute,half) -> IP-uri unice in acea fereastra
        "day_bounds": {},  # day -> [min_line_start_pos, max_line_end_pos] EXACT, calculat gratuit
                           # in aceeasi trecere -- inlocuieste complet cautarea binara + a doua
                           # trecere de validare (vezi _process_chunk / _merge_partials / api_upload)
        "path_bandwidth": Counter(),    # path -> total bytes (cine consuma cel mai mult trafic)
        "ip_bandwidth": Counter(),      # ip -> total bytes
        "err_hour_counter": Counter(),  # (day,hour) -> nr cereri cu status 4xx
        "err5_hour_counter": Counter(), # (day,hour) -> nr cereri cu status 5xx
        "minute_counter": Counter(),    # (day,hour,minute) -> nr cereri (fallback granularitate fina)
        "err_minute_counter": Counter(),   # (day,hour,minute) -> nr cereri 4xx
        "err5_minute_counter": Counter(),  # (day,hour,minute) -> nr cereri 5xx
        "cron_minute_counter": Counter(),  # (day,hour,minute) -> nr cereri wp-cron.php in acel minut
                                            # (detectie "stacking": executii suprapuse/duplicate)
        "wp_cron_day_counter": Counter(),  # day -> nr cereri wp-cron.php (detectie volum ridicat/zi)
        # Activitate admin/WP per IP -- login-uri, acces wp-admin, instalare/
        # editare plugin-uri/teme etc. Vezi comentariul din _process_chunk.
        "admin_activity_actions": defaultdict(Counter),  # ip -> Counter(label -> nr)
        "admin_activity_events": defaultdict(list),      # ip -> [(label,time,method,path,status), ...] (capat)
        "ua_bandwidth": Counter(),      # user-agent -> total bytes (pentru bandwidth per categorie Traffic Composition)
        # --- Revendicari de identitate crawler (Tier 1, vezi CRAWLER_IDENTITY_CATALOG) ---
        # Populat DOAR pentru liniile al caror UA trece de filtrul rapid
        # CRAWLER_CLAIM_QUICK_RE -- o fractiune mica din trafic in practica,
        # deci costul suplimentar per-linie e neglijabil pe trafic normal.
        "claim_ip_identity": {},              # ip -> identitatea revendicata (ultima UA vazuta cu acel ip)
        "claim_ip_requests": Counter(),       # ip -> nr cereri cu UA revendicand o identitate cunoscuta
        "claim_ip_bandwidth": Counter(),      # ip -> bytes (doar cererile de mai sus)
        "claim_ip_paths": defaultdict(Counter),   # ip -> Counter(path_only -> nr)
        "claim_ip_status": defaultdict(Counter),  # ip -> Counter(status -> nr)
        "claim_ip_time_range": defaultdict(list),  # ip -> [[first_tstr,last_tstr], ...] (un pair per chunk in care apare)
        # --- Faza 2: query params / 404 hotspots / clasificare burst ---
        "query_key_counter": Counter(),   # nume parametru query -> nr cereri (vezi categorize_query_key)
        "path_404_counter": Counter(),    # path_only -> nr cereri cu status 404 (pentru "404 hotspots")
        "burst_meta": defaultdict(_new_burst_meta),  # burst_key -> semnale (vezi _new_burst_meta/classify_burst)
        # "Breakdown profesional" pe path (Eduard) -- doar un increment ieftin
        # in bucla deja existenta, REFOLOSIND referer-ul deja parsat pentru
        # linie (nicio parsare noua). path_only -> nr cereri fara referer
        # (gol sau "-"), folosit in build_summary pt. no_referer_pct.
        "path_no_referer_counter": Counter(),
    }


# --------------------------------------------------------------------------
# Severitate standardizata (Faza 2) -- inlocuieste folosirea informala de
# pana acum (doar "HIGH"/"MEDIUM" imprastiate prin cod) cu o scala completa
# de 5 niveluri, folosita CONSISTENT atat pentru "findings" (semnal concret,
# cu o regula clara care s-a potrivit -- ex: pattern de webshell, brute
# force confirmat, semnatura de atac) cat si pentru "anomalies" (semnal mai
# slab/statistic -- volum neobisnuit, deviatie fata de baseline, corelatie
# fara o regula concreta -- "merita o privire", nu "e clar rau"). Ordinea de
# mai jos e si ordinea de sortare (CRITICAL primul).
SEVERITY_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITY_LEVELS)}
# Scor numeric folosit la agregari (ex: compromise_trail) unde severitatile
# mai multor evenimente trebuie combinate intr-un singur scor de prioritizare.
SEVERITY_SCORE = {"CRITICAL": 15, "HIGH": 10, "MEDIUM": 5, "LOW": 2, "INFO": 1}


def _add_finding(result, rule_cap_key, finding):
    if result["findings_cap_hit"][rule_cap_key] >= MAX_FINDINGS_PER_RULE_PER_CHUNK:
        return
    result["findings_cap_hit"][rule_cap_key] += 1
    result["findings"].append(finding)


FILTER_KEYS = ("filter_", "filtru=", "filtre=", "add_to_wishlist", "orderby", "min_price", "max_price", "q=")

# --------------------------------------------------------------------------
# Analiza parametrilor de query (Faza 2) -- categorizeaza CHEILE de query
# vazute in log (nu valorile -- doar numele parametrului, ex "utm_source",
# nu "utm_source=facebook") in 3 grupe, calculata dintr-un simplu Counter de
# frecventa (query_key_counter, populat GRATUIT in bucla existenta care deja
# desparte query string-ul pentru pattern_stats -- vezi _process_chunk, zero
# trecere suplimentara):
#   "tracking"   -- parametri de tracking normal (utm_*, fbclid, gclid etc.)
#   "functional" -- parametri functionali/aplicatie cunoscuti (paginare,
#                   sortare, filtrare de catalog e-commerce) -- normali
#   "suspicious" -- parametri deja tratati ca semnal de abuz in alta parte a
#                   aplicatiei (FILTER_KEYS -- enumerare/abuz de filtre, vezi
#                   distributed_enum) SAU chei al caror NUME arata ca o
#                   incercare de injectie/traversal/comanda (rar, dar ieftin
#                   de verificat cu un singur regex)
#   "other"      -- restul, necategorizat
QP_TRACKING_EXACT = frozenset((
    "fbclid", "gclid", "msclkid", "ttclid", "mc_cid", "mc_eid", "_ga", "_gl",
    "ref", "referrer", "source", "campaign", "campaignid", "yclid", "dclid",
    # Eduard: gad_source/gad_campaignid/gbraid/wbraid apar pe orice pagina
    # de aterizare venita dintr-un click pe reclama Google Ads (gbraid/
    # wbraid sunt varianta "privacy-safe" de gclid, pt. iOS/Android fara
    # cookie tert) -- pana acum cadeau in "other" desi sunt exact acelasi
    # tip de semnal ca gclid. li_fat_id (LinkedIn Ads), twclid (X/Twitter
    # Ads) si igshid (Instagram share/redirect) adaugate din acelasi motiv
    # -- generic, functioneaza pe orice site, nu doar cel curent.
    "gad_source", "gad_campaignid", "gbraid", "wbraid", "li_fat_id",
    "twclid", "igshid",
))
QP_FUNCTIONAL_EXACT = frozenset((
    "page", "paged", "sort", "order", "category", "cat", "id", "p", "s",
    "per_page", "limit", "offset", "lang", "currency", "size", "color",
    "view", "tag", "author", "post_type", "product_cat", "attribute",
))
# Chei tratate deja ca semnal de abuz IN ALTA PARTE a motorului (FILTER_KEYS
# de mai sus e text-matching pe query INTREG, aici e match pe NUMELE cheii
# individuale -- "q" e exclus intentionat, e prea generic/comun ca nume de
# parametru normal de cautare ca sa il marcam singur drept suspect).
QP_SUSPICIOUS_KEY_EXACT = frozenset(("add_to_wishlist", "min_price", "max_price", "filtru", "filtre"))
# "filtr" (fara "e"/"_"/"u" dupa) prinde si varianta romaneasca de navigare
# fatetata (ex: roinstalatii.ro foloseste "?filtru=..." nu "?filter_...=...")
# pe langa engleza "filter_" -- vazut in productie, nu doar teoretic.
QP_SUSPICIOUS_KEY_PREFIXES = ("filter_", "filtr")
# Nume de parametru care AU forma unei incercari de injectie/traversal/
# comanda (nu valoarea -- doar cheia insasi, ex "?../../etc=1" ca nume de
# cheie e deja anormal). Rar in practica, dar un singur regex ieftin.
QP_SUSPICIOUS_KEY_PATTERN_RE = re.compile(r"\.\.|[<>;|`]|\$\(|union|select|base64|passthru|exec\(|eval\(", re.I)

# Parametri de cache-busting -- adaugati AUTOMAT de browser/jQuery/pluginuri
# ca sa forteze un raspuns necachiat (ex: "?_=1695400000123", timestamp-ul
# curent in milisecunde), FARA nicio legatura cu continutul cerut. Eduard:
# tabelul "Parametri de query" arata "_" cu zeci de mii de cereri sub
# categoria "Altele" ("other") si e confuz -- nu e "necunoscut", are un nume
# si o explicatie foarte specifice, deci merita categoria proprie, verificata
# INAINTE de "other" (dar dupa tracking/suspicious/functional, ca sa nu
# rescriem acele semnale deja existente).
QP_CACHE_BUSTING_EXACT = frozenset(("_", "v", "ver", "t", "cb", "_t", "rand"))


def categorize_query_key(key):
    kl = key.lower().strip()
    if not kl:
        return "other"
    if kl.startswith("utm_") or kl in QP_TRACKING_EXACT:
        return "tracking"
    if kl in QP_SUSPICIOUS_KEY_EXACT or any(kl.startswith(p) for p in QP_SUSPICIOUS_KEY_PREFIXES):
        return "suspicious"
    if QP_SUSPICIOUS_KEY_PATTERN_RE.search(kl):
        return "suspicious"
    if kl in QP_FUNCTIONAL_EXACT:
        return "functional"
    if kl in QP_CACHE_BUSTING_EXACT:
        return "cache_busting"
    return "other"


# --------------------------------------------------------------------------
# Clasificare de burst (Faza 2) -- vezi build_summary (unde e apelata, doar
# pentru cele 3 bursturi afisate in "top_bursts") pentru cum se combina
# semnalele de mai jos (deja agregate GRATUIT per-fereastra-de-30s in
# bucla per-linie, vezi "burst_meta" din _new_partial/_process_chunk) intr-o
# eticheta + un motiv scurt. IMPORTANT (principiul deja stabilit in restul
# aplicatiei, vezi STATIC_ASSET_PHP_DISGUISE_RE/subnet suspicious mai sus):
# volumul de cereri NU e prin el insusi un semnal -- un Googlebot verificat
# care face crawl rapid la sute de pagini NU e "suspect" doar pentru ca a
# generat un burst; combinam mereu volumul cu semnale de UA/identitate/
# tipar-de-path inainte sa etichetam ceva altfel decat "Normal"/"Unknown".
def _new_burst_meta():
    """Factory picklabila pentru defaultdict (vezi burst_meta din
    _new_partial) -- semnale ieftine per fereastra de 30s, acumulate GRATUIT
    in aceeasi bucla per-linie care calculeaza deja burst_key_of(tstr)."""
    return {
        "paths": set(),          # path_only distincte vazute in fereastra (plafonat, vezi _process_chunk)
        "subnets": set(),        # subnet-uri /24 distincte (plafonat)
        "security_hits": 0,      # cereri catre wp-login.php/xmlrpc.php/wp-admin (fara ajax) in fereastra
        "crawler_claim_hits": 0, # cereri cu UA ce revendica o identitate de crawler cunoscuta (Tier 1)
        "generic_hits": 0,       # cereri cu UA de tip script/tool generic (curl/wget/python-requests etc.) sau gol
    }


# Aceleasi needles ca in BOT_CATALOG ("Script / tool..."), reutilizate direct
# aici ca sa nu dubleze definitia -- doar un filtru rapid, un singur
# .search() per linie pe cazul comun (traficul normal, cu UA de browser real,
# nu se potriveste niciodata).
_GENERIC_TOOL_UA_NEEDLES = dict(BOT_CATALOG)["Script / tool (necunoscut ca provenienta)"]
_GENERIC_TOOL_UA_RE = re.compile("|".join(re.escape(n) for n in _GENERIC_TOOL_UA_NEEDLES), re.IGNORECASE)
_GENERIC_TOOL_UA_RE_LOW = re.compile("|".join(re.escape(n.lower()) for n in _GENERIC_TOOL_UA_NEEDLES))  # vezi CRAWLER_CLAIM_QUICK_RE_LOW


def classify_burst(count, n_ips, n_paths, n_subnets, sec_hits, crawler_hits, generic_hits):
    """Vezi comentariul de mai sus. Intoarce (eticheta, motiv_scurt).
    Ordinea verificarilor conteaza (prima potrivire castiga) -- de la cel
    mai specific/concret semnal (scanare de securitate) catre cel mai vag
    (Unknown, cand nimic din de mai jos nu se potriveste clar)."""
    sec_ratio = sec_hits / count if count else 0
    crawler_ratio = crawler_hits / count if count else 0
    generic_ratio = generic_hits / count if count else 0

    if sec_ratio >= 0.4 and n_ips <= 5:
        return "Security scan", (
            f"{sec_hits}/{count} cereri ({sec_ratio * 100:.0f}%) catre endpoint-uri sensibile "
            f"(wp-login/xmlrpc/wp-admin), concentrate pe doar {n_ips} IP(-uri) -- tipar de "
            f"scanare/brute-force pe endpoint-uri de login, nu de navigare normala."
        )
    if crawler_ratio >= 0.5 and n_paths >= 8:
        return "Crawler", (
            f"{crawler_hits}/{count} cereri ({crawler_ratio * 100:.0f}%) au User-Agent care revendica "
            f"un crawler cunoscut, acoperind {n_paths} path-uri distincte -- tipar de crawl rapid al "
            f"unui bot legitim (identitate revendicata prin UA, vezi sectiunea Crawlere pentru "
            f"verificarea DNS Tier 2). Volumul mare NU e, prin el insusi, un semnal de atac aici."
        )
    if n_ips >= 15 and n_subnets >= 5 and n_paths <= max(5, n_ips // 4):
        return "Distributed crawl", (
            f"{n_ips} IP-uri distincte din {n_subnets} subnet-uri /24 diferite au lovit doar "
            f"{n_paths} path-uri in aceeasi fereastra de 30s -- posibil crawl/proxy distribuit "
            f"sau retea de boti, nu vizitatori independenti care navigheaza organic."
        )
    if generic_ratio >= 0.5 and crawler_hits == 0:
        return "Suspicious automation", (
            f"{generic_hits}/{count} cereri ({generic_ratio * 100:.0f}%) cu User-Agent de tip "
            f"script/tool (curl/wget/python-requests etc.) sau gol, fara nicio revendicare de "
            f"identitate de crawler cunoscut -- automatizare neidentificata, merita verificat."
        )
    if n_ips >= 3 and n_paths >= 3 and sec_ratio < 0.2 and generic_ratio < 0.3:
        return "Normal", (
            f"{n_ips} IP-uri distincte navigand pe {n_paths} path-uri diferite, fara concentrare pe "
            f"endpoint-uri sensibile si fara semnal clar de automatizare -- tipar compatibil cu "
            f"trafic normal aglomerat (ex: promotie, share viral)."
        )
    return "Unknown", (
        "Volumul e ridicat, dar semnalele disponibile (IP-uri, path-uri, User-Agent) nu se potrivesc "
        "clar cu niciun tipar cunoscut -- verifica manual liniile brute din acest burst."
    )


def _process_chunk(args):
    """Hot-path per-linie. OPTIMIZAT (v11) fata de versiunea initiala:
    1) variabilele din `result` (dict de Counter/set/defaultdict) sunt legate
       o singura data la variabile LOCALE inainte de bucla -- un lookup
       `result["x"]` in Python e mai scump decat un nume local, si asta se
       repeta la fiecare linie, de zeci de ori;
    2) cele doua verificari cele mai scumpe (semnatura de scanare CMS si
       pattern-uri suspecte) rulau INAINTE necontitionat pe fiecare linie,
       chiar si pe trafic normal -- acum au un singur .search() de regex ca
       filtru rapid (SCAN_SIG_QUICK_RE / SUSPICIOUS_QUICK_RE), si bucla
       detaliata (care determina EXACT ce semnatura/pattern s-a potrivit)
       ruleaza doar daca filtrul rapid a gasit ceva. Verificat cu profiler pe
       500k linii sintetice: ~20% mai rapid, rezultat byte-identic cu
       versiunea veche (comparat automat inainte de livrare).
    3) hour_filter/minute_filter (optionale) restrang agregarea la un
       sub-interval al unei zile (ex: doar ora 14, sau doar minutele
       20:00-20:09) -- folosite de /summary_range, ca sa poti vedea
       statistici complete (nu doar liniile brute) pentru orice interval
       exact, nu doar pentru o zi intreaga."""
    path, start, end, day_filter, hour_filter, minute_filter, segments = args[:7]
    # 8th element optional: calea unui shard SQLite in care sa scriem, in
    # ACEEASI trecere, randurile indexului de triaj (vezi run_engine,
    # index_workdir). Doar trecerea de upload il da; drill-down-urile nu.
    shard_path = args[7] if len(args) > 7 else None
    progress_path = args[8] if len(args) > 8 else (shard_path + ".progress" if shard_path else None)
    shard = None
    shard_rows = []
    shard_n = 0
    _colc = None   # v44: coloanele indexului columnar, colectate in aceeasi trecere
    if shard_path:
        shard = triage_engine.connect_shard(shard_path)
        _shard_sql = (f"INSERT INTO events ({','.join(triage_engine.COLUMNS)}) "
                      f"VALUES ({','.join(['?'] * len(triage_engine.COLUMNS))})")
        if triage_columnar.AVAILABLE:
            _colc = triage_columnar.ChunkCollector()
    # Memo per worker -- cardinalitate mica pe loguri reale (ariesul.ro:
    # ~3.3k IP-uri si ~330 UA-uri unice la 2.65M linii), deci un lookup in
    # dict inlocuieste un geoip/regex per linie (masurat: geoip 1.31s ->
    # 0.06s la 300k linii).
    _cc_memo = {}
    _claim_memo = {}
    _subnet_memo = {}
    # UA -> id in dictionarul `uas` al indexului. Id-ul e unic GLOBAL fara
    # remapare la lipirea shard-urilor: (offsetul de inceput al chunk-ului
    # << 24) | index local -- doua chunk-uri nu pot avea acelasi start.
    _ua_ids = {}
    _ua_base = start << 24
    _qk_susp_memo = {}  # nume parametru query -> e 'suspicious'? (categorize_query_key)
    _hour_epoch_memo = {}  # '30/Sep/2026:11 +0300' -> epoch-ul orei (vezi randul de triaj)
    # v43.3 -- memo-uri per valoare UNICA pentru tot ce depinde doar de
    # path / UA / referer (functii pure). Pe logul real: 2.65M linii, ~63k
    # path-uri, ~330 UA-uri -> peste 97% din linii nu mai refac lower(),
    # find('?'), regex-urile de scanare/pattern suspect si clasificarea de
    # triaj. Plafonate la _MEMO_CAP intrari: un log cu milioane de URL-uri
    # unice (scanare cu query random) nu poate umfla RAM-ul -- peste plafon
    # se calculeaza direct, cu acelasi rezultat.
    _path_memo = {}   # path_raw -> (path_low, qpos, path_only, q, scan_sig, susp_quick)
    _ua_memo = {}     # ua -> (ua_low, is_crawler_claim, identity)
    _refq_memo = {}   # referer -> SUSPICIOUS_QUICK_RE pe referer.lower()
    _cls_memo = {}    # (method, path_raw, status, nonro, susp) -> clasificare triaj
    result = _new_partial()

    ip_counter = result["ip_counter"]
    ua_counter = result["ua_counter"]
    status_counter = result["status_counter"]
    top_paths = result["top_paths"]
    method_counter = result["method_counter"]
    day_counter = result["day_counter"]
    day_hour_counter = result["day_hour_counter"]
    burst_counter = result["burst_counter"]
    burst_ips = result["burst_ips"]
    path_ips = result["path_ips"]
    ua_ips = result["ua_ips"]
    subnet_counter = result["subnet_counter"]
    subnet_ips = result["subnet_ips"]
    pattern_stats = result["pattern_stats"]
    filter_ip_hits = result["filter_ip_hits"]
    dist_path_ips = result["dist_path_ips"]
    dist_path_count = result["dist_path_count"]
    path_prefix_counter = result["path_prefix_counter"]
    path_prefix_ips = result["path_prefix_ips"]
    path_prefix_bandwidth = result["path_prefix_bandwidth"]
    path_facet_count = result["path_facet_count"]
    path_facet_ips = result["path_facet_ips"]
    wp = result["wp"]
    wp_login_ips = result["wp_login_ips"]
    login_attempts = result["login_attempts"]
    enum_hits = result["enum_hits"]
    enum_hits_last_time = result["enum_hits_last_time"]
    enum_hits_last_domain = result["enum_hits_last_domain"]
    wp_admin_hits = result["wp_admin_hits"]
    scan_hits = result["scan_hits"]
    day_bounds = result["day_bounds"]
    path_bandwidth = result["path_bandwidth"]
    ip_bandwidth = result["ip_bandwidth"]
    err_hour_counter = result["err_hour_counter"]
    err5_hour_counter = result["err5_hour_counter"]
    minute_counter = result["minute_counter"]
    err_minute_counter = result["err_minute_counter"]
    err5_minute_counter = result["err5_minute_counter"]
    cron_minute_counter = result["cron_minute_counter"]
    wp_cron_day_counter = result["wp_cron_day_counter"]
    admin_activity_actions = result["admin_activity_actions"]
    admin_activity_events = result["admin_activity_events"]
    ua_bandwidth = result["ua_bandwidth"]
    claim_ip_identity = result["claim_ip_identity"]
    claim_ip_requests = result["claim_ip_requests"]
    claim_ip_bandwidth = result["claim_ip_bandwidth"]
    claim_ip_paths = result["claim_ip_paths"]
    claim_ip_status = result["claim_ip_status"]
    claim_ip_time_range = result["claim_ip_time_range"]
    query_key_counter = result["query_key_counter"]
    path_404_counter = result["path_404_counter"]
    burst_meta = result["burst_meta"]
    path_no_referer_counter = result["path_no_referer_counter"]
    _chunk_claim_first_last = {}  # ip -> [first_tstr, last_tstr] EXCLUSIV pentru acest chunk (vezi finalul functiei)
    total = 0
    bad = 0
    bandwidth = 0

    def _log_admin(ip_, label, tstr_, method_, path_raw_, status_, domain_=None):
        """Inregistreaza o actiune admin/WP pentru un IP -- vezi cardul nou
        'Activitate admin / WordPress' din dashboard. Actiunile urmarite:
        login-uri (incercari si reusite), acces /wp-admin/ dupa login,
        instalare/editare plugin-uri sau teme, upload prin admin-ajax
        (file manager), fisiere .php ajunse in uploads/cache (webshell).
        domain_ (optional) -- domeniul/subdomeniul sursa, DOAR cand dataset-ul
        e combinat din mai multe fisiere (vezi _dom() mai jos)."""
        admin_activity_actions[ip_][label] += 1
        ev = admin_activity_events[ip_]
        if len(ev) < MAX_ADMIN_EVENTS_PER_IP:
            ev.append((label, tstr_, method_, path_raw_, status_, domain_))

    def _dom(offset):
        """Domeniul/subdomeniul sursa pentru byte-ul `offset` din fisierul
        combinat -- None instant daca dataset-ul are un singur fisier
        (cazul normal, fara niciun cost). `segments` are cateva elemente
        (numarul de fisiere incarcate deodata), deci scanarea liniara e
        ieftina -- si oricum apelata doar in ramurile deja rare (findings/
        admin/login), niciodata pe bucla per-linie completa."""
        if not segments:
            return None
        for seg_start, seg_end, seg_domain in segments:
            if seg_start <= offset < seg_end:
                return seg_domain
        return None

    with open(path, "rb") as f:
        f.seek(start)
        pos = start
        while pos < end:
            line_start = pos
            raw_line = f.readline()
            if not raw_line:
                break
            pos = f.tell()
            line = raw_line.decode("utf-8", errors="replace")

            rec = parse_line_fast(line)
            if rec is None:
                if line.strip():
                    bad += 1
                    # spec §8: raportam liniile invalide, cu cateva exemple
                    # (afisate escapate in UI) ca sa se poata verifica.
                    if len(result["bad_samples"]) < 5:
                        result["bad_samples"].append(line.rstrip("\r\n")[:300])
                else:
                    result["blank"] += 1
                continue
            ip, method, path_raw, status, referer, ua, tstr, size = rec
            day = day_of(tstr)

            # Index per-zi EXACT, calculat gratuit in aceeasi trecere (nicio
            # a doua trecere de validare nu mai e necesara -- vezi comentariul
            # din _new_partial). Facut INAINTE de filtrul de zi, ca sa
            # functioneze si cand run_engine() e apelat cu day_filter (ex:
            # motorul principal de la upload nu foloseste day_filter, deci
            # rularea asta se face mereu o singura data, la scanarea completa).
            db = day_bounds.get(day)
            if db is None:
                day_bounds[day] = [line_start, pos]
            else:
                if line_start < db[0]:
                    db[0] = line_start
                if pos > db[1]:
                    db[1] = pos

            if day_filter and day != day_filter:
                continue

            if hour_filter or minute_filter is not None:
                hr_check = hour_of(tstr)
                if hour_filter and hr_check != hour_filter:
                    continue
                if minute_filter is not None:
                    if len(tstr) < 17:
                        continue
                    mtxt = tstr[15:17]
                    if not mtxt.isdigit():
                        continue
                    mstart, mspan = minute_filter
                    if not (mstart <= int(mtxt) < mstart + mspan):
                        continue

            total += 1
            if progress_path is not None and not (total & 0xFFFF):
                # progres pentru UI (spec §4): un fisier mic per worker, citit
                # de job -- fara memorie partajata intre procesele pool-ului.
                try:
                    with open(progress_path, "w") as _pf:
                        _pf.write(f"{total + bad} {pos - start}")
                except OSError:
                    pass
            _pm = _path_memo.get(path_raw)
            if _pm is None:
                _pl = path_raw.lower()
                _qp = path_raw.find("?")
                _pm = (_pl, _qp, path_raw[:_qp] if _qp != -1 else path_raw,
                       path_raw[_qp + 1:] if _qp != -1 else "",
                       scan_signature_of(_pl), bool(SUSPICIOUS_QUICK_RE.search(_pl)))
                if len(_path_memo) < _MEMO_CAP:
                    _path_memo[path_raw] = _pm
            path_low, qpos, path_only, q, _pm_scan, _pm_suspq = _pm

            ip_counter[ip] = ip_counter.get(ip, 0) + 1
            ua_counter[ua] = ua_counter.get(ua, 0) + 1
            status_counter[status] = status_counter.get(status, 0) + 1
            top_paths[path_only] = top_paths.get(path_only, 0) + 1
            # "Breakdown profesional" (Eduard): % din cererile catre acest
            # path care NU au referer -- reutilizeaza referer-ul deja parsat
            # mai sus, un singur increment ieftin, nicio parsare noua.
            if not referer or referer == "-":
                path_no_referer_counter[path_only] = path_no_referer_counter.get(path_only, 0) + 1
            method_counter[method] = method_counter.get(method, 0) + 1
            day_counter[day] = day_counter.get(day, 0) + 1
            hr = hour_of(tstr)
            dh_key = (day, hr)
            day_hour_counter[dh_key] = day_hour_counter.get(dh_key, 0) + 1
            bandwidth += size
            path_bandwidth[path_only] = path_bandwidth.get(path_only, 0) + size
            ip_bandwidth[ip] = ip_bandwidth.get(ip, 0) + size
            ua_bandwidth[ua] = ua_bandwidth.get(ua, 0) + size

            # --- Revendicare identitate crawler (Tier 1) -- vezi comentariul
            # din _new_partial. Filtru rapid intai (un singur .search()), ca
            # sa nu platim costul needle-by-needle pe traficul normal.
            # Rezultatul (_is_crawler_claim) e REFOLOSIT mai jos la
            # clasificarea de burst (Faza 2) -- evita un al doilea
            # .search() pe acelasi UA in aceeasi linie.
            _um = _ua_memo.get(ua)
            if _um is None:
                _ul = ua.lower()
                _ic = bool(CRAWLER_CLAIM_QUICK_RE_LOW.search(_ul))
                _um = (_ul, _ic, classify_crawler_claim(ua) if _ic else None)
                if len(_ua_memo) < _MEMO_CAP:
                    _ua_memo[ua] = _um
            ua_low, _is_crawler_claim, _ua_identity = _um
            if _is_crawler_claim:
                identity = _ua_identity
                if identity is not None:
                    claim_ip_identity[ip] = identity
                    claim_ip_requests[ip] = claim_ip_requests.get(ip, 0) + 1
                    claim_ip_bandwidth[ip] = claim_ip_bandwidth.get(ip, 0) + size
                    claim_ip_paths[ip][path_only] += 1
                    claim_ip_status[ip][status] += 1
                    fl = _chunk_claim_first_last.get(ip)
                    if fl is None:
                        _chunk_claim_first_last[ip] = [tstr, tstr]
                    else:
                        fl[1] = tstr
            if status >= 500:
                err5_hour_counter[dh_key] = err5_hour_counter.get(dh_key, 0) + 1
            elif status >= 400:
                err_hour_counter[dh_key] = err_hour_counter.get(dh_key, 0) + 1
                if status == 404:
                    # "404 hotspots" -- path-uri lovite repetat cu 404, semnal
                    # de scanare pentru fisiere/endpoint-uri necunoscute (vezi
                    # build_summary: top_paths_404). Un singur Counter in plus,
                    # acelasi cost ca top_paths de mai sus.
                    path_404_counter[path_only] = path_404_counter.get(path_only, 0) + 1

            # Bucket pe minut -- folosit doar ca fallback de granularitate
            # fina pentru graficul "Trafic in timp" cand intervalul selectat
            # (ex: statistici pentru un interval de 30 min) se aduna oricum
            # intr-un singur bucket de ora, unde un grafic pe ore ar arata un
            # singur punct inutil (vezi build_summary).
            if len(tstr) >= 17 and tstr[15:17].isdigit():
                dhm_key = (day, hr, tstr[15:17])
                minute_counter[dhm_key] = minute_counter.get(dhm_key, 0) + 1
                if status >= 500:
                    err5_minute_counter[dhm_key] = err5_minute_counter.get(dhm_key, 0) + 1
                elif status >= 400:
                    err_minute_counter[dhm_key] = err_minute_counter.get(dhm_key, 0) + 1
                if path_only.endswith("wp-cron.php"):
                    # Bucket pe minut DOAR pentru wp-cron.php -- detecteaza
                    # "stacking" (executii suprapuse: system cron + trigger
                    # la fiecare pageview, sau cron dublat), vezi build_summary.
                    cron_minute_counter[dhm_key] = cron_minute_counter.get(dhm_key, 0) + 1

            subnet = _subnet_memo.get(ip, _subnet_memo)
            if subnet is _subnet_memo:
                subnet = _subnet_memo[ip] = subnet24_of(ip)
            if subnet:
                subnet_counter[subnet] = subnet_counter.get(subnet, 0) + 1
                sset = subnet_ips[subnet]
                if len(sset) < MAX_IPS_PER_BUCKET:
                    sset.add(ip)

            bkey = burst_key_of(tstr)
            if bkey is not None:
                _bcount = burst_counter[bkey] = burst_counter.get(bkey, 0) + 1
                bips = burst_ips[bkey]
                if len(bips) < MAX_IPS_PER_BUCKET:
                    bips.add(ip)
                # --- Semnale ieftine per-fereastra pentru clasificarea de
                # burst (Faza 2, vezi classify_burst) -- plafonate individual
                # ca sa nu creasca nemarginit pe un burst uriaș; doar
                # cardinalitatea/raportul conteaza pentru clasificare, nu
                # lista exhaustiva. PERF: pornim colectarea abia de la a
                # treia cerere din fereastra -- marea majoritate a
                # ferestrelor de 30s de pe un site normal au 1-2 cereri (fara
                # nicio sansa sa devina unul din top 3 bursturi afisate), deci
                # sarim complet costul de mai jos pentru ele; pentru
                # ferestrele care CHIAR devin bursturi (sute de cereri),
                # a rata primele 2 cereri e neglijabil pentru clasificare.
                if _bcount >= 3:
                    bm = burst_meta[bkey]
                    bm_paths = bm["paths"]
                    if len(bm_paths) < 80:
                        bm_paths.add(path_only)
                    if subnet:
                        bm_subnets = bm["subnets"]
                        if len(bm_subnets) < 80:
                            bm_subnets.add(subnet)
                    if ("wp-login.php" in path_low or "xmlrpc.php" in path_low
                            or ("/wp-admin/" in path_low and "admin-ajax.php" not in path_low)):
                        bm["security_hits"] += 1
                    # Reutilizeaza _is_crawler_claim calculat mai sus (evita un
                    # al doilea .search() pe acelasi UA). Pentru "generic tool"
                    # (curl/wget/python-requests etc.), un .startswith("Mozilla")
                    # ieftin (fara regex) elimina INSTANT marea majoritate a
                    # traficului (browsere reale) -- .search() ruleaza doar pe
                    # UA-urile ramase (deja o mica fractie), tinand costul jos
                    # chiar cu semnalul suplimentar (vezi masuratoarea din
                    # audit-ul de profiling, unde .search() era de departe cea
                    # mai scumpa operatie per-linie).
                    if _is_crawler_claim:
                        bm["crawler_claim_hits"] += 1
                    elif not ua or ua == "-":
                        bm["generic_hits"] += 1
                    elif not ua.startswith("Mozilla") and _GENERIC_TOOL_UA_RE_LOW.search(ua_low):
                        bm["generic_hits"] += 1

            pips = path_ips[path_only]
            if len(pips) < MAX_IPS_PER_BUCKET:
                pips.add(ip)
            uips = ua_ips[ua]
            if len(uips) < MAX_IPS_PER_BUCKET:
                uips.add(ip)

            if q:
                # normalize_pattern inline: acelasi split pe '&' refolosit mai
                # jos (inainte q.split('&') rula de doua ori per linie).
                _qtoks = q.split("&")
                _qnames = set()
                for _t in _qtoks:
                    if _t:
                        _n = _t.split("=", 1)[0]
                        if _n:
                            _qnames.add(_n)
                # pattern_stats alimenteaza EXCLUSIV param_abuse (build_summary),
                # care pastreaza un pattern doar daca unul din parametrii lui e
                # categorizat "suspicious" -- decizie care depinde DOAR de
                # numele parametrilor (categorize_query_key(nume)), cunoscute
                # deja aici. Un pattern fara niciun nume suspect nu poate ajunge
                # niciodata in rezultat, deci nu il mai urmarim (rezultat
                # identic). Pe logul real: ~310k pattern-uri unice per 500k
                # linii, fiecare cu dict+set+Counter propriu -- cea mai mare
                # structura transferata intre procese si cea mai scumpa la
                # contopire (vezi audit v43.2).
                _track_pat = False
                for _n in _qnames:
                    _cq = _qk_susp_memo.get(_n)
                    if _cq is None:
                        _cq = _qk_susp_memo[_n] = (categorize_query_key(_n) == "suspicious")
                    if _cq:
                        _track_pat = True
                        break
                if _qnames:
                    # forma normalizata /path?a=*&b=* -- construita doar daca o urmarim
                    ps = (pattern_stats[path_only + "?" + "&".join(f"{n}=*" for n in sorted(_qnames))]
                          if _track_pat else None)
                    if ps is not None:
                        ps["count"] += 1
                        if len(ps["ips"]) < MAX_IPS_PER_BUCKET:
                            ps["ips"].add(ip)
                    for tok in _qtoks:
                        if "=" in tok:
                            key = tok.split("=", 1)[0]
                            if ps is not None:
                                ps["params"][key] += 1
                            # "Query parameters" (Faza 2) -- Counter global de
                            # frecventa a NUMELUI parametrului, categorizat
                            # ulterior in build_summary (vezi categorize_query_key).
                            # Reutilizeaza split-ul deja facut mai sus, zero cost
                            # suplimentar de parsare.
                            query_key_counter[key] = query_key_counter.get(key, 0) + 1
                if any(k in q for k in FILTER_KEYS):
                    filter_ip_hits[ip] = filter_ip_hits.get(ip, 0) + 1
                    pset = dist_path_ips[path_only]
                    if len(pset) < MAX_IPS_PER_BUCKET:
                        pset.add(ip)
                    dist_path_count[path_only] = dist_path_count.get(path_only, 0) + 1

            # --- Agregare pe prefixul de path (primul segment, ex: /bijuterii)
            # -- separat de top_paths (care e pe URL EXACT si rateaza cataloage
            # mari unde fiecare produs/pagina are propriul URL unic -- mii de
            # URL-uri distincte, fiecare cu 2-3 cereri, niciodata suficient de
            # sus in top 30 ca sa apara, desi prefixul in ansamblu poate fi
            # majoritatea traficului. Vezi build_summary: top_path_prefixes).
            slash2 = path_only.find("/", 1)
            prefix = path_only[:slash2] if slash2 > 0 else path_only
            if prefix and prefix != "/":
                path_prefix_counter[prefix] = path_prefix_counter.get(prefix, 0) + 1
                path_prefix_bandwidth[prefix] = path_prefix_bandwidth.get(prefix, 0) + size
                ppset = path_prefix_ips[prefix]
                if len(ppset) < MAX_IPS_PER_BUCKET:
                    ppset.add(ip)

                # --- Enumerare distribuita prin SEGMENTE de path (navigare pe
                # fatete cu combinatii codificate direct in URL, ex:
                # /shape/bagheta-&-rotunda*forma-ovala*princess...) -- acelasi
                # principiu ca enumerarea prin query string (FILTER_KEYS) de
                # mai sus, dar semnalul e in PATH, nu in query. Filtru rapid:
                # caracterele '&'/'*' aparute direct in path (path_only exclude
                # deja query string-ul) sunt foarte rare in path-uri de continut
                # normale si tipice pt. combinatorica de filtre. Vezi
                # build_summary: distributed_path_enum.
                if "&" in path_only or "*" in path_only:
                    pfset = path_facet_ips[prefix]
                    if len(pfset) < MAX_IPS_PER_BUCKET:
                        pfset.add(ip)
                    path_facet_count[prefix] = path_facet_count.get(prefix, 0) + 1

            # --- WordPress ---
            if "/wp-admin/" in path_low:
                wp["wp_admin"] = wp.get("wp_admin", 0) + 1
                if method == "GET" and status == 200 and _is_admin_page(path_only.lower()):
                    # acces reusit (200) la o pagina din /wp-admin/, altul
                    # decat login/ajax -- semnal de corelare pentru "login
                    # reusit" (vezi build_summary)
                    hits = wp_admin_hits[ip]
                    if len(hits) < MAX_LOGIN_ATTEMPTS_PER_IP:
                        hits.append(tstr)
                    _log_admin(ip, "Acces /wp-admin/ (200)", tstr, method, path_raw, status, _dom(line_start))
            if "admin-ajax.php" in path_low:
                wp["admin_ajax"] = wp.get("admin_ajax", 0) + 1
            if "xmlrpc.php" in path_low:
                wp["xmlrpc"] = wp.get("xmlrpc", 0) + 1
            if "/wp-json/" in path_low:
                wp["wp_json"] = wp.get("wp_json", 0) + 1
            if path_only.endswith("wp-cron.php"):
                wp["wp_cron"] = wp.get("wp_cron", 0) + 1
                wp_cron_day_counter[day] = wp_cron_day_counter.get(day, 0) + 1
            if _is_login_ep(path_only):
                if method == "GET":
                    wp["wp_login_get"] = wp.get("wp_login_get", 0) + 1
                elif method == "POST":
                    wp["wp_login_post"] = wp.get("wp_login_post", 0) + 1
                    wp_login_ips[ip] += 1
                    _log_admin(ip, "Login POST wp-login.php", tstr, method, path_raw, status, _dom(line_start))
                    if status == 302:
                        _log_admin(ip, "Login reusit (302)", tstr, method, path_raw, status, _dom(line_start))

            if method == "POST" and (_is_login_ep(path_only) or _is_xmlrpc_ep(path_only)):
                attempts = login_attempts[ip]
                if len(attempts) < MAX_LOGIN_ATTEMPTS_PER_IP:
                    attempts.append((status, tstr, _dom(line_start)))

            if "author=" in q or "/wp-json/wp/v2/users" in path_low:
                if "/wp-json/wp/v2/users" in path_low:
                    enum_hits[ip] = enum_hits.get(ip, 0) + 1
                    enum_hits_last_time[ip] = tstr
                    enum_hits_last_domain[ip] = _dom(line_start)
                else:
                    idx = q.find("author=")
                    tail = q[idx + 7:idx + 18]
                    if tail[:1].isdigit():
                        enum_hits[ip] = enum_hits.get(ip, 0) + 1
                        enum_hits_last_time[ip] = tstr
                        enum_hits_last_domain[ip] = _dom(line_start)

            # --- Scanare CMS / fisiere sensibile: filtru rapid (un singur
            # regex.search) inainte de bucla detaliata pe semnaturi -- vezi
            # docstring-ul functiei. Restul verificarilor de mai jos sunt deja
            # ieftine (cateva "in" pe un string deja calculat) si raman
            # neconditionate, ca in versiunea originala.
            _scan_sig = _pm_scan  # = scan_signature_of(path_low), memo per path
            if _scan_sig is not None:
                scan_hits[_scan_sig] = scan_hits.get(_scan_sig, 0) + 1

            if ("plugin-install.php" in path_low or "theme-editor.php" in path_low
                    or "plugin-editor.php" in path_low
                    or ("update.php" in path_low and "action=upload-plugin" in path_low)):
                # Acelasi principiu status-aware ca la webshell (mai sus): un
                # 404/403 la un endpoint admin sensibil inseamna doar o
                # CERERE care n-a ajuns nicaieri (pagina inexistenta/blocata),
                # nu o dovada de acces reusit la editor de plugin/tema.
                if 200 <= status < 300:
                    _asev = "MEDIUM"
                    _areason = (f"Endpoint WordPress care poate instala sau edita cod pe server (editor de "
                                f"plugin/tema, sau upload de plugin) a raspuns cu SUCCES (status {status}) -- "
                                f"daca nu e administratorul legitim, e un pas concret spre compromitere completa.")
                else:
                    _asev = "LOW"
                    _areason = (f"Cerere catre un endpoint admin sensibil (editor plugin/tema, upload), dar "
                                f"serverul NU a raspuns cu succes (status {status}) -- incercare fara acces "
                                f"confirmat, nu o dovada de folosire reala a editorului.")
                _add_finding(result, "admin", {
                    "severity": _asev,
                    "confidence": "high",
                    "rule": "Acces admin sensibil (plugin/theme editor, upload)",
                    "reason": _areason,
                    "detail": f"IP {ip}: {method} {path_raw} -> {status} la {tstr}",
                    "ip": ip, "time": tstr, "domain": _dom(line_start),
                    # eveniment SINGULAR (o singura linie de log) -- nu exista
                    # agregate suplimentare fata de ce vezi deja in 'detail';
                    # evidence doar structureaza aceleasi campuri, nu inventeaza date noi.
                    "evidence": {"ip": ip, "method": method, "path": path_raw,
                                 "status": status, "time": tstr},
                })
                _log_admin(ip, "Plugin/tema: instalare sau editare", tstr, method, path_raw, status, _dom(line_start))

            # BUG raportat de Eduard (captura din dashboard): un webshell era
            # etichetat CRITICAL identic indiferent daca status-ul era 200
            # (fisierul chiar a fost SERVIT -- compromitere reala) sau 404
            # (fisierul nu exista pe server -- doar o CERERE/scanare care a
            # esuat) -- "cum e confirmat atacul daca e 404?". Severitatea SI
            # textul motivului reflecta acum diferenta, in acelasi spirit ca
            # _classify_trail_event() (care deja facea distinctia asta pentru
            # traseul de compromitere, dar NU si pentru findings-urile brute
            # din tabelul de Findings -- de-acolo venea discrepanta).
            _webshell_is_2xx = 200 <= status < 300
            if (("wp-content/uploads" in path_low or "wp-content/cache" in path_low)
                    and path_low.split("?", 1)[0].endswith(".php")):
                if _webshell_is_2xx:
                    _wsev, _wrule = "CRITICAL", "Fisier .php in uploads/cache -- SERVIT cu succes (webshell activ)"
                    _wreason = (f"Un fisier .php dintr-un folder de uploads/cache (destinat doar continutului "
                                f"incarcat de utilizatori, nu codului) a fost EFECTIV SERVIT cu succes "
                                f"(status {status}) -- dovada puternica de webshell activ, nu doar o cerere.")
                else:
                    _wsev, _wrule = "HIGH", "Fisier .php in uploads/cache -- incercare (posibil webshell)"
                    _wreason = (f"Cerere catre un fisier .php intr-un folder de uploads/cache (tipar clasic de "
                                f"webshell), dar serverul NU a raspuns cu succes (status {status}) -- "
                                f"incercare/scanare esuata, fara confirmare ca fisierul exista sau a fost executat.")
                _add_finding(result, "webshell_path", {
                    "severity": _wsev,
                    "confidence": "high",
                    "rule": _wrule,
                    "reason": _wreason,
                    "detail": f"IP {ip}: {method} {path_raw} -> {status} la {tstr}",
                    "ip": ip, "time": tstr, "domain": _dom(line_start),
                    "evidence": {"ip": ip, "method": method, "path": path_raw,
                                 "status": status, "time": tstr},
                })
                _log_admin(ip, "Fisier .php in uploads/cache (posibil webshell)", tstr, method, path_raw, status, _dom(line_start))
            elif "/wp-" in path_low and STATIC_ASSET_PHP_DISGUISE_RE.search(path_low):
                if _webshell_is_2xx:
                    _wsev, _wrule = "CRITICAL", "Fisier .php deghizat ca asset static -- SERVIT cu succes (webshell activ)"
                    _wreason = (f"Un fisier .php dintr-un folder WordPress rezervat strict assets-urilor statice "
                                f"(css/js/imagini/fonturi) a fost EFECTIV SERVIT cu succes (status {status}) -- "
                                f"dovada puternica de webshell activ, nu doar o cerere.")
                else:
                    _wsev, _wrule = "HIGH", "Fisier .php deghizat ca asset static -- incercare (posibil webshell)"
                    _wreason = (f"Cerere catre un fisier .php intr-un folder WordPress rezervat strict assets-urilor "
                                f"statice (tehnica de deghizare a unui webshell), dar serverul NU a raspuns cu "
                                f"succes (status {status}) -- incercare/scanare esuata, fara confirmare de executie.")
                _add_finding(result, "webshell_asset_disguise", {
                    "severity": _wsev,
                    "confidence": "high",
                    "rule": _wrule,
                    "reason": _wreason,
                    "detail": f"IP {ip}: {method} {path_raw} -> {status} la {tstr}",
                    "ip": ip, "time": tstr, "domain": _dom(line_start),
                    "evidence": {"ip": ip, "method": method, "path": path_raw,
                                 "status": status, "time": tstr},
                })
                _log_admin(ip, "Fisier .php deghizat ca asset static (posibil webshell)", tstr, method, path_raw, status, _dom(line_start))

            if "admin-ajax.php" in path_low and FILE_MGR_ACTIONS.search(path_raw):
                _add_finding(result, "ajax", {
                    "severity": "MEDIUM",
                    "confidence": "medium",
                    "rule": "admin-ajax.php cu actiune de upload/file manager",
                    "reason": "Actiune AJAX care poate accepta upload de fisiere (file manager/plugin "
                              "upload) -- normala daca vine de la un administrator autentificat, dar un "
                              "canal cunoscut de plasare a unui webshell daca nu e cazul.",
                    "detail": f"IP {ip}: {path_raw} -> {status} la {tstr}",
                    "ip": ip, "time": tstr, "domain": _dom(line_start),
                    "evidence": {"ip": ip, "method": method, "path": path_raw,
                                 "status": status, "time": tstr},
                })
                _log_admin(ip, "admin-ajax: upload/file manager", tstr, method, path_raw, status, _dom(line_start))

            # --- Pattern-uri suspecte (filtru rapid, vezi docstring) ---
            # Calculat O SINGURA DATA (_suspicious_match_name) si refolosit si
            # pentru findings si pentru randul de triaj de mai jos.
            _rq = _refq_memo.get(referer)
            if _rq is None:
                _rq = bool(SUSPICIOUS_QUICK_RE.search((referer or "").lower()))
                if len(_refq_memo) < _MEMO_CAP:
                    _refq_memo[referer] = _rq
            # filtrul rapid (path SAU referer) e exact cel din
            # _suspicious_match_name; potrivirea completa doar pe liniile rare.
            _susp = _suspicious_match_name(path_low, path_raw, referer) if (_pm_suspq or _rq) else None
            if _susp:
                name = _susp
                # SQLi confirmat (union/error-blind/time-blind/exfil) e
                # CRITICAL, nu HIGH -- potrivire directa pe o semnatura de
                # exploatare DB, acelasi nivel ca un webshell confirmat.
                sev = pattern_severity(name, status)
                _add_finding(result, f"pattern_{name}", {
                    "severity": sev,
                    "confidence": "high",
                    "rule": f"Pattern suspect: {name}",
                    "reason": f"Path-ul sau referer-ul contine un tipar cunoscut de atac ({name}) -- "
                              f"potrivire directa de regex pe o semnatura de exploatare (SQLi/LFI-RFI/"
                              f"nume de webshell cunoscut), nu doar volum sau trafic neobisnuit.",
                    "detail": f"IP {ip}: {method} {path_raw} -> {status} la {tstr}",
                    "ip": ip, "time": tstr, "domain": _dom(line_start),
                    "evidence": {"ip": ip, "method": method, "path": path_raw,
                                 "status": status, "time": tstr, "pattern": name},
                })

            # --- Rand de index de triaj, in ACEEASI trecere (v43.2) ---
            # Inainte era o a doua trecere completa prin fisier (re-citire,
            # re-parsare, geoip per linie): +70s pe logul real. Acum refolosim
            # tot ce am calculat deja mai sus pentru linia asta.
            if shard is not None:
                _cc = _cc_memo.get(ip)
                if _cc is None:
                    _cc = _cc_memo[ip] = (country_of(ip) or "")
                _nonro = 1 if (_cc and _cc != "RO") else 0
                _ck = (method, path_raw, status, _nonro, _susp)
                _cls = _cls_memo.get(_ck)
                if _cls is None:
                    _cls = classify_event_pre(
                        method, path_raw, path_low, path_only, status, bool(_nonro), _susp, _scan_sig)
                    if len(_cls_memo) < _MEMO_CAP:
                        _cls_memo[_ck] = _cls
                _sev, _risk, _act, _lbl = _cls
                # epoch = baza orei (memo, calendar.timegm o data pe ora) +
                # mm*60+ss -- exact acelasi rezultat ca _fast_epoch(tstr),
                # timegm fiind liniar in minute/secunde; ~10x mai ieftin.
                _hk = tstr[:14] + tstr[20:26]
                _hb = _hour_epoch_memo.get(_hk)
                if _hb is None:
                    _hb = _hour_epoch_memo[_hk] = _fast_epoch(tstr[:15] + "00:00" + tstr[20:])
                try:
                    _ts_epoch = (_hb + int(tstr[15:17]) * 60 + int(tstr[18:20])) if _hb else _fast_epoch(tstr)
                except ValueError:
                    _ts_epoch = _fast_epoch(tstr)
                _uid = _ua_ids.get(ua)
                if _uid is None:
                    _uid = _ua_ids[ua] = _ua_base | len(_ua_ids)
                shard_rows.append((
                    _ts_epoch, tstr, ip, _cc, _nonro, method, path_raw, status, size,
                    _uid, referer, _sev, _risk, _act, _lbl, _dom(line_start) or "",
                    line_start, pos,
                ))
                if _colc is not None:
                    _colc.add(_ts_epoch, ip, _cc, method, path_raw, status, size, _uid - _ua_base,
                              _cls, day, line_start, pos - line_start)
                if len(shard_rows) >= 50000:
                    shard.executemany(_shard_sql, shard_rows)
                    shard_n += len(shard_rows)
                    shard_rows = []

    if shard is not None:
        try:
            if shard_rows:
                shard.executemany(_shard_sql, shard_rows)
                shard_n += len(shard_rows)
            shard.executemany("INSERT INTO uas (id, ua) VALUES (?, ?)", [(i, u) for u, i in _ua_ids.items()])
            shard.commit()
        finally:
            shard.close()
        _cols_path = None
        if _colc is not None:
            try:
                _cols_path = _colc.save(shard_path + ".cols.pkl", list(_ua_ids))
            except Exception:
                _cols_path = None   # indexul columnar e optional: fara el, calea SQL
            _colc = None
        result["_shard"] = (shard_path, shard_n, _cols_path)
    result["total"] = total
    result["bad"] = bad
    result["bandwidth"] = bandwidth
    for ip, fl in _chunk_claim_first_last.items():
        claim_ip_time_range[ip].append(fl)
    return result


def _scan_chunk_raw(args):
    """Worker paralel pentru drill-down: scaneaza un byte-range si intoarce
    (matches, hit_cap). hit_cap=True daca s-a oprit din cauza plafonului
    (nu pentru ca a ajuns la finalul chunk-ului) -- folosit pentru flag-ul
    'truncated' din raspuns."""
    (path, start, end, ip, subnet_prefix, path_filter, day_filter, cap,
     burst_key, sig_filter, hour_filter, minute_filter, ua_filter, second_filter,
     qkey_re, country_filter, identity_filter) = args[:17]
    # 18-lea element optional: o lista/generator de (start, end) -- liniile
    # pre-selectate din indexul de triaj (vezi api_raw). Predicatul de mai jos
    # ramane IDENTIC; indexul doar evita citirea liniilor care sigur nu trec.
    ranges = args[17] if len(args) > 17 and args[17] is not None else ((start, end),)
    matches = []
    hit_cap = False
    with open(path, "rb") as f:
      for start, end in ranges:
        if hit_cap:
            break
        f.seek(start)
        pos = start
        while pos < end:
            if len(matches) >= cap:
                hit_cap = True
                break
            raw_line = f.readline()
            if not raw_line:
                break
            pos = f.tell()
            line = raw_line.decode("utf-8", errors="replace")
            rec = parse_line_fast(line)
            if rec is None:
                continue
            rip, method, praw, status, referer, ua, tstr, _size = rec
            if ip and rip != ip:
                continue
            if subnet_prefix and not subnet_matches(rip, subnet_prefix):
                continue
            if path_filter and path_filter not in praw:
                continue
            if day_filter and day_of(tstr) != day_filter:
                continue
            if burst_key and burst_key_of(tstr) != burst_key:
                continue
            if hour_filter and hour_of(tstr) != hour_filter:
                continue
            if minute_filter is not None:
                # minute_filter = (start_minute, span_minutes) -- span=1 e
                # "minut exact", span=10/30 e un interval (ex: [20,30) ),
                # calculat DOAR cu slicing pe string, fara strptime.
                if len(tstr) < 17:
                    continue
                mtxt = tstr[15:17]
                if not mtxt.isdigit():
                    continue
                mnum = int(mtxt)
                mstart, mspan = minute_filter
                if not (mstart <= mnum < mstart + mspan):
                    continue
            if sig_filter and scan_signature_of(praw.lower()) != sig_filter:
                continue
            if ua_filter and ua != ua_filter:
                continue
            if qkey_re is not None:
                qpos = praw.find("?")
                if qpos == -1 or not qkey_re.search(praw[qpos:]):
                    continue
            if country_filter is not None:
                # country_of() e rapid (geoip2fast offline, ~150k lookup-uri
                # in 0.65s masurat) -- ok sa-l calculam per-linie AICI pentru
                # ca /raw e deja un endpoint on-demand, scanat pe cerere,
                # NU parte din trecerea de upload (vezi comentariul din task).
                # Sentinela "__NON_RO__" (Eduard, cardul RO vs restul lumii):
                # "orice tara AFARA de RO", nu un cod exact de 2 litere --
                # foloseste la scoperea drill-down-ului de identitate pe
                # partea NON-RO a cardului (vezi identity_filter mai jos).
                if country_filter == "__NON_RO__":
                    # v44: "non-RO" = tara CUNOSCUTA si diferita de RO -- un IP
                    # nedeterminat nu e atribuit nicaieri (aceeasi semantica
                    # ca indexul de triaj si sinteza; inainte era numarat
                    # aici ca non-RO, dar nu si in index => cifre diferite).
                    _cc_r = (country_of(rip) or "").upper()
                    if not _cc_r or _cc_r == "RO":
                        continue
                elif country_filter == "??":
                    # Sentinela "??" (folosita si in country_totals/ro_vs_world
                    # pentru IP-uri unde GeoIP nu a putut rezolva nicio tara --
                    # vezi build_summary) -- country_of() intoarce "" (string
                    # gol) pentru aceste IP-uri, NU literalul "??". Fara acest
                    # branch, "??" nu se potrivea NICIODATA cu country_of(rip),
                    # deci drill-down-ul pe randul "??" din tabele returna
                    # mereu 0 rezultate (bug raportat de Eduard).
                    if country_of(rip):
                        continue
                elif (country_of(rip) or "").upper() != country_filter:
                    continue
            if identity_filter is not None:
                # identity: filtreaza cererile brute a caror UA REVENDICA
                # (Tier 1, classify_crawler_claim) identitatea data -- click
                # pe un rand din bar chart-ul "Compus din (identitate)" al
                # cardului RO vs restul lumii. Sentinela "__none__" = liniile
                # FARA nicio revendicare de identitate cunoscuta (bara "Fara
                # identitate cunoscuta"). Match case-insensitiv, calculat per
                # linie (acelasi cost ca country_of() de mai sus -- endpoint
                # deja on-demand).
                claim = classify_crawler_claim(ua)
                if identity_filter == "__none__":
                    if claim:
                        continue
                elif (claim or "").lower() != identity_filter:
                    continue
            if second_filter is not None:
                # cautare exacta pe timestamp +/- fereastra (in secunde), cerute
                # din UI-ul "Vezi cererile dintr-un moment exact" cand e completat
                # campul de ora exacta (HH:MM:SS). Calculat DOAR prin slicing pe
                # string (fara strptime), la fel ca burst_key_of/minute_filter mai
                # sus -- ramane ieftin in bucla per-linie.
                if len(tstr) < 20:
                    continue
                hh_tok, mm_tok, ss_tok = tstr[12:14], tstr[15:17], tstr[18:20]
                if not (hh_tok.isdigit() and mm_tok.isdigit() and ss_tok.isdigit()):
                    continue
                line_seconds = int(hh_tok) * 3600 + int(mm_tok) * 60 + int(ss_tok)
                target_seconds, window_seconds = second_filter
                if abs(line_seconds - target_seconds) > window_seconds:
                    continue
            matches.append({
                "time": tstr, "ip": rip, "method": method, "path": praw,
                "status": status, "referer": referer, "ua": ua,
                "raw": line.rstrip("\n"),
            })
    return matches, hit_cap


# ==========================================================================
# Explorator de loguri (Eduard): panou separat -- alegi o zi + o marime de
# fereastra (30s/60s/10min), combini oricate din cele ~11 filtre de mai jos,
# si aplicatia iti scoate TOATE ferestrele cu cel putin o cerere care trece
# de filtre, ca sa poti sorta dupa cereri/IP-uri unice/cele mai vechi/cele
# mai noi si sa dai click pe orice fereastra ca sa vezi liniile brute
# complete pentru EXACT acel interval + aceleasi filtre.
#
# Implementare DELIBERAT separata de _scan_chunk_raw/api_raw de mai sus (NU
# adaugam campuri noi in tuplul pozitional al lui _scan_chunk_raw) -- exact
# ca sa nu repetam bug-ul deja reparat in aceasta sesiune (burst_raw trimitea
# un tuplu cu un camp lipsa fata de semnatura lui _scan_chunk_raw, cauzand
# "not enough values to unpack"). Filtrele de-aici sunt un DICT cu chei
# explicite (nu o pozitie intr-un tuplu) -- o cheie lipsa/gresita da rezultat
# gresit vizibil imediat la testare, nu un crash silentios greu de gasit.
# ==========================================================================
_SUSPICIOUS_PATTERNS_BY_NAME = dict(SUSPICIOUS_PATTERNS)
_STATUS_CLASS_MAP = {"2xx": 2, "3xx": 3, "4xx": 4, "5xx": 5}


def _window_line_matches(rip, method_, praw, status, referer, ua, filters):
    """True daca linia (deja parsata) trece de TOATE filtrele active din
    `filters` (dict) -- orice cheie absenta/None inseamna "fara acest
    filtru". Oglindeste filtrele deja existente in _scan_chunk_raw (ip/
    subnet/path/qkey/country/identity), plus cateva noi (status/metoda/
    are-query/referer-gol/semnatura-de-atac) cerute pentru Explorator."""
    if filters.get("ip") and rip != filters["ip"]:
        return False
    if filters.get("subnet_prefix") and not subnet_matches(rip, filters["subnet_prefix"]):
        return False
    if filters.get("path_filter") and filters["path_filter"] not in praw:
        return False
    if filters.get("method") and method_.upper() != filters["method"]:
        return False
    if filters.get("status_class") is not None and (status // 100) != filters["status_class"]:
        return False
    if filters.get("status_exact") is not None and status != filters["status_exact"]:
        return False
    if filters.get("ua_filter") and filters["ua_filter"] not in ua.lower():
        return False
    if filters.get("has_query") is not None:
        if ("?" in praw) != filters["has_query"]:
            return False
    if filters.get("referer_empty") is not None:
        r_empty = (not referer) or referer == "-"
        if r_empty != filters["referer_empty"]:
            return False
    if filters.get("qkey_re") is not None:
        qpos = praw.find("?")
        if qpos == -1 or not filters["qkey_re"].search(praw[qpos:]):
            return False
    if filters.get("country_filter") is not None:
        cf = filters["country_filter"]
        if cf == "__NON_RO__":
            _cc_r = (country_of(rip) or "").upper()
            if not _cc_r or _cc_r == "RO":   # nedeterminat != non-RO (v44)
                return False
        elif cf == "??":
            if country_of(rip):
                return False
        elif (country_of(rip) or "").upper() != cf:
            return False
    if filters.get("identity_filter") is not None:
        claim = classify_crawler_claim(ua)
        idf = filters["identity_filter"]
        if idf == "__none__":
            if claim:
                return False
        elif (claim or "").lower() != idf:
            return False
    if filters.get("ip_set") is not None and rip not in filters["ip_set"]:
        return False
    if filters.get("ua_category") is not None and classify_ua(ua) != filters["ua_category"]:
        return False
    if filters.get("pattern_name") is not None:
        # acelasi filtru rapid ca motorul principal (vezi _process_chunk) --
        # fara el, "orice atac" pe tot fisierul rula toate regex-urile pe
        # fiecare linie
        if not (SUSPICIOUS_QUICK_RE.search(praw.lower()) or
                (referer and SUSPICIOUS_QUICK_RE.search(referer.lower()))):
            return False
        full = unquote(praw) + " " + unquote(referer or "")
        pname = filters["pattern_name"]
        if pname == "any_attack":
            if not any(p.search(full) for _, p in SUSPICIOUS_PATTERNS):
                return False
        else:
            pat = _SUSPICIOUS_PATTERNS_BY_NAME.get(pname)
            if pat is None or not pat.search(full):
                return False
    return True


def _seconds_to_hhmmss(s):
    s = int(s) % 86400
    return f"{s // 3600:02d}:{(s % 3600) // 60:02d}:{s % 60:02d}"


def _parse_window_filters(ip, subnet, path, method, status_class, status, ua, has_query,
                           referer_empty, country, identity, pattern, qkey, ua_category=""):
    """Traduce query-params-urile brute (toate string-uri, toate optionale)
    intr-un dict de filtre gata de folosit in _window_line_matches -- o
    cheie e prezenta DOAR daca userul chiar a completat filtrul respectiv."""
    subnet_prefix = normalize_subnet_filter(subnet)
    filters = {}
    if ip and ip.strip():
        filters["ip"] = ip.strip()
    if subnet_prefix:
        filters["subnet_prefix"] = subnet_prefix
    if path and path.strip():
        filters["path_filter"] = path.strip()
    if method and method.strip():
        filters["method"] = method.strip().upper()
    if status_class and status_class.strip():
        sc = _STATUS_CLASS_MAP.get(status_class.strip().lower())
        if sc:
            filters["status_class"] = sc
    if status and status.strip():
        try:
            filters["status_exact"] = int(status.strip())
        except ValueError:
            pass
    if ua and ua.strip():
        filters["ua_filter"] = ua.strip().lower()
    if has_query and has_query.strip().lower() in ("true", "false"):
        filters["has_query"] = has_query.strip().lower() == "true"
    if referer_empty and referer_empty.strip().lower() in ("true", "false"):
        filters["referer_empty"] = referer_empty.strip().lower() == "true"
    if qkey and qkey.strip():
        filters["qkey_re"] = re.compile(r"(?:^|[?&])" + re.escape(qkey.strip()) + r"=")
    if country and country.strip():
        _c = country.strip()
        _cn = normalize_country_value(_c)
        if _cn is None:
            raise ValueError(f"Tara '{_c}' nu e recunoscuta -- foloseste codul ISO din 2 litere (ex. RO, DE), "
                             f"'??' pentru tara nedeterminata sau __non_ro__.")
        filters["country_filter"] = "??" if _cn == "" else _cn
    if identity and identity.strip():
        filters["identity_filter"] = identity.strip().lower()
    if pattern and pattern.strip():
        filters["pattern_name"] = pattern.strip()
    if ua_category and ua_category.strip():
        filters["ua_category"] = ua_category.strip()
    return filters


def _fake_crawler_ips(dataset_id, identity=""):
    """IP-urile care revendica o identitate de crawler (optional doar una
    anume) dar au PICAT verificarea DNS (verified False = PTR lipsa/gresit
    sau forward-confirm esuat). Folosit de filtrul crawler_fake."""
    idl = (identity or "").strip().lower()
    with _CRAWLER_JOBS_LOCK:
        job = _CRAWLER_JOBS.get(dataset_id)
        results = dict(job["results"]) if job else {}
    return {ip for ip, r in results.items()
            if r.get("verified") is False and (not idl or (r.get("identity") or "").lower() == idl)}


def _scan_chunk_windows(args):
    """Worker paralel: scaneaza un byte-range, aplica filtrele combinate
    (_window_line_matches) si grupeaza liniile care trec in ferestre de
    `window_seconds` secunde (bucket = floor(secunda-din-zi / window_seconds)),
    numarand cereri + IP-uri unice per fereastra. NU colecteaza liniile brute
    (vezi _scan_chunk_window_raw pentru asta cand userul da click pe o
    fereastra anume) -- raspunsul ramane mic indiferent cate cereri se
    potrivesc filtrelor.
    In ACELASI pas (Eduard: 'o rubrica cu procentaj user agent / crawler' +
    'o rubrica cu procentaje subnets') agregam si doua Counter-e globale
    (nu per-fereastra) pe TOATE liniile care trec de filtre -- categoria
    User-Agent/crawler (classify_ua, acelasi catalog ca 'Boti & crawlere')
    si subnetul /16 (subnet16_of). Cost neglijabil: se calculeaza doar pentru
    liniile deja retinute de filtre, nu pentru fiecare linie din fisier."""
    path, start, end, day_filter, window_seconds, filters = args
    buckets = {}  # bucket_start_seconds -> {"requests": int, "ips": set(...)}
    ua_counter = Counter()
    subnet_counter = Counter()
    with open(path, "rb") as f:
        f.seek(start)
        pos = start
        while pos < end:
            raw_line = f.readline()
            if not raw_line:
                break
            pos = f.tell()
            line = raw_line.decode("utf-8", errors="replace")
            rec = parse_line_fast(line)
            if rec is None:
                continue
            rip, method_, praw, status, referer, ua, tstr, _size = rec
            if day_filter and day_of(tstr) != day_filter:
                continue
            if len(tstr) < 20:
                continue
            hh_tok, mm_tok, ss_tok = tstr[12:14], tstr[15:17], tstr[18:20]
            if not (hh_tok.isdigit() and mm_tok.isdigit() and ss_tok.isdigit()):
                continue
            if not _window_line_matches(rip, method_, praw, status, referer, ua, filters):
                continue
            secs = int(hh_tok) * 3600 + int(mm_tok) * 60 + int(ss_tok)
            bucket_start = (secs // window_seconds) * window_seconds
            b = buckets.get(bucket_start)
            if b is None:
                b = {"requests": 0, "ips": set()}
                buckets[bucket_start] = b
            b["requests"] += 1
            b["ips"].add(rip)
            ua_counter[classify_ua(ua)] += 1
            subnet_counter[subnet16_of(rip) or "IPv6"] += 1
    return buckets, ua_counter, subnet_counter


def _merge_windows(results, window_seconds):
    """`results` = lista de (buckets, ua_counter, subnet_counter) -- cate un
    tuplu per chunk (vezi _scan_chunk_windows). Intoarce (windows, ua_total,
    subnet_total)."""
    merged = {}
    ua_total = Counter()
    subnet_total = Counter()
    for buckets, ua_counter, subnet_counter in results:
        for bucket_start, b in buckets.items():
            m = merged.get(bucket_start)
            if m is None:
                m = {"requests": 0, "ips": set()}
                merged[bucket_start] = m
            m["requests"] += b["requests"]
            m["ips"] |= b["ips"]
        ua_total.update(ua_counter)
        subnet_total.update(subnet_counter)
    out = []
    for bucket_start, b in merged.items():
        out.append({
            "bucket_start_seconds": bucket_start,
            "start_label": _seconds_to_hhmmss(bucket_start),
            "end_label": _seconds_to_hhmmss(bucket_start + window_seconds),
            "requests": b["requests"],
            "unique_ips": len(b["ips"]),
            "unique_ip_ratio": round(len(b["ips"]) / b["requests"], 3) if b["requests"] else 0,
        })
    return out, ua_total, subnet_total


def _scan_chunk_window_raw(args):
    """La fel ca _scan_chunk_raw, dar scopat la o SINGURA fereastra exacta
    (bucket_start .. bucket_start+window_seconds) + filtrele combinate din
    Explorator -- folosit de butonul "vezi tot" de pe o fereastra anume."""
    path, start, end, day_filter, window_seconds, bucket_start, filters, cap = args
    bucket_end = bucket_start + window_seconds
    matches = []
    hit_cap = False
    with open(path, "rb") as f:
        f.seek(start)
        pos = start
        while pos < end:
            if len(matches) >= cap:
                hit_cap = True
                break
            raw_line = f.readline()
            if not raw_line:
                break
            pos = f.tell()
            line = raw_line.decode("utf-8", errors="replace")
            rec = parse_line_fast(line)
            if rec is None:
                continue
            rip, method_, praw, status, referer, ua, tstr, _size = rec
            if day_filter and day_of(tstr) != day_filter:
                continue
            if len(tstr) < 20:
                continue
            hh_tok, mm_tok, ss_tok = tstr[12:14], tstr[15:17], tstr[18:20]
            if not (hh_tok.isdigit() and mm_tok.isdigit() and ss_tok.isdigit()):
                continue
            secs = int(hh_tok) * 3600 + int(mm_tok) * 60 + int(ss_tok)
            if not (bucket_start <= secs < bucket_end):
                continue
            if not _window_line_matches(rip, method_, praw, status, referer, ua, filters):
                continue
            matches.append({
                "time": tstr, "ip": rip, "method": method_, "path": praw,
                "status": status, "referer": referer, "ua": ua,
                "raw": line.rstrip("\n"),
            })
    return matches, hit_cap


def _scan_chunk_ip_detail(args):
    """Worker paralel pentru panoul de detaliu per-IP (Faza 3) -- la fel ca
    _scan_chunk_raw (acelasi tipar de scanare paralela pe byte-range, scoped
    strict la un IP), dar in loc sa colecteze liniile brute, AGREGA direct in
    worker (total cereri, bandwidth, path-uri unice, status/metode, prima/
    ultima vazuta) -- raspunsul ramane mic (nu creste cu numarul de cereri
    ale IP-ului), fara sa tina nicio linie bruta in memorie. Scanarea insasi
    NU se face niciodata la upload -- doar la deschiderea panoului (vezi
    /api/dataset/{id}/ip_detail), deci nu afecteaza bugetul de upload."""
    path, start, end, ip, day_filter = args
    count = 0
    bandwidth = 0
    paths = Counter()
    status_counter = Counter()
    methods = Counter()
    first = None
    last = None
    with open(path, "rb") as f:
        f.seek(start)
        pos = start
        while pos < end:
            raw_line = f.readline()
            if not raw_line:
                break
            pos = f.tell()
            line = raw_line.decode("utf-8", errors="replace")
            rec = parse_line_fast(line)
            if rec is None:
                continue
            rip, method, praw, status, referer, ua, tstr, size = rec
            if rip != ip:
                continue
            if day_filter and day_of(tstr) != day_filter:
                continue
            count += 1
            bandwidth += size
            path_only = praw.split("?", 1)[0]
            # plafon defensiv -- un IP cu o coada enorma de path-uri unice
            # (scan foarte agresiv) nu trebuie sa umple memoria workerului;
            # dupa prag, restul cererilor tot conteaza la total/bandwidth,
            # doar nu mai adauga path-uri NOI in top (Counter-ul deja existent
            # tot se incrementeaza normal pentru path-uri deja vazute).
            if path_only in paths or len(paths) < 5000:
                paths[path_only] += 1
            status_counter[status] += 1
            methods[method] += 1
            if first is None or tstr < first:
                first = tstr
            if last is None or tstr > last:
                last = tstr
    return {
        "count": count, "bandwidth": bandwidth, "paths": paths,
        "status": status_counter, "methods": methods, "first": first, "last": last,
    }


def _scan_chunk_country_subnets(args):
    """Worker paralel pentru 'Sa vad subneturile ? care il alcatuiesc?'
    (Eduard) -- acelasi tipar de scanare paralela pe byte-range ca
    _scan_chunk_raw/_scan_chunk_ip_detail, scopat la o singura tara (sau la
    sentinela '??' = IP-uri neresolvate de geoip -- vezi exact aceeasi
    logica ca in _scan_chunk_raw, unde a fost deja depanat bug-ul "??").
    Agrega direct in worker pe subnet /24 (cereri + IP-uri unice), NU
    colecteaza liniile brute -- raspunsul ramane mic. Ruleaza DOAR la
    cerere (click pe o tara in cardul RO vs restul lumii / tabelul de
    tari), niciodata la upload."""
    path, start, end, country_filter, day_filter = args
    subnet_reqs = Counter()
    subnet_ips = defaultdict(set)
    with open(path, "rb") as f:
        f.seek(start)
        pos = start
        while pos < end:
            raw_line = f.readline()
            if not raw_line:
                break
            pos = f.tell()
            line = raw_line.decode("utf-8", errors="replace")
            rec = parse_line_fast(line)
            if rec is None:
                continue
            rip, method, praw, status, referer, ua, tstr, size = rec
            if day_filter and day_of(tstr) != day_filter:
                continue
            if country_filter == "??":
                # Vezi comentariul identic din _scan_chunk_raw: country_of()
                # intoarce "" (nu literalul "??") pentru IP-uri neresolvate.
                if country_of(rip):
                    continue
            elif (country_of(rip) or "").upper() != country_filter:
                continue
            # subnet_key_of: /24 pentru IPv4, /64 pentru IPv6 -- vezi
            # comentariul de la ipv6_subnet64_of (fara asta, bucketul "??"
            # -- majoritar IPv6 -- ar disparea aproape complet din raspuns).
            subnet = subnet_key_of(rip)
            if not subnet:
                continue
            subnet_reqs[subnet] += 1
            # plafon defensiv, la fel ca in _scan_chunk_ip_detail -- dupa
            # prag, cererile tot conteaza in subnet_reqs, doar setul de
            # IP-uri unice nu mai creste nelimitat pentru un subnet foarte
            # activ.
            if rip in subnet_ips[subnet] or len(subnet_ips[subnet]) < 2000:
                subnet_ips[subnet].add(rip)
    return {
        "subnet_reqs": subnet_reqs,
        "subnet_ips": {k: v for k, v in subnet_ips.items()},
    }


def _path_breakdown_new_bucket():
    """Factory picklabila pentru un bucket (copil sau exact-match) din
    path-breakdown. Vezi _scan_chunk_path_breakdown."""
    return {
        "count": 0, "ips": set(), "status": Counter(), "bytes": 0,
        "first": None, "last": None, "with_query": 0, "has_children": False,
    }


def _path_breakdown_update(bucket, rip, status, size, tstr, has_query):
    bucket["count"] += 1
    bucket["ips"].add(rip)
    bucket["status"][status // 100] += 1  # 2/3/4/5 (xx)
    bucket["bytes"] += size
    if has_query:
        bucket["with_query"] += 1
    # min/max PE STRING, la fel ca alte comparatii ieftine din acest fisier
    # (day_of/hour_of prin slicing) -- e corect atata timp cat bucket-ul nu
    # traverseaza mai multe luni diferite (caz uzual pentru un singur upload
    # de log); nu facem strptime in hot loop (vezi comentariul de la
    # minute_filter din _scan_chunk_raw pentru acelasi principiu).
    if bucket["first"] is None or tstr < bucket["first"]:
        bucket["first"] = tstr
    if bucket["last"] is None or tstr > bucket["last"]:
        bucket["last"] = tstr


def _scan_chunk_path_breakdown(args):
    """Worker paralel pentru Path Explorer (drill-down ierarhic): scaneaza un
    byte-range si agrega DOAR liniile al caror path_only incepe cu `prefix`,
    grupate pe segmentul de path IMEDIAT URMATOR lui `prefix` (un singur
    nivel mai adanc -- nu tot path-ul ramas).

    IMPORTANT (vezi cerinta lui Eduard): gruparea se face pe path_only
    (path-ul din URL, FARA query string) -- niciodata pe path_raw brut cu
    query string inclus. Doua cereri catre acelasi path cu query string-uri
    diferite (parametri de tracking, filtre fatetate etc.) cad in ACELASI
    bucket -- exact scopul feature-ului (elimina zgomotul de query string
    din structura de path). Semnalul "avea query string sau nu" nu se
    pierde insa -- e numarat separat per bucket (`with_query`), ca semnal
    suplimentar de abuz de parametri/navigare fatetata.

    Returneaza un dict cu:
      children: {child_path: bucket}  -- bucket-uri UN nivel mai adanc
      exact: bucket  -- liniile al caror path_only == prefix (sau prefix
             cu "/" final, fara nimic dupa) -- "fara sub-segment"
    """
    (path, start, end, prefix, day_filter, hour_filter, minute_filter, second_filter) = args
    children = defaultdict(_path_breakdown_new_bucket)
    exact = _path_breakdown_new_bucket()

    is_root = prefix in ("", "/")
    prefix_norm = "" if is_root else prefix.rstrip("/")

    with open(path, "rb") as f:
        f.seek(start)
        pos = start
        while pos < end:
            raw_line = f.readline()
            if not raw_line:
                break
            pos = f.tell()
            line = raw_line.decode("utf-8", errors="replace")
            rec = parse_line_fast(line)
            if rec is None:
                continue
            rip, method, praw, status, referer, ua, tstr, size = rec
            if day_filter and day_of(tstr) != day_filter:
                continue
            # BUG raportat de Eduard ("clasificarea pe ore"): Path Explorer-ul
            # nu aplica NICIODATA scoparea pe ora/minut/secunda aleasa in
            # widgetul "Vezi cererile dintr-un moment exact" -- doar ziua. Daca
            # userul bifeaza ora 20 si apasa "Statistici pe interval", apoi
            # exploreaza un prefix de path, breakdown-ul (si liniile brute
            # deschise din el) veneau din ZIUA INTREAGA, nu din ora 20 -- de-aici
            # liniile din alta ora (15) aparute in loc de cele asteptate.
            # Acelasi tipar de filtrare ca in _scan_chunk_raw (slicing pe
            # string, fara strptime, ca sa ramana ieftin in bucla per-linie).
            if hour_filter and hour_of(tstr) != hour_filter:
                continue
            if minute_filter is not None:
                if len(tstr) < 17:
                    continue
                mtxt = tstr[15:17]
                if not mtxt.isdigit():
                    continue
                mnum = int(mtxt)
                mstart, mspan = minute_filter
                if not (mstart <= mnum < mstart + mspan):
                    continue
            if second_filter is not None:
                if len(tstr) < 20:
                    continue
                hh_tok, mm_tok, ss_tok = tstr[12:14], tstr[15:17], tstr[18:20]
                if not (hh_tok.isdigit() and mm_tok.isdigit() and ss_tok.isdigit()):
                    continue
                line_seconds = int(hh_tok) * 3600 + int(mm_tok) * 60 + int(ss_tok)
                target_seconds, window_seconds = second_filter
                if abs(line_seconds - target_seconds) > window_seconds:
                    continue

            qpos = praw.find("?")
            path_only = praw[:qpos] if qpos != -1 else praw
            has_query = qpos != -1

            if not is_root:
                if path_only == prefix_norm:
                    remainder = ""
                elif path_only.startswith(prefix_norm + "/"):
                    remainder = path_only[len(prefix_norm):]
                else:
                    continue  # nu se potriveste cu prefixul -- ignorat
            else:
                if not path_only.startswith("/"):
                    continue
                remainder = path_only

            if remainder in ("", "/"):
                _path_breakdown_update(exact, rip, status, size, tstr, has_query)
                continue

            # remainder incepe mereu cu "/" aici (fie ramas din prefix,
            # fie path_only intreg la radacina)
            sub = remainder[1:]
            slash_idx = sub.find("/")
            if slash_idx == -1:
                next_seg = sub
                rest_after = ""
            else:
                next_seg = sub[:slash_idx]
                rest_after = sub[slash_idx + 1:]
            if not next_seg:
                # segment gol (ex: "//" in path) -- trateaza ca exact-match
                # ca sa nu produca un bucket "fantoma"
                _path_breakdown_update(exact, rip, status, size, tstr, has_query)
                continue

            child_path = (prefix_norm + "/" + next_seg) if not is_root else ("/" + next_seg)
            bucket = children[child_path]
            _path_breakdown_update(bucket, rip, status, size, tstr, has_query)
            if rest_after != "":
                bucket["has_children"] = True

    return {"children": dict(children), "exact": exact}


def _merge_path_breakdown_bucket(dst, src):
    dst["count"] += src["count"]
    dst["ips"] |= src["ips"]
    dst["status"].update(src["status"])
    dst["bytes"] += src["bytes"]
    dst["with_query"] += src["with_query"]
    dst["has_children"] = dst["has_children"] or src["has_children"]
    if src["first"] is not None and (dst["first"] is None or src["first"] < dst["first"]):
        dst["first"] = src["first"]
    if src["last"] is not None and (dst["last"] is None or src["last"] > dst["last"]):
        dst["last"] = src["last"]


def _merge_path_breakdown(results):
    merged_children = defaultdict(_path_breakdown_new_bucket)
    merged_exact = _path_breakdown_new_bucket()
    for r in results:
        for child_path, bucket in r["children"].items():
            _merge_path_breakdown_bucket(merged_children[child_path], bucket)
        _merge_path_breakdown_bucket(merged_exact, r["exact"])
    return merged_children, merged_exact


def _merge_partials(results):
    merged = _new_partial()
    for r in results:
        merged["total"] += r["total"]
        merged["bad"] += r["bad"]
        merged["blank"] += r.get("blank", 0)
        if len(merged["bad_samples"]) < 5:
            merged["bad_samples"].extend(r.get("bad_samples", [])[:5 - len(merged["bad_samples"])])
        merged["ip_counter"].update(r["ip_counter"])
        merged["ua_counter"].update(r["ua_counter"])
        merged["status_counter"].update(r["status_counter"])
        merged["top_paths"].update(r["top_paths"])
        merged["method_counter"].update(r["method_counter"])
        merged["filter_ip_hits"].update(r["filter_ip_hits"])
        for p, ips in r["dist_path_ips"].items():
            merged["dist_path_ips"][p] |= ips
        merged["dist_path_count"].update(r["dist_path_count"])
        merged["path_prefix_counter"].update(r["path_prefix_counter"])
        merged["path_prefix_bandwidth"].update(r["path_prefix_bandwidth"])
        for p, ips in r["path_prefix_ips"].items():
            merged["path_prefix_ips"][p] |= ips
        merged["path_facet_count"].update(r["path_facet_count"])
        for p, ips in r["path_facet_ips"].items():
            merged["path_facet_ips"][p] |= ips
        for ip, attempts in r["login_attempts"].items():
            merged["login_attempts"][ip].extend(attempts)
        merged["enum_hits"].update(r["enum_hits"])
        merged["enum_hits_last_time"].update(r["enum_hits_last_time"])  # last-write-wins e suficient (doar pt. afisare)
        merged["enum_hits_last_domain"].update(r["enum_hits_last_domain"])
        merged["findings"].extend(r["findings"])
        merged["day_counter"].update(r["day_counter"])
        merged["day_hour_counter"].update(r["day_hour_counter"])
        merged["subnet_counter"].update(r["subnet_counter"])
        for s, ips in r["subnet_ips"].items():
            merged["subnet_ips"][s] |= ips
        merged["wp"].update(r["wp"])
        for ip, c in r["wp_login_ips"].items():
            merged["wp_login_ips"][ip] += c
        for pat, ps in r["pattern_stats"].items():
            mp_ = merged["pattern_stats"][pat]
            mp_["count"] += ps["count"]
            mp_["ips"] |= ps["ips"]
            mp_["params"].update(ps["params"])
        merged["scan_hits"].update(r["scan_hits"])
        merged["bandwidth"] += r["bandwidth"]
        for p, ips in r["path_ips"].items():
            merged["path_ips"][p] |= ips
        for u, ips in r["ua_ips"].items():
            merged["ua_ips"][u] |= ips
        for ip, times in r["wp_admin_hits"].items():
            merged["wp_admin_hits"][ip].extend(times)
        merged["burst_counter"].update(r["burst_counter"])
        for bkey, ips in r["burst_ips"].items():
            merged["burst_ips"][bkey] |= ips
        merged["path_bandwidth"].update(r["path_bandwidth"])
        merged["ip_bandwidth"].update(r["ip_bandwidth"])
        merged["err_hour_counter"].update(r["err_hour_counter"])
        merged["err5_hour_counter"].update(r["err5_hour_counter"])
        merged["minute_counter"].update(r["minute_counter"])
        merged["err_minute_counter"].update(r["err_minute_counter"])
        merged["err5_minute_counter"].update(r["err5_minute_counter"])
        merged["cron_minute_counter"].update(r["cron_minute_counter"])
        merged["wp_cron_day_counter"].update(r["wp_cron_day_counter"])
        for ip, actions in r["admin_activity_actions"].items():
            merged["admin_activity_actions"][ip].update(actions)
        for ip, events in r["admin_activity_events"].items():
            merged["admin_activity_events"][ip].extend(events)
        merged["ua_bandwidth"].update(r["ua_bandwidth"])
        for ip, identity in r["claim_ip_identity"].items():
            merged["claim_ip_identity"][ip] = identity
        merged["claim_ip_requests"].update(r["claim_ip_requests"])
        merged["claim_ip_bandwidth"].update(r["claim_ip_bandwidth"])
        for ip, c in r["claim_ip_paths"].items():
            merged["claim_ip_paths"][ip].update(c)
        for ip, c in r["claim_ip_status"].items():
            merged["claim_ip_status"][ip].update(c)
        for ip, ranges in r["claim_ip_time_range"].items():
            merged["claim_ip_time_range"][ip].extend(ranges)
        merged["query_key_counter"].update(r["query_key_counter"])
        merged["path_404_counter"].update(r["path_404_counter"])
        merged["path_no_referer_counter"].update(r["path_no_referer_counter"])
        for bkey, bm in r["burst_meta"].items():
            mbm = merged["burst_meta"][bkey]
            mbm["paths"] |= bm["paths"]
            mbm["subnets"] |= bm["subnets"]
            mbm["security_hits"] += bm["security_hits"]
            mbm["crawler_claim_hits"] += bm["crawler_claim_hits"]
            mbm["generic_hits"] += bm["generic_hits"]
        for day, (dstart, dend) in r["day_bounds"].items():
            mdb = merged["day_bounds"].get(day)
            if mdb is None:
                merged["day_bounds"][day] = [dstart, dend]
            else:
                if dstart < mdb[0]:
                    mdb[0] = dstart
                if dend > mdb[1]:
                    mdb[1] = dend
    return merged


def day_offsets_from_bounds(day_bounds):
    """Construieste indexul per-zi DIRECT din day_bounds (min/max byte-uri
    exacte unde a aparut fiecare zi, calculate gratuit in timpul singurei
    treceri complete a motorului). Spre deosebire de vechea abordare
    (cautare binara + o A DOUA trecere completa de validare), regiunea
    [start,end) rezultata e GARANTAT corecta (contine toate liniile acelei
    zile) indiferent daca logul e scris cronologic sau nu -- pentru ca
    provine dintr-un parse complet, nu dintr-o presupunere. Zero cost
    suplimentar, zero risc de a rata linii."""
    return {day: (bounds[0], bounds[1]) for day, bounds in day_bounds.items()}


def _available_ram_mb():
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) / 1024
    except Exception:
        return None
    return None


# os.cpu_count() raporteaza nucleele FIZICE ale node-ului gazda, nu limita
# reala de CPU a acestui container/LVE -- pe un CT OpenVZ/CloudLinux
# throttle-uit (ex: limita LVE de CPU mult sub nr. de nuclee ale node-ului),
# asta duce la un Pool supra-dimensionat: N procese care se bat pe o felie
# de CPU mult mai mica decat N nuclee, deci thrashing (load mare, context
# switch-uri multe) in loc de paralelizare reala -- wall-time mai mare decat
# daca am fi folosit mai putini workeri. Incercam, in ordine: cgroup v2
# (cpu.max), cgroup v1 (cpu.cfs_quota_us/cpu.cfs_period_us -- cum expune de
# obicei CloudLinux LVE CPU-ul alocat unui cPanel/CT), afinitatea CPU a
# procesului (sched_getaffinity -- utila pe cpuset-uri), si doar la final
# fallback la os.cpu_count() (comportamentul vechi, neschimbat daca nimic
# altceva nu e detectabil).
def _cpu_quota_cores():
    try:
        with open("/sys/fs/cgroup/cpu.max") as f:
            quota_s, period_s = f.read().split()
        if quota_s != "max":
            q = int(quota_s) / float(period_s)
            if q > 0:
                return max(1, int(q))
    except Exception:
        pass
    try:
        with open("/sys/fs/cgroup/cpu/cpu.cfs_quota_us") as f:
            quota = int(f.read().strip())
        if quota > 0:
            with open("/sys/fs/cgroup/cpu/cpu.cfs_period_us") as f:
                period = int(f.read().strip())
            if period > 0:
                return max(1, int(quota / period))
    except Exception:
        pass
    try:
        return max(1, len(os.sched_getaffinity(0)))
    except Exception:
        pass
    return max(1, os.cpu_count() or 1)


# Plafonul de baza pentru toate Pool-urile din acest fisier -- vezi
# _cpu_quota_cores() mai sus. Poate fi FORTAT explicit cu variabila de mediu
# LOGSCAN_MAX_WORKERS, utila cand detectia automata nu se aplica (ex. limita
# LVE nu e expusa prin cgroup pe acest CT): LOGSCAN_MAX_WORKERS=2 python3
# app.py ...  -- override-ul explicit are intotdeauna prioritate.
_ENV_MAX_WORKERS = os.environ.get("LOGSCAN_MAX_WORKERS", "").strip()


def _default_worker_count():
    if _ENV_MAX_WORKERS:
        try:
            v = int(_ENV_MAX_WORKERS)
            if v > 0:
                return v
        except ValueError:
            pass
    return _cpu_quota_cores()


# Sub acest prag, pornirea unui multiprocessing.Pool (fork de N procese noi
# prin forkserver) costa efectiv MAI MULT decat ar economisi paralelizarea --
# masurat direct: ~0.9-1.1 SECUNDE doar pentru crearea pool-ului, indiferent
# cat de mica e regiunea scanata. Pentru un drill-down interactiv (click pe
# un IP/path/burst), asta insemna o taxa fixa de ~1s la FIECARE click, chiar
# si cand regiunea de scanat (ex: o singura zi dintr-un log mic/mediu) se
# parcurge in cateva zeci de milisecunde pe un singur proces. Pragul de mai
# jos garanteaza minim ~8MB de lucru per worker, ca sa merite paralelizarea.
MIN_BYTES_PER_WORKER = 8 * 1024 * 1024

# Plafon per memo per worker (vezi _process_chunk): ~200k intrari * cateva
# sute de bytes = zeci de MB in cel mai rau caz, indiferent de marimea logului.
_MEMO_CAP = 200_000


def _safe_worker_count(size_bytes, requested_workers):
    """Alege nr de workeri pe baza a DOUA constrangeri independente:
    1) RAM disponibila (ca inainte -- nu porni mai multi workeri decat isi
       poate permite memoria disponibila);
    2) marimea EFECTIVA a regiunii de scanat (size_bytes) -- daca e prea mica
       ca sa merite costul de pornire al unui Pool, foloseste un singur
       proces (vezi MIN_BYTES_PER_WORKER mai sus). IMPORTANT: apelantul
       trebuie sa dea marimea REGIUNII scanate, nu marimea fisierului
       intreg -- altfel un drill-down pe o singura zi dintr-un log de cativa
       GB tot ar porni degeaba un pool mare pentru o regiune mica."""
    size_workers = max(1, size_bytes // MIN_BYTES_PER_WORKER)
    requested_workers = min(requested_workers, size_workers)
    avail_mb = _available_ram_mb()
    if avail_mb is None:
        return max(1, requested_workers)
    est_mb_per_worker = max(150.0, (size_bytes / (1024 * 1024)) / max(1, requested_workers) * 3)
    budget_workers = max(1, int((avail_mb * 0.7) / est_mb_per_worker))
    return max(1, min(requested_workers, budget_workers))


def run_engine(path, n_workers=None, day_filter=None, region=None, hour_filter=None, minute_filter=None, segments=None,
               index_workdir=None, progress_dir=None):
    """Motorul principal: imparte fisierul (sau doar o regiune de byte-uri
    din el) pe core-uri, agrega in paralel.
    day_filter (ex: '18/Sep/2026') restrange analiza la o singura zi, fara
    sa mai re-decomprime fisierul (deja plain pe disc).
    region=(start,end): daca e dat (din indexul per-zi calculat la upload),
    motorul citeste DOAR acel byte-range in loc de tot fisierul -- day_filter
    ramane aplicat per-linie in _process_chunk, deci rezultatul e corect
    chiar daca regiunea nu e perfect exacta (contine cateva linii in plus
    de la ziua vecina)."""
    n_workers = n_workers or _default_worker_count()
    # IMPORTANT: marimea folosita pentru decizia nr. de workeri e a REGIUNII
    # efectiv scanate (cand e data), nu a fisierului intreg -- altfel un
    # filtru pe o singura zi dintr-un log de multi-GB ar porni degeaba un
    # Pool mare pentru o regiune posibil mica (vezi _safe_worker_count).
    if region is not None:
        scan_size = max(0, region[1] - region[0])
    else:
        scan_size = os.path.getsize(path) if os.path.exists(path) else 0
    n_workers = _safe_worker_count(scan_size, n_workers)
    if region is not None:
        chunks = find_chunk_offsets(path, n_workers, region_start=region[0], region_end=region[1])
    else:
        chunks = find_chunk_offsets(path, n_workers)
    if not chunks:
        return _new_partial()
    # index_workdir (doar la upload): fiecare worker scrie si un shard SQLite
    # cu randurile de triaj, in ACEEASI trecere -- vezi _process_chunk.
    def _a(i, s, e):
        a = (path, s, e, day_filter, hour_filter, minute_filter, segments)
        if index_workdir:
            a = a + (os.path.join(index_workdir, f"shard_{i}.sqlite"),)
        elif progress_dir:
            # fara shard, doar raport de progres (re-analiza unei selectii)
            a = a + (None, os.path.join(progress_dir, f"part_{i}.progress"))
        return a
    if len(chunks) == 1:
        partials = [_process_chunk(_a(0, chunks[0][0], chunks[0][1]))]
    else:
        partials = _pool_map(_process_chunk, [_a(i, s, e) for i, (s, e) in enumerate(chunks)], len(chunks))
    shards = [p.pop("_shard") for p in partials if "_shard" in p]
    merged = partials[0] if len(partials) == 1 else _merge_partials(partials)
    if index_workdir:
        merged["_shards"] = shards
    return merged


_INVESTIGATION_CONF_ORDER = {"high": 0, "medium": 1, "low": 2, "": 3}


def _build_investigation_queue(findings, anomalies, max_items=20):
    """Coada de investigare (Faza 3) -- NU o detectie noua, doar o
    RE-SORTARE/AGREGARE a findings + anomalies deja calculate mai jos in
    build_summary (approach 'c' din spec: sortare/filtrare peste date deja
    agregate, zero cost de re-scanare). Combina cele doua liste intr-un
    singur clasament (findings inaintea anomaliilor la aceeasi severitate --
    un finding e un semnal concret, o anomalie e statistica), sortat
    severitate -> incredere, si taie la `max_items` (contorul complet ramane
    in `total`, ca UI-ul sa poata arata 'si inca N')."""
    items = []
    for f in findings:
        items.append({
            "source": "finding", "severity": f.get("severity", ""),
            "confidence": f.get("confidence", ""), "rule": f.get("rule", ""),
            "reason": f.get("reason", ""), "detail": f.get("detail", ""),
            "ip": f.get("ip", ""), "path": f.get("path"), "subnet": f.get("subnet"),
            "time": f.get("time", ""), "domain": f.get("domain"),
        })
    for a in anomalies:
        items.append({
            "source": "anomaly", "severity": a.get("severity", ""),
            "confidence": a.get("confidence", ""), "rule": a.get("rule", ""),
            "reason": a.get("reason", ""), "detail": a.get("detail", ""),
            "ip": a.get("ip", ""), "path": a.get("path"), "subnet": a.get("subnet"),
            "time": a.get("time", ""), "domain": a.get("domain"),
        })
    src_order = {"finding": 0, "anomaly": 1}
    items.sort(key=lambda x: (
        SEVERITY_ORDER.get(x["severity"], 9),
        src_order.get(x["source"], 9),
        _INVESTIGATION_CONF_ORDER.get(x.get("confidence", ""), 9),
    ))
    total = len(items)
    top = items[:max_items]
    return {
        "items": top,
        "total": total,
        "more": max(0, total - len(top)),
        "disclaimer": ("Prioritizare, NU dovada de atac -- ordinea arata pe ce sa te uiti PRIMUL "
                       "(severitate + incredere), nu o concluzie ca fiecare rand e un incident real."),
    }


# --------------------------------------------------------------------------
# Constructia raspunsului de analiza (folosita atat pentru "toate zilele"
# cat si pentru o zi filtrata)
# --------------------------------------------------------------------------
def build_summary(merged, days_all=None):
    order = SEVERITY_ORDER

    def _dom_label(doms):
        """Un singur domeniu -> el; mai multe -> lista lor separata prin
        virgula; niciunul cunoscut (dataset dintr-un singur fisier, sau
        domeniu neghicit) -> None. Folosit pt. findings agregate pe mai
        multe linii (brute force, enumerare), unde un singur eveniment
        poate proveni din linii de domenii diferite."""
        doms = {d for d in doms if d}
        if not doms:
            return None
        if len(doms) == 1:
            return next(iter(doms))
        return ", ".join(sorted(doms))

    # findings = semnal CONCRET (o regula clara s-a potrivit -- pattern de
    # atac, endpoint sensibil accesat, prag clar de brute force depasit).
    # anomalies = semnal mai SLAB/statistic (volum neobisnuit, corelatie fara
    # o regula concreta, deviatie fata de baseline) -- "merita o privire",
    # nu "e clar rau". Vezi SEVERITY_LEVELS/SEVERITY_ORDER mai sus. Ambele
    # liste carora `severity`+`confidence`+`reason` (+ `evidence` cand exista
    # date structurate) -- niciodata un procent fals de "certitudine".
    findings = list(merged["findings"])
    anomalies = []
    for ip, attempts in merged["login_attempts"].items():
        if len(attempts) >= 20:
            status_counts = Counter(a[0] for a in attempts)
            times = [a[1] for a in attempts if a[1]]
            n = len(attempts)
            findings.append({
                # v47: brute force = tentativa, nu compromitere (CRITICAL
                # ramane doar "login reusit dupa brute force", mai jos).
                "severity": "HIGH" if n >= 100 else "MEDIUM",
                "confidence": "high",
                "rule": "Brute force wp-login/xmlrpc",
                "reason": f"{n} incercari POST catre wp-login.php/xmlrpc.php de la acelasi IP -- volum "
                          f"mult peste orice utilizare legitima (un om nu incearca sa se logheze de zeci "
                          f"de ori), tipar clasic de brute force automatizat.",
                "detail": f"IP {ip}: {len(attempts)} incercari POST (statusuri: {dict(status_counts)})",
                "ip": ip, "time": attempts[-1][1] if attempts else "",
                "domain": _dom_label(a[2] for a in attempts),
                # date structurate din spatele findingului -- afisate ca panel
                # expandabil in UI (vezi dashboard.html), nu doar in textul
                # din 'detail'. Threshold-ul relevant e >=20 incercari.
                "evidence": {
                    "ip": ip, "requests": len(attempts),
                    "first_seen": min(times) if times else "",
                    "last_seen": max(times) if times else "",
                    "status_breakdown": dict(status_counts),
                    "threshold_name": "min. incercari POST pentru brute force",
                    "threshold_value": 20,
                    "endpoint": "wp-login.php / xmlrpc.php",
                },
            })
        if len(attempts) >= 10:
            fails = 0
            for status, t, dom in attempts:
                if status in (200, 302) and fails >= 8:
                    findings.append({
                        "severity": "CRITICAL",
                        "confidence": "medium",
                        "rule": "Posibil login reusit dupa brute force",
                        "reason": f"Dupa {fails} incercari esuate consecutive, acelasi IP a primit un "
                                  f"raspuns {status} (de obicei succes/redirect) -- posibil brute force "
                                  f"reusit. Increderea e MEDIE fiindca accesul logului singur nu poate "
                                  f"confirma cu certitudine un login reusit (vezi nota din evidence).",
                        "detail": f"IP {ip}: status {status} dupa {fails} esecuri, la {t}. "
                                  f"Successful login cannot be confirmed from access logs alone.",
                        "ip": ip, "time": t, "domain": dom,
                        "evidence": {
                            "ip": ip, "failed_attempts_before": fails,
                            "success_status": status, "success_time": t,
                            "threshold_name": "min. esecuri consecutive inainte de succes",
                            "threshold_value": 8,
                            "endpoint": "wp-login.php / xmlrpc.php",
                            "note": "Successful login cannot be confirmed from access logs alone.",
                        },
                    })
                    break
                if status not in (200, 302):
                    fails += 1

    for ip, c in merged["enum_hits"].items():
        if c >= 5:
            findings.append({
                "severity": "MEDIUM",
                "confidence": "medium",
                "rule": "Enumerare utilizatori WordPress",
                "reason": f"{c} cereri catre ?author=<n> sau /wp-json/wp/v2/users de la acelasi IP -- "
                          f"tehnica directa de descoperire a username-urilor WordPress valide, de obicei "
                          f"pasul dinaintea unui brute force tintit pe acele conturi.",
                "detail": f"IP {ip}: {c} cereri ?author=/wp-json users",
                "ip": ip, "time": merged["enum_hits_last_time"].get(ip, ""),
                "domain": merged["enum_hits_last_domain"].get(ip),
                "evidence": {
                    "ip": ip, "requests": c,
                    "last_seen": merged["enum_hits_last_time"].get(ip, ""),
                    "threshold_name": "min. cereri ?author=/wp-json users",
                    "threshold_value": 5,
                    "endpoint": "?author=<n> / /wp-json/wp/v2/users",
                },
            })

    # --- wp-cron.php: doua semnale STATISTICE (volum/deviatie fata de un
    # baseline asteptat, nu o regula de atac concreta) -- clasificate ca
    # ANOMALII, nu findings: sunt foarte des cauzate de o configurare
    # obisnuita de hosting (cron dublat, DISABLE_WP_CRON lipsa), nu de un
    # atac. Ambele foarte intalnite pe shared
    # hosting si vazute direct in access log:
    # 1) "Stacking" -- mai multe cereri wp-cron.php in ACEEASI fereastra de
    #    1 minut = semn clasic de cron duplicat (system cron + trigger la
    #    fiecare pageload, sau job cron dublat), care produce varfuri de
    #    load. Prag: >=5 cereri/minut (comparabil ca ordin de marime cu
    #    fereastra de 30s folosita la bursturi, dar pe minut intreg fiindca
    #    wp-cron nu ruleaza in mod normal decat rar).
    # 2) Volum disproportionat -- wp-cron.php reprezinta o parte prea mare
    #    din traficul zilei SAU un numar brut foarte mare -- de obicei
    #    inseamna ca DISABLE_WP_CRON nu e setat (deci wp-cron se declanseaza
    #    la fiecare vizitator) sau ca cineva loveste direct wp-cron.php.
    WP_CRON_STACK_THRESHOLD = 5        # cereri wp-cron.php in aceeasi fereastra de 1 minut
    WP_CRON_DAY_ABS_THRESHOLD = 2000   # cereri wp-cron.php intr-o singura zi (prag brut, indiferent de share)
    WP_CRON_DAY_SHARE_THRESHOLD = 0.02 # 2% din traficul zilei
    WP_CRON_DAY_MIN_REQUESTS = 200     # sub acest nr de cereri wp-cron/zi, nu raportam (zgomot pe loguri mici)

    for (cday, chour, cminute), ccount in merged["cron_minute_counter"].items():
        if ccount >= WP_CRON_STACK_THRESHOLD:
            anomalies.append({
                "severity": "MEDIUM" if ccount >= WP_CRON_STACK_THRESHOLD * 3 else "LOW",
                "confidence": "medium",
                "rule": "wp-cron.php: executii suprapuse in aceeasi fereastra (posibil cron duplicat)",
                "reason": f"{ccount} cereri wp-cron.php in acelasi minut -- de obicei o configurare de "
                          f"cron dublata (system cron + trigger la fiecare pageload, sau job cron "
                          f"duplicat), nu un atac; merita verificat daca produce varfuri de load.",
                "detail": f"{ccount} cereri wp-cron.php in fereastra {cday} {chour}:{cminute} (acelasi minut) -- "
                          f"posibil cron dublat (system cron + trigger la fiecare pageload, sau job cron duplicat).",
                "ip": "", "time": f"{cday} {chour}:{cminute}", "domain": None,
                "path": "wp-cron.php", "day": cday, "hour": chour, "minute": cminute,
                "evidence": {
                    "requests_in_window": ccount, "window": f"{cday} {chour}:{cminute}",
                    "threshold_name": "min. cereri wp-cron.php in aceeasi fereastra de 1 minut",
                    "threshold_value": WP_CRON_STACK_THRESHOLD,
                    "endpoint": "wp-cron.php",
                },
            })

    for cday, dcount in merged["wp_cron_day_counter"].items():
        day_total = merged["day_counter"].get(cday, 0)
        share = (dcount / day_total) if day_total else 0
        if dcount >= WP_CRON_DAY_MIN_REQUESTS and (dcount >= WP_CRON_DAY_ABS_THRESHOLD or share >= WP_CRON_DAY_SHARE_THRESHOLD):
            anomalies.append({
                "severity": "LOW",
                "confidence": "low",
                "rule": "Volum ridicat wp-cron.php (posibil DISABLE_WP_CRON lipsa)",
                "reason": f"wp-cron.php reprezinta {share * 100:.1f}% din traficul zilei ({dcount} cereri) -- "
                          f"peste baseline-ul asteptat pentru un cron care ruleaza rar; de obicei "
                          f"DISABLE_WP_CRON nu e setat (declansat la fiecare pageview), rareori un atac direct.",
                "detail": f"{dcount} cereri wp-cron.php in {cday} ({share * 100:.1f}% din traficul zilei) -- "
                          f"posibil DISABLE_WP_CRON nesetat (wp-cron declansat la fiecare pageview) sau atac direct pe wp-cron.php.",
                "ip": "", "time": cday, "domain": None,
                "path": "wp-cron.php", "day": cday,
                "evidence": {
                    "requests_that_day": dcount, "day_total_requests": day_total,
                    "share_of_day": round(share * 100, 2),
                    "threshold_name": "prag absolut (cereri/zi) SAU prag procentual din trafic",
                    "threshold_value": f">= {WP_CRON_DAY_ABS_THRESHOLD} cereri SAU >= {WP_CRON_DAY_SHARE_THRESHOLD * 100:.0f}%",
                    "endpoint": "wp-cron.php",
                },
            })

    findings.sort(key=lambda f: order.get(f["severity"], 9))
    # anomalies.sort() ruleaza mai jos, dupa ce TOATE anomaliile (inclusiv
    # cele din distributed_enum/subnets/top_bursts, calculate mai jos) au
    # fost adaugate -- vezi finalul functiei.

    status_5xx = sum(c for s, c in merged["status_counter"].items() if s >= 500)
    status_4xx = sum(c for s, c in merged["status_counter"].items() if 400 <= s < 500)
    status_2xx = sum(c for s, c in merged["status_counter"].items() if 200 <= s < 300)
    status_3xx = sum(c for s, c in merged["status_counter"].items() if 300 <= s < 400)

    enum_ips = {ip: c for ip, c in merged["filter_ip_hits"].items() if c >= 5}

    distributed_enum = []
    for base, count in merged["dist_path_count"].items():
        n_ips = len(merged["dist_path_ips"][base])
        if count >= 50 and n_ips / count >= 0.7:
            distributed_enum.append({
                "path": base, "requests": count, "unique_ips": n_ips,
                "ratio": round(n_ips / count, 2),
            })
    distributed_enum.sort(key=lambda x: -x["requests"])
    # Semnal STATISTIC (multe IP-uri, raport IP/cereri neobisnuit de mare
    # catre acelasi path) -- fara o regula de atac concreta care sa se fi
    # potrivit, deci ANOMALIE, nu finding (vezi principiul de la inceputul
    # sectiunii de findings). Doar primele 20 (cele mai mari), ca sa nu
    # domine lista de anomalii cu zeci de intrari aproape identice.
    for d in distributed_enum[:20]:
        anomalies.append({
            "severity": "MEDIUM" if d["ratio"] >= 0.9 else "LOW",
            "confidence": "medium",
            "rule": "Enumerare distribuita (multe IP-uri, acelasi path)",
            "reason": f"{d['unique_ips']} IP-uri distincte au facut impreuna {d['requests']} cereri "
                      f"catre {d['path']} (raport IP/cereri {d['ratio']}) -- prea multe IP-uri facand "
                      f"prea putine cereri fiecare pentru navigare organica; tipar de enumerare "
                      f"distribuita (posibil rotatie de proxy-uri).",
            "detail": f"{d['path']}: {d['requests']} cereri, {d['unique_ips']} IP-uri unice (raport {d['ratio']})",
            "ip": "", "time": "", "domain": None, "path": d["path"],
            "evidence": {"path": d["path"], "requests": d["requests"], "unique_ips": d["unique_ips"],
                         "ratio": d["ratio"], "threshold_name": "min. cereri SI raport IP/cereri",
                         "threshold_value": ">= 50 cereri SI raport >= 0.7"},
        })

    # Prefixe de path cu trafic mare -- lista COMPLETA (nu doar cele
    # suspecte), grupata pe primul segment de path in loc de URL exact.
    # Prag minim doar ca sa nu se umple lista cu prefixe atinse intamplator.
    TOP_PATH_PREFIXES_MIN_REQUESTS = 20
    top_path_prefixes = []
    for prefix, count in merged["path_prefix_counter"].items():
        if count >= TOP_PATH_PREFIXES_MIN_REQUESTS:
            top_path_prefixes.append({
                "path": prefix, "requests": count,
                "unique_ips": len(merged["path_prefix_ips"][prefix]),
                "bandwidth": merged["path_prefix_bandwidth"].get(prefix, 0),
            })
    top_path_prefixes.sort(key=lambda x: -x["requests"])

    # Breakdown pe ADANCIME de segmente sub fiecare prefix (Eduard: "X = tot,
    # x/* = un nivel mai jos, x/*/* = doua niveluri mai jos, diferenta").
    # 100% GENERIC -- nu presupune nicio structura de site (WooCommerce cu
    # /product-category/, un magazin flat cu -c<id>-p<n>, orice). O singura
    # trecere peste path_only-urile UNICE deja calculate (merged["top_paths"],
    # acelasi Counter folosit si pentru unique_paths mai sus) -- cost marginal,
    # NU o trecere noua prin log. Pentru fiecare prefix, numaram cate cereri
    # au EXACT N segmente sub el, apoi transformam in cumulativ ("cel putin
    # N segmente") -- daca site-ul e flat (fara "/" intern, ex: roinstalatii.ro
    # gen slug-c75-p1), toate cererile cad la adancime 1 si nivelurile 2+
    # ies onest 0, fara sa inventam o structura care nu exista.
    # IMPORTANT: folosim EXACT aceeasi formula de prefix ca path_prefix_counter
    # (linia ~1567: slash2 = path_only.find("/", 1)) -- ca sa nu aparem cu doua
    # numere "totale" usor diferite pentru acelasi prefix (o discrepanta de
    # eticheta ar fi mai rea decat lipsa breakdown-ului). De-asta NU calculam
    # aici un "total" propriu -- doar nivelurile 2+, folosite ca detaliu
    # SUPLIMENTAR langa "requests" (coloana deja existenta = total real).
    PATH_DEPTH_MAX = 4  # niveluri sub prefix afisate distinct (al 4-lea = "4+")
    _depth_exact = defaultdict(lambda: [0] * (PATH_DEPTH_MAX + 1))  # prefix -> [d0(nefolosit), d1, d2, d3, d4+]
    # Acelasi pass calculeaza si cat de "static" e fiecare prefix (Eduard:
    # "vreau sa-l separam" -- separa prefixele de infrastructura/assets
    # statice de prefixele de continut/categorii reale). Folosim EXACT
    # is_static_path (deja existenta, folosita si pentru top_paths_static)
    # si EXACT acelasi total per-prefix acumulat aici pentru depth breakdown
    # -- ca sa nu introducem un al doilea total usor diferit (vezi comentariul
    # de mai sus despre discrepanta de eticheta).
    _static_hits = defaultdict(int)   # prefix -> cereri catre path-uri statice
    _prefix_total = defaultdict(int)  # prefix -> total cereri vazute in ACEST pass
    for _p, _c in merged["top_paths"].items():
        _slash2 = _p.find("/", 1)
        _prefix = _p[:_slash2] if _slash2 > 0 else _p
        if not _prefix or _prefix == "/":
            continue
        _prefix_total[_prefix] += _c
        if is_static_path(_p):
            _static_hits[_prefix] += _c
        _depth = min(_p.count("/"), PATH_DEPTH_MAX)
        if _depth < 1:
            continue
        _depth_exact[_prefix][_depth] += _c
    path_depth_breakdown = {}
    for _prefix, _levels in _depth_exact.items():
        # cumulativ: nivel N = cereri cu CEL PUTIN N segmente sub prefix
        _cum = [0] * (PATH_DEPTH_MAX + 1)
        _running = 0
        for _d in range(PATH_DEPTH_MAX, 0, -1):
            _running += _levels[_d]
            _cum[_d] = _running
        # Nivelul 1 e redundant cu "requests" (coloana deja existenta, din
        # path_prefix_counter) -- afisam doar 2+ ca detaliu de adancime.
        path_depth_breakdown[_prefix] = [
            {"depth": _d, "label": ("/*" * _d) if _d < PATH_DEPTH_MAX else f"/* x{PATH_DEPTH_MAX}+",
             "requests": _cum[_d]}
            for _d in range(2, PATH_DEPTH_MAX + 1)
        ]
    STATIC_PREFIX_RATIO_THRESHOLD = 0.7
    for _row in top_path_prefixes:
        _row["depth_levels"] = path_depth_breakdown.get(_row["path"], [])
        _ptotal = _prefix_total.get(_row["path"], 0)
        _pstatic = _static_hits.get(_row["path"], 0)
        _row["is_static_prefix"] = bool(_ptotal > 0 and (_pstatic / _ptotal) >= STATIC_PREFIX_RATIO_THRESHOLD)

    # Enumerare distribuita prin SEGMENTE de path (navigare pe fatete) --
    # acelasi principiu ca distributed_enum de mai sus (multe IP-uri unice,
    # fiecare facand putine cereri, catre acelasi prefix), doar ca semnalul
    # e in structura path-ului (caractere combinatorii &/*), nu in query
    # string -- vezi comentariul din _process_chunk.
    distributed_path_enum = []
    for prefix, count in merged["path_facet_count"].items():
        n_ips = len(merged["path_facet_ips"][prefix])
        if count >= 50 and n_ips / count >= 0.5:
            distributed_path_enum.append({
                "path": prefix, "requests": count, "unique_ips": n_ips,
                "ratio": round(n_ips / count, 2),
            })
    distributed_path_enum.sort(key=lambda x: -x["requests"])

    # Parameter / filter abuse -- normalizat pe forma path?param1=*&param2=*
    # (varianta 4, aleasa de Eduard: doar pattern-uri al caror parametru e
    # deja categorizat "suspicious" de categorize_query_key -- filter_*,
    # add_to_wishlist, min_price, max_price, chei cu forma de injectie/
    # traversal. Elimina automat zgomotul de cache-busting pe assets
    # statice (?_=<timestamp> pe .js/.css), care nu e niciodata "suspicious"
    # -- fara o lista noua de exceptii hardcodata, doar reutilizeaza
    # categorizarea deja construita pentru "Parametri de query".)
    param_abuse = []
    for pat, ps in merged["pattern_stats"].items():
        n_ips = len(ps["ips"])
        if ps["count"] < 30 or n_ips < 3:
            continue
        if not any(categorize_query_key(p) == "suspicious" for p in ps["params"]):
            continue
        param_abuse.append({
            "pattern": pat,
            "requests": ps["count"],
            "unique_ips": n_ips,
            "ip_request_ratio": round(n_ips / ps["count"], 2) if ps["count"] else 0,
            "top_params": [p for p, _ in ps["params"].most_common(5)],
        })
    param_abuse.sort(key=lambda x: -x["requests"])

    # --- Cross-reference "acest prefix a avut un semnal REAL" (Eduard: un
    # atac distribuit real -- burst 34.x.x.x GCP catre
    # /centrale-termice-pe-gaz-c75-p1?filtru=producator[...], toate 503 --
    # trebuie sa se vada DIRECT langa numarul mare din "Prefixe de continut",
    # nu doar in tabelul separat de "Abuz parametri". NU e o trecere noua
    # prin log: doar unim doua liste deja calculate mai sus in build_summary
    # (findings -- semnale concrete, NU anomalii statistice -- si
    # param_abuse), reducem fiecare la un path/pattern de baza (taiat la "?")
    # si verificam care prefix din top_path_prefixes e un PREFIX al acelui
    # path de baza. Bursturile sunt SARITE intentionat aici (un burst poate
    # atinge multe path-uri diferite, "path-ul dominant" nu e ieftin de
    # calculat fara o trecere noua) -- (a)+(b) acopera deja exact exemplul
    # lui Eduard, verificat impotriva /tmp/roinstalatii_test.log.
    _signal_sources = []  # listă de (base_path, "descriere scurta a regulii care a prins-o")
    for _pa in param_abuse:
        _base = _pa["pattern"].split("?", 1)[0]
        if _base and _base != "/":
            _signal_sources.append((
                _base,
                f"Abuz parametri: {_pa['pattern']} ({_pa['requests']} cereri, {_pa['unique_ips']} IP-uri)",
            ))
    for _f in findings:
        _fp = _f.get("path") or (_f.get("evidence") or {}).get("path")
        if _fp:
            _base = _fp.split("?", 1)[0]
            if _base and _base != "/":
                _signal_sources.append((_base, f"Finding: {_f.get('rule') or 'semnal concret'} ({_fp})"))
    for _row in top_path_prefixes:
        _prefix = _row["path"]
        _matched_summaries = []
        for _base, _desc in _signal_sources:
            if _base.startswith(_prefix) and _desc not in _matched_summaries:
                _matched_summaries.append(_desc)
            if len(_matched_summaries) >= 3:
                break
        _row["has_signal"] = bool(_matched_summaries)
        _row["signal_summary"] = "; ".join(_matched_summaries) if _matched_summaries else None

    # Revendicare de identitate crawler la nivel de subnet (Bug #1 fix,
    # Eduard) -- daca MAJORITATEA IP-urilor unui subnet flagged au UA-uri
    # care revendica aceeasi identitate de crawler cunoscuta (Tier 1, vezi
    # claim_ip_identity/claim_ip_requests), asta e cel mai probabil crawling
    # legitim (ex: Bingbot navigand fatete de filtrare), nu un atac -- semnalul
    # NU se arunca (UA poate fi falsificat), dar nu mai trebuie sa citeasca
    # ca "atac cu severitate mare" doar pe baza unui text de User-Agent.
    # Verificarea DNS (Tier 2) ruleaza ASYNC dupa upload (vezi
    # _verify_one_ip/crawler_verification) -- aici stim DOAR revendicarea,
    # nu adevarul confirmat, de-asta textul mentioneaza explicit asta.
    def _majority_crawler_claim(ip_set):
        counts = Counter()
        n = 0
        for ip in ip_set:
            n += 1
            if merged["claim_ip_requests"].get(ip, 0) > 0:
                identity = merged["claim_ip_identity"].get(ip)
                if identity:
                    counts[identity] += 1
        if not counts or n == 0:
            return None
        identity, hits = counts.most_common(1)[0]
        return identity if hits / n >= 0.5 else None

    # Subnet-uri (/24) cu activitate suspecta
    subnets = []
    for subnet, count in merged["subnet_counter"].items():
        n_ips = len(merged["subnet_ips"][subnet])
        if n_ips >= 5 and count >= 100:
            reasons = []
            if count / max(1, n_ips) > 20:
                reasons.append("High Traffic")
            if n_ips >= 20:
                reasons.append("Suspicious Distributed Activity")
            if not reasons:
                continue
            subnets.append({
                "subnet": subnet, "ips": n_ips, "requests": count,
                "reasons": reasons,
                "crawler_claim": _majority_crawler_claim(merged["subnet_ips"][subnet]),
            })
    subnets.sort(key=lambda x: -x["requests"])
    # Semnal STATISTIC (volum/densitate de IP-uri pe subnet peste un prag),
    # fara o regula de atac concreta -- ANOMALIE, nu finding. Doar primele 20.
    for s in subnets[:20]:
        crawler_claim = s.get("crawler_claim")
        if crawler_claim:
            # Majoritatea IP-urilor din subnet revendica aceeasi identitate de
            # crawler cunoscut -- plafonam la LOW (niciodata HIGH/MEDIUM) si
            # explicam clar ca e o revendicare Tier 1, nu o verificare DNS.
            severity = "LOW"
            reason = (f"Subnetul {s['subnet']} a generat {s['requests']} cereri din {s['ips']} IP-uri "
                      f"({', '.join(s['reasons'])}), dar majoritatea acestor IP-uri revendica identitatea "
                      f"{crawler_claim} (verificare DNS asincrona in sectiunea Crawlere -- daca apare ca "
                      f"verificat, foarte probabil crawling legitim; daca apare ca nesigur/spoofing, "
                      f"ridica prioritatea).")
        else:
            severity = "MEDIUM" if "Suspicious Distributed Activity" in s["reasons"] else "LOW"
            reason = (f"Subnetul {s['subnet']} a generat {s['requests']} cereri din {s['ips']} IP-uri "
                      f"({', '.join(s['reasons'])}) -- deviatie de la traficul tipic per-subnet, fara sa "
                      f"se potriveasca vreo regula de atac concreta; poate fi legitim (NAT/CGNAT, retea "
                      f"corporate) sau un semn de activitate coordonata.")
        anomalies.append({
            "severity": severity,
            "confidence": "low",
            "rule": "Subnet /24 cu activitate statistic neobisnuita",
            "reason": reason,
            "detail": f"{s['subnet']}: {s['requests']} cereri, {s['ips']} IP-uri unice -- {', '.join(s['reasons'])}",
            "ip": "", "time": "", "domain": None, "subnet": s["subnet"],
            "evidence": {"subnet": s["subnet"], "requests": s["requests"], "unique_ips": s["ips"],
                         "reasons": s["reasons"], "crawler_claim": crawler_claim},
        })

    # Toate subnet-urile /24 cu trafic (lista COMPLETA, fara filtrarea dupa
    # motiv de suspiciune de mai sus -- acolo un subnet trebuie sa aiba
    # >=5 IP-uri SI >=100 cereri SI (trafic/IP mare SAU >=20 IP-uri) ca sa
    # apara, ceea ce lasa pe dinafara subnet-uri active dar sub acel prag
    # (ex: un /24 cu putine IP-uri insa cereri reale, sau invers). Aici
    # pragul e minimal -- doar destul cat sa nu umple lista cu /24-uri
    # atinse intamplator de 1-2 cereri -- ca sa poti gasi ORICE subnet activ,
    # nu doar pe cele deja marcate suspicious mai sus.
    ALL_SUBNETS_MIN_REQUESTS = 20
    ALL_SUBNETS_MIN_IPS = 3
    all_subnets = []
    for subnet, count in merged["subnet_counter"].items():
        n_ips = len(merged["subnet_ips"][subnet])
        if count >= ALL_SUBNETS_MIN_REQUESTS and n_ips >= ALL_SUBNETS_MIN_IPS:
            all_subnets.append({"subnet": subnet, "ips": n_ips, "requests": count})
    all_subnets.sort(key=lambda x: -x["requests"])

    # IP-uri suspecte, cu motive explicite (nu scor arbitrar)
    ip_reasons = defaultdict(list)
    ip_has_concrete_finding = set()  # IP-uri flagged de un FINDING concret (nu doar semnal statistic)
    for f in findings:
        if f.get("ip"):
            ip_reasons[f["ip"]].append(f["rule"])
            ip_has_concrete_finding.add(f["ip"])
    for ip, c in enum_ips.items():
        ip_reasons[ip].append(f"{c} cereri cu parametri filter_ (posibila enumerare)")
    subnet_flagged_ips = set()
    for s in subnets:
        for ip in merged["subnet_ips"].get(s["subnet"], ()):
            subnet_flagged_ips.add(ip)
    for ip in subnet_flagged_ips:
        if ip in ip_reasons:
            ip_reasons[ip].append("Parte dintr-un subnet cu activitate distribuita suspecta")

    # Bug #1 fix (Eduard): revendicare de identitate crawler (Tier 1, vezi
    # claim_ip_identity/claim_ip_requests) per IP -- NU stergem semnalul (UA
    # poate fi falsificat), dar un IP care revendica un crawler cunoscut si a
    # fost flagged DOAR pe baza unor semnale statistice (>=5 cereri filter_,
    # subnet distribuit) -- nu si de un finding concret (webshell, brute
    # force etc.) -- nu ar trebui sa citeasca ca "atac HIGH". Verificarea DNS
    # (Tier 2) ruleaza async dupa upload -- aici avem doar revendicarea UA.
    suspicious_ips = []
    for ip, reasons in ip_reasons.items():
        reasons = list(reasons)
        crawler_claim = None
        if merged["claim_ip_requests"].get(ip, 0) > 0:
            crawler_claim = merged["claim_ip_identity"].get(ip)
        if crawler_claim:
            c = enum_ips.get(ip)
            if c:
                old_reason = f"{c} cereri cu parametri filter_ (posibila enumerare)"
                if old_reason in reasons:
                    reasons[reasons.index(old_reason)] = (
                        f"{c} cereri filter_ de la un IP care revendica identitatea {crawler_claim} "
                        f"(verificare DNS asincrona in sectiunea Crawlere -- daca apare ca verificat, "
                        f"foarte probabil crawling legitim; daca apare ca nesigur/spoofing, ridica "
                        f"prioritatea).")
        risk = "HIGH" if len(set(reasons)) >= 2 else "MEDIUM"
        if crawler_claim and ip not in ip_has_concrete_finding:
            risk = "LOW"
        suspicious_ips.append({
            "ip": ip,
            "requests": merged["ip_counter"].get(ip, 0),
            "reasons": sorted(set(reasons)),
            "risk": risk,
            "crawler_claim": crawler_claim,
        })
    suspicious_ips.sort(key=lambda x: (-len(x["reasons"]), -x["requests"]))

    wp = merged["wp"]
    wp_top_login_ips = sorted(merged["wp_login_ips"].items(), key=lambda x: -x[1])[:200]

    # --- Login-uri WP posibil reusite (HEURISTICA, nu certitudine) ---
    # WordPress normal: login gresit -> reafiseaza formularul (status 200);
    # login corect -> redirect (302) catre wp-admin. Un POST wp-login.php cu
    # 302 e un semnal DESTUL DE PUTERNIC, dar nu o dovada -- alte cauze
    # (2FA, redirect canonic, plugin de securitate) pot produce acelasi cod.
    # Confidenta HIGH = 302 urmat, in max 5 min, de un acces GET 200 real in
    # /wp-admin/ de la aceeasi IP (confirma ca sesiunea a functionat).
    # Confidenta MEDIUM = doar 302, fara acces ulterior confirmat.
    WP_LOGIN_CORRELATE_WINDOW_SEC = 300
    wp_successful_logins = []
    for ip, attempts in merged["login_attempts"].items():
        admin_times_parsed = None
        for status, tstr, dom in attempts:
            if status != 302:
                continue
            confidence = "MEDIUM"
            confirmed_at = ""
            login_dt = parse_apache_time(tstr)
            if login_dt is not None:
                if admin_times_parsed is None:
                    admin_times_parsed = sorted(
                        dt for dt in (parse_apache_time(t) for t in merged["wp_admin_hits"].get(ip, ()))
                        if dt is not None
                    )
                for adt in admin_times_parsed:
                    delta = (adt - login_dt).total_seconds()
                    if 0 <= delta <= WP_LOGIN_CORRELATE_WINDOW_SEC:
                        confidence = "HIGH"
                        confirmed_at = adt.strftime("%d/%b/%Y:%H:%M:%S %z")
                        break
            wp_successful_logins.append({
                "ip": ip, "time": tstr, "country": country_of(ip),
                "confidence": confidence, "confirmed_access_at": confirmed_at,
                "domain": dom,
            })
    order_conf = {"HIGH": 0, "MEDIUM": 1}
    wp_successful_logins.sort(key=lambda x: (order_conf.get(x["confidence"], 9), x["time"]))

    # --- Split path-uri in 3 categorii, pe baza unor SEMNALE CONCRETE, nu a
    # volumului de trafic:
    #   "static"  -- assets (css/js/imagini/fonturi/favicon), fara risc
    #   "risc"    -- se potriveste cu o semnatura de atac/scanare cunoscuta
    #                (vezi is_risk_path: wp-login/xmlrpc/enumerare useri,
    #                fisiere sensibile, .php in uploads, etc.)
    #   "populare"-- restul: pagini de business normale, chiar daca au
    #                trafic mare (o pagina de produs/oferta populara NU e
    #                "risc" doar pentru ca are multe cereri)
    top_paths_static = []
    top_paths_risk = []
    top_paths_popular = []
    # "Dynamic/API paths" (Faza 2) -- vedere TRANSVERSALA (nu mutual-exclusiva
    # cu static/risc/popular -- ex: xmlrpc.php e si risc si dinamic): ce parte
    # din trafic loveste cod care ruleaza efectiv pe server (wp-json,
    # admin-ajax, REST-like, cart/checkout/cont), fata de fisiere servite
    # direct. Calculat din ACELASI Counter deja agregat (top_paths), fara
    # nicio trecere suplimentara -- vezi is_dynamic_path().
    top_paths_dynamic = []
    # Praguri ridicate substantial (ordin de marime) fata de versiunea
    # anterioara (30/50/30 din top 300) -- Eduard vrea sa poata vedea mult
    # mai mult decat top-ul strans, iar frontend-ul are acum propriul
    # dropdown de "cate randuri arat" care taie clientside din array-ul deja
    # primit (vezi dashboard.html: applyRowLimit). Iteram tot Counter-ul
    # (most_common() fara argument = TOATE path-urile), nu doar un subset.
    for p, c in merged["top_paths"].most_common():
        _n_ips = len(merged["path_ips"].get(p, ()))
        # "Breakdown profesional" (Eduard) -- doi indicatori ieftini (deja
        # avem ambele numere, doar impartim), fara nicio trecere noua prin
        # log: no_referer_pct = cat % din cererile catre path nu au referer,
        # ip_request_ratio = cat de aproape de 1.0 e raportul IP-uri unice /
        # cereri (aproape de 1.0 = aproape fiecare cerere vine de la alt IP --
        # semnatura de enumerare/bot cand e combinat cu no_referer_pct mare).
        entry = {
            "path": p, "requests": c, "unique_ips": _n_ips,
            "no_referer_pct": round(100 * merged["path_no_referer_counter"].get(p, 0) / c, 1) if c else 0,
            "ip_request_ratio": round(_n_ips / c, 2) if c else 0,
        }
        p_is_static = is_static_path(p)
        if p_is_static:
            if len(top_paths_static) < 300:
                top_paths_static.append(entry)
        elif is_risk_path(p):
            if len(top_paths_risk) < 500:
                top_paths_risk.append(entry)
        else:
            if len(top_paths_popular) < 300:
                top_paths_popular.append(entry)
        # PERF: un asset static (css/js/imagine/font) nu poate fi niciodata
        # un endpoint dinamic/API -- sarim peste is_dynamic_path() pentru el
        # (elimina cea mai mare parte din catalog pe site-uri cu multe
        # imagini/produse, fara sa schimbe rezultatul). Pragul c >= 2 elimina
        # in plus coada lunga de path-uri vazute o SINGURA data (pe cataloage
        # mari, adesea majoritatea path-urilor unice) -- rezonabil pentru o
        # categorie informativa de "hotspot-uri", spre deosebire de risc
        # (top_paths_risk NU are acest prag -- un singur hit pe wp-login.php
        # tot conteaza ca semnal).
        if not p_is_static and c >= 2 and len(top_paths_dynamic) < 300 and is_dynamic_path(p):
            top_paths_dynamic.append(entry)
        # PERF: top_paths_dynamic NU intra in conditia de break -- e o
        # categorie rara (majoritatea site-urilor au putine path-uri
        # dinamice/API distincte fata de cele statice/populare), deci daca
        # am astepta sa ajunga si ea la 300 bucata, break-ul de mai jos
        # aproape NICIODATA nu s-ar declansa devreme si am termina prin a
        # itera intregul catalog de path-uri unice (poate sute de mii pe
        # loguri mari) -- exact costul pe care break-ul early il evita
        # pentru celelalte 3 categorii. E acceptabil ca top_paths_dynamic
        # sa nu prinda toate cele 300 posibile pe cataloage foarte mari cu
        # putine hit-uri dinamice repetate -- prinde oricum tot ce apare in
        # portiunea (mult mai populata) din top parcursa pana la break.
        if (len(top_paths_static) >= 300 and len(top_paths_risk) >= 500
                and len(top_paths_popular) >= 300):
            break

    # "404 hotspots" (Faza 2) -- path-uri lovite repetat cu 404, semnal de
    # scanare pentru fisiere/endpoint-uri necunoscute (backup-uri, config-uri
    # vechi, plugin-uri dezinstalate etc.). Calculat direct din
    # path_404_counter (agregat GRATUIT in _process_chunk -- vezi mai sus),
    # zero trecere suplimentara prin log.
    PATH_404_MIN_HITS = 5
    top_paths_404 = []
    for p, c404 in merged["path_404_counter"].most_common(300):
        if c404 < PATH_404_MIN_HITS:
            break  # most_common() e deja descrescator -- restul sunt si mai mici
        total_p = merged["top_paths"].get(p, c404)
        top_paths_404.append({
            "path": p, "count_404": c404, "requests": total_p,
            "rate_404": round(100 * c404 / total_p, 1) if total_p else 0,
            "unique_ips": len(merged["path_ips"].get(p, ())),
        })

    # --- Top 3 bursturi de 30 secunde (volumul cel mai mare de cereri intr-o
    # fereastra scurta -- semnal puternic de atac/flood). Tara e calculata
    # DOAR pentru IP-urile din cele 3 bursturi castigatoare (bounded, ieftin),
    # niciodata pentru toate bucket-urile de 30s.
    # Eduard vrea sa poata rasfoi TOATE bursturile, nu doar top 3 (lucrul e
    # ieftin per-burst -- doar country lookup + classify_burst, munca
    # marginita, nicio re-trecere prin log) -- acelasi tipar de "plafon
    # generos, client-ul decide cate randuri arata" ca top_paths/all_subnets
    # de mai sus (vezi most_common(300) folosit la top_ua etc.).
    top_bursts = []
    for bkey, count in merged["burst_counter"].most_common(500):
        ips = merged["burst_ips"].get(bkey, set())
        country_counts = Counter(country_of(ip) for ip in ips)
        country_counts.pop("", None)
        top_countries = [{"country": cc, "count": n} for cc, n in country_counts.most_common(5)]
        day, hour, minute, half = bkey
        # --- Clasificare de burst (Faza 2, vezi classify_burst) -- combina
        # volumul cu semnale de UA/identitate/tipar-de-path deja agregate
        # GRATUIT per-fereastra in _process_chunk (burst_meta). Volumul
        # SINGUR nu decide niciodata clasificarea (vezi comentariul de la
        # classify_burst).
        bmeta = merged["burst_meta"].get(bkey, {})
        n_paths = len(bmeta.get("paths", ()))
        n_subnets = len(bmeta.get("subnets", ()))
        sec_hits = bmeta.get("security_hits", 0)
        crawler_hits = bmeta.get("crawler_claim_hits", 0)
        generic_hits = bmeta.get("generic_hits", 0)
        classification, class_reason = classify_burst(
            count, len(ips), n_paths, n_subnets, sec_hits, crawler_hits, generic_hits)
        burst_key_str = f"{day}|{hour}|{minute}|{half}"
        top_bursts.append({
            "day": day, "hour": hour, "minute": minute, "half": half,
            "label": burst_window_label(bkey),
            "requests": count,
            "unique_ips": len(ips),
            "top_countries": top_countries,
            "burst_key": burst_key_str,
            "classification": classification,
            "classification_reason": class_reason,
        })
        # Volumul singur NU e o dovada de atac (principiu deja stabilit in
        # aplicatie) -- doar bursturile clasificate diferit de "Normal"/
        # "Crawler" (adica NU explicate de navigare normala sau de un
        # crawler legitim care face crawl rapid) ajung in Anomalii, ca
        # semnal "merita o privire", fara sa fie tratate ca findings concrete.
        if classification not in ("Normal", "Crawler"):
            sev_by_class = {
                "Security scan": "MEDIUM", "Suspicious automation": "MEDIUM",
                "Distributed crawl": "LOW", "Unknown": "INFO",
            }
            anomalies.append({
                "severity": sev_by_class.get(classification, "INFO"),
                "confidence": "medium" if classification != "Unknown" else "low",
                "rule": f"Burst clasificat: {classification}",
                "reason": class_reason,
                "detail": f"{count} cereri / 30s la {burst_window_label(bkey)}, {len(ips)} IP-uri unice.",
                "ip": "", "time": burst_window_label(bkey), "domain": None,
                "burst_key": burst_key_str,
                "evidence": {
                    "requests": count, "unique_ips": len(ips), "window": burst_window_label(bkey),
                    "distinct_paths": n_paths, "distinct_subnets": n_subnets,
                    "security_endpoint_hits": sec_hits, "crawler_claim_hits": crawler_hits,
                    "generic_tool_ua_hits": generic_hits, "classification": classification,
                },
            })

    # --- Bandwidth: cine consuma cel mai mult trafic (util pentru diagnoza
    # de load/depasire cota) -- top 20 IP-uri dupa bytes transferati, calculat
    # gratuit in aceeasi trecere (ip_bandwidth acumulat per-linie in
    # _process_chunk). Ruptura pe PATH exact (path_bandwidth) nu mai e
    # expusa aici: pe site-uri cu navigare fatetata e dominata de mii de
    # URL-uri aproape-unice cu 1-2 cereri fiecare (zgomot, nu semnal) --
    # vezi in schimb top_path_prefixes (bandwidth pe categorie/prefix).
    top_bandwidth_ips = [
        {"ip": ip, "bandwidth": b, "requests": merged["ip_counter"].get(ip, 0),
         "country": country_of(ip)}
        for ip, b in merged["ip_bandwidth"].most_common(20)
    ]

    # --- Bot/crawler breakdown -- clasificare pe User-Agent UNIC (nu per
    # linie, vezi classify_ua), agregata pe categorie. Raspunde direct la
    # intrebarea "ce e legit si ce ar trebui blocat/limitat" fara sa mai
    # trebuiasca cautat manual fiecare User-Agent in parte.
    bot_cat_requests = Counter()
    bot_cat_ips = defaultdict(set)
    bot_cat_uas = defaultdict(set)
    bot_cat_ua_list = defaultdict(list)  # cat -> [(ua, requests, unique_ips), ...]
    for ua, c in merged["ua_counter"].items():
        cat = classify_ua(ua)
        bot_cat_requests[cat] += c
        bot_cat_uas[cat].add(ua)
        n_ips = len(merged["ua_ips"].get(ua, ()))
        bot_cat_ua_list[cat].append((ua, c, n_ips))
        for ip in merged["ua_ips"].get(ua, ()):
            if len(bot_cat_ips[cat]) < MAX_IPS_PER_BUCKET:
                bot_cat_ips[cat].add(ip)
    bot_breakdown = [
        {
            "category": cat, "requests": c,
            "unique_ips": len(bot_cat_ips.get(cat, ())),
            "unique_uas": len(bot_cat_uas.get(cat, ())),
            # top 12 User-Agents EXACTE din aceasta categorie, ca sa vezi
            # concret ce s-a clasificat asa (ex: "AI crawler" -- e chiar
            # ClaudeBot, sau altceva?) -- fara sa mai cauti manual in tabelul
            # de User-Agents.
            "sample_uas": [
                {"ua": u, "requests": r, "unique_ips": n}
                for u, r, n in sorted(bot_cat_ua_list.get(cat, []), key=lambda x: -x[1])[:12]
            ],
        }
        for cat, c in bot_cat_requests.most_common()
    ]

    # --- Traffic Composition -- ACELASI sistem de clasificare de mai sus
    # (classify_ua), doar RECONCILIAT intr-un set de 9 categorii distincte
    # cerute de Eduard (vezi classify_composition/_OLD_TO_NEW_CATEGORY), cu
    # bandwidth si top 3 UA/IP per categorie in plus fata de bot_breakdown.
    # Nu recalculeaza classify_ua -- reutilizeaza direct 'cat' calculat mai
    # sus (bot_cat_ua_list are deja (ua, requests, unique_ips) per categorie
    # veche), deci costul suplimentar e doar un dict lookup per UA unic.
    comp_cat_requests = Counter()
    comp_cat_bandwidth = Counter()
    comp_cat_ips = defaultdict(set)
    comp_cat_ua_list = defaultdict(list)
    for old_cat, ua_list in bot_cat_ua_list.items():
        for ua, c, n_ips in ua_list:
            comp_cat = classify_composition(ua, old_cat)
            comp_cat_requests[comp_cat] += c
            comp_cat_bandwidth[comp_cat] += merged["ua_bandwidth"].get(ua, 0)
            comp_cat_ua_list[comp_cat].append((ua, c, n_ips))
            for ip in merged["ua_ips"].get(ua, ()):
                if len(comp_cat_ips[comp_cat]) < MAX_IPS_PER_BUCKET:
                    comp_cat_ips[comp_cat].add(ip)
    traffic_composition = []
    for comp_cat, c in comp_cat_requests.most_common():
        ip_set = comp_cat_ips.get(comp_cat, ())
        # Top 3 IP-uri dupa cereri DIN aceasta categorie -- APROXIMARE: nu
        # tinem cereri per-(ip,categorie) (ar insemna o structura noua,
        # per-linie, pentru un caz de utilizare secundar), doar per-ip
        # (global) si per-ua (deja mapat pe categorie). Folosim cererile
        # TOTALE ale IP-ului (merged["ip_counter"]) ca proxy -- corect cat
        # timp un IP foloseste consistent UA-uri din aceeasi categorie (cazul
        # normal pt. crawlere/scripturi), optimist doar pt. IP-uri rare care
        # amesteca UA-uri din categorii diferite.
        top_ips_in_cat = sorted(
            ({"ip": ip, "requests": merged["ip_counter"].get(ip, 0)} for ip in ip_set),
            key=lambda x: -x["requests"]
        )[:3]
        top_uas_in_cat = [
            {"ua": u, "requests": r, "unique_ips": n}
            for u, r, n in sorted(comp_cat_ua_list.get(comp_cat, []), key=lambda x: -x[1])[:3]
        ]
        traffic_composition.append({
            "category": comp_cat,
            "requests": c,
            "pct": round(100 * c / merged["total"], 2) if merged["total"] else 0,
            "unique_ips": len(ip_set),
            "bandwidth": comp_cat_bandwidth.get(comp_cat, 0),
            "top_uas": top_uas_in_cat,
            "top_ips": top_ips_in_cat,
        })

    # --- Crawlers (Build 3) -- furnizori de crawlere CUNOSCUTI, agregati pe
    # identitate revendicata (Tier 1, vezi claim_ip_identity), plus doua
    # rânduri "fara Tier 2" (Unknown crawler / Suspicious automation)
    # preluate direct din Traffic Composition de mai sus. Verificarea DNS
    # (Tier 2, verified/unverified) NU se calculeaza aici -- ruleaza async
    # separat (vezi _start_crawler_verification) si e interogata de frontend
    # prin /crawler_verification(_status); aici doar pregatim datele "statice"
    # (cereri/bandwidth/IP-uri/detaliu per IP) disponibile instant.
    def _claim_ip_first_last(ip):
        ranges = merged["claim_ip_time_range"].get(ip) or []
        parsed = [p for pair in ranges for p in (parse_apache_time(pair[0]), parse_apache_time(pair[1])) if p is not None]
        if not parsed:
            return "", ""
        return min(parsed).strftime("%d/%b/%Y:%H:%M:%S %z"), max(parsed).strftime("%d/%b/%Y:%H:%M:%S %z")

    identity_agg = defaultdict(lambda: {"requests": 0, "bandwidth": 0, "ips": set()})
    for ip, identity in merged["claim_ip_identity"].items():
        agg = identity_agg[identity]
        agg["requests"] += merged["claim_ip_requests"].get(ip, 0)
        agg["bandwidth"] += merged["claim_ip_bandwidth"].get(ip, 0)
        agg["ips"].add(ip)

    crawlers_section = []
    MAX_CRAWLER_IPS_PER_PROVIDER = 500  # plafon pe cate IP-uri detaliem per provider (expand-ul din UI)
    for identity, _needles, _suffixes in CRAWLER_IDENTITY_CATALOG:
        agg = identity_agg.get(identity)
        if not agg:
            continue
        ip_details = []
        ranked_ips = sorted(agg["ips"], key=lambda x: -merged["claim_ip_requests"].get(x, 0))
        for ip in ranked_ips[:MAX_CRAWLER_IPS_PER_PROVIDER]:
            first_s, last_s = _claim_ip_first_last(ip)
            ip_details.append({
                "ip": ip, "country": country_of(ip),
                "requests": merged["claim_ip_requests"].get(ip, 0),
                "bandwidth": merged["claim_ip_bandwidth"].get(ip, 0),
                "top_paths": [{"path": p, "requests": n}
                              for p, n in merged["claim_ip_paths"].get(ip, Counter()).most_common(10)],
                "status_breakdown": dict(merged["claim_ip_status"].get(ip, Counter())),
                "first_seen": first_s, "last_seen": last_s,
            })
        crawlers_section.append({
            "provider": identity,
            "requests": agg["requests"],
            "unique_ips": len(agg["ips"]),
            "bandwidth": agg["bandwidth"],
            "has_tier2": True,   # are tabel PTR -- verificarea DNS (Tier 2) se aplica
            "ip_details": ip_details,
        })
    # "Unknown crawler" (fost "Alt bot / crawler") si "Suspicious automation"
    # -- fara identitate revendicata cunoscuta, deci FARA verificare Tier 2
    # (nu exista tabel de sufixe PTR pentru "bot generic"/"headless generic").
    for src_cat, provider_label in (("Other crawler/bot", "Unknown crawler"),
                                     ("Suspicious automation", "Suspicious automation")):
        tc = next((t for t in traffic_composition if t["category"] == src_cat), None)
        if not tc:
            continue
        crawlers_section.append({
            "provider": provider_label,
            "requests": tc["requests"],
            "unique_ips": tc["unique_ips"],
            "bandwidth": tc["bandwidth"],
            "has_tier2": False,
            # doar top 3 IP-uri disponibile aici (din Traffic Composition) --
            # fara path/status/first-last per IP, pentru ca nu tinem acele
            # detalii decat pentru IP-uri care revendica o identitate
            # cunoscuta (vezi claim_ip_paths/claim_ip_status mai sus).
            "ip_details": [{"ip": x["ip"], "requests": x["requests"], "country": country_of(x["ip"])}
                            for x in tc["top_ips"]],
        })
    crawlers_section.sort(key=lambda x: -x["requests"])

    # --- Activitate admin / WordPress per IP -- login-uri (incercari si
    # reusite), acces /wp-admin/ dupa login, instalare/editare plugin-uri
    # sau teme, upload prin admin-ajax (file manager), fisiere .php in
    # uploads/cache (posibil webshell). Un singur loc unde vezi, per IP, CE
    # anume a facut (nu doar CA a facut ceva) -- fara sa cauti manual prin
    # findings/WP panel/tabelul de IP-uri suspecte.
    admin_activity = []
    for ip, actions in merged["admin_activity_actions"].items():
        events = sorted(merged["admin_activity_events"].get(ip, []), key=lambda e: e[1])
        domains_seen = sorted({e[5] for e in events if e[5]})
        admin_activity.append({
            "ip": ip,
            "country": country_of(ip),
            "domains": domains_seen,
            "total_actions": sum(actions.values()),
            "actions": dict(actions.most_common()),
            "first_seen": events[0][1] if events else "",
            "last_seen": events[-1][1] if events else "",
            "events": [
                {"label": lbl, "time": t, "method": m, "path": p, "status": st, "domain": dom}
                for lbl, t, m, p, st, dom in events[:MAX_ADMIN_EVENTS_PER_IP]
            ],
        })
    admin_activity.sort(key=lambda x: -x["total_actions"])

    # --- Traseu de compromitere (compromise trail) -- pentru fiecare IP care
    # a generat cel putin un semnal (finding, login WP posibil reusit, sau
    # activitate admin/WP), unificam TOATE semnalele intr-o cronologie
    # unica, sortata dupa ora reala (nu alfabetic -- vezi parse_apache_time).
    # Raspunde direct la "cum a evoluat aceasta compromitere, de la primul
    # contact suspect pana la ce a facut efectiv" fara sa mai trebuiasca
    # corelat manual findings + panoul WP + activitatea admin. Scorul de risc
    # e o eristica DE PRIORITIZARE (pe ce IP sa te uiti primul), nu o
    # certitudine de compromitere.
    # SEVERITY_SCORE e acum definit la nivel de modul (vezi langa
    # _add_finding), cu toate cele 5 niveluri (CRITICAL..INFO) -- refolosit
    # aici direct, fara sa mai redefinim un dict local partial.
    ip_findings = defaultdict(list)
    for f in findings:
        if f.get("ip"):
            ip_findings[f["ip"]].append(f)
    ip_logins = defaultdict(list)
    for wl in wp_successful_logins:
        ip_logins[wl["ip"]].append(wl)

    trail_ip_set = set(ip_findings) | set(merged["admin_activity_actions"]) | set(ip_logins)
    compromise_trail = []
    for tip in trail_ip_set:
        events = []
        score = 0.0
        trail_domains = set()
        for f in ip_findings.get(tip, []):
            events.append({
                "type": "finding", "time": f.get("time", ""),
                "_dt": parse_apache_time(f.get("time", "")),
                "label": f.get("rule", ""), "detail": f.get("detail", ""),
                "severity": f.get("severity", ""), "domain": f.get("domain"),
                "status": (f.get("evidence") or {}).get("status"),
            })
            if f.get("domain"):
                trail_domains.add(f["domain"])
            score += SEVERITY_SCORE.get(f.get("severity", ""), 1)
        for lg in ip_logins.get(tip, []):
            conf = lg.get("confidence", "")
            events.append({
                "type": "login", "time": lg.get("time", ""),
                "_dt": parse_apache_time(lg.get("time", "")),
                "label": f"Login WP posibil reusit ({conf})",
                "detail": (f"confirmat printr-un acces /wp-admin/ real la {lg['confirmed_access_at']}"
                           if lg.get("confirmed_access_at") else "doar redirect 302, fara acces confirmat ulterior"),
                "severity": "HIGH" if conf == "HIGH" else "MEDIUM", "domain": lg.get("domain"),
            })
            if lg.get("domain"):
                trail_domains.add(lg["domain"])
            score += 8 if conf == "HIGH" else 4
        admin_events_ip = merged["admin_activity_events"].get(tip, [])
        for lbl, t, m, p, st, dom in admin_events_ip[:MAX_ADMIN_EVENTS_PER_IP]:
            events.append({
                "type": "admin", "time": t, "_dt": parse_apache_time(t),
                "label": lbl, "detail": f"{m} {p} -> {st}", "severity": "", "domain": dom,
                "status": st,
            })
            if dom:
                trail_domains.add(dom)
        admin_total = sum(merged["admin_activity_actions"].get(tip, {}).values())
        score += min(admin_total, 50) * 0.3
        country = country_of(tip)
        if country and country != "RO":
            score += 3
        if not events:
            continue
        events.sort(key=lambda e: (e["_dt"] is None, e["_dt"]))
        for e in events:
            e.pop("_dt", None)
        # --- Reclasificare (Faza 3, vezi _classify_trail_event) -- fiecare
        # eveniment primeste o categorie clara ("cerere suspecta"/"incercare
        # de atac"/"login reusit"/"activitate admin confirmata"/"compromitere
        # confirmata") + un motiv scurt, in loc sa fie doar implicit tratate
        # ca "traseu de compromitere". Categoria dominanta a IP-ului = cea
        # mai severa categorie aparuta macar o data (ordine fixa de
        # severitate), afisata direct in tabel, fara sa mai fie nevoie sa
        # deschizi fiecare eveniment ca sa vezi daca e ceva confirmat sau
        # doar suspiciune.
        cat_counts = Counter()
        for e in events:
            cat, reason = _classify_trail_event(e)
            e["category"] = cat
            e["category_label"] = _TRAIL_CATEGORY_LABELS.get(cat, cat)
            e["category_reason"] = reason
            cat_counts[cat] += 1
        _CAT_SEVERITY = ("confirmed_compromise", "successful_login", "attack_attempt",
                          "confirmed_admin_activity", "login_attempt", "suspicious_request")
        dominant_cat = next((c for c in _CAT_SEVERITY if cat_counts.get(c)), "suspicious_request")
        compromise_trail.append({
            "ip": tip,
            "country": country,
            "domains": sorted(trail_domains),
            "risk_score": round(score, 1),
            "total_events": len(events),
            "first_seen": events[0]["time"],
            "last_seen": events[-1]["time"],
            "summary": _narrate_compromise(events),
            "events": events[:300],
            "dominant_category": dominant_cat,
            "dominant_category_label": _TRAIL_CATEGORY_LABELS.get(dominant_cat, dominant_cat),
            "category_counts": dict(cat_counts),
        })
    compromise_trail.sort(key=lambda x: -x["risk_score"])
    compromise_trail = compromise_trail[:100]

    # --- Wordfence: path-uri de plugin-uri/teme WP cu vulnerabilitati
    # cunoscute in baza Wordfence, gasite in log. Best-effort -- lista e
    # goala daca feed-ul nu a fost (inca) descarcat cu succes. NU confirma
    # exploatare (access log-ul nu arata versiunea instalata) -- vezi
    # comentariul de la wordfence_match_paths().
    wordfence_matches = wordfence_match_paths(merged["top_paths"], merged["path_ips"])

    # --- Analiza parametrilor de query (Faza 2) -- categorizare din
    # query_key_counter (Counter de frecventa a NUMELUI parametrului,
    # agregat GRATUIT in _process_chunk, vezi mai sus) in 3 grupe +
    # "other" (vezi categorize_query_key). Cost: o singura iterare peste
    # cheile UNICE de query (de obicei zeci-sute, nu miliarde de linii).
    query_params = {"tracking": [], "functional": [], "suspicious": [], "cache_busting": [], "other": []}
    for key, c in merged["query_key_counter"].most_common(1000):
        cat = categorize_query_key(key)
        if len(query_params[cat]) < 150:
            query_params[cat].append({"key": key, "requests": c})

    # Toate anomaliile fusesera adaugate pana aici (wp-cron, distributed_enum,
    # subnets, top_bursts) -- sortare finala, o singura data, dupa severitate.
    anomalies.sort(key=lambda f: order.get(f["severity"], 9))

    days = sorted(merged["day_counter"].keys(), key=lambda d: _day_sort_key(d))
    # Graficul "Trafic in timp" e inutil (un singur punct) cand logul acopera
    # o singura zi -- caz FOARTE des intalnit (un access log rotit zilnic).
    # In cazul asta trecem automat pe granularitate ORARA. Si cand ORELE
    # colapseaza tot intr-un singur bucket (ex: statistici pentru un
    # interval de 30 minute dintr-o singura ora -- vezi /summary_range),
    # trecem mai departe pe granularitate pe MINUT, altfel graficul ar arata
    # un singur punct la fel de inutil. Cu 2+ zile ramanem la granularitatea
    # zilnica, ca inainte. Toate cele trei niveluri sunt calculate gratuit
    # (day_counter/day_hour_counter/minute_counter acumulate per-linie, fara
    # cost suplimentar aici).
    only_day = days[0] if len(days) == 1 else None
    hrs = sorted(h for (d, h) in merged["day_hour_counter"].keys() if d == only_day and h) if only_day else []
    if len(days) > 1:
        timeline = [{"day": d, "requests": merged["day_counter"][d]} for d in days]
        error_timeline = [
            {"day": d,
             "4xx": sum(c for (dd, hh), c in merged["err_hour_counter"].items() if dd == d),
             "5xx": sum(c for (dd, hh), c in merged["err5_hour_counter"].items() if dd == d)}
            for d in days
        ]
        timeline_granularity = "day"
    elif len(hrs) > 1:
        timeline = [{"day": f"{only_day} {h}:00", "requests": merged["day_hour_counter"][(only_day, h)]}
                    for h in hrs]
        error_timeline = [
            {"day": f"{only_day} {h}:00",
             "4xx": merged["err_hour_counter"].get((only_day, h), 0),
             "5xx": merged["err5_hour_counter"].get((only_day, h), 0)}
            for h in hrs
        ]
        timeline_granularity = "hour"
    else:
        only_hour = hrs[0] if hrs else None
        mins = sorted(m for (d, h, m) in merged["minute_counter"].keys() if d == only_day and h == only_hour)
        timeline = [{"day": f"{only_day} {only_hour}:{m}", "requests": merged["minute_counter"][(only_day, only_hour, m)]}
                    for m in mins]
        error_timeline = [
            {"day": f"{only_day} {only_hour}:{m}",
             "4xx": merged["err_minute_counter"].get((only_day, only_hour, m), 0),
             "5xx": merged["err5_minute_counter"].get((only_day, only_hour, m), 0)}
            for m in mins
        ]
        timeline_granularity = "minute"

    hours = sorted({h for (_, h) in merged["day_hour_counter"].keys() if h})
    heatmap = []
    for d in days:
        row = {"day": d, "hours": {h: merged["day_hour_counter"].get((d, h), 0) for h in hours}}
        heatmap.append(row)

    # Total cereri per tara (raspuns la "cate cereri a facut BD in total?").
    # O singura trecere peste ip_counter (deja calculat, un rand per IP unic,
    # NU per cerere), deci cost marginal: ~0.65s pentru 150k IP-uri unice
    # (geoip2fast, offline, masurat). Nu adauga nicio trecere noua prin log.
    _country_req = Counter()
    _country_ips = Counter()
    # RO vs restul lumii, compus dupa identitatea revendicata (Eduard: "de
    # obicei traficul non-RO e 90% Google" -- vrea sa vada asta direct, nu
    # doar suma bruta pe tara). Aceeasi trecere peste ip_counter de mai sus
    # (deja o singura trecere, geoip inclus) -- adaugam DOAR o acumulare
    # suplimentara in Counter-e separate pe RO/non-RO, folosind
    # claim_ip_identity/claim_ip_requests deja populate GRATUIT in bucla
    # per-linie existenta (Tier 1, UA claim) -- zero trecere noua prin log.
    _rvw_ro_by_identity = Counter()
    _rvw_nonro_by_identity = Counter()
    _rvw_ro_total = 0
    _rvw_nonro_total = 0
    # v44: IP-urile fara tara (GeoIP nu le rezolva) au propriul bucket -- NU
    # mai sunt numarate ca "non-RO" (aceeasi semantica ca indexul de triaj,
    # filtrul __non_ro__ si drill-down-urile; nu atribuim tari ghicite).
    _rvw_unk_by_identity = Counter()
    _rvw_unk_total = 0
    for _ip, _c in merged["ip_counter"].items():
        _cc = country_of(_ip) or "??"
        _country_req[_cc] += _c
        _country_ips[_cc] += 1
        _identity = merged["claim_ip_identity"].get(_ip) or "Fara identitate cunoscuta"
        if _cc == "RO":
            _rvw_ro_total += _c
            _rvw_ro_by_identity[_identity] += _c
        elif _cc == "??":
            _rvw_unk_total += _c
            _rvw_unk_by_identity[_identity] += _c
        else:
            _rvw_nonro_total += _c
            _rvw_nonro_by_identity[_identity] += _c
    _total_req_for_pct = sum(_country_req.values()) or 1
    country_totals = [
        {"country": cc, "requests": c, "unique_ips": _country_ips[cc],
         "pct": round(100.0 * c / _total_req_for_pct, 2)}
        for cc, c in _country_req.most_common(250)
    ]

    def _rvw_bucket(counter, total):
        denom = total or 1
        by_identity = [
            {"identity": ident, "requests": c, "pct": round(100.0 * c / denom, 2)}
            for ident, c in counter.most_common(30)
        ]
        return {"total": total, "by_identity": by_identity}

    ro_vs_world = {
        "ro": _rvw_bucket(_rvw_ro_by_identity, _rvw_ro_total),
        "non_ro": _rvw_bucket(_rvw_nonro_by_identity, _rvw_nonro_total),
        "unknown": _rvw_bucket(_rvw_unk_by_identity, _rvw_unk_total),
    }

    return {
        "total": merged["total"],
        "bad": merged["bad"],
        # spec §8: bilantul importului -- linii procesate / invalide / goale
        "lines": {"processed": merged["total"], "invalid": merged["bad"],
                  "blank": merged.get("blank", 0), "invalid_samples": merged.get("bad_samples", [])},
        "unique_ips": len(merged["ip_counter"]),
        # Distinct path_only (fara query string) -- len() direct pe Counter-ul
        # deja calculat in bucla per-linie (top_paths), zero cost suplimentar.
        # Distinct full path+query nu e tinut separat nicaieri in motor (ar fi
        # cardinalitate foarte mare pe site-uri cu navigare fatetata, fara
        # beneficiu clar) -- un singur numar e suficient aici (vezi spec KPI).
        "unique_paths": len(merged["top_paths"]),
        "bandwidth": merged["bandwidth"],
        "status": {
            "2xx": status_2xx, "3xx": status_3xx, "4xx": status_4xx, "5xx": status_5xx,
            "detail": {str(s): c for s, c in sorted(merged["status_counter"].items())
                       if s in (401, 403, 404, 405, 429, 500, 502, 503, 504)},
        },
        "top_ips": [{"ip": ip, "requests": c, "country": country_of(ip)}
                    for ip, c in merged["ip_counter"].most_common(300)],
        "top_ua": [{"ua": ua, "requests": c, "unique_ips": len(merged["ua_ips"].get(ua, ()))}
                   for ua, c in merged["ua_counter"].most_common(150)],
        "top_paths": [{"path": p, "requests": c, "unique_ips": len(merged["path_ips"].get(p, ()))}
                      for p, c in merged["top_paths"].most_common(300)],
        "top_paths_static": top_paths_static,
        "top_paths_risk": top_paths_risk,
        "top_paths_popular": top_paths_popular,
        "top_paths_dynamic": top_paths_dynamic,
        "top_paths_404": top_paths_404,
        "top_bursts": top_bursts,
        # cate ferestre de 30s ating/depasesc BURST_KPI_MIN_REQUESTS -- pentru
        # KPI-ul "Bursturi" (numarul brut de ferestre "de 30s cu trafic" ar fi
        # inutil de mare, aproape orice fereastra are >=1 cerere pe un site activ).
        "burst_window_count": sum(1 for cnt in merged["burst_counter"].values() if cnt >= BURST_KPI_MIN_REQUESTS),
        "methods": dict(merged["method_counter"]),
        # Praguri ridicate ~10x fata de versiunea veche (500/20/100/20/30/
        # 20/300/50) -- lista completa e disponibila la client, care taie
        # local cate randuri arata (vezi dashboard.html: dropdown "Arata").
        "findings": findings[:10000],
        "findings_count": len(findings),
        "anomalies": anomalies[:10000],
        "anomalies_count": len(anomalies),
        "query_params": query_params,
        "ro_vs_world": ro_vs_world,
        "distributed_enum": distributed_enum[:200],
        "top_path_prefixes": top_path_prefixes[:1000],
        "distributed_path_enum": distributed_path_enum[:200],
        "param_abuse": param_abuse[:300],
        "subnets": [
            {**s, "country": country_of(next(iter(merged["subnet_ips"].get(s["subnet"], ())), ""))}
            for s in subnets[:200]
        ],
        "all_subnets": [
            {**s, "country": country_of(next(iter(merged["subnet_ips"].get(s["subnet"], ())), ""))}
            for s in all_subnets[:3000]
        ],
        "all_subnets_min_requests": ALL_SUBNETS_MIN_REQUESTS,
        "all_subnets_min_ips": ALL_SUBNETS_MIN_IPS,
        "suspicious_ips": [{**s, "country": country_of(s["ip"])} for s in suspicious_ips[:500]],
        "wp": {
            "wp_admin": wp.get("wp_admin", 0),
            "admin_ajax": wp.get("admin_ajax", 0),
            "xmlrpc": wp.get("xmlrpc", 0),
            "wp_json": wp.get("wp_json", 0),
            "wp_cron": wp.get("wp_cron", 0),
            "wp_login_get": wp.get("wp_login_get", 0),
            "wp_login_post": wp.get("wp_login_post", 0),
            "top_login_ips": [{"ip": ip, "attempts": c, "country": country_of(ip)} for ip, c in wp_top_login_ips],
            "successful_logins": wp_successful_logins[:200],
            "successful_logins_count": len(wp_successful_logins),
            "note": "Successful login cannot be confirmed from access logs alone. "
                    "Lista de mai jos e o HEURISTICA (302 dupa POST wp-login.php, "
                    "optional confirmata de acces ulterior in /wp-admin/), nu o certitudine.",
        },
        "scan_hits": dict(merged["scan_hits"]),
        "timeline": timeline,
        "timeline_granularity": timeline_granularity,
        "error_timeline": error_timeline,
        "heatmap": {"days": days, "hours": hours, "rows": heatmap},
        "days_available": days_all if days_all is not None else days,
        "top_bandwidth_ips": top_bandwidth_ips,
        "bot_breakdown": bot_breakdown,
        "traffic_composition": traffic_composition,
        "crawlers": crawlers_section,
        "admin_activity": admin_activity[:200],
        "compromise_trail": compromise_trail,
        "wordfence_matches": wordfence_matches[:100],
        "wordfence_status": wordfence_status(),
        "investigation_queue": _build_investigation_queue(findings, anomalies),
        "country_totals": country_totals,
    }


_MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
           "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}


def _day_sort_key(day_str):
    # "18/Sep/2026" -> (2026, 9, 18)
    try:
        d, mon, y = day_str.split("/")
        return (int(y), _MONTHS.get(mon, 0), int(d))
    except Exception:
        return (0, 0, 0)


# --------------------------------------------------------------------------
# Verificare identitate crawler -- Tier 2 (DNS, async, in background dupa ce
# raspunsul principal de upload/summary a plecat deja -- vezi
# _start_crawler_verification, apelat din api_upload).
# --------------------------------------------------------------------------
# Executor PERSISTENT (nu recreat per dataset) -- concurenta maxima de IP-uri
# verificate simultan (nu de lookup-uri DNS individuale, vezi _call_with_timeout
# mai jos pentru cum se aplica timeout-ul per lookup).
_dns_executor = ThreadPoolExecutor(max_workers=DNS_VERIFY_MAX_WORKERS, thread_name_prefix="dnsverify")

# Cache in memorie, viata procesului, cheie=IP -- evita re-verificarea
# aceluiasi IP intre dataset-uri diferite (sau la re-analiza aceluiasi log).
# Fara persistenta pe disc (nu e nevoie -- se repopuleaza rapid). Plafon
# simplu (CRAWLER_VERIFY_CACHE_MAX): odata atins, pur si simplu nu mai
# adaugam intrari noi (cache-ul ramane util pentru IP-urile deja vazute,
# fara complexitatea unei politici LRU reale).
_CRAWLER_VERIFY_CACHE: Dict[str, Any] = {}
_CRAWLER_VERIFY_CACHE_LOCK = threading.Lock()

# dataset_id -> job dict: {total, completed, verified, unverified, not_checked,
# pending, results: {ip: {...}}}
_CRAWLER_JOBS: Dict[str, Dict[str, Any]] = {}
_CRAWLER_JOBS_LOCK = threading.Lock()


def _call_with_timeout(fn, args, timeout):
    """Ruleaza fn(*args) intr-un thread daemon separat si asteapta cel mult
    `timeout` secunde. socket.gethostbyaddr/gethostbyname NU respecta
    socket.setdefaulttimeout() (sunt wrappere directe peste resolver-ul de
    sistem, nu creaza un obiect socket Python) -- de-aia timeout-ul se aplica
    aici, la nivel de thread, nu la nivel de socket. Daca thread-ul nu
    termina la timp, il ABANDONAM (Python nu poate omori un thread blocat
    intr-un apel C) -- fiind daemon, nu blocheaza oprirea procesului; in cel
    mai rau caz ramane un thread agatat in fundal per lookup care a expirat,
    impact marginal pentru volumul de IP-uri unice verificate aici (Tier 1
    dedupe deja limiteaza la IP-uri care revendica o identitate cunoscuta).
    Intoarce (valoare, eroare_sau_None); la timeout eroarea e "timeout"."""
    box = {}

    def _run():
        try:
            box["value"] = fn(*args)
        except Exception as e:
            box["error"] = e

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        return None, "timeout"
    if "error" in box:
        return None, str(box["error"])
    return box.get("value"), None


def _verify_one_ip(ip, identity):
    """Tier 2: verificare DNS in doi pasi pentru un (ip, identitate
    revendicata prin UA la Tier 1):
    1) reverse DNS (PTR) -- hostname-ul trebuie sa se termine cu unul din
       sufixele acceptate pentru identitatea respectiva (CRAWLER_PTR_SUFFIXES);
    2) forward-confirm -- rezolvam acel hostname INAPOI la o adresa IP si
       verificam ca se potriveste cu IP-ul original. Fara acest pas, oricine
       isi poate seta manual (pe un domeniu pe care il controleaza) un PTR
       care ARATA a googlebot.com pe orice IP -- forward-confirm functioneaza
       pentru ca rezolvarea A/AAAA a acelui hostname e sub controlul
       proprietarului legitim al domeniului (google.com), nu al celui care
       a pus User-Agent-ul fals.
    verified=True doar daca AMBII pasi trec; False daca PTR raspunde dar nu
    se potriveste / forward-confirm esueaza (posibil spoofing); None
    ("not checked") daca lookup-ul a expirat sau a esuat tehnic (nu e o
    concluzie despre autenticitate, doar "n-am putut verifica")."""
    suffixes = CRAWLER_PTR_SUFFIXES.get(identity, ())
    if not suffixes:
        return {"verified": None, "ptr_hostname": "", "method": ["no_ptr_table"], "confidence": "not_checked"}
    # Retele publicate oficial (cand exista) -- verificare fara DNS
    for net in _CRAWLER_KNOWN_NETS.get(identity, ()):
        try:
            if ipaddress.ip_address(ip) in net:
                return {"verified": True, "ptr_hostname": "", "method": ["known_ip_range"], "confidence": "verified"}
        except ValueError:
            break
    if identity not in CRAWLER_DNS_VERIFIABLE:
        # Furnizorul NU documenteaza verificare prin reverse DNS (publica doar
        # liste de IP-uri / ASN) -- un PTR lipsa NU inseamna UA fals. Inainte
        # le marcam "unverified" (fals), ceea ce dadea fals-pozitive masive
        # (ex: Meta 2a03:2880::/32, ClaudeBot 216.73.216.x marcate false).
        # Acceptam doar un PTR care SE potriveste (verified True); altfel
        # "neverificabil", nu "fals".
        ptr_result, ptr_err = _call_with_timeout(socket.gethostbyaddr, (ip,), DNS_LOOKUP_TIMEOUT_SEC)
        if ptr_err is None and ptr_result:
            ptr_host = ptr_result[0]
            if any(ptr_host.rstrip(".").lower().endswith(suf) for suf in suffixes):
                fwd_result, fwd_err = _call_with_timeout(socket.gethostbyname, (ptr_host,), DNS_LOOKUP_TIMEOUT_SEC)
                if fwd_err is None and fwd_result == ip:
                    return {"verified": True, "ptr_hostname": ptr_host, "method": ["ptr_match", "forward_confirmed"], "confidence": "verified"}
            return {"verified": None, "ptr_hostname": ptr_host, "method": ["not_dns_verifiable"], "confidence": "not_checked"}
        return {"verified": None, "ptr_hostname": "", "method": ["not_dns_verifiable"], "confidence": "not_checked"}
    ptr_result, ptr_err = _call_with_timeout(socket.gethostbyaddr, (ip,), DNS_LOOKUP_TIMEOUT_SEC)
    if ptr_err == "timeout":
        return {"verified": None, "ptr_hostname": "", "method": ["ptr_timeout"], "confidence": "not_checked"}
    if ptr_err is not None or not ptr_result:
        return {"verified": False, "ptr_hostname": "", "method": ["ptr_lookup_failed"], "confidence": "unverified"}
    ptr_host = ptr_result[0]
    ptr_low = ptr_host.rstrip(".").lower()
    if not any(ptr_low.endswith(suf) for suf in suffixes):
        return {"verified": False, "ptr_hostname": ptr_host, "method": ["ptr_mismatch"], "confidence": "unverified"}
    fwd_result, fwd_err = _call_with_timeout(socket.gethostbyname, (ptr_host,), DNS_LOOKUP_TIMEOUT_SEC)
    if fwd_err == "timeout":
        return {"verified": None, "ptr_hostname": ptr_host, "method": ["ptr_match", "forward_timeout"], "confidence": "not_checked"}
    if fwd_err is not None or not fwd_result:
        return {"verified": False, "ptr_hostname": ptr_host, "method": ["ptr_match", "forward_failed"], "confidence": "unverified"}
    if fwd_result != ip:
        return {"verified": False, "ptr_hostname": ptr_host, "method": ["ptr_match", "forward_mismatch"], "confidence": "unverified"}
    return {"verified": True, "ptr_hostname": ptr_host, "method": ["ptr_match", "forward_confirmed"], "confidence": "verified"}


def _record_crawler_result(dataset_id, ip, res):
    with _CRAWLER_JOBS_LOCK:
        job = _CRAWLER_JOBS.get(dataset_id)
        if not job:
            return
        job["results"][ip] = res
        job["completed"] += 1
        v = res.get("verified")
        if v is True:
            job["verified"] += 1
        elif v is False:
            job["unverified"] += 1
        else:
            job["not_checked"] += 1


def _start_crawler_verification(dataset_id, claim_ip_identity):
    """Porneste (in fundal, thread daemon separat) verificarea DNS Tier 2
    pentru fiecare IP unic care revendica o identitate cunoscuta (Tier 1 --
    claim_ip_identity e deja deduplicat pe IP). NU blocheaza apelantul --
    raspunsul HTTP de /api/upload trebuie sa plece INAINTE ca verificarea sa
    se termine (poate dura cateva secunde pentru sute de IP-uri). Progresul
    se interogheaza prin /crawler_verification_status (polling din frontend)."""
    ip_identity_pairs = list(claim_ip_identity.items())
    with _CRAWLER_JOBS_LOCK:
        _CRAWLER_JOBS[dataset_id] = {
            "total": len(ip_identity_pairs), "completed": 0,
            "verified": 0, "unverified": 0, "not_checked": 0,
            "pending": bool(ip_identity_pairs), "results": {},
        }
    if not ip_identity_pairs:
        return

    def _runner():
        futures = {}
        for ip, identity in ip_identity_pairs:
            with _CRAWLER_VERIFY_CACHE_LOCK:
                cached = _CRAWLER_VERIFY_CACHE.get(ip)
            if cached is not None and cached.get("identity") == identity:
                _record_crawler_result(dataset_id, ip, cached)
                continue
            fut = _dns_executor.submit(_verify_one_ip, ip, identity)
            futures[fut] = (ip, identity)
        for fut in as_completed(list(futures.keys())):
            ip, identity = futures[fut]
            try:
                res = fut.result()
            except Exception:
                res = {"verified": None, "ptr_hostname": "", "method": ["internal_error"], "confidence": "not_checked"}
            res = dict(res)
            res["identity"] = identity
            with _CRAWLER_VERIFY_CACHE_LOCK:
                if len(_CRAWLER_VERIFY_CACHE) < CRAWLER_VERIFY_CACHE_MAX:
                    _CRAWLER_VERIFY_CACHE[ip] = res
            _record_crawler_result(dataset_id, ip, res)
        with _CRAWLER_JOBS_LOCK:
            job = _CRAWLER_JOBS.get(dataset_id)
            if job:
                job["pending"] = False

    threading.Thread(target=_runner, daemon=True, name=f"crawlerverify-{dataset_id[:8]}").start()


# --------------------------------------------------------------------------
# ==========================================================================
# Security Triage Engine (v43) -- index SQLite per-dataset + job de fundal
# pentru upload chunked (vezi triage_engine.py pentru schema/interogari
# generice, fara nicio dependinta de constantele de mai sus).
#
# Functiile de AICI cunosc clasificarea de securitate -- reutilizeaza
# regex-urile/needle-urile deja definite si validate mai sus in acest fisier
# (STATIC_ASSET_PHP_DISGUISE_RE, SUSPICIOUS_PATTERNS, is_risk_path,
# scan_signature_of), ca evenimentele indexate sa foloseasca EXACT acelasi
# vocabular ca findings-urile existente. _triage_index_chunk ramane TOP-LEVEL
# (nu closure) ca sa poata fi trimisa prin multiprocessing.Pool, exact ca
# _process_chunk/_scan_chunk_raw mai sus.
# ==========================================================================
ADMIN_GET_ACTION = "admin_get"
ADMIN_POST_ACTION = "admin_login_post"
ADMIN_SUCCESS_ACTION = "admin_login_success"

def _is_login_ep(po):
    """v47.3: wp-login.php se executa si cu PATH_INFO ('/wp-login.php/',
    '/wp-login.php/x') -- folosit de atacatori ca sa ocoleasca regulile care
    blocheaza exact 'wp-login.php'. Aceeasi definitie in triage_engine (GLOB)
    si triage_columnar."""
    return po.endswith("wp-login.php") or "wp-login.php/" in po


def _is_xmlrpc_ep(po):
    return po.endswith("xmlrpc.php") or "xmlrpc.php/" in po



# v47.4: fisiere din /wp-admin/ pe care WordPress le serveste FARA autentificare
# (le incarca chiar pagina de login, sau raspund 200 oricui). Un 200 pe ele NU
# e acces in admin; doar paginile care cer sesiune valida conteaza.
_WP_ADMIN_PUBLIC = ("load-styles.php", "load-scripts.php", "admin-ajax.php", "admin-post.php",
                    "install.php", "upgrade.php", "setup-config.php", "repair.php")
_WP_ADMIN_ASSET_EXT = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
                       ".woff", ".woff2", ".ttf", ".eot", ".map", ".txt")


def _is_admin_page(path_only_low):
    """True daca URL-ul (fara query, lowercase) e o pagina din /wp-admin/ care
    cere autentificare -- nu un fisier static sau un endpoint public."""
    i = path_only_low.find("/wp-admin/")
    if i < 0:
        return False
    rest = path_only_low[i + len("/wp-admin/"):]
    if rest.endswith(_WP_ADMIN_ASSET_EXT):
        return False
    base = rest.rsplit("/", 1)[-1]
    return base not in _WP_ADMIN_PUBLIC



def _fast_epoch(time_str):
    """'18/Sep/2026:15:02:05 +0300' -> epoch UTC (int), fara strptime (prea
    lent pe milioane de linii) -- acelasi principiu ca burst_key_of/day_of/
    hour_of mai sus (doar slicing + int(), fara regex)."""
    if len(time_str) == 20:
        time_str = time_str + " +0000"   # fara fus orar in log => UTC (vezi _TS_SHAPE_RE)
    if len(time_str) < 26:
        return 0
    try:
        day = int(time_str[0:2])
        mon = _MONTHS.get(time_str[3:6], 0)
        if not mon:
            return 0
        year = int(time_str[7:11])
        hh = int(time_str[12:14])
        mm = int(time_str[15:17])
        ss = int(time_str[18:20])
        tz_sign = 1 if time_str[21] == "+" else -1
        tz_hh = int(time_str[22:24])
        tz_mm = int(time_str[24:26])
        return calendar.timegm((year, mon, day, hh, mm, ss)) - tz_sign * (tz_hh * 3600 + tz_mm * 60)
    except Exception:
        return 0


def pattern_severity(name, status):
    """v47: severitatea unui tipar de atac in functie de codul de raspuns."""
    ok = 200 <= status < 300
    if name.startswith("sqli"):
        return "CRITICAL" if (ok or status >= 500) else "HIGH"
    return "HIGH" if ok else "MEDIUM"


def _suspicious_match_name(path_low, path_raw, referer):
    """Numele PRIMULUI pattern din SUSPICIOUS_PATTERNS care se potriveste pe
    path+referer (sau None). Acelasi algoritm folosit si de findings (in
    _process_chunk) si de clasificarea de triaj -- calculat O SINGURA DATA per
    linie si refolosit de amandoua, in loc sa fie rulat de doua ori."""
    if SUSPICIOUS_QUICK_RE.search(path_low) or SUSPICIOUS_QUICK_RE.search((referer or "").lower()):
        full = unquote(path_raw) + " " + unquote(referer or "")
        for name, pattern in SUSPICIOUS_PATTERNS:
            if pattern.search(full):
                return name
    return None


def classify_event_pre(method, path_raw, path_low, path_only, status, is_non_ro, susp_name, scan_sig):
    """Clasifica O SINGURA linie deja parsata -- severitate (CRITICAL/HIGH/
    MEDIUM/LOW/INFO), risk_score (0-100), action_type (eticheta scurta si
    stabila, folosita de UI pentru badge-uri/filtre) si un label de afisat.

    Primeste valorile DEJA calculate de bucla per-linie (path_low, path_only,
    numele pattern-ului suspect, semnatura de scanare) ca sa nu le recalculeze
    -- pe logul real (2.65M linii) recalcularea lor costa ~23s pe un core.
    Rezultat identic cu classify_event (verificat pe toate liniile din
    testing/test_parser.py).

    Corelarea INTRE linii (login POST -> GET 200 confirmat in max 5 min)
    NU se face aici -- functie stateless; se face in SQL, pe indecsi, in
    triage_engine.finalize_login_success(), dupa indexarea completa."""
    is_2xx = 200 <= status < 300
    pclean = path_only.lower()
    if ("wp-content/uploads" in path_low or "wp-content/cache" in path_low) and pclean.endswith(".php"):
        if is_2xx:
            return ("CRITICAL", 100, "webshell_active",
                    "Fisier .php in uploads/cache SERVIT cu succes -- webshell activ")
        return ("HIGH", 70, "webshell_attempt",
                "Fisier .php in uploads/cache -- incercare de webshell")
    if "/wp-" in path_low and STATIC_ASSET_PHP_DISGUISE_RE_LOW.search(path_low):
        if is_2xx:
            return ("CRITICAL", 100, "webshell_active",
                    "Fisier .php deghizat ca asset static -- SERVIT cu succes (webshell activ)")
        return ("HIGH", 70, "webshell_attempt",
                "Fisier .php deghizat ca asset static -- incercare de webshell")

    if susp_name:
        # v47: severitatea depinde de RASPUNSUL serverului, nu doar de tipar.
        #   sqli + 2xx/5xx  -> CRITICAL (payload procesat / eroare DB)
        #   alt tipar + 2xx -> HIGH (payload servit)
        #   3xx/4xx         -> tentativa blocata/redirectata: HIGH (sqli) / MEDIUM
        sev = pattern_severity(susp_name, status)
        risk = {"CRITICAL": 95, "HIGH": 65, "MEDIUM": 30}.get(sev, 10)
        return (sev, risk, f"pattern_{susp_name}", f"Pattern suspect: {susp_name}")

    if method == "POST" and (_is_login_ep(path_only) or _is_xmlrpc_ep(path_only)):
        if is_non_ro:
            return ("MEDIUM", 35, ADMIN_POST_ACTION, "Login POST wp-login/xmlrpc dintr-un IP non-RO")
        return ("LOW", 20, ADMIN_POST_ACTION, "Login POST wp-login/xmlrpc")

    if method == "GET" and status == 200 and _is_admin_page(path_only.lower()):
        if is_non_ro:
            return ("HIGH", 55, ADMIN_GET_ACTION, "Acces /wp-admin/ (200) dintr-un IP non-RO")
        return ("INFO", 5, ADMIN_GET_ACTION, "Acces /wp-admin/ (200)")

    risky = is_risk_path(path_only)
    if is_non_ro and risky:
        # v47: simpla atingere a wp-login/xmlrpc din strainatate = zgomot de
        # internet, nu compromitere -> MEDIUM (era HIGH).
        return ("MEDIUM", 30, "non_ro_admin_touch", "IP non-RO pe endpoint sensibil WordPress")

    if scan_sig:
        return ("MEDIUM", 25, "scan_signature", f"Semnatura de scanare: {scan_sig}")

    if risky:
        return ("LOW", 10, "risk_path", "Endpoint sensibil WordPress")

    if is_non_ro:
        return ("INFO", 1, "non_ro", "")
    return ("INFO", 0, "normal", "")


def classify_event(ip, method, path_raw, status, ua, referer, country):
    """Varianta de sine statatoare (calculeaza singura tot ce ii trebuie) --
    folosita de teste si de cai care nu au valorile precalculate. Delegheaza
    la classify_event_pre, deci exista o SINGURA implementare a regulilor."""
    path_low = path_raw.lower()
    qpos = path_raw.find("?")
    path_only = path_raw[:qpos] if qpos != -1 else path_raw
    is_non_ro = bool(country) and country.upper() != "RO"
    return classify_event_pre(method, path_raw, path_low, path_only, status, is_non_ro,
                              _suspicious_match_name(path_low, path_raw, referer),
                              scan_signature_of(path_low))


def _finalize_triage_index(dataset_id, workdir, shard_paths):
    """Finalizeaza indexul de triaj din shard-urile scrise DEJA de trecerea
    principala (run_engine cu index_workdir): primul shard devine indexul
    (redenumire), restul se lipesc, apoi indecsii + ANALYZE + corelarea de
    login-uri. Nu mai exista a doua trecere prin fisier (v43.1 o facea: +70s
    pe logul real). Seteaza triage_ready/triage_error pe dataset."""
    store = None
    try:
        t = time.time()
        db_path = triage_engine.db_path_for(workdir)
        entries = [tuple(sp) if isinstance(sp, (tuple, list)) else (sp,) for sp in (shard_paths or [])]
        sqlite_paths = [e[0] for e in entries]
        col_paths = [e[2] if len(e) > 2 else None for e in entries]
        rest = triage_engine.adopt_first_shard(db_path, sqlite_paths)
        conn = triage_engine.connect(db_path, for_write=True)
        try:
            t1 = time.time(); triage_engine.merge_shards(conn, rest); t_merge = time.time() - t1
            # v44: indexul COLUMNAR (coloane deja colectate de workeri in
            # trecerea de parsare) -> gata in 1-2 s, fara indecsi SQL/rollup-uri
            # (23 s pe 2M linii in v43.3) si fara cubul de agregare (19 s).
            if triage_columnar.AVAILABLE and col_paths and all(col_paths):
                try:
                    t1 = time.time()
                    store = triage_columnar.ColStore.build(col_paths, conn)
                    n_login = store.correlate_logins(conn)
                    store.order_asc  # precalcul ordine tabel (prima pagina instant)
                    # vederea implicita (fara filtre) + alertele: calculate o
                    # data aici, ca prima deschidere a panoului sa fie instanta
                    _ov_all = store.overview({})
                    store.top_alerts(60)
                    print(f"[timing] index_columnar={time.time()-t1:.1f}s randuri={store.n} "
                          f"login_ok={n_login} ram={store.memory_bytes() / 1048576:.0f}MB "
                          f"merge={t_merge:.1f}s", flush=True)
                except Exception as ce:
                    store = None
                    print(f"[triage] index columnar indisponibil ({ce}) -- se foloseste calea SQL", flush=True)
            if store is None:
                t1 = time.time(); triage_engine.create_indexes(conn); t_idx = time.time() - t1
                t1 = time.time(); triage_engine.finalize_login_success(conn); t_fin = time.time() - t1
                t1 = time.time(); triage_engine.build_rollups(conn); t_roll = time.time() - t1
                print(f"[timing] index_finalize={time.time()-t:.1f}s (merge={t_merge:.1f}s indexes={t_idx:.1f}s "
                      f"login_corr={t_fin:.1f}s rollups={t_roll:.1f}s shards={len(sqlite_paths)})", flush=True)
        finally:
            conn.close()
        try:
            _c2 = triage_engine.connect(db_path)
            _r = _c2.execute("SELECT ts_str FROM events LIMIT 1").fetchone()
            _c2.close()
            m_tz = re.search(r"([+-])(\d\d)(\d\d)$", _r[0] if _r else "")
            if m_tz:
                _LOG_TZ_OFFSET[0] = (1 if m_tz.group(1) == "+" else -1) * (int(m_tz.group(2)) * 3600 + int(m_tz.group(3)) * 60)
        except Exception:
            pass
        with DATASETS_LOCK:
            if dataset_id in DATASETS:
                DATASETS[dataset_id]["_col"] = store
                DATASETS[dataset_id]["engine"] = "columnar" if store is not None else "sql"
                if store is not None:
                    DATASETS[dataset_id]["_overview_cache"] = {"{}": dict(_ov_all, elapsed_ms=0)}
                DATASETS[dataset_id]["triage_ready"] = True
        # fisierele de progres/coloane ale workerilor nu mai sunt necesare
        for fn in os.listdir(workdir):
            if fn.endswith(".progress") or fn.endswith(".cols.pkl"):
                try:
                    os.unlink(os.path.join(workdir, fn))
                except OSError:
                    pass
    except Exception as e:
        with DATASETS_LOCK:
            if dataset_id in DATASETS:
                DATASETS[dataset_id]["triage_error"] = str(e)
        print(f"[triage] indexare esuata: {e}", flush=True)
        return
    if store is not None:
        return
    # Cubul de agregare (vezi triage_engine.build_cube) se construieste DUPA
    # ce indexul e marcat gata -- nu intarzie nimic; pana termina, sinteza
    # foloseste interogarea directa (acelasi rezultat, doar mai lent).
    try:
        t1 = time.time()
        conn = triage_engine.connect(triage_engine.db_path_for(workdir), for_write=True)
        try:
            n = triage_engine.build_cube(conn)
        finally:
            conn.close()
        with DATASETS_LOCK:
            if dataset_id in DATASETS:
                DATASETS[dataset_id].pop("_overview_cache", None)
        print(f"[timing] cub_agregare={time.time()-t1:.1f}s ({n} randuri)", flush=True)
    except Exception as e:
        print(f"[triage] cubul de agregare nu s-a putut construi (se foloseste interogarea directa): {e}", flush=True)


# --------------------------------------------------------------------------
# Job-uri de fundal + upload chunked (v43) -- raspunsul de upload NU mai
# asteapta parsarea+indexarea (care, pe un log mare, putea tine conexiunea
# HTTP deschisa minute la rand -- sursa timeout-urilor pe fisiere masive).
# Clientul trimite fisierul in bucati mici (/api/upload2/*), primeste un
# job_id imediat dupa ultima bucata, si interogheaza /api/jobs/{job_id}
# periodic pana la "done".
# --------------------------------------------------------------------------
JOBS: Dict[str, Dict[str, Any]] = {}
JOBS_LOCK = threading.Lock()
# max_workers=2: ThreadPoolExecutor NU porneste thread-uri la constructie
# (doar la primul submit()) -- sigur fata de mp.set_start_method("forkserver",
# force=True) din main(), care trebuie sa ruleze INAINTE sa existe orice alt
# thread (vezi comentariul din main()). Threadul in care ruleaza run_engine/
# _build_triage_index (care la randul lor fac mp.Pool()) e identic cu
# thread-ul de executie al unui "def" sincron FastAPI/Starlette deja folosit
# azi de api_upload -- zero risc nou.
_INGEST_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="ingest")
UPLOADS: Dict[str, Dict[str, Any]] = {}
UPLOADS_LOCK = threading.Lock()


def _set_job(job_id, **fields):
    with JOBS_LOCK:
        job = JOBS.setdefault(job_id, {"created": time.time()})
        job.update(fields)
        job["updated"] = time.time()


def _get_job(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        return dict(job) if job else None


def _run_ingest_job(job_id, plain_path, workdir, display_name, filenames, file_segments, content_sha=None):
    try:
        _set_job(job_id, status="parsing", progress=15, lines_done=0)
        _t = time.time()
        _total_bytes = max(1, os.path.getsize(plain_path))
        _mon_stop = threading.Event()

        def _progress_monitor():
            # Citeste fisierele *.progress scrise de workeri (vezi _process_chunk)
            # si actualizeaza job-ul: 15% -> 85% proportional cu bytes parcursi,
            # plus nr. de linii procesate pana acum.
            while not _mon_stop.wait(1.0):
                lines = done = 0
                try:
                    for fn in os.listdir(workdir):
                        if fn.endswith(".progress"):
                            try:
                                a, b = open(os.path.join(workdir, fn)).read().split()
                                lines += int(a); done += int(b)
                            except (OSError, ValueError):
                                pass
                except OSError:
                    pass
                pct = 15 + int(70 * min(1.0, done / _total_bytes))
                _set_job(job_id, progress=pct, lines_done=lines,
                         elapsed=round(time.time() - _t, 1))

        _mon = threading.Thread(target=_progress_monitor, daemon=True)
        _mon.start()
        try:
            merged = run_engine(plain_path, n_workers=None, day_filter=None, segments=file_segments,
                                index_workdir=workdir)
        finally:
            _mon_stop.set()
        _t_engine = time.time() - _t
        _set_job(job_id, progress=88, lines_done=merged.get("total", 0) + merged.get("bad", 0),
                 status="summarizing")
        shards = merged.pop("_shards", [])

        _t = time.time()
        summary = build_summary(merged)
        _t_summary = time.time() - _t
        print(f"[timing] run_engine={_t_engine:.1f}s build_summary={_t_summary:.1f}s "
              f"(workeri={_default_worker_count()}, cpu_count={os.cpu_count()}, "
              f"override={_ENV_MAX_WORKERS or '-'})", flush=True)
        days_available = summary["days_available"]
        try:
            day_offsets = day_offsets_from_bounds(merged["day_bounds"])
        except Exception:
            day_offsets = {}
        dataset_id = _new_dataset_id()
        with DATASETS_LOCK:
            DATASETS[dataset_id] = {
                "id": dataset_id,
                "created": time.time(), "workdir": workdir, "plain_path": plain_path,
                "filename": display_name, "source_files": filenames,
                "file_segments": file_segments, "days_available": days_available,
                "day_offsets": day_offsets, "summary_cache": {"ALL": summary},
                "triage_ready": False, "triage_error": None,
                "content_sha": content_sha,
            }
        _start_crawler_verification(dataset_id, merged["claim_ip_identity"])
        # "done" IMEDIAT ce sumarul e gata: toate taburile v42 devin utilizabile
        # fara sa mai astepte indexul. Indexul (deja scris in shard-uri in
        # aceeasi trecere) se finalizeaza imediat dupa, iar tabul Triaj arata
        # progresul si se populeaza singur cand e gata (triage_status).
        _set_job(job_id, status="done", progress=100, dataset_id=dataset_id,
                 filename=display_name, days=days_available, summary=summary)
        _finalize_triage_index(dataset_id, workdir, shards)
    except Exception as e:
        _set_job(job_id, status="error", error=str(e))


# --------------------------------------------------------------------------
# Dataset store (in memorie, cu TTL)
# --------------------------------------------------------------------------
def _new_dataset_id():
    return uuid.uuid4().hex


def sweeper():
    while True:
        time.sleep(120)
        now = time.time()
        with DATASETS_LOCK:
            expired = [did for did, ds in DATASETS.items() if now - ds["created"] > DATASET_TTL_SECONDS]
            for did in expired:
                ds = DATASETS.pop(did, None)
                if ds and ds.get("workdir") and os.path.isdir(ds["workdir"]):
                    shutil.rmtree(ds["workdir"], ignore_errors=True)
        with _CRAWLER_JOBS_LOCK:
            for did in expired:
                _CRAWLER_JOBS.pop(did, None)
        # v44: job-urile de upload tin sumarul COMPLET in memorie (zeci de MB
        # pe loguri mari) -- inainte nu se stergeau niciodata.
        with JOBS_LOCK:
            for jid in [j for j, job in JOBS.items() if now - job.get("updated", job.get("created", now)) > 3600]:
                JOBS.pop(jid, None)


# --------------------------------------------------------------------------
# FastAPI app
# --------------------------------------------------------------------------
app = FastAPI()


@app.get("/", response_class=HTMLResponse)
def index():
    dash_path = os.path.join(APP_DIR, "dashboard.html")
    if os.path.exists(dash_path):
        with open(dash_path, "r", encoding="utf-8") as f:
            # no-store: dupa o actualizare browserul nu mai poate servi dashboard-ul vechi din cache
            return HTMLResponse(f.read(), headers={"Cache-Control": "no-store"})
    return HTMLResponse("<h1>dashboard.html lipseste din directorul aplicatiei</h1>", status_code=500)


LOGSCAN_VERSION = "51.1"
_STATIC_FONTS = os.path.join(APP_DIR, "static", "fonts")


@app.get("/static/fonts/{name}")
def static_font(name: str):
    """Fonturile interfetei (IBM Plex, licenta OFL) -- servite local, fara CDN."""
    if not re.fullmatch(r"[a-z0-9-]+\.woff2", name):
        return JSONResponse({"error": "not found"}, status_code=404)
    path = os.path.join(_STATIC_FONTS, name)
    if not os.path.isfile(path):
        return JSONResponse({"error": "not found"}, status_code=404)
    return FileResponse(path, media_type="font/woff2", headers={"Cache-Control": "public, max-age=604800"})


_STATIC_FLAGS = os.path.join(APP_DIR, "static", "flags")


@app.get("/static/flags/{name}")
def static_flag(name: str):
    """v50: steagurile tarilor (flag-icons, licenta MIT) -- servite local, fara CDN."""
    if not re.fullmatch(r"[a-z]{2}\.svg", name):
        return JSONResponse({"error": "not found"}, status_code=404)
    path = os.path.join(_STATIC_FLAGS, name)
    if not os.path.isfile(path):
        return JSONResponse({"error": "not found"}, status_code=404)
    return FileResponse(path, media_type="image/svg+xml",
                        headers={"Cache-Control": "public, max-age=604800", "X-Content-Type-Options": "nosniff"})


@app.get("/api/version")
def api_version():
    """Versiunea care ruleaza (verificare rapida dupa instalare)."""
    return JSONResponse({"version": LOGSCAN_VERSION, "columnar": bool(getattr(triage_columnar, "AVAILABLE", False)),
                         "upload_gzip": True})


@app.post("/api/upload")
def api_upload(files: List[UploadFile] = File(...), force: bool = Form(default=False)):
    # IMPORTANT: def sincron, NU async def. Motorul de mai jos foloseste
    # multiprocessing.Pool (fork()), care e periculos daca ruleaza direct pe
    # thread-ul buclei asyncio a serverului -- daca fork-ul are loc exact
    # cand alt thread tine un lock intern, procesul-copil ramane blocat
    # definitiv (deadlock post-fork), fara sa mai raspunda niciodata. Cu
    # "def" simplu, FastAPI/Starlette ruleaza handler-ul intr-un thread din
    # pool-ul propriu, separat de bucla asyncio, ceea ce evita problema si,
    # in plus, nu mai blocheaza tot serverul (ex: /healthz) cat timp se
    # analizeaza un fisier mare.
    #
    # Suporta mai multe fisiere/arhive incarcate deodata (ex: log-uri din
    # luni diferite ale ACELUIASI domeniu) -- toate se decompreseaza si se
    # concateneaza intr-un singur fisier plain, care e apoi parsat o
    # singura data ca un dataset combinat (indexul per-zi/motorul de
    # analiza nu au nevoie de nicio modificare, ele oricum nu presupun ca
    # fisierul e cronologic -- vezi README, punctul 4).
    workdir = tempfile.mkdtemp(prefix="logscan_ds_")
    filenames: List[str] = []
    domain_guesses = []
    plain_parts: List[str] = []
    try:
        for f in files:
            raw_path = os.path.join(workdir, f"src_{len(filenames)}_{f.filename or 'upload.log'}")
            with open(raw_path, "wb") as out:
                shutil.copyfileobj(f.file, out, length=4 * 1024 * 1024)
            filenames.append(f.filename or "upload.log")
            try:
                part_path = decompress_to_plain(raw_path, workdir)
            except Exception as e:
                shutil.rmtree(workdir, ignore_errors=True)
                return JSONResponse({"error": f"{f.filename}: {e}"}, status_code=400)
            was_archive = part_path != raw_path
            # redenumim la un nume unic, ca sa nu se suprapuna cu urmatorul
            # decompress_to_plain din bucla, care ar produce mereu "plain.log"
            fixed = os.path.join(workdir, f"plain_{len(plain_parts)}.log")
            os.replace(part_path, fixed)
            part_path = fixed
            if was_archive and os.path.exists(raw_path):
                os.remove(raw_path)  # nu mai avem nevoie de arhiva comprimata
            plain_parts.append(part_path)
            domain_guesses.append(extract_domain_from_filename(f.filename))
    except Exception as e:
        shutil.rmtree(workdir, ignore_errors=True)
        return JSONResponse({"error": str(e)}, status_code=400)

    if not plain_parts:
        shutil.rmtree(workdir, ignore_errors=True)
        return JSONResponse({"error": "Niciun fisier primit."}, status_code=400)

    # Detectie mismatch de domeniu: comparam doar fisierele la care am putut
    # ghici un domeniu din nume -- daca sunt cel putin 2 domenii DIFERITE
    # detectate, avertizam (dar nu blocam automat -- userul poate confirma
    # explicit cu force=true, poate stie el ce face, ex. redirect-uri intre
    # domenii sau nume de fisier atipice).
    known_domains = sorted(set(d for d in domain_guesses if d))
    domain_mismatch = len(known_domains) > 1
    if domain_mismatch and not force:
        shutil.rmtree(workdir, ignore_errors=True)
        return JSONResponse({
            "domain_mismatch": True,
            "domains_detected": known_domains,
            "per_file": [{"filename": fn, "domain": dg} for fn, dg in zip(filenames, domain_guesses)],
            "message": (
                "Fisierele incarcate nu par sa fie din acelasi domeniu (domenii "
                "detectate din nume: " + ", ".join(known_domains) + "). Daca esti "
                "sigur ca vrei sa le combini oricum, confirma si incarca din nou."
            ),
        }, status_code=409)

    # file_segments: pentru upload-uri multi-fisier, byte-range-ul exact
    # [start,end) al fiecarui fisier sursa in fisierul combinat, cu eticheta
    # de domeniu (din numele fisierului, sau numele fisierului insusi daca
    # domeniul n-a putut fi ghicit). Permite motorului sa marcheze fiecare
    # eveniment (login, activitate admin, finding) cu domeniul/subdomeniul
    # exact pe care s-a intamplat -- esential cand combini loguri de la mai
    # multe subdomenii/domenii intr-un singur dataset (vezi build_summary /
    # "Traseu de compromitere"). None pentru un singur fisier -- fara cost.
    file_segments = None
    if len(plain_parts) == 1:
        plain_path = plain_parts[0]
    else:
        plain_path = os.path.join(workdir, "combined.log")
        file_segments = []
        with open(plain_path, "wb") as fout:
            for idx, part in enumerate(plain_parts):
                seg_start = fout.tell()
                with open(part, "rb") as fin:
                    shutil.copyfileobj(fin, fout, length=4 * 1024 * 1024)
                fout.write(b"\n")
                seg_end = fout.tell()
                label = domain_guesses[idx] or os.path.splitext(filenames[idx])[0]
                file_segments.append((seg_start, seg_end, label))
                os.remove(part)

    merged = run_engine(plain_path, n_workers=None, day_filter=None, segments=file_segments,
                        index_workdir=workdir)
    _shards = merged.pop("_shards", [])
    summary = build_summary(merged)

    days_available = summary["days_available"]
    # Indexul per-zi vine GRATUIT din day_bounds, calculat in aceeasi (si
    # singura) trecere completa de mai sus -- fara nicio a doua trecere prin
    # fisier ca in versiunile anterioare (asta era, de departe, cel mai mare
    # cost la upload pentru fisiere mari). Vezi day_offsets_from_bounds().
    try:
        day_offsets = day_offsets_from_bounds(merged["day_bounds"])
    except Exception:
        day_offsets = {}  # daca ceva neasteptat esueaza, filtrarea pe zi ramane corecta, doar mai lenta

    display_name = filenames[0] if len(filenames) == 1 else f"{filenames[0]} (+{len(filenames)-1} alte fisiere)"
    dataset_id = _new_dataset_id()
    with DATASETS_LOCK:
        DATASETS[dataset_id] = {
            "id": dataset_id,
            "created": time.time(),
            "workdir": workdir,
            "plain_path": plain_path,
            "filename": display_name,
            "source_files": filenames,
            "file_segments": file_segments,
            "days_available": days_available,
            "day_offsets": day_offsets,
            # "ALL" e deja calculat aici, zero cost suplimentar -- il
            # pre-populam in cache ca sa fie instant la orice revenire pe
            # "toate zilele" dupa ce userul a navigat pe zile individuale.
            "summary_cache": {"ALL": summary},
            # Index SQLite (v43, Security Triage) -- construit separat, in
            # fundal (vezi _index_only_job mai jos), ca sa nu intarzie
            # raspunsul de upload. Tab-ul "Triaj" afiseaza "se indexeaza..."
            # pana devine True (de obicei cateva secunde).
            "triage_ready": False,
            "triage_error": None,
        }

    # Tier 2 (verificare DNS) porneste AICI, in fundal -- dupa ce dataset-ul
    # e deja salvat, dar INAINTE de raspunsul HTTP de mai jos (care pleaca
    # imediat, fara sa astepte verificarea -- vezi _start_crawler_verification).
    # claim_ip_identity e deja deduplicat pe IP (Tier 1, calculat in aceeasi
    # trecere ca restul motorului -- vezi _process_chunk).
    _start_crawler_verification(dataset_id, merged["claim_ip_identity"])
    # Index de securitate (v43) -- la fel, in fundal, dupa raspuns.
    _INGEST_EXECUTOR.submit(_finalize_triage_index, dataset_id, workdir, _shards)

    return JSONResponse({
        "dataset_id": dataset_id,
        "filename": display_name,
        "source_files": filenames,
        "days": summary["days_available"],
        "summary": summary,
    })


def _get_dataset(dataset_id):
    with DATASETS_LOCK:
        return DATASETS.get(dataset_id)


def _region_for_day(ds, day_filter):
    """Intoarce (start,end) din indexul per-zi calculat la upload, daca
    exista pentru ziua ceruta -- altfel None (motorul scaneaza tot
    fisierul, mai lent dar tot corect)."""
    if not day_filter:
        return None
    return ds.get("day_offsets", {}).get(day_filter)


def _cache_key(day):
    return "ALL" if day in ("ALL", "", None) else day


@app.get("/api/dataset/{dataset_id}/summary")
def api_summary(dataset_id: str, day: str = Query(default="ALL")):
    ds = _get_dataset(dataset_id)
    if not ds:
        return JSONResponse({"error": "Dataset expirat sau inexistent. Reincarca fisierul."}, status_code=404)
    ckey = _cache_key(day)
    cache = ds.setdefault("summary_cache", {})
    cached = cache.get(ckey)
    if cached is not None:
        return JSONResponse(_summary_without_fp(dataset_id, cached))
    day_filter = None if ckey == "ALL" else ckey
    region = _region_for_day(ds, day_filter)
    merged = run_engine(ds["plain_path"], n_workers=None, day_filter=day_filter, region=region,
                         segments=ds.get("file_segments"))
    # lista completa de zile ramane cea a fisierului intreg (calculata o data la upload)
    full_days = ds.get("days_available")
    summary = build_summary(merged, days_all=full_days)
    with DATASETS_LOCK:
        cache[ckey] = summary
    return JSONResponse(_summary_without_fp(dataset_id, summary))


_FP_KEEP_RULE_WORDS = ("login reusit", "SERVIT", "webshell activ")


def _summary_without_fp(dataset_id, summary):
    return _reconcile_summary(dataset_id, _summary_without_fp_raw(dataset_id, summary))


def _summary_without_fp_raw(dataset_id, summary):
    """v47: scoate din findings / IP-uri suspecte crawlerele VERIFICATE prin
    DNS (fals pozitive), pastrand doar dovezile reale de compromitere.
    Numarul eliminat e raportat in summary["fp_suppressed"]."""
    ds = _get_dataset(dataset_id) or {}
    if ds.get("show_fp"):
        return summary
    ver = _verified_crawler_ips(dataset_id)
    if not ver:
        return summary
    out = dict(summary)
    keep = lambda f: (f.get("ip") not in ver) or any(w in (f.get("rule") or "") for w in _FP_KEEP_RULE_WORDS)
    fs = summary.get("findings") or []
    out["findings"] = [f for f in fs if keep(f)]
    sips = summary.get("suspicious_ips") or []
    out["suspicious_ips"] = [x for x in sips if x.get("ip") not in ver]
    out["fp_suppressed"] = {"findings": len(fs) - len(out["findings"]),
                            "suspicious_ips": len(sips) - len(out["suspicious_ips"]),
                            "verified_crawler_ips": len(ver)}
    return out


@app.get("/api/dataset/{dataset_id}/crawler_verification_status")
def api_crawler_verification_status(dataset_id: str):
    """Progres al verificarii DNS Tier 2 (vezi _start_crawler_verification) --
    frontend-ul face polling la asta la ~1-2s cat timp 'pending' e true, apoi
    se opreste. Raspunde instant (doar citeste un dict in memorie)."""
    ds = _get_dataset(dataset_id)
    if not ds:
        return JSONResponse({"error": "Dataset expirat sau inexistent. Reincarca fisierul."}, status_code=404)
    with _CRAWLER_JOBS_LOCK:
        job = _CRAWLER_JOBS.get(dataset_id)
        if not job:
            return JSONResponse({"total_to_check": 0, "completed": 0, "verified_count": 0,
                                  "unverified_count": 0, "not_checked_count": 0, "pending": False})
        return JSONResponse({
            "total_to_check": job["total"],
            "completed": job["completed"],
            "verified_count": job["verified"],
            "unverified_count": job["unverified"],
            "not_checked_count": job["not_checked"],
            "pending": job["pending"],
        })


@app.get("/api/dataset/{dataset_id}/crawler_verification")
def api_crawler_verification(dataset_id: str):
    """Rezultatele per-IP ale verificarii DNS Tier 2, pe masura ce devin
    disponibile (partial in timp ce 'pending' e true, complet dupa)."""
    ds = _get_dataset(dataset_id)
    if not ds:
        return JSONResponse({"error": "Dataset expirat sau inexistent. Reincarca fisierul."}, status_code=404)
    with _CRAWLER_JOBS_LOCK:
        job = _CRAWLER_JOBS.get(dataset_id)
        results = dict(job["results"]) if job else {}
        pending = job["pending"] if job else False
    out = {
        ip: {
            "claimed": res.get("identity"),
            "verified": res.get("verified"),
            "ptr_hostname": res.get("ptr_hostname", ""),
            "method": res.get("method", []),
            "confidence": res.get("confidence", ""),
        }
        for ip, res in results.items()
    }
    return JSONResponse({"pending": pending, "results": out})


@app.get("/api/dataset/{dataset_id}/summary_range")
def api_summary_range(dataset_id: str, day: str = Query(default=""), hour: str = Query(default=""),
                       minute: str = Query(default=""), span: int = Query(default=1)):
    """La fel ca /summary, dar restrans la un interval exact in interiorul
    unei zile (ora, sau ora+minut cu granularitate 10/30/exact) -- acelasi
    JSON complet (KPI-uri, timeline, top IP-uri/path-uri, findings etc.) ca
    orice alta selectie de zi, doar ca pentru intervalul cerut. Fara asta,
    'Vezi cererile dintr-un moment exact' arata doar liniile brute -- util,
    dar nu si un total/agregat pentru acel interval. Nu foloseste
    summary_cache (intervalele sunt combinatii prea multe ca sa merite
    cache-uite), dar ramane rapid: regiunea scanata e restransa la ziua
    respectiva (day_offsets calculat la upload), iar in interiorul ei
    filtrarea pe ora/minut se face per-linie in aceeasi trecere, fara cost
    suplimentar de I/O."""
    ds = _get_dataset(dataset_id)
    if not ds:
        return JSONResponse({"error": "Dataset expirat sau inexistent. Reincarca fisierul."}, status_code=404)
    day_filter = day or None
    hour_filter = hour or None
    minute_filter = None
    if minute != "":
        try:
            minute_filter = (int(minute), max(1, min(60, span)))
        except ValueError:
            minute_filter = None
    region = _region_for_day(ds, day_filter)
    merged = run_engine(ds["plain_path"], n_workers=None, day_filter=day_filter, region=region,
                         hour_filter=hour_filter, minute_filter=minute_filter,
                         segments=ds.get("file_segments"))
    full_days = ds.get("days_available")
    summary = build_summary(merged, days_all=full_days)
    return JSONResponse(summary)


def _coalesce_ranges(offsets):
    """(start,end) consecutive (end == urmatorul start) -> un singur interval,
    ca citirea sa fie secventiala acolo unde liniile candidate sunt adiacente."""
    cur = None
    for a, b in offsets:
        if cur is not None and a == cur[1]:
            cur[1] = b
            continue
        if cur is not None:
            yield (cur[0], cur[1])
        cur = [a, b]
    if cur is not None:
        yield (cur[0], cur[1])


def _raw_index_filters(dataset_id, ds, ip="", path="", ua="", country_filter=None, day=""):
    """Filtrele de drill-down exprimabile in index, sau None daca indexul nu
    ajuta (nu e gata, sau filtrul nu e selectiv). Filtrele neexprimabile
    (subnet, semnatura, qkey, identitate, ora/minut/secunda) sunt aplicate
    oricum de predicatul exact din _scan_chunk_raw pe fiecare candidat."""
    if not ds.get("triage_ready"):
        return None
    f = {}
    if ip:
        f["ip"] = ip
    if ua:
        f["ua"] = ua
    if path:
        f["path_contains"] = path
    if country_filter:
        share = _country_share(dataset_id, ds, country_filter)
        if share is not None and share <= 0.25:
            f["countries"] = [country_filter]
    if not f:
        return None  # nimic selectiv: scanarea veche (cu oprire la plafon) e deja rapida
    if day:
        f["ts_str_day"] = day
    return f


def _country_share(dataset_id, ds, country_filter):
    """Ponderea tarii in dataset (din valorile precalculate ale indexului)."""
    cache = ds.get("_country_share")
    if cache is None:
        cache = {}
        store = _col_store(ds)
        rows = None
        if store is not None:
            rows = store.distinct("country")
        else:
            conn, _err = _get_triage_conn(dataset_id)
            if conn is not None:
                try:
                    rows = triage_engine.distinct_values(conn, "country")
                finally:
                    conn.close()
        if rows is not None:
            total = sum(r["count"] for r in rows) or 1
            cache = {(r["value"] or "??"): r["count"] / total for r in rows}
            cache["__NON_RO__"] = 1.0 - cache.get("RO", 0.0) - cache.get("??", 0.0)
        ds["_country_share"] = cache
    key = country_filter if country_filter in ("__NON_RO__", "??") else (country_filter or "").upper()
    return cache.get(key, 0.0) if cache else None


@app.get("/api/dataset/{dataset_id}/raw")
def api_raw(dataset_id: str, ip: str = Query(default=""), path: str = Query(default=""),
            subnet: str = Query(default=""), day: str = Query(default=""),
            sig: str = Query(default=""), hour: str = Query(default=""),
            minute: str = Query(default=""), span: int = Query(default=1),
            ua: str = Query(default=""), limit: int = Query(default=MAX_RAW_MATCHES),
            second: str = Query(default=""), window_seconds: int = Query(default=30),
            qkey: str = Query(default=""), country: str = Query(default=""),
            identity: str = Query(default=""),
        gf: str = Query(default="")):
    ds = _get_dataset(dataset_id)
    if not ds:
        return JSONResponse({"error": "Dataset expirat sau inexistent."}, status_code=404)
    gf_f, gf_err = _gf_for_scan(ds, gf)
    if gf_err is not None:
        return gf_err

    subnet_prefix = normalize_subnet_filter(subnet)
    plain_path = ds["plain_path"]

    # `limit` vine de la clientul din browser (picker-ul din modalul de
    # drill-down: 500/2000/10000/"tot, in limita a 20000") -- clampat intre
    # 1 si RAW_MATCHES_HARD_CAP, ca sa nu poata cere cineva un numar absurd
    # de linii (accidental sau nu) si sa umple memoria/raspunsul HTTP.
    effective_limit = max(1, min(int(limit) if limit else MAX_RAW_MATCHES, RAW_MATCHES_HARD_CAP))

    # minute_filter = (minut_start, span_in_minute) -- span permite intervale
    # de 10/30 min, nu doar un minut exact (span=1).
    minute_filter = None
    if minute:
        try:
            minute_filter = (int(minute), max(1, min(60, span)))
        except ValueError:
            minute_filter = None

    # second_filter: cautare pe timestamp exact (HH:MM:SS) +/- window_seconds,
    # prioritar fata de hour/minute_filter cand e completat -- vezi
    # _scan_chunk_raw. Format asteptat strict "HH:MM:SS" (cel al
    # <input type="time" step="1">); orice altceva e ignorat silentios.
    second_filter = None
    if second:
        m = re.match(r"^(\d{1,2}):(\d{2}):(\d{2})$", second.strip())
        if m:
            hh, mm, ss = (int(x) for x in m.groups())
            if 0 <= hh < 24 and 0 <= mm < 60 and 0 <= ss < 60:
                target_seconds = hh * 3600 + mm * 60 + ss
                second_filter = (target_seconds, max(0, min(3600, window_seconds)))
                # cand se cere fereastra exacta, ignoram hour/minute_filter
                # (second_filter e mai precis si le include pe amandoua)
                minute_filter = None
                hour = ""

    # qkey: filtreaza cererile a caror QUERY STRING contine parametrul dat ca
    # nume de cheie (ex: qkey=filter_culoare potriveste ?filter_culoare=x&...
    # dar NU ?altceva=filter_culoare). Match doar pe partea de query (dupa
    # "?"), aceeasi clasa de cost ca filtrele ua/path existente -- niciun scan
    # nou, doar un regex .search() suplimentar in worker-ul deja existent.
    qkey_re = None
    if qkey:
        qkey_re = re.compile(r"(?:^|[?&])" + re.escape(qkey) + r"=")

    # country: filtreaza cererile brute a caror IP se rezolva (geoip offline,
    # country_of()) la codul de tara dat (potrivire EXACTA pe 2 litere,
    # case-insensitive) -- click pe un rand din tabelul "Cereri totale pe
    # tara" (tblCountry, dashboard.html). Vezi _scan_chunk_raw pentru unde
    # se aplica efectiv filtrul (per linie, in acelasi worker deja folosit
    # de ip/path/ua/qkey).
    country_filter = None
    if country and country.strip():
        _country_raw = country.strip()
        # Sentinela "__non_ro__" (frontend, cardul RO vs restul lumii): orice
        # tara AFARA de RO -- vezi _scan_chunk_raw pentru unde se aplica.
        # Codurile reale de tara raman neschimbate (potrivire exacta pe 2
        # litere, case-insensitive).
        _cn = normalize_country_value(_country_raw)
        if _cn is None:
            return JSONResponse({"error": f"Tara '{_country_raw}' nu e recunoscuta -- foloseste codul ISO din 2 "
                                          f"litere (ex. RO, DE), '??' pentru tara nedeterminata sau __non_ro__."},
                                status_code=400)
        country_filter = "??" if _cn == "" else _cn

    # identity: filtreaza cererile brute a caror UA revendica (Tier 1,
    # classify_crawler_claim) identitatea data -- click pe cardul RO vs
    # restul lumii, bar chart-ul "Compus din (identitate)". Sentinela
    # "__none__" = liniile FARA nicio revendicare cunoscuta ("Fara identitate
    # cunoscuta"). Vezi _scan_chunk_raw pentru unde se aplica efectiv.
    identity_filter = None
    if identity and identity.strip():
        identity_filter = identity.strip().lower()

    # --- v43.2: drill-down prin index cand filtrul e SELECTIV ---------------
    # Varianta veche rescana tot fisierul (764 MB pe logul real) la FIECARE
    # click; pentru un filtru rar (un IP, o tara mica, un UA, un path rar)
    # asta insemna citirea aproape a intregului fisier. Indexul de triaj stie
    # offset-ul fiecarei linii: citim DOAR liniile candidate si le aplicam
    # EXACT acelasi predicat (_scan_chunk_raw), deci rezultatul e identic.
    # Pentru filtre dominante (ex. o tara cu 97% din trafic) scanarea veche,
    # care se opreste la plafon dupa primele linii, e deja instantanee.
    idx_filters = _raw_index_filters(dataset_id, ds, ip=ip, path=path, ua=ua,
                                     country_filter=country_filter, day=day)
    if gf_f is not None:
        # v45: drilldown = selectia globala (perioada + filtre) SI entitatea
        base = dict(idx_filters or {})
        if base.get("countries"):
            base["countries"] = ["" if c == "??" else c for c in base["countries"]]
        idx_filters = _gf_merge(gf_f, base)
    if idx_filters is not None:
        store = _col_store(ds)
        if store is not None:
            # v44: offset-urile vin direct din indexul columnar (exact aceeasi
            # selectie ca SQL), fara nicio interogare
            if idx_filters.get("countries"):
                idx_filters["countries"] = ["" if c == "??" else c for c in idx_filters["countries"]]
            matches, hit_cap = _scan_chunk_raw((
                plain_path, 0, 0, ip, subnet_prefix, path, day, effective_limit, None,
                sig or None, hour or None, minute_filter, ua or None, second_filter, qkey_re,
                country_filter, identity_filter, store.offsets(idx_filters)))
            return JSONResponse({"matches": matches[:effective_limit],
                                 "truncated": bool(hit_cap or len(matches) > effective_limit),
                                 "limit": effective_limit, "via_index": True})
        conn, _err = _get_triage_conn(dataset_id)
        if conn is not None:
            try:
                ranges = _coalesce_ranges(triage_engine.candidate_offsets(conn, idx_filters))
                matches, hit_cap = _scan_chunk_raw((
                    plain_path, 0, 0, ip, subnet_prefix, path, day, effective_limit, None,
                    sig or None, hour or None, minute_filter, ua or None, second_filter, qkey_re,
                    country_filter, identity_filter, ranges))
            finally:
                conn.close()
            return JSONResponse({"matches": matches[:effective_limit],
                                 "truncated": bool(hit_cap or len(matches) > effective_limit),
                                 "limit": effective_limit, "via_index": True})

    region = _region_for_day(ds, day) if day else None
    n_workers = _default_worker_count()
    # marimea REGIUNII (nu a fisierului intreg) -- vezi comentariul din
    # run_engine/_safe_worker_count: un drill-down pe o singura zi nu trebuie
    # sa porneasca un Pool dimensionat dupa tot fisierul.
    scan_size = (region[1] - region[0]) if region is not None else os.path.getsize(plain_path)
    n_workers = _safe_worker_count(scan_size, n_workers)
    if region is not None:
        chunks = find_chunk_offsets(plain_path, n_workers, region_start=region[0], region_end=region[1])
    else:
        chunks = find_chunk_offsets(plain_path, n_workers)
    args = [(plain_path, s, e, ip, subnet_prefix, path, day, effective_limit, None,
              sig or None, hour or None, minute_filter, ua or None, second_filter, qkey_re,
              country_filter, identity_filter) for s, e in chunks]

    if len(chunks) <= 1:
        chunk_results = [_scan_chunk_raw(args[0])] if args else []
    else:
        chunk_results = _pool_map(_scan_chunk_raw, args, len(chunks))

    matches = []
    truncated = False
    for cmatches, hit_cap in chunk_results:
        matches.extend(cmatches)
        if hit_cap:
            truncated = True
    if len(matches) > effective_limit:
        truncated = True
    matches = matches[:effective_limit]

    return JSONResponse({"matches": matches, "truncated": truncated, "limit": effective_limit})


@app.get("/api/dataset/{dataset_id}/windows")
def api_windows(dataset_id: str, day: str = Query(default=""),
                 window_seconds: int = Query(default=30),
                 ip: str = Query(default=""), subnet: str = Query(default=""),
                 path: str = Query(default=""), method: str = Query(default=""),
                 status_class: str = Query(default=""), status: str = Query(default=""),
                 ua: str = Query(default=""), has_query: str = Query(default=""),
                 referer_empty: str = Query(default=""), country: str = Query(default=""),
                 identity: str = Query(default=""), pattern: str = Query(default=""),
                 qkey: str = Query(default=""),
                 ua_category: str = Query(default=""), crawler_fake: str = Query(default=""),
                 limit: int = Query(default=300),
        gf: str = Query(default="")):
    """Explorator de loguri (Eduard): dat un interval (zi) + o marime de
    fereastra (30/60/600s) + orice combinatie din cele ~11 filtre (vezi
    _parse_window_filters), intoarce TOATE ferestrele cu cel putin o cerere
    care trece de filtre -- clientul sorteaza/afiseaza (implicit primele 10,
    dupa nr. de cereri) fara sa mai re-interogheze serverul la schimbarea
    sortarii, pentru ca intreaga lista mica (bucket-uri, nu linii brute) vine
    deja in acest singur raspuns."""
    ds = _get_dataset(dataset_id)
    if not ds:
        return JSONResponse({"error": "Dataset expirat sau inexistent."}, status_code=404)
    gf_f, gf_err = _gf_for_scan(ds, gf)
    if gf_err is not None:
        return gf_err

    window_seconds = window_seconds if window_seconds in (30, 60, 600) else 30
    day_filter = day or None
    try:
        filters = _parse_window_filters(ip, subnet, path, method, status_class, status, ua,
                                         has_query, referer_empty, country, identity, pattern, qkey,
                                         ua_category=ua_category)
    except ValueError as _ve:
        return JSONResponse({"error": str(_ve)}, status_code=400)
    if crawler_fake in ("1", "true"):
        # doar IP-urile care au picat verificarea DNS pt identitatea ceruta
        filters["ip_set"] = frozenset(_fake_crawler_ips(dataset_id, identity))

    plain_path, chunks = _scan_plan(ds, day_filter, gf_f)
    args = [(plain_path, s, e, day_filter, window_seconds, filters) for s, e in chunks]

    if len(chunks) <= 1:
        chunk_results = [_scan_chunk_windows(args[0])] if args else []
    else:
        chunk_results = _pool_map(_scan_chunk_windows, args, len(chunks))

    windows, ua_total, subnet_total = _merge_windows(chunk_results, window_seconds)
    windows.sort(key=lambda w: w["requests"], reverse=True)
    total_matches = sum(w["requests"] for w in windows)

    # Rubricile de procentaj (Eduard): user-agent/crawler si subnete /16,
    # calculate pe TOATE cererile care trec de filtre (nu doar pe ferestrele
    # afisate) -- lista completa, sortata descrescator; frontend-ul strange
    # top 8 + "Altele" (acelasi tipar ca RO vs restul lumii).
    ua_breakdown = [
        {"category": k, "requests": v, "pct": round(100 * v / total_matches, 1) if total_matches else 0}
        for k, v in ua_total.most_common()
    ]
    subnet_breakdown = [
        {"subnet": k, "requests": v, "pct": round(100 * v / total_matches, 1) if total_matches else 0}
        for k, v in subnet_total.most_common()
    ]

    effective_limit = max(1, min(int(limit) if limit else 300, 1000))
    return JSONResponse({
        "day": day_filter, "window_seconds": window_seconds,
        "total_matching_requests": total_matches,
        "total_windows": len(windows),
        "windows": windows[:effective_limit],
        "ua_breakdown": ua_breakdown,
        "subnet16_breakdown": subnet_breakdown,
    })


@app.get("/api/dataset/{dataset_id}/window_raw")
def api_window_raw(dataset_id: str, day: str = Query(default=""),
                    window_seconds: int = Query(default=30),
                    bucket_start: int = Query(...),
                    ip: str = Query(default=""), subnet: str = Query(default=""),
                    path: str = Query(default=""), method: str = Query(default=""),
                    status_class: str = Query(default=""), status: str = Query(default=""),
                    ua: str = Query(default=""), has_query: str = Query(default=""),
                    referer_empty: str = Query(default=""), country: str = Query(default=""),
                    identity: str = Query(default=""), pattern: str = Query(default=""),
                    qkey: str = Query(default=""),
                 ua_category: str = Query(default=""), crawler_fake: str = Query(default=""),
                 limit: int = Query(default=MAX_RAW_MATCHES),
        gf: str = Query(default="")):
    """Liniile brute complete dintr-o SINGURA fereastra a Explorator-ului
    (aceleasi filtre + aceeasi marime de fereastra ca /windows) -- butonul
    "vezi tot" de pe o fereastra din lista."""
    ds = _get_dataset(dataset_id)
    if not ds:
        return JSONResponse({"error": "Dataset expirat sau inexistent."}, status_code=404)
    gf_f, gf_err = _gf_for_scan(ds, gf)
    if gf_err is not None:
        return gf_err
    window_seconds = window_seconds if window_seconds in (30, 60, 600) else 30
    day_filter = day or None
    try:
        filters = _parse_window_filters(ip, subnet, path, method, status_class, status, ua,
                                         has_query, referer_empty, country, identity, pattern, qkey,
                                         ua_category=ua_category)
    except ValueError as _ve:
        return JSONResponse({"error": str(_ve)}, status_code=400)
    if crawler_fake in ("1", "true"):
        # doar IP-urile care au picat verificarea DNS pt identitatea ceruta
        filters["ip_set"] = frozenset(_fake_crawler_ips(dataset_id, identity))
    effective_limit = max(1, min(int(limit) if limit else MAX_RAW_MATCHES, RAW_MATCHES_HARD_CAP))

    plain_path, chunks = _scan_plan(ds, day_filter, gf_f)
    args = [(plain_path, s, e, day_filter, window_seconds, bucket_start, filters, effective_limit)
            for s, e in chunks]

    if len(chunks) <= 1:
        chunk_results = [_scan_chunk_window_raw(args[0])] if args else []
    else:
        chunk_results = _pool_map(_scan_chunk_window_raw, args, len(chunks))

    matches = []
    truncated = False
    for cmatches, hit_cap in chunk_results:
        matches.extend(cmatches)
        if hit_cap:
            truncated = True
    if len(matches) > effective_limit:
        truncated = True
    matches = matches[:effective_limit]

    return JSONResponse({
        "matches": matches, "truncated": truncated, "limit": effective_limit,
        "label": f"{_seconds_to_hhmmss(bucket_start)} - {_seconds_to_hhmmss(bucket_start + window_seconds)}",
    })


# ==========================================================================
# "Prezentare IP" (Eduard) -- pagina noua, separata, sus in navigare. Cerere
# EXPLICITA: sa aiba STRICT nr. de cereri, IP-uri unice, subnetele /16
# principale (cu cate cereri), user-agent/crawler daca e cazul, si de
# preferat sa poata seta si un interval exact (zi + optional ora start/ora
# sfarsit). Motor DEDICAT, separat de run_engine/build_summary (acela e mult
# mai greu -- calculeaza findings/anomalii complete pe zeci de reguli) --
# aici nu ne trebuie decat 4 agregate simple, cat mai rapid, indiferent de
# marimea fisierului. Acelasi tipar dict/tuplu explicit ca la Explorator.
# ==========================================================================
def _parse_hms_seconds(s):
    """'HH:MM' sau 'HH:MM:SS' -> secunde de la miezul noptii, sau None daca
    string gol/invalid (filtrul de ora nu se aplica in acel caz)."""
    if not s or not s.strip():
        return None
    bits = s.strip().split(":")
    try:
        bits = [int(b) for b in bits]
    except ValueError:
        return None
    while len(bits) < 3:
        bits.append(0)
    h, m, sec = bits[:3]
    if not (0 <= h < 24 and 0 <= m < 60 and 0 <= sec < 60):
        return None
    return h * 3600 + m * 60 + sec


def _time_filter_secs(tstr, start_sec, end_sec):
    """True daca linia trece de intervalul orar [start_sec, end_sec]
    (ambele optionale). Linii cu timestamp nevalid pica filtrul doar daca
    un interval chiar e cerut."""
    if start_sec is None and end_sec is None:
        return True
    if len(tstr) < 20:
        return False
    hh_tok, mm_tok, ss_tok = tstr[12:14], tstr[15:17], tstr[18:20]
    if not (hh_tok.isdigit() and mm_tok.isdigit() and ss_tok.isdigit()):
        return False
    secs = int(hh_tok) * 3600 + int(mm_tok) * 60 + int(ss_tok)
    if start_sec is not None and secs < start_sec:
        return False
    if end_sec is not None and secs > end_sec:
        return False
    return True


def _scan_chunk_ip_overview(args):
    """Worker paralel pentru "Prezentare" -- O SINGURA trecere, tot ce
    trebuie pentru rubrici + verdict + raport. Intoarce un DICT cu chei
    explicite (nu tuplu pozitional -- vezi bug-ul burst_raw din istoric).
    NU facem GeoIP aici (country_of e gandit doar pe IP-uri unice deja
    agregate) -- tarile se calculeaza dupa merge."""
    path, start, end, day_filter, start_sec, end_sec = args
    r = {
        "total": 0, "ip": Counter(), "s16": Counter(), "s24": Counter(),
        "ua_cat": Counter(), "ua_raw": Counter(), "crawler_ip": Counter(),
        "status": Counter(), "path": Counter(), "with_query": 0,
        "attack": Counter(), "attack_2xx": Counter(), "attack_ip": Counter(),
        "attack_s24": Counter(), "minute": Counter(), "bytes": 0,
        "first": None, "last": None,
        "static": 0, "prefix": Counter(), "prefix_paths": {},
        "dyn_query": 0, "path_q": Counter(),
    }
    v6_48, v6_64 = {}, {}
    with open(path, "rb") as f:
        f.seek(start)
        pos = start
        while pos < end:
            raw_line = f.readline()
            if not raw_line:
                break
            pos = f.tell()
            line = raw_line.decode("utf-8", errors="replace")
            rec = parse_line_fast(line)
            if rec is None:
                continue
            rip, _method, praw, status, referer, ua, tstr, size = rec
            if day_filter and day_of(tstr) != day_filter:
                continue
            if not _time_filter_secs(tstr, start_sec, end_sec):
                continue
            r["total"] += 1
            if r["first"] is None:
                r["first"] = tstr
            r["last"] = tstr
            r["ip"][rip] += 1
            if ":" in rip:
                k48 = v6_48.get(rip)
                if k48 is None:
                    k48 = v6_48[rip] = ipv6_subnet48_of(rip) or "IPv6 (invalid)"
                k64 = v6_64.get(rip)
                if k64 is None:
                    k64 = v6_64[rip] = ipv6_subnet64_of(rip) or "IPv6 (invalid)"
                r["s16"][k48] += 1
                r["s24"][k64] += 1
            else:
                s24 = subnet24_of(rip) or "necunoscut"
                r["s16"][subnet16_of(rip) or "necunoscut"] += 1
                r["s24"][s24] += 1
            r["ua_cat"][classify_ua(ua)] += 1
            r["ua_raw"][ua] += 1
            if CRAWLER_CLAIM_QUICK_RE.search(ua):
                identity = classify_crawler_claim(ua)
                if identity:
                    r["crawler_ip"][(identity, rip)] += 1
            r["status"][status] += 1
            qpos = praw.find("?")
            ponly = praw if qpos == -1 else praw[:qpos]
            r["path"][ponly] += 1
            if qpos != -1:
                r["with_query"] += 1
            if is_static_path(ponly):
                r["static"] += 1
            else:
                if qpos != -1 and not ponly.endswith(_BENIGN_QUERY_ENDPOINTS):
                    r["dyn_query"] += 1
                    r["path_q"][ponly] += 1
                # prefix = primul segment (/bijuterii/...), + cate URL-uri
                # DISTINCTE (cu query) au fost cerute sub el -- semnalul
                # principal pt. enumerare de filtre/scraping distribuit
                seg_end = ponly.find("/", 1)
                pref = ponly if seg_end == -1 else ponly[:seg_end + 1]
                r["prefix"][pref] += 1
                ps = r["prefix_paths"].get(pref)
                if ps is None:
                    ps = r["prefix_paths"][pref] = set()
                if len(ps) < PREFIX_DISTINCT_CAP:
                    ps.add(praw)
            r["bytes"] += size or 0
            if len(tstr) >= 17:
                r["minute"][tstr[:17]] += 1   # "14/Sep/2026:14:44"
            plow = praw.lower()
            if SUSPICIOUS_QUICK_RE.search(plow) or (referer and SUSPICIOUS_QUICK_RE.search(referer.lower())):
                full = unquote(praw) + " " + unquote(referer or "")
                for name, pattern in SUSPICIOUS_PATTERNS:
                    if pattern.search(full):
                        r["attack"][name] += 1
                        if 200 <= status < 300:
                            r["attack_2xx"][name] += 1
                        r["attack_ip"][rip] += 1
                        r["attack_s24"][subnet_key_of(rip) or "necunoscut"] += 1
                        break
    return r


def _merge_ip_overview(results):
    m = None
    for r in results:
        if m is None:
            m = r
            continue
        m["total"] += r["total"]
        m["with_query"] += r["with_query"]
        m["bytes"] += r["bytes"]
        m["static"] += r["static"]
        m["dyn_query"] += r["dyn_query"]
        m["path_q"].update(r["path_q"])
        m["prefix"].update(r["prefix"])
        for pref, ps in r["prefix_paths"].items():
            cur = m["prefix_paths"].setdefault(pref, set())
            if len(cur) < PREFIX_DISTINCT_CAP:
                cur |= ps
        for k in ("ip", "s16", "s24", "ua_cat", "ua_raw", "crawler_ip", "status", "path",
                  "attack", "attack_2xx", "attack_ip", "attack_s24", "minute"):
            m[k].update(r[k])
        # chunk-urile vin in ordine cronologica (ordinea byte-urilor)
        if m["first"] is None:
            m["first"] = r["first"]
        if r["last"] is not None:
            m["last"] = r["last"]
    if m is None:
        m = _scan_chunk_ip_overview_empty()
    return m


def _scan_chunk_ip_overview_empty():
    return {"total": 0, "ip": Counter(), "s16": Counter(), "s24": Counter(), "ua_cat": Counter(),
            "ua_raw": Counter(), "crawler_ip": Counter(), "status": Counter(), "path": Counter(),
            "with_query": 0, "attack": Counter(), "attack_2xx": Counter(), "attack_ip": Counter(),
            "attack_s24": Counter(), "minute": Counter(), "bytes": 0, "first": None, "last": None,
            "static": 0, "prefix": Counter(), "prefix_paths": {}, "dyn_query": 0, "path_q": Counter()}


def _pct_breakdown(counter, key_name, total, top_n=30):
    return [
        {key_name: k, "requests": v, "pct": round(100 * v / total, 1) if total else 0}
        for k, v in counter.most_common(top_n)
    ]


def _parse_log_ts(tstr):
    try:
        return datetime.strptime(tstr[:20], "%d/%b/%Y:%H:%M:%S")
    except (TypeError, ValueError):
        return None


IPOV_CACHE_MAX = 12
# endpoint-uri care au query string in mod normal (cron/ajax/API) -- nu conteaza la "enumerare"
_BENIGN_QUERY_ENDPOINTS = ("/wp-cron.php", "/admin-ajax.php", "/xmlrpc.php", "/wp-login.php")
PREFIX_DISTINCT_CAP = 20000   # plafon de URL-uri distincte numarate per prefix (memorie)


def _ip_overview_merged(dataset_id, ds, day_filter, start_sec, end_sec, subset=None, gf_key=""):
    """Scanare (sau cache) pentru o combinatie zi+interval(+filtre globale).
    Cache-ul tine agregatele BRUTE (Counter-e), nu raspunsul -- partea de
    verificare DNS a crawlerelor se recalculeaza la fiecare cerere, ca sa
    reflecte progresul verificarii care ruleaza in fundal dupa upload.
    subset=(cale, bytes): fisierul cu liniile selectiei globale (v44)."""
    key = (day_filter or "", start_sec, end_sec, gf_key)
    with DATASETS_LOCK:
        cache = ds.setdefault("ipov_cache", {})
        hit = cache.get(key)
    if hit is not None:
        return hit, True
    if subset is not None:
        plain_path = subset[0]
        region = None
    else:
        plain_path = ds["plain_path"]
        region = _region_for_day(ds, day_filter)
    n_workers = _default_worker_count()
    scan_size = (region[1] - region[0]) if region is not None else os.path.getsize(plain_path)
    n_workers = _safe_worker_count(scan_size, n_workers)
    if region is not None:
        chunks = find_chunk_offsets(plain_path, n_workers, region_start=region[0], region_end=region[1])
    else:
        chunks = find_chunk_offsets(plain_path, n_workers)
    args = [(plain_path, s, e, day_filter, start_sec, end_sec) for s, e in chunks]
    if len(chunks) <= 1:
        chunk_results = [_scan_chunk_ip_overview(args[0])] if args else []
    else:
        chunk_results = _pool_map(_scan_chunk_ip_overview, args, len(chunks))
    merged = _merge_ip_overview(chunk_results)
    # in cache pastram doar NUMARUL de URL-uri distincte per prefix, nu seturile
    merged["prefix_distinct"] = {k: len(v) for k, v in merged.pop("prefix_paths", {}).items()}
    with DATASETS_LOCK:
        cache = ds.setdefault("ipov_cache", {})
        if len(cache) >= IPOV_CACHE_MAX:
            cache.pop(next(iter(cache)))
        cache[key] = merged
    return merged, False


def _crawler_verification_breakdown(dataset_id, crawler_ip, total):
    """Per identitate revendicata: cereri totale, din care de la IP-uri
    VERIFICATE DNS, de la IP-uri FALSE (au picat verificarea), si inca
    neverificate (verificarea ruleaza in fundal dupa upload, sau a expirat)."""
    with _CRAWLER_JOBS_LOCK:
        job = _CRAWLER_JOBS.get(dataset_id)
        results = dict(job["results"]) if job else {}
        pending = bool(job and job["pending"])
    per = {}
    for (identity, ip), c in crawler_ip.items():
        d = per.setdefault(identity, {"identity": identity, "requests": 0, "verified": 0, "fake": 0,
                                      "unchecked": 0, "ips": 0, "fake_ips": 0, "fake_ip_list": [],
                                      "dns_verifiable": identity in CRAWLER_DNS_VERIFIABLE})
        d["requests"] += c
        d["ips"] += 1
        res = results.get(ip)
        # verificarea s-a facut pt identitatea revendicata PRIMA de acel IP;
        # daca acelasi IP revendica si alta identitate, nu reutilizam verdictul
        v = res.get("verified") if (res and res.get("identity") == identity) else None
        if v is True:
            d["verified"] += c
        elif v is False:
            d["fake"] += c
            d["fake_ips"] += 1
            if len(d["fake_ip_list"]) < 500:
                d["fake_ip_list"].append(ip)
        else:
            d["unchecked"] += c
    out = sorted(per.values(), key=lambda d: d["requests"], reverse=True)
    for d in out:
        d["pct"] = round(100 * d["requests"] / total, 1) if total else 0
    return out, pending


_ATTACK_LABELS = {
    "sqli_union": "SQL injection (UNION SELECT)",
    "sqli_error_blind": "SQL injection (error-based)",
    "sqli_time_blind": "SQL injection (time-based)",
    "sqli_exfil": "SQL injection (exfiltrare/RCE)",
    "sqli": "SQLi / citire fisiere (/etc/passwd, base64, php)",
    "lfi_rfi": "LFI/RFI (includere fisiere)",
    "webshell_name": "Acces la webshell cunoscut",
    "xss_tag": "XSS (tag executabil)",
    "xss_payload": "XSS (payload)",
    "xss_html_entity": "XSS (entitate HTML)",
}


def _fmt_int(n):
    return f"{int(n):,}".replace(",", ".")


def _build_ip_overview_response(dataset_id, m, day_filter, start, end, start_sec, end_sec):
    total = m["total"]
    ip_counter = m["ip"]
    unique_ips = len(ip_counter)

    country_counter = Counter()
    ip_country = {}
    for ip, c in ip_counter.items():
        cc = country_of(ip) or "??"
        country_counter[cc] += c
    for ip, _c in ip_counter.most_common(30):
        ip_country[ip] = country_of(ip) or "??"
    for ip, _c in m["attack_ip"].most_common(15):
        ip_country.setdefault(ip, country_of(ip) or "??")

    crawler_breakdown, crawler_pending = _crawler_verification_breakdown(dataset_id, m["crawler_ip"], total)

    st = m["status"]
    status_class = Counter()
    for code, c in st.items():
        status_class[f"{code // 100}xx"] += c
    status_breakdown = _pct_breakdown(status_class, "status", total, 6)
    status_codes = _pct_breakdown(Counter({str(k): v for k, v in st.items()}), "code", total, 12)

    t_first = _parse_log_ts(m["first"]) if m["first"] else None
    t_last = _parse_log_ts(m["last"]) if m["last"] else None
    duration_sec = int((t_last - t_first).total_seconds()) + 1 if (t_first and t_last) else 0
    per_min_avg = round(total / max(1.0, duration_sec / 60.0), 1) if total else 0

    # timeline: zi / ora / minut, dupa cat de lung e intervalul
    minute = m["minute"]
    def _day_sort(d):
        return _parse_log_ts(d + ":00:00:00") or datetime.min
    days_seen = sorted({k[:11] for k in minute}, key=_day_sort)
    if len(days_seen) > 3:
        gran = "day"
        agg = Counter()
        for k, c in minute.items():
            agg[k[:11]] += c
        timeline = [{"label": d, "day": d, "requests": agg[d]} for d in days_seen]
    elif duration_sec and duration_sec <= 3 * 3600:
        gran = "minute"
        timeline = [{"label": k[12:17], "day": k[:11], "hm": k[12:17], "requests": c}
                    for k, c in sorted(minute.items(), key=lambda kv: (_day_sort(kv[0][:11]), kv[0][12:17]))]
    else:
        gran = "hour"
        agg = Counter()
        for k, c in minute.items():
            agg[k[:14]] += c   # "21/Sep/2026:22"
        keys = sorted(agg, key=lambda k: (_day_sort(k[:11]), k[12:14]))
        multi = len(days_seen) > 1
        timeline = [{"label": (k[:6] + " " if multi else "") + k[12:14] + ":00", "day": k[:11], "hh": k[12:14],
                     "requests": agg[k]} for k in keys]
    peak_key, peak_count = (minute.most_common(1)[0] if minute else (None, 0))

    attacks = []
    for name, c in m["attack"].most_common():
        attacks.append({"pattern": name, "label": _ATTACK_LABELS.get(name, name), "requests": c,
                        "served_2xx": m["attack_2xx"].get(name, 0),
                        "pct": round(100 * c / total, 2) if total else 0})
    attack_total = sum(m["attack"].values())
    attack_2xx_total = sum(m["attack_2xx"].values())

    top_ips = [{"ip": ip, "requests": c, "pct": round(100 * c / total, 1) if total else 0,
                "country": ip_country.get(ip, "??")} for ip, c in ip_counter.most_common(30)]
    attack_ips = [{"ip": ip, "requests": c, "country": ip_country.get(ip, "??")}
                  for ip, c in m["attack_ip"].most_common(15)]

    single_hit_ips = sum(1 for c in ip_counter.values() if c == 1)
    pdist = m.get("prefix_distinct", {})
    top_prefixes = [{"prefix": pf, "requests": c, "pct": round(100 * c / total, 1) if total else 0,
                     "distinct_urls": pdist.get(pf, 0), "capped": pdist.get(pf, 0) >= PREFIX_DISTINCT_CAP}
                    for pf, c in m["prefix"].most_common(20)]
    stats = {
        "single_hit_ips": single_hit_ips, "static": m["static"], "top_prefixes": top_prefixes,
        "ro_requests": country_counter.get("RO", 0),
        "total": total, "unique_ips": unique_ips, "duration_sec": duration_sec,
        "per_min_avg": per_min_avg, "peak_minute": peak_key, "peak_count": peak_count,
        "status_class": dict(status_class), "with_query": m["with_query"],
        "attack_total": attack_total, "attack_2xx_total": attack_2xx_total,
        "bytes": m["bytes"],
    }
    verdict = _build_verdict(stats, attacks, attack_ips, top_ips, m, crawler_breakdown, country_counter)

    label_bits = [day_filter or "toate zilele"]
    if start_sec is not None or end_sec is not None:
        s_lbl = _seconds_to_hhmmss(start_sec if start_sec is not None else 0)
        e_lbl = _seconds_to_hhmmss(end_sec if end_sec is not None else 86399)
        label_bits.append(f"{s_lbl} - {e_lbl}")
    return {
        "day": day_filter, "start": start or None, "end": end or None,
        "label": " ".join(label_bits),
        "first_seen": m["first"], "last_seen": m["last"], "duration_sec": duration_sec,
        "total_requests": total, "unique_ips": unique_ips, "bytes": m["bytes"],
        "per_min_avg": per_min_avg,
        "peak_minute": peak_key, "peak_minute_requests": peak_count,
        "with_query": m["with_query"],
        "subnet16_breakdown": _pct_breakdown(m["s16"], "subnet", total),
        "subnet24_breakdown": _pct_breakdown(m["s24"], "subnet", total),
        "ua_breakdown": _pct_breakdown(m["ua_cat"], "category", total),
        "ua_raw_breakdown": _pct_breakdown(m["ua_raw"], "ua", total, top_n=20),
        "crawler_breakdown": crawler_breakdown, "crawler_verification_pending": crawler_pending,
        "country_breakdown": _pct_breakdown(country_counter, "country", total, top_n=60),
        "top_ips": top_ips,
        "top_paths": _pct_breakdown(m["path"], "path", total, top_n=20),
        "top_prefixes": top_prefixes,
        "single_hit_ips": single_hit_ips,
        "static_requests": m["static"],
        "status_breakdown": status_breakdown, "status_codes": status_codes,
        "attacks": attacks, "attack_total": attack_total, "attack_2xx_total": attack_2xx_total,
        "attack_ips": attack_ips,
        "attack_subnets": _pct_breakdown(m["attack_s24"], "subnet", attack_total or 1, top_n=10),
        "timeline": timeline, "timeline_granularity": gran,
        "verdict": verdict,
    }


def _build_verdict(stats, attacks, attack_ips, top_ips, m, crawler_breakdown, country_counter):
    """Concluzie automata, in romana, pe baza cifrelor -- NU o certitudine:
    fiecare rand spune pe ce cifra se bazeaza. level: critical/high/medium/
    info/ok. Recomandarile sunt actiuni concrete (blocare, verificari)."""
    total = stats["total"]
    lines, recs = [], []
    level_rank = {"ok": 0, "info": 1, "medium": 2, "high": 3, "critical": 4}
    level = "ok"

    def bump(lv):
        nonlocal level
        if level_rank[lv] > level_rank[level]:
            level = lv

    if not total:
        return {"level": "info", "headline": "Nicio cerere in intervalul ales.", "lines": [], "recommendations": []}

    sc = stats["status_class"]
    e5 = sc.get("5xx", 0)
    e4 = sc.get("4xx", 0)
    p5 = 100.0 * e5 / total
    p4 = 100.0 * e4 / total

    # --- atacuri pe semnatura
    headline = None
    if stats["attack_total"]:
        top_att = attacks[0]
        src = attack_ips[0] if attack_ips else None
        att_sub = m["attack_s24"].most_common(1)[0] if m["attack_s24"] else None
        served = stats["attack_2xx_total"]
        is_sqli_served = any(a["pattern"].startswith("sqli") and a["served_2xx"] for a in attacks)
        is_shell_served = any(a["pattern"] == "webshell_name" and a["served_2xx"] for a in attacks)
        lines.append(
            f"{_fmt_int(stats['attack_total'])} cereri cu semnaturi de atac "
            f"(principal: {top_att['label']}, {_fmt_int(top_att['requests'])} cereri); "
            f"{_fmt_int(served)} au primit raspuns 2xx (procesate de aplicatie), restul au fost respinse (3xx/4xx/5xx).")
        if src:
            lines.append(f"Sursa principala a atacurilor: IP {src['ip']} ({src['country']}), {_fmt_int(src['requests'])} cereri"
                         + (f"; subnet {att_sub[0]} -- {_fmt_int(att_sub[1])} cereri." if att_sub else "."))
        if is_sqli_served or is_shell_served:
            bump("critical")
            headline = (f"Atac {'SQL injection' if is_sqli_served else 'webshell'} cu raspunsuri 2xx -- "
                        f"posibil exploatat, necesita verificare imediata")
            recs.append("Verifica aplicatia/baza de date pentru efectele cererilor cu raspuns 2xx (continut modificat, "
                        "conturi noi de admin, date exfiltrate) -- un 200 inseamna ca cererea a fost procesata, "
                        "nu neaparat ca atacul a reusit.")
            recs.append("Actualizeaza/patch-uieste scriptul vizat (vezi path-urile din liniile brute) si schimba parolele DB/admin daca se confirma exfiltrarea.")
        elif stats["attack_total"] >= 100:
            bump("high")
            headline = f"Scanare/atac automatizat ({top_att['label']}), respins in majoritate"
        else:
            bump("medium")
            headline = f"Incercari izolate de atac ({top_att['label']})"
        if src:
            recs.append(f"Blocheaza sursa: IP {src['ip']}" + (f" sau subnetul {att_sub[0]}" if att_sub else "")
                        + " (reguli gata de copiat in panoul de blocare).")

    # --- trafic distribuit (botnet / proxy rotativ): multe IP-uri cu 1-2
    # cereri fiecare, fara fisiere statice, concentrat pe un prefix de URL
    # cu mii de variante -- tiparul clasic de enumerare de filtre/scraping,
    # pe care semnaturile de atac si concentrarea pe IP NU il prind.
    if total >= 3000:
        single_share = stats["single_hit_ips"] / total
        static_share = stats["static"] / total
        ips_per_req = stats["unique_ips"] / total
        tp = stats["top_prefixes"][0] if stats["top_prefixes"] else None
        distributed = ips_per_req >= 0.25
        if distributed:
            bump("high")
            lines.append(f"Trafic distribuit: {_fmt_int(stats['unique_ips'])} IP-uri unice pentru {_fmt_int(total)} cereri "
                         f"({ips_per_req * 100:.0f} IP-uri la 100 de cereri); {_fmt_int(stats['single_hit_ips'])} IP-uri apar o singura data. "
                         f"Vizitatorii reali fac zeci de cereri fiecare (pagina + fisiere) -- tipar de botnet / proxy-uri rotative.")
        if distributed and static_share < 0.05:
            # (daca site-ul e in spatele unui CDN care cache-uieste staticele,
            # procentul e mic si la trafic legitim -- de-asta doar ca semnal
            # suplimentar pe langa "distribuit", nu singur)
            lines.append(f"Doar {static_share * 100:.1f}% din cereri sunt fisiere statice (css/js/imagini) -- browserele reale le incarca, botii nu "
                         f"(exceptie: statice servite din CDN/cache).")
        if tp and tp["distinct_urls"] >= 1000 and tp["pct"] >= 15:
            bump("high")
            more = "+" if tp["capped"] else ""
            lines.append(f"Enumerare pe {tp['prefix']}: {_fmt_int(tp['distinct_urls'])}{more} URL-uri distincte, {tp['pct']}% din trafic "
                         f"({_fmt_int(tp['requests'])} cereri) -- tipic pentru parcurgerea combinatiilor de filtre/categorii.")
            recs.append(f"Cloudflare: regula de rate limiting sau Managed Challenge pe (starts_with(http.request.uri.path, \"{tp['prefix']}\")), "
                        f"excluzand Romania si botii verificati (not cf.client.bot) -- blocarea pe IP nu ajuta cand fiecare cerere vine de la alt IP.")
            if not headline:
                headline = f"Atac distribuit / scraping pe {tp['prefix']} de la {_fmt_int(stats['unique_ips'])} IP-uri"
        elif distributed and not headline:
            headline = f"Trafic distribuit de la {_fmt_int(stats['unique_ips'])} IP-uri (tipar de botnet / scraping)"
        if distributed:
            recs.append("Verifica in tab-ul Path-uri (Enumerare distribuita / Prefixe) ce URL-uri sunt parcurse si daca sunt parametri de filtrare.")
        ro_share = stats["ro_requests"] / total
        if distributed and ro_share < 0.1:
            lines.append(f"Doar {ro_share * 100:.1f}% din trafic vine din Romania.")

    # --- concentrare trafic
    if top_ips:
        tip = top_ips[0]
        if tip["pct"] >= 20 and tip["requests"] >= 1000:
            bump("medium")
            lines.append(f"Trafic concentrat: IP {tip['ip']} ({tip['country']}) face {tip['pct']}% din cereri ({_fmt_int(tip['requests'])}).")
            if not headline:
                headline = f"Un singur IP ({tip['ip']}) genereaza {tip['pct']}% din trafic"
            recs.append(f"Verifica ce face IP-ul {tip['ip']} (liniile brute) si limiteaza-l daca nu e legitim.")
    top24 = m["s24"].most_common(1)
    if top24 and total >= 1000:
        s, c = top24[0]
        pct = 100.0 * c / total
        if pct >= 25:
            # cat din subnet e un crawler revendicat (ex: Meta 57.141.x) -- schimba complet interpretarea
            ident_c = Counter()
            for (ident, ip), cc in m["crawler_ip"].items():
                if (subnet_key_of(ip) or "") == s:
                    ident_c[ident] += cc
            ctx = ""
            if ident_c:
                ident, ic = ident_c.most_common(1)[0]
                if ic / c >= 0.5:
                    ctx = f" -- {100.0 * ic / c:.0f}% din ele cu User-Agent {ident} (crawler; vezi verificarea in rubrica Crawlere)"
            bump("medium")
            lines.append(f"Subnetul {s} genereaza {pct:.1f}% din trafic ({_fmt_int(c)} cereri){ctx}.")
            if not headline:
                headline = f"Subnetul {s} genereaza {pct:.0f}% din trafic" + (f" ({ident_c.most_common(1)[0][0]})" if ctx else "")

    # --- varf
    if stats["peak_count"] and stats["per_min_avg"] and stats["peak_count"] >= max(300, 8 * stats["per_min_avg"]):
        bump("medium")
        lines.append(f"Varf de trafic: {_fmt_int(stats['peak_count'])} cereri in minutul {stats['peak_minute']} "
                     f"(media: {stats['per_min_avg']}/min).")
        if not headline:
            headline = f"Varf de trafic de {_fmt_int(stats['peak_count'])} cereri/minut la {stats['peak_minute']}"

    # --- erori
    if e5 and p5 >= 3:
        bump("high" if p5 >= 10 else "medium")
        lines.append(f"Erori 5xx: {_fmt_int(e5)} ({p5:.1f}%) -- serverul/aplicatia nu a putut raspunde (load, limite PHP/LVE, DB).")
        recs.append("Verifica load-ul si limitele (LVE/PHP-FPM/MySQL) in intervalul varfului; corelat cu traficul de mai sus.")
        if not headline:
            headline = f"Rata ridicata de erori 5xx ({p5:.1f}%)"
    if p4 >= 30 and e4 >= 500:
        bump("medium")
        lines.append(f"Erori 4xx: {_fmt_int(e4)} ({p4:.1f}%) -- multe cereri respinse/inexistente (scanare, 403 de la WAF, 404).")
        if not headline:
            headline = f"Rata mare de erori 4xx ({p4:.0f}%)"

    # --- filtre / enumerare
    # doar cereri dinamice (fara statice -- "?ver=" pe css/js e cache-busting normal)
    dyn_total = total - stats["static"]
    dq = m.get("dyn_query", 0)
    if dyn_total >= 2000 and dq / dyn_total >= 0.5:
        paths_q = m["path_q"].most_common(1)
        lines.append(f"{100.0 * dq / dyn_total:.0f}% din cererile catre pagini (fara fisiere statice) au query string -- tipar posibil de enumerare filtre/scraping"
                     + (f" (cel mai lovit: {paths_q[0][0]}, {_fmt_int(paths_q[0][1])} cereri)." if paths_q else "."))
        bump("medium")
        if not headline:
            headline = f"{100.0 * dq / dyn_total:.0f}% din cererile catre pagini au parametri (posibila enumerare de filtre)"
        recs.append("Daca e enumerare de filtre (WooCommerce/PrestaShop layered nav): regula Cloudflare de rate limiting "
                    "sau Managed Challenge pe URI-urile cu parametri de filtrare.")

    # --- crawlere false
    fake = sum(d["fake"] for d in crawler_breakdown)
    if fake:
        names = ", ".join(f"{d['identity']} ({_fmt_int(d['fake'])})" for d in crawler_breakdown if d["fake"])
        lines.append(f"{_fmt_int(fake)} cereri de la crawlere FALSE (User-Agent de bot cunoscut, dar DNS-ul IP-ului nu confirma): {names}.")
        if fake >= 100 or fake / total >= 0.01:
            bump("medium")
            if not headline:
                headline = f"Crawlere false: {_fmt_int(fake)} cereri cu User-Agent de motor de cautare, neconfirmate DNS"
        recs.append('Blocheaza crawlerele false in Cloudflare: (http.user_agent contains "Googlebot" and not cf.client.bot) -> Block.')

    # --- tari
    if country_counter:
        cc, c = country_counter.most_common(1)[0]
        ro = country_counter.get("RO", 0)
        lines.append(f"Tara principala: {cc} ({100.0 * c / total:.1f}%); trafic din Romania: {100.0 * ro / total:.1f}%.")

    if not headline and level != "ok" and lines:
        headline = "De verificat: " + lines[0].split(" -- ")[0].rstrip(".")
    if not headline:
        headline = "Trafic fara semnale majore de atac in intervalul ales"
        if level == "ok":
            lines.insert(0, "Nicio semnatura de atac, fara varfuri sau concentrari anormale, rata de erori normala.")
    return {"level": level, "headline": headline, "lines": lines, "recommendations": recs}


@app.get("/api/dataset/{dataset_id}/ip_overview")
def api_ip_overview(dataset_id: str, day: str = Query(default=""),
                     start: str = Query(default=""), end: str = Query(default=""),
                     country: List[str] = Query(default=[]), severity: List[str] = Query(default=[]),
                     status: List[int] = Query(default=[]), action: List[str] = Query(default=[]),
                     ip: str = Query(default=""), method: str = Query(default=""),
                     path_contains: str = Query(default=""), ua_contains: str = Query(default=""),
                     gf: str = Query(default="")):
    """Pagina 'Prezentare' (pagina principala): toate rubricile + verdict +
    date pentru raport, pentru o zi + interval orar optional. Cache per
    (zi, interval, filtre globale) -- a doua cerere pentru aceeasi selectie
    e instanta. v44: filtrele globale de CONTINUT (tara, IP, cod, URL, UA,
    severitate, actiune, metoda) se aplica si aici -- rubricile se calculeaza
    pe subsetul de linii ales prin index; intervalul ramane cel al paginii."""
    ds = _get_dataset(dataset_id)
    if not ds:
        return JSONResponse({"error": "Dataset expirat sau inexistent."}, status_code=404)
    f, err = _gf_checked(None, None, country, severity, status, action, ip, method, path_contains, ua_contains, "",
                         gf_raw=gf)
    if err:
        return err
    subset = None
    if not _gf_is_empty(f):
        if not ds.get("triage_ready"):
            return JSONResponse({"error": "Filtrele globale devin aplicabile aici dupa indexare (cateva secunde).",
                                 "indexing": True}, status_code=202)
        subset = _subset_for_filters(ds, f)
    day_filter = day or None
    start_sec = _parse_hms_seconds(start)
    end_sec = _parse_hms_seconds(end)
    t0 = time.time()
    m, cached = _ip_overview_merged(dataset_id, ds, day_filter, start_sec, end_sec,
                                    subset=subset, gf_key=_gf_key(f) if subset else "")
    resp = _build_ip_overview_response(dataset_id, m, day_filter, start, end, start_sec, end_sec)
    resp["cached"] = cached
    resp["global_filters"] = json.loads(_gf_key(f)) if subset else {}
    if subset and (f.get("ts_from") is not None or f.get("ts_to") is not None) and not day_filter and not start:
        resp["label"] = _gf_label({"ts_from": f.get("ts_from"), "ts_to": f.get("ts_to")}, ds)
    resp["elapsed_sec"] = round(time.time() - t0, 2)
    doms = {extract_domain_from_filename(fn) for fn in (ds.get("source_files") or [ds.get("filename", "")])}
    doms.discard(None); doms.discard("")
    resp["domain"] = ", ".join(sorted(doms))
    return JSONResponse(resp)


@app.get("/api/dataset/{dataset_id}/ip_compare")
def api_ip_compare(dataset_id: str,
                    day_a: str = Query(default=""), start_a: str = Query(default=""), end_a: str = Query(default=""),
                    day_b: str = Query(default=""), start_b: str = Query(default=""), end_b: str = Query(default=""),
                    gf_a: str = Query(default=""), gf_b: str = Query(default="")):
    """Comparatie intre doua intervale (ex: inainte/dupa mitigare). Cifrele
    brute nu sunt comparabile daca intervalele au lungimi diferite -- de
    aceea intoarcem si rate normalizate (cereri/minut)."""
    ds = _get_dataset(dataset_id)
    if not ds:
        return JSONResponse({"error": "Dataset expirat sau inexistent."}, status_code=404)
    out = {}
    for tag, d, s, e, g in (("a", day_a, start_a, end_a, gf_a), ("b", day_b, start_b, end_b, gf_b)):
        dayf = d or None
        ss, es = _parse_hms_seconds(s), _parse_hms_seconds(e)
        # v45: fiecare parte poate fi o selectie globala completa (perioada + filtre)
        gfx, gerr = _gf_for_scan(ds, g)
        if gerr is not None:
            return gerr
        subset = _subset_for_filters(ds, gfx) if gfx else None
        m, _cached = _ip_overview_merged(dataset_id, ds, dayf, ss, es, subset=subset,
                                         gf_key=_gf_key(gfx) if gfx else "")
        full = _build_ip_overview_response(dataset_id, m, dayf, s, e, ss, es)
        if gfx and not dayf and not s:
            full["label"] = _gf_label(gfx, ds) or full["label"]
        sc = {x["status"]: x["requests"] for x in full["status_breakdown"]}
        mins = max(1.0, full["duration_sec"] / 60.0)
        out[tag] = {
            "label": full["label"], "first_seen": full["first_seen"], "last_seen": full["last_seen"],
            "duration_sec": full["duration_sec"],
            "total_requests": full["total_requests"], "unique_ips": full["unique_ips"],
            "per_min": round(full["total_requests"] / mins, 1) if full["total_requests"] else 0,
            "unique_ips_per_min": round(full["unique_ips"] / mins, 2) if full["unique_ips"] else 0,
            "pct_4xx": round(100 * sc.get("4xx", 0) / full["total_requests"], 1) if full["total_requests"] else 0,
            "pct_5xx": round(100 * sc.get("5xx", 0) / full["total_requests"], 1) if full["total_requests"] else 0,
            "attack_total": full["attack_total"], "attack_2xx_total": full["attack_2xx_total"],
            "attack_per_min": round(full["attack_total"] / mins, 1) if full["attack_total"] else 0,
            "peak_minute_requests": full["peak_minute_requests"],
            "top_subnets24": full["subnet24_breakdown"][:8],
            "top_countries": full["country_breakdown"][:8],
            "verdict_level": full["verdict"]["level"], "verdict_headline": full["verdict"]["headline"],
        }
    return JSONResponse(out)


# --------------------------------------------------------------------------
# Extractie linii brute (Eduard: "posibilitati de filtrare si extragere
# linii log complete / sa filtram dupa ora, minut, ultimele loguri, primele
# loguri") -- ACELASI motor de filtre ca Explorator de loguri
# (_parse_window_filters/_window_line_matches, dict cu chei explicite), dar
# FARA bucketing pe ferestre -- doar primele/ultimele N linii care trec de
# filtre, in ordine cronologica. Fisierul de log e deja in ordine
# cronologica (liniile se adauga la coada) -- byte-range-urile scanate in
# paralel sunt deci si ele in ordine cronologica (chunk 0 = cele mai vechi),
# asa cappentru "primele N" e suficient sa pastram primele N gasite per
# chunk si sa concatenam chunk-urile IN ORDINE; pentru "ultimele N" pastram
# ultimele N per chunk (deque marginit) si concatenam la fel -- ambele
# concatenari raman corect ordonate global, fara sa fie nevoie sa adunam
# toate liniile intr-o lista uriasa.
# --------------------------------------------------------------------------
def _scan_chunk_extract(args):
    path, start, end, day_filter, start_sec, end_sec, filters, cap = args
    total = 0
    first_buf = []
    last_buf = deque(maxlen=cap)
    with open(path, "rb") as f:
        f.seek(start)
        pos = start
        while pos < end:
            raw_line = f.readline()
            if not raw_line:
                break
            pos = f.tell()
            line = raw_line.decode("utf-8", errors="replace")
            rec = parse_line_fast(line)
            if rec is None:
                continue
            rip, method_, praw, status, referer, ua, tstr, _size = rec
            if day_filter and day_of(tstr) != day_filter:
                continue
            if start_sec is not None or end_sec is not None:
                if len(tstr) < 20:
                    continue
                hh_tok, mm_tok, ss_tok = tstr[12:14], tstr[15:17], tstr[18:20]
                if not (hh_tok.isdigit() and mm_tok.isdigit() and ss_tok.isdigit()):
                    continue
                secs = int(hh_tok) * 3600 + int(mm_tok) * 60 + int(ss_tok)
                if start_sec is not None and secs < start_sec:
                    continue
                if end_sec is not None and secs > end_sec:
                    continue
            if not _window_line_matches(rip, method_, praw, status, referer, ua, filters):
                continue
            total += 1
            rowd = {"time": tstr, "ip": rip, "method": method_, "path": praw,
                    "status": status, "referer": referer, "ua": ua,
                    "raw": line.rstrip("\n")}
            if len(first_buf) < cap:
                first_buf.append(rowd)
            last_buf.append(rowd)
    return total, first_buf, list(last_buf)


@app.get("/api/dataset/{dataset_id}/extract_raw")
def api_extract_raw(dataset_id: str, day: str = Query(default=""),
                     start: str = Query(default=""), end: str = Query(default=""),
                     ip: str = Query(default=""), subnet: str = Query(default=""),
                     path: str = Query(default=""), method: str = Query(default=""),
                     status_class: str = Query(default=""), status: str = Query(default=""),
                     ua: str = Query(default=""), has_query: str = Query(default=""),
                     referer_empty: str = Query(default=""), country: str = Query(default=""),
                     identity: str = Query(default=""), pattern: str = Query(default=""),
                     qkey: str = Query(default=""),
                 ua_category: str = Query(default=""), crawler_fake: str = Query(default=""),
                 limit: int = Query(default=200),
        gf: str = Query(default="")):
    """Extractie de linii brute (Eduard): primele N / ultimele N linii care
    trec de ORICE combinatie a celor ~12 filtre (acelasi motor ca Explorator
    de loguri), optional restranse la o zi + un interval orar exact. Ambele
    liste (primele si ultimele) vin in ACELASI raspuns -- clientul alege ce
    sa arate fara sa mai re-interogheze serverul."""
    ds = _get_dataset(dataset_id)
    if not ds:
        return JSONResponse({"error": "Dataset expirat sau inexistent."}, status_code=404)
    gf_f, gf_err = _gf_for_scan(ds, gf)
    if gf_err is not None:
        return gf_err

    day_filter = day or None
    start_sec = _parse_hms_seconds(start)
    end_sec = _parse_hms_seconds(end)
    try:
        filters = _parse_window_filters(ip, subnet, path, method, status_class, status, ua,
                                         has_query, referer_empty, country, identity, pattern, qkey,
                                         ua_category=ua_category)
    except ValueError as _ve:
        return JSONResponse({"error": str(_ve)}, status_code=400)
    if crawler_fake in ("1", "true"):
        # doar IP-urile care au picat verificarea DNS pt identitatea ceruta
        filters["ip_set"] = frozenset(_fake_crawler_ips(dataset_id, identity))
    effective_limit = max(1, min(int(limit) if limit else 200, MAX_RAW_MATCHES))

    plain_path, chunks = _scan_plan(ds, day_filter, gf_f)
    args = [(plain_path, s, e, day_filter, start_sec, end_sec, filters, effective_limit)
            for s, e in chunks]

    if len(chunks) <= 1:
        chunk_results = [_scan_chunk_extract(args[0])] if args else []
    else:
        chunk_results = _pool_map(_scan_chunk_extract, args, len(chunks))

    total = 0
    first_all, last_all = [], []
    for t, fb, lb in chunk_results:
        total += t
        first_all.extend(fb)
        last_all.extend(lb)
    first_lines = first_all[:effective_limit]
    last_lines = last_all[-effective_limit:]

    return JSONResponse({
        "total_matching_requests": total,
        "limit": effective_limit,
        "first": first_lines,
        "last": last_lines,
    })


@app.get("/api/dataset/{dataset_id}/ip_detail")
def api_ip_detail(dataset_id: str, ip: str = Query(default=""), day: str = Query(default=""),
        gf: str = Query(default="")):
    """Panou de detaliu per-IP (Faza 3) -- total cereri, path-uri unice,
    bandwidth, prima/ultima vazuta, top path-uri, breakdown status/metode.
    Aceleasi date pe care le-am putea deriva prin findings/anomalies/top_ips
    NU includ total/bandwidth/first-last pentru un IP oarecare (top_ips
    tine doar primele 300, top_bandwidth_ips doar primele 20) -- de-aici
    RE-SCAN SCOPAT (exact acelasi tipar paralel ca /raw si /path_breakdown),
    care ruleaza DOAR cand userul deschide panoul, nu la upload. Restul
    panoului (findings/anomalies/bursts/crawler_verification/admin_activity/
    compromise_trail care implica acest IP) se filtreaza client-side din
    summary-ul deja incarcat -- zero cost suplimentar de server pentru asta."""
    ds = _get_dataset(dataset_id)
    if not ds:
        return JSONResponse({"error": "Dataset expirat sau inexistent."}, status_code=404)
    gf_f, gf_err = _gf_for_scan(ds, gf)
    if gf_err is not None:
        return gf_err
    ip = (ip or "").strip()
    if not ip:
        return JSONResponse({"error": "Parametrul 'ip' e obligatoriu."}, status_code=400)

    day_filter = day or None
    plain_path, chunks = _scan_plan(ds, day_filter, gf_f)
    args = [(plain_path, s, e, ip, day_filter) for s, e in chunks]

    if len(chunks) <= 1:
        chunk_results = [_scan_chunk_ip_detail(args[0])] if args else []
    else:
        chunk_results = _pool_map(_scan_chunk_ip_detail, args, len(chunks))

    total = 0
    bandwidth = 0
    paths: Counter[str] = Counter()
    status_counter: Counter[Any] = Counter()
    methods: Counter[str] = Counter()
    first = None
    last = None
    for r in chunk_results:
        total += r["count"]
        bandwidth += r["bandwidth"]
        paths.update(r["paths"])
        status_counter.update(r["status"])
        methods.update(r["methods"])
        if r["first"] is not None and (first is None or r["first"] < first):
            first = r["first"]
        if r["last"] is not None and (last is None or r["last"] > last):
            last = r["last"]

    return JSONResponse({
        "ip": ip,
        "country": country_of(ip),
        "requests": total,
        "unique_paths": len(paths),
        "bandwidth": bandwidth,
        "first_seen": first or "",
        "last_seen": last or "",
        "top_paths": [{"path": p, "requests": c} for p, c in paths.most_common(20)],
        "status_breakdown": {str(s): c for s, c in status_counter.most_common(10)},
        "methods": dict(methods),
    })


@app.get("/api/dataset/{dataset_id}/country_subnets")
def api_country_subnets(dataset_id: str, country: str = Query(default=""), day: str = Query(default=""),
        gf: str = Query(default="")):
    """'Sa vad subneturile ? care il alcatuiesc?' (Eduard) -- top subnete /24
    dintr-o tara (sau din bucketul '??' = neresolvat geoip), fiecare cu
    nr. de cereri si IP-uri unice. Re-scan scopat paralel, exact acelasi
    tipar ca /ip_detail si /raw -- ruleaza doar la deschiderea acestui
    panou, nu la upload."""
    ds = _get_dataset(dataset_id)
    if not ds:
        return JSONResponse({"error": "Dataset expirat sau inexistent."}, status_code=404)
    gf_f, gf_err = _gf_for_scan(ds, gf)
    if gf_err is not None:
        return gf_err
    country = (country or "").strip()
    if not country:
        return JSONResponse({"error": "Parametrul 'country' e obligatoriu."}, status_code=400)
    _cn = normalize_country_value(country)
    if _cn is None:
        return JSONResponse({"error": f"Tara '{country}' nu e recunoscuta -- foloseste codul ISO din 2 litere "
                                      f"sau '??' pentru tara nedeterminata."}, status_code=400)
    if _cn == "__NON_RO__":
        return JSONResponse({"error": "Subnetele se pot lista doar pentru o tara anume (nu pentru __non_ro__)."},
                            status_code=400)
    country_filter = "??" if _cn == "" else _cn

    day_filter = day or None
    plain_path, chunks = _scan_plan(ds, day_filter, gf_f)
    args = [(plain_path, s, e, country_filter, day_filter) for s, e in chunks]

    if len(chunks) <= 1:
        chunk_results = [_scan_chunk_country_subnets(args[0])] if args else []
    else:
        chunk_results = _pool_map(_scan_chunk_country_subnets, args, len(chunks))

    subnet_reqs: Counter[str] = Counter()
    subnet_ips: Dict[str, Set[str]] = defaultdict(set)
    for r in chunk_results:
        subnet_reqs.update(r["subnet_reqs"])
        for k, v in r["subnet_ips"].items():
            subnet_ips[k] |= v

    subnets = [
        {"subnet": s, "requests": c, "unique_ips": len(subnet_ips.get(s, ()))}
        for s, c in subnet_reqs.most_common(100)
    ]
    return JSONResponse({
        "country": country_filter,
        "total_requests": sum(subnet_reqs.values()),
        "total_subnets": len(subnet_reqs),
        "subnets": subnets,
    })


def _serialize_breakdown_bucket(bucket):
    n_ips = len(bucket["ips"])
    subnets = {subnet24_of(ip) for ip in bucket["ips"]}
    subnets.discard(None)
    return {
        "requests": bucket["count"],
        "unique_ips": n_ips,
        "unique_subnets": len(subnets),
        "bytes": bucket["bytes"],
        "status": {
            "2xx": bucket["status"].get(2, 0), "3xx": bucket["status"].get(3, 0),
            "4xx": bucket["status"].get(4, 0), "5xx": bucket["status"].get(5, 0),
        },
        "with_query": bucket["with_query"],
        "first_seen": bucket["first"] or "",
        "last_seen": bucket["last"] or "",
    }


@app.get("/api/dataset/{dataset_id}/path_breakdown")
def api_path_breakdown(dataset_id: str, prefix: str = Query(default="/"), day: str = Query(default=""),
                        hour: str = Query(default=""), minute: str = Query(default=""),
                        span: int = Query(default=1), second: str = Query(default=""),
                        window_seconds: int = Query(default=30),
        gf: str = Query(default="")):
    """Path Explorer: pentru `prefix` (path pe care userul a dat deja drill-down,
    "" sau "/" = radacina), intoarce bucket-uri agregate UN singur nivel mai
    adanc (vezi _scan_chunk_path_breakdown pentru semantica exacta, inclusiv
    tratarea query string-ului si a liniilor care se opresc exact la prefix).
    Scaneaza intreaga regiune relevanta (ziua selectata, sau tot fisierul) de
    fiecare data -- fara trunchiere/esantionare inainte de agregare, acelasi
    standard de corectitudine ca top_path_prefixes/subnet-uri.

    hour/minute/span/second/window_seconds: ACEEASI scopare ca la /raw si
    /summary_range, folosite ca sa Path Explorer-ul respecte intervalul ales
    in widgetul "Vezi cererile dintr-un moment exact" (bug raportat de Eduard:
    inainte, orice explorare de prefix ignora complet ora aleasa si scana
    mereu ziua intreaga -- de-aici liniile brute dintr-o ora gresita)."""
    ds = _get_dataset(dataset_id)
    if not ds:
        return JSONResponse({"error": "Dataset expirat sau inexistent. Reincarca fisierul."}, status_code=404)
    gf_f, gf_err = _gf_for_scan(ds, gf)
    if gf_err is not None:
        return gf_err

    prefix = (prefix or "/").strip()
    if not prefix.startswith("/"):
        prefix = "/" + prefix

    hour_filter = hour or None
    minute_filter = None
    if minute:
        try:
            minute_filter = (int(minute), max(1, min(60, span)))
        except ValueError:
            minute_filter = None

    second_filter = None
    if second:
        m = re.match(r"^(\d{1,2}):(\d{2}):(\d{2})$", second.strip())
        if m:
            hh, mm, ss = (int(x) for x in m.groups())
            if 0 <= hh < 24 and 0 <= mm < 60 and 0 <= ss < 60:
                target_seconds = hh * 3600 + mm * 60 + ss
                second_filter = (target_seconds, max(0, min(3600, window_seconds)))
                minute_filter = None
                hour_filter = None

    day_filter = day or None
    plain_path, chunks = _scan_plan(ds, day_filter, gf_f)
    args = [(plain_path, s, e, prefix, day_filter, hour_filter, minute_filter, second_filter) for s, e in chunks]

    if len(chunks) <= 1:
        chunk_results = [_scan_chunk_path_breakdown(args[0])] if args else []
    else:
        chunk_results = _pool_map(_scan_chunk_path_breakdown, args, len(chunks))

    merged_children, merged_exact = _merge_path_breakdown(chunk_results)

    children_out = []
    for child_path, bucket in merged_children.items():
        entry = {"path": child_path, "has_children": bucket["has_children"]}
        entry.update(_serialize_breakdown_bucket(bucket))
        children_out.append(entry)
    children_out.sort(key=lambda x: -x["requests"])

    exact_out = _serialize_breakdown_bucket(merged_exact) if merged_exact["count"] > 0 else None

    parent_total = sum(c["requests"] for c in children_out) + (exact_out["requests"] if exact_out else 0)
    for c in children_out:
        c["pct_of_parent"] = round(100.0 * c["requests"] / parent_total, 2) if parent_total else 0.0
    if exact_out is not None:
        exact_out["pct_of_parent"] = round(100.0 * exact_out["requests"] / parent_total, 2) if parent_total else 0.0

    return JSONResponse({
        "prefix": prefix,
        "day": day_filter or "ALL",
        "parent_total": parent_total,
        "exact": exact_out,
        "children": children_out,
    })


@app.get("/api/dataset/{dataset_id}/burst_raw")
def api_burst_raw(dataset_id: str, burst_key: str = Query(default=""),
                   limit: int = Query(default=MAX_RAW_MATCHES),
        gf: str = Query(default="")):
    """Liniile brute complete dintr-o fereastra de 30 secunde (un 'burst'),
    identificata prin burst_key = 'day|hour|minute|half' (vezi build_summary/
    top_bursts). Restrange scanarea la ziua respectiva (folosind indexul de
    zi deja calculat, daca exista) inainte sa filtreze exact pe fereastra."""
    ds = _get_dataset(dataset_id)
    if not ds:
        return JSONResponse({"error": "Dataset expirat sau inexistent."}, status_code=404)
    gf_f, gf_err = _gf_for_scan(ds, gf)
    if gf_err is not None:
        return gf_err
    parts = burst_key.split("|")
    if len(parts) != 4:
        return JSONResponse({"error": "burst_key invalid."}, status_code=400)
    day, hour, minute, half_s = parts
    try:
        half = int(half_s)
    except ValueError:
        return JSONResponse({"error": "burst_key invalid."}, status_code=400)
    bkey = (day, hour, minute, half)
    effective_limit = max(1, min(int(limit) if limit else MAX_RAW_MATCHES, RAW_MATCHES_HARD_CAP))

    plain_path, chunks = _scan_plan(ds, day, gf_f)
    # BUG (Eduard, "erori de parsare"): tuplul de mai jos avea 16 elemente,
    # dar _scan_chunk_raw despacheteaza 17 campuri (vezi semnatura ei -- a
    # crescut de-a lungul sesiunii cu qkey_re/country_filter/identity_filter).
    # Un tuplu prea scurt -> "not enough values to unpack" in worker ->
    # exceptie ne-prinsa -> FastAPI intoarce o pagina de eroare HTML in loc
    # de JSON -> exact eroarea "JSON.parse: unexpected character at line 1
    # column 1" raportata din modalul de burst. Adaugat campul lipsa
    # (identity_filter=None) ca sa se potriveasca la 17.
    args = [(plain_path, s, e, "", None, "", "", effective_limit, bkey, None, None, None, None, None, None, None, None) for s, e in chunks]

    if len(chunks) <= 1:
        chunk_results = [_scan_chunk_raw(args[0])] if args else []
    else:
        chunk_results = _pool_map(_scan_chunk_raw, args, len(chunks))

    matches = []
    truncated = False
    for cmatches, hit_cap in chunk_results:
        matches.extend(cmatches)
        if hit_cap:
            truncated = True
    if len(matches) > effective_limit:
        truncated = True
    matches = matches[:effective_limit]

    return JSONResponse({"matches": matches, "truncated": truncated, "label": burst_window_label(bkey), "limit": effective_limit})


def _get_or_build_summary(ds, day):
    """Cache lookup partajat de export.json/export.csv/ip_detail-ish helpers
    -- identic cu tiparul deja folosit in /summary (nicio scanare noua daca
    ziua respectiva a fost deja calculata o data)."""
    ckey = _cache_key(day)
    cache = ds.setdefault("summary_cache", {})
    summary = cache.get(ckey)
    if summary is None:
        day_filter = None if ckey == "ALL" else ckey
        region = _region_for_day(ds, day_filter)
        merged = run_engine(ds["plain_path"], n_workers=None, day_filter=day_filter, region=region)
        summary = build_summary(merged, days_all=ds.get("days_available"))
        with DATASETS_LOCK:
            cache[ckey] = summary
    return summary


def _summary_for_export(ds, day, gf_raw):
    """v45: exporturile urmeaza selectia globala (perioada + filtre). Fara
    selectie -> sumarul zilei/al logului, ca inainte."""
    gfx, err = _gf_for_scan(ds, gf_raw)
    if err is not None:
        return None, err
    if not gfx:
        return _get_or_build_summary(ds, day), None
    key = _gf_key(gfx)
    cached = ds.get("_fsum_cache", {}).get(key)
    if cached is not None:
        return cached, None
    sub_path, _nb = _subset_for_filters(ds, gfx)
    summary = build_summary(run_engine(sub_path, n_workers=None), days_all=ds.get("days_available"))
    summary["_filtered"] = {"filters": json.loads(key)}
    with _FSUM_LOCK:
        fc = ds.setdefault("_fsum_cache", {})
        if len(fc) >= 6:
            fc.pop(next(iter(fc)))
        fc[key] = summary
    return summary, None


def _restructure_export(summary):
    """Restructureaza summary-ul plat (deja calculat de build_summary) in 11
    sectiuni tematice cerute pentru export -- PUR reorganizare/serializare
    (aceleasi liste/dict-uri deja calculate, doar regrupate sub alte chei),
    fara nicio recalculare."""
    return {
        "summary": {
            "total": summary.get("total"), "bad": summary.get("bad"),
            "unique_ips": summary.get("unique_ips"), "unique_paths": summary.get("unique_paths"),
            "bandwidth": summary.get("bandwidth"), "status": summary.get("status"),
            "findings_count": summary.get("findings_count"), "anomalies_count": summary.get("anomalies_count"),
            "days_available": summary.get("days_available"),
            "timeline_granularity": summary.get("timeline_granularity"),
            "burst_window_count": summary.get("burst_window_count"),
        },
        "traffic": {
            "methods": summary.get("methods"),
            "traffic_composition": summary.get("traffic_composition"),
            "bot_breakdown": summary.get("bot_breakdown"),
            "query_params": summary.get("query_params"),
            "heatmap": summary.get("heatmap"),
            "scan_hits": summary.get("scan_hits"),
        },
        "crawlers": summary.get("crawlers"),
        "bursts": {
            "top_bursts": summary.get("top_bursts"),
            "burst_window_count": summary.get("burst_window_count"),
        },
        "paths": {
            "top_paths": summary.get("top_paths"),
            "top_paths_static": summary.get("top_paths_static"),
            "top_paths_risk": summary.get("top_paths_risk"),
            "top_paths_popular": summary.get("top_paths_popular"),
            "top_paths_dynamic": summary.get("top_paths_dynamic"),
            "top_paths_404": summary.get("top_paths_404"),
            "top_path_prefixes": summary.get("top_path_prefixes"),
            "distributed_enum": summary.get("distributed_enum"),
            "distributed_path_enum": summary.get("distributed_path_enum"),
            "param_abuse": summary.get("param_abuse"),
        },
        "ips": {
            "top_ips": summary.get("top_ips"),
            "suspicious_ips": summary.get("suspicious_ips"),
            "subnets": summary.get("subnets"),
            "all_subnets": summary.get("all_subnets"),
            "top_bandwidth_ips": summary.get("top_bandwidth_ips"),
        },
        "findings": summary.get("findings"),
        "anomalies": summary.get("anomalies"),
        "wordpress": {
            "wp": summary.get("wp"),
            "admin_activity": summary.get("admin_activity"),
            "wordfence_matches": summary.get("wordfence_matches"),
            "wordfence_status": summary.get("wordfence_status"),
        },
        "security": {
            "scan_hits": summary.get("scan_hits"),
            "investigation_queue": summary.get("investigation_queue"),
        },
        "timeline": {
            "timeline": summary.get("timeline"),
            "error_timeline": summary.get("error_timeline"),
            "timeline_granularity": summary.get("timeline_granularity"),
            "compromise_trail": summary.get("compromise_trail"),
        },
    }


@app.get("/api/dataset/{dataset_id}/export.json")
def api_export_json(dataset_id: str, day: str = Query(default="ALL"), gf: str = Query(default="")):
    ds = _get_dataset(dataset_id)
    if not ds:
        return JSONResponse({"error": "Dataset expirat sau inexistent."}, status_code=404)
    summary, err = _summary_for_export(ds, day, gf)
    if err is not None:
        return err
    # v49: exportul = EXACT ce arata interfata (aceeasi reconciliere / grupare)
    summary = _summary_without_fp(dataset_id, summary)
    restructured = _restructure_export(summary)
    restructured["_export"] = {"tip": "SUMAR / STATISTICI (nu liniile brute)", "selectie_gf": json.loads(gf) if gf else {},
                               "zi": day, "cereri_in_selectie": summary.get("total"),
                               "versiune": LOGSCAN_VERSION}
    return Response(content=json.dumps(restructured, ensure_ascii=False, indent=2),
                     media_type="application/json",
                     headers={"Content-Disposition": "attachment; filename=logscan_sumar.json"})


# Coloanele CSV per tip de export -- vezi api_export_csv. Fiecare tip
# corespunde uneia din sectiunile deja calculate de build_summary (nicio
# recalculare, doar serializare CSV).
def _csv_rows_findings(summary):
    return (["severity", "confidence", "rule", "reason", "detail", "ip", "domain", "time"],
            [[f.get("severity", ""), f.get("confidence", ""), f.get("rule", ""), f.get("reason", ""),
              f.get("detail", ""), f.get("ip", ""), f.get("domain") or "", f.get("time", "")]
             for f in summary.get("findings", [])])


def _csv_rows_anomalies(summary):
    return (["severity", "confidence", "rule", "reason", "detail", "ip", "domain", "time"],
            [[a.get("severity", ""), a.get("confidence", ""), a.get("rule", ""), a.get("reason", ""),
              a.get("detail", ""), a.get("ip", ""), a.get("domain") or "", a.get("time", "")]
             for a in summary.get("anomalies", [])])


def _csv_rows_ips(summary):
    bw_map = {x["ip"]: x.get("bandwidth", 0) for x in summary.get("top_bandwidth_ips", [])}
    susp_map = {x["ip"]: x for x in summary.get("suspicious_ips", [])}
    return (["ip", "country", "requests", "bandwidth", "risk", "reasons"],
            [[r["ip"], r.get("country", ""), r.get("requests", 0), bw_map.get(r["ip"], ""),
              susp_map.get(r["ip"], {}).get("risk", ""),
              "; ".join(susp_map.get(r["ip"], {}).get("reasons", []))]
             for r in summary.get("top_ips", [])])


def _csv_rows_crawlers(summary):
    return (["provider", "requests", "unique_ips", "bandwidth", "has_tier2_verification"],
            [[c.get("provider", ""), c.get("requests", 0), c.get("unique_ips", 0),
              c.get("bandwidth", 0), c.get("has_tier2", False)]
             for c in summary.get("crawlers", [])])


def _csv_rows_paths(summary):
    return (["path", "requests", "unique_ips"],
            [[p.get("path", ""), p.get("requests", 0), p.get("unique_ips", 0)]
             for p in summary.get("top_paths", [])])


def _csv_rows_bursts(summary):
    return (["window", "requests", "unique_ips", "classification", "classification_reason"],
            [[b.get("label", ""), b.get("requests", 0), b.get("unique_ips", 0),
              b.get("classification", ""), b.get("classification_reason", "")]
             for b in summary.get("top_bursts", [])])


_CSV_EXPORTS = {
    "findings": _csv_rows_findings,
    "anomalies": _csv_rows_anomalies,
    "ips": _csv_rows_ips,
    "crawlers": _csv_rows_crawlers,
    "paths": _csv_rows_paths,
    "bursts": _csv_rows_bursts,
}


@app.get("/api/dataset/{dataset_id}/export.csv")
def api_export_csv(dataset_id: str, day: str = Query(default="ALL"), type: str = Query(default="findings"),
                   gf: str = Query(default="")):
    """Export CSV -- separat pe tip (findings/anomalies/ips/crawlers/paths/
    bursts), fiecare cu propriile coloane relevante. Implicit 'findings',
    pastrand exact comportamentul vechi al butonului existent din UI daca
    nu se cere alt tip explicit."""
    ds = _get_dataset(dataset_id)
    if not ds:
        return PlainTextResponse("Dataset expirat sau inexistent.", status_code=404)
    t = (type or "findings").strip().lower()
    builder = _CSV_EXPORTS.get(t)
    if builder is None:
        return PlainTextResponse(
            f"Tip export CSV necunoscut: '{t}'. Tipuri valide: {', '.join(_CSV_EXPORTS)}.",
            status_code=400)
    summary, err = _summary_for_export(ds, day, gf)
    if err is not None:
        return err
    summary = _summary_without_fp(dataset_id, summary)
    header, rows = builder(summary)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    for row in rows:
        w.writerow(row)
    return Response(content=buf.getvalue(), media_type="text/csv",
                     headers={"Content-Disposition": f"attachment; filename=logscan_sumar_{t}.csv"})


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/api/wordfence/status")
def api_wordfence_status():
    return JSONResponse(wordfence_status())


@app.post("/api/wordfence/refresh")
def api_wordfence_refresh():
    # Descarcare fortata, la cerere (butonul din UI) -- tot pe thread separat,
    # ca sa nu blocheze raspunsul HTTP cat timp se descarca feed-ul (poate
    # dura pana la ~1 minut). Raspunsul e imediat; statusul se verifica apoi
    # din /api/wordfence/status.
    threading.Thread(target=wordfence_refresh, kwargs={"force": True}, daemon=True).start()
    return JSONResponse({"started": True})


# ==========================================================================
# v43 -- Upload chunked + joburi de fundal (vezi _run_ingest_job mai sus).
# Flux: init() -> chunk() x N -> complete() (intoarce job_id) -> polling pe
# /api/jobs/{job_id} pana la status "done" (acelasi shape de raspuns ca
# vechiul /api/upload: dataset_id/filename/days/summary). Suporta un singur
# fisier per sesiune de upload -- combinarea mai multor arhive (feature
# existent) ramane pe calea veche /api/upload, sincrona dar deja rapida
# pentru cazul ala (fisiere de obicei mai mici, cateva luni de loguri).
# ==========================================================================
@app.post("/api/upload2/init")
def api_upload2_init(payload: dict):
    filename = (payload or {}).get("filename") or "upload.log"
    try:
        total_size = int((payload or {}).get("total_size") or 0)
    except (TypeError, ValueError):
        total_size = 0
    if total_size > MAX_UPLOAD_BYTES:
        return JSONResponse({"error": "Fisier peste limita permisa (8 GB)."}, status_code=400)
    upload_id = uuid.uuid4().hex
    workdir = tempfile.mkdtemp(prefix="logscan_ds_")
    safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", filename) or "upload.log"
    # v50: browserul comprima bucatile cu gzip inainte de trimitere (logurile
    # scad de ~10 ori) -- fisierul primit e atunci un gzip multi-membru, pe
    # care decompress_to_plain il recunoaste dupa extensie.
    if (payload or {}).get("encoding") == "gzip" and not safe_name.lower().endswith(".gz"):
        safe_name += ".gz"
    raw_path = os.path.join(workdir, "incoming_" + safe_name)
    open(raw_path, "wb").close()
    with UPLOADS_LOCK:
        UPLOADS[upload_id] = {
            "workdir": workdir, "raw_path": raw_path, "filename": filename,
            "total_size": total_size, "received": 0, "next_index": 0, "created": time.time(),
            # amprenta continutului, calculata pe masura ce sosesc bucatile
            # (~0.1s la 40 MB) -- vezi deduplicarea din api_upload2_complete
            "sha": hashlib.sha256(),
        }
    return JSONResponse({"upload_id": upload_id})


@app.post("/api/upload2/chunk/{upload_id}")
async def api_upload2_chunk(upload_id: str, request: Request, index: int = Query(default=0)):
    with UPLOADS_LOCK:
        up = UPLOADS.get(upload_id)
    if not up:
        return JSONResponse({"error": "Upload inexistent sau expirat. Reincarca fisierul."}, status_code=404)
    if index != up["next_index"]:
        return JSONResponse(
            {"error": f"Bucata out-of-order (asteptat {up['next_index']}, primit {index})."},
            status_code=409,
        )
    body = await request.body()
    with open(up["raw_path"], "ab") as f:
        f.write(body)
    up["sha"].update(body)
    up["received"] += len(body)
    up["next_index"] += 1
    if up["received"] > MAX_UPLOAD_BYTES:
        with UPLOADS_LOCK:
            UPLOADS.pop(upload_id, None)
        shutil.rmtree(up["workdir"], ignore_errors=True)
        return JSONResponse({"error": "Fisier peste limita permisa (8 GB)."}, status_code=400)
    return JSONResponse({"received": up["received"], "next_index": up["next_index"]})


@app.post("/api/upload2/complete/{upload_id}")
def api_upload2_complete(upload_id: str):
    with UPLOADS_LOCK:
        up = UPLOADS.pop(upload_id, None)
    if not up:
        return JSONResponse({"error": "Upload inexistent sau expirat. Reincarca fisierul."}, status_code=404)
    workdir = up["workdir"]
    raw_path = up["raw_path"]
    filename = up["filename"]
    # Spec §4 -- "evitarea procesarii repetate a aceluiasi fisier": acelasi
    # continut (SHA-256 identic) deja incarcat si inca activ => refolosim
    # datasetul existent (analiza, index, cub), raspuns instant.
    digest = up["sha"].hexdigest() if up.get("sha") else None
    if digest:
        with DATASETS_LOCK:
            hit = next(((did, d) for did, d in DATASETS.items()
                        if d.get("content_sha") == digest and not d.get("triage_error")
                        and os.path.isdir(d.get("workdir") or "")), None)
            if hit:
                hit[1]["created"] = time.time()   # prelungim TTL-ul, e din nou in uz
        if hit:
            did, d = hit
            shutil.rmtree(workdir, ignore_errors=True)
            job_id = uuid.uuid4().hex
            _set_job(job_id, status="done", progress=100, dataset_id=did, filename=filename,
                     days=d.get("days_available"), summary=d["summary_cache"]["ALL"], reused=True)
            print(f"[upload] {filename}: continut identic cu datasetul {did} -- refolosit", flush=True)
            return JSONResponse({"job_id": job_id, "reused": True})
    try:
        decompressed = decompress_to_plain(raw_path, workdir)
        plain_path = os.path.join(workdir, "plain_0.log")
        os.replace(decompressed, plain_path)
        if decompressed != raw_path and os.path.exists(raw_path):
            os.remove(raw_path)
    except Exception as e:
        shutil.rmtree(workdir, ignore_errors=True)
        return JSONResponse({"error": f"{filename}: {e}"}, status_code=400)

    job_id = uuid.uuid4().hex
    _set_job(job_id, status="queued", progress=0, filename=filename)
    _INGEST_EXECUTOR.submit(_run_ingest_job, job_id, plain_path, workdir, filename, [filename], None, digest)
    return JSONResponse({"job_id": job_id})


@app.get("/api/jobs/{job_id}")
def api_job_status(job_id: str):
    job = _get_job(job_id)
    if not job:
        return JSONResponse({"error": "Job inexistent sau expirat."}, status_code=404)
    return JSONResponse(job)


# ==========================================================================
# v43/v44 -- Security Triage + FILTRE GLOBALE + PANOU INFERIOR.
# Toate rutele de mai jos raspund din indexul COLUMNAR (triage_columnar, v44)
# cand e disponibil -- milisecunde indiferent de marimea selectiei -- si cad
# automat pe indexul SQLite (triage_engine) cand numpy lipseste. Randurile
# complete (tabel, detalii, audit) vin mereu din SQLite, prin cheia primara.
# ==========================================================================
def _get_triage_conn(dataset_id):
    """(conn, None) sau (None, JSONResponse-de-eroare) -- tipar simplu de
    folosit direct in return la inceputul fiecarei rute de mai jos."""
    ds = _get_dataset(dataset_id)
    if not ds:
        return None, JSONResponse({"error": "Dataset expirat sau inexistent. Reincarca fisierul."}, status_code=404)
    if not ds.get("triage_ready"):
        if ds.get("triage_error"):
            return None, JSONResponse({"error": f"Indexarea a esuat: {ds['triage_error']}"}, status_code=500)
        return None, JSONResponse(
            {"error": "Indexarea de securitate e inca in curs -- reincearca in cateva secunde.", "indexing": True},
            status_code=202,
        )
    db_path = triage_engine.db_path_for(ds["workdir"])
    if not os.path.exists(db_path):
        return None, JSONResponse({"error": "Indexul de securitate nu exista pentru acest dataset."},
                                   status_code=404)
    return triage_engine.connect(db_path, for_write=False), None


def _verified_crawler_ips(dataset_id):
    """IP-urile care revendica un crawler cunoscut SI au trecut verificarea
    DNS (PTR + forward-confirm sau interval oficial de IP-uri)."""
    with _CRAWLER_JOBS_LOCK:
        job = _CRAWLER_JOBS.get(dataset_id)
        results = dict(job["results"]) if job else {}
    return {ip for ip, r in results.items() if r.get("verified") is True}


_UNCONF_ADMIN_LABEL = "Acces /wp-admin/ NECONFIRMAT (fara login si fara dovada de autentificare)"


def _sync_sql_unconfirmed(db_path, ips):
    """Aceeasi retrogradare si in indexul SQL (motorul de rezerva), ca ambele
    motoare sa dea exact aceleasi alerte/severitati."""
    if not ips or not os.path.exists(db_path):
        return 0
    conn = triage_engine.connect(db_path, for_write=True)
    try:
        with triage_engine._WRITE_LOCK:
            q = ",".join("?" * len(ips))
            cur = conn.execute(
                f"UPDATE events SET severity = 'MEDIUM', label = ?, risk_score = MIN(risk_score, 20) "
                f"WHERE ip IN ({q}) AND action_type = 'admin_get' AND severity IN ('CRITICAL', 'HIGH')",
                [_UNCONF_ADMIN_LABEL] + list(ips))
            n = cur.rowcount
            try:
                conn.execute("DELETE FROM meta WHERE key IN ('alerts', 'filters')")
            except Exception:
                pass   # fara tabela meta -> nimic precalculat de invalidat
            conn.commit()
        if n and triage_engine.cube_ready(conn):
            triage_engine.build_cube(conn)
        return n
    except Exception as e:
        print("[v47.6] sync SQL:", e)
        return 0
    finally:
        conn.close()


def _col_store(ds):
    """Indexul columnar al datasetului (sau None -> calea SQL).
    v47: aplica (incremental) retrogradarea crawlerelor verificate."""
    store = ds.get("_col") if (ds and ds.get("triage_ready")) else None
    if store is not None and not getattr(store, "_fake_wp_done", False):
        try:
            if store.demote_fake_wp_paths():
                for k in ("_overview_cache", "_fsum_cache"):
                    ds.pop(k, None)
        except Exception:
            pass
    if store is not None and getattr(store, "_fake_wp_done", False) and not getattr(store, "_unconf_admin_done", False):
        # v47.6: acces /wp-admin/ fara login si fara dovada de autentificare ->
        # MEDIUM peste tot (alerte, cronologie, tabel), consecvent cu rubrica admin.
        store._unconf_admin_done = True
        try:
            st = _admin_compute(ds, store, None)["status"]
            bad = [store.d_ip[ip] for ip, v in st.items() if v == "neconfirmat" and ip in store.d_ip]
            hi = [store.d_sev[x] for x in ("CRITICAL", "HIGH") if x in store.d_sev]
            acts = [store.d_act[a] for a in ("admin_get",) if a in store.d_act]
            if bad and hi and acts:
                mm = np.isin(store.ip, bad) & np.isin(store.sev, hi) & np.isin(store.act, acts)
                if store.demote_rows(mm, "MEDIUM", _UNCONF_ADMIN_LABEL):
                    store.unconf_demoted_ips = sorted(store.v_ip[c] for c in bad)
                    for k in ("_overview_cache", "_fsum_cache", "_admin_cache"):
                        ds.pop(k, None)
                    if ds.get("workdir"):
                        _sync_sql_unconfirmed(triage_engine.db_path_for(ds["workdir"]), store.unconf_demoted_ips)
        except Exception as e:
            print("[v47.6] demote neconfirmat:", e)
    if store is not None and not ds.get("show_fp"):
        try:
            ver = _verified_crawler_ips(ds.get("id") or ds.get("dataset_id") or "")
            new = ver - getattr(store, "suppressed_ips", set())
            if new and store.suppress_verified_crawlers(new):
                for k in ("_overview_cache", "_fsum_cache"):
                    ds.pop(k, None)
        except Exception:
            pass
    return store


def _fetch_events_by_ids(conn, ids):
    """Randurile complete (cu UA reconstituit) pentru id-urile date, IN
    ORDINEA data -- cateva zeci de citiri pe cheia primara."""
    if not ids:
        return []
    found = {}
    for i in range(0, len(ids), 900):
        batch = ids[i:i + 900]
        for r in conn.execute(
                f"SELECT {triage_engine._EVENT_COLS} FROM events e LEFT JOIN uas u ON u.id = e.ua_id "
                f"WHERE e.id IN ({','.join('?' * len(batch))})", batch):
            found[r["id"]] = dict(r)
    return [found[i] for i in ids if i in found]


@app.get("/api/dataset/{dataset_id}/triage_status")
def api_triage_status(dataset_id: str):
    ds = _get_dataset(dataset_id)
    if not ds:
        return JSONResponse({"error": "Dataset expirat sau inexistent."}, status_code=404)
    store = _col_store(ds)
    return JSONResponse({"ready": bool(ds.get("triage_ready")), "error": ds.get("triage_error"),
                         "content_sha": ds.get("content_sha"), "filename": ds.get("filename"),
                         "geoip": geoip_status(), "engine": ds.get("engine") or ("columnar" if store else "sql"),
                         "columnar_available": triage_columnar.AVAILABLE,
                         "rows": store.n if store is not None else None,
                         "index_ram_mb": round(store.memory_bytes() / 1048576, 1) if store is not None else None})


def _gf_checked(ts_from=None, ts_to=None, country=(), severity=(), status=(), action=(),
                ip="", method="", path_contains="", ua_contains="", day="", gf_raw=""):
    """(filtre, None) sau (None, raspuns 400 cu motivul) -- validarea e
    explicita: o tara nerecunoscuta nu mai produce o lista goala muta.
    v45: gf_raw = selectia globala completa, serializata JSON de frontend
    (UN SINGUR mecanism pentru toate rutele, inclusiv drilldown-urile) --
    cand e data, ea e sursa de adevar."""
    if gf_raw:
        return _gf_parse_json(gf_raw)
    bad = [c for c in (country or []) if normalize_country_value(c) is None]
    if bad:
        return None, JSONResponse({"error": "Tara nerecunoscuta: " + ", ".join(repr(b) for b in bad) +
                                            " -- foloseste codul ISO din 2 litere (ex. RO, DE), '??' pentru "
                                            "tara nedeterminata sau __non_ro__.", "bad_country": bad},
                                  status_code=400)
    try:
        return _gf_from_params(ts_from, ts_to, country, severity, status, action, ip, method,
                               path_contains, ua_contains, day), None
    except (TypeError, ValueError) as e:
        return None, JSONResponse({"error": f"Filtru invalid: {e}"}, status_code=400)


@app.get("/api/dataset/{dataset_id}/events")
def api_triage_events(dataset_id: str,
                       ts_from: Optional[int] = Query(default=None),
                       ts_to: Optional[int] = Query(default=None),
                       country: List[str] = Query(default=[]),
                       severity: List[str] = Query(default=[]),
                       status: List[int] = Query(default=[]),
                       action: List[str] = Query(default=[]),
                       ip: str = Query(default=""),
                       method: str = Query(default=""),
                       path_contains: str = Query(default=""),
                       ua_contains: str = Query(default=""),
                       day: str = Query(default=""),
                       sort: str = Query(default="ts_desc"),
                       limit: int = Query(default=200),
                       offset: int = Query(default=0),
                       with_count: bool = Query(default=False),
                       raw: bool = Query(default=False),
                       gf: str = Query(default=""),
                       kind: str = Query(default=""), value: str = Query(default="")):
    filters, err = _gf_checked(ts_from, ts_to, country, severity, status, action, ip, method,
                               path_contains, ua_contains, day, gf_raw=gf)
    if not err and kind and kind != "sel":
        # v45: evenimentele unei entitati (panoul de explorare) = selectia globala SI entitatea
        ent, emsg = _entity_filter(kind, value)
        if emsg:
            return JSONResponse({"error": emsg}, status_code=400)
        filters = _gf_merge(filters, ent)
    if err:
        return err
    conn, err = _get_triage_conn(dataset_id)
    if err:
        return err
    try:
        t = time.time()
        store = _col_store(_get_dataset(dataset_id))
        if store is not None:
            idx = store.page(filters, limit=limit, offset=offset, sort=sort)
            rows = _fetch_events_by_ids(conn, store.ids_of(idx).tolist())
        else:
            rows = triage_engine.query_events(conn, filters, limit=limit, offset=offset, sort=sort)
        if raw:
            _attach_raw_lines(_get_dataset(dataset_id), rows)
        resp = {"events": rows, "limit": limit, "offset": offset}
        if with_count:
            resp["total"] = store.count(filters) if store is not None else triage_engine.count_events(conn, filters)
        resp["elapsed_ms"] = int((time.time() - t) * 1000)
        return JSONResponse(resp)
    finally:
        conn.close()


def _attach_raw_lines(ds, rows):
    """Linia ORIGINALA din fisier pentru fiecare rand (cateva sute, citite
    prin offset -- fara scanare)."""
    try:
        with open(ds["plain_path"], "rb") as f:
            for r in rows:
                a, b = int(r.get("offset_start") or 0), int(r.get("offset_end") or 0)
                if 0 <= a < b and b - a <= 1 << 20:
                    f.seek(a)
                    r["raw_line"] = f.read(b - a).decode("utf-8", errors="replace").rstrip("\r\n")
    except (OSError, KeyError, TypeError, ValueError):
        pass


@app.get("/api/dataset/{dataset_id}/event")
def api_triage_event(dataset_id: str, id: int = Query(...)):
    """Detaliul complet al unui eveniment din panoul inferior: toate campurile
    indexului + LINIA ORIGINALA din log (spec §8: RAW LOG disponibil pentru
    verificarea analizelor). Textul e date neincredere -- UI-ul il escapeaza."""
    conn, err = _get_triage_conn(dataset_id)
    if err:
        return err
    try:
        rows = _fetch_events_by_ids(conn, [int(id)])
    finally:
        conn.close()
    if not rows:
        return JSONResponse({"error": f"Evenimentul {id} nu exista in acest dataset."}, status_code=404)
    ev = rows[0]
    ds = _get_dataset(dataset_id)
    raw = ""
    try:
        a, b = int(ev["offset_start"]), int(ev["offset_end"])
        if 0 <= a < b and b - a <= 1 << 20:
            with open(ds["plain_path"], "rb") as f:
                f.seek(a)
                raw = f.read(b - a).decode("utf-8", errors="replace").rstrip("\r\n")
    except (OSError, KeyError, TypeError, ValueError):
        raw = ""
    path = ev.get("path") or ""
    qpos = path.find("?")
    ev["raw_line"] = raw
    ev["path_decoded"] = unquote(path)
    ev["path_only"] = path if qpos == -1 else path[:qpos]
    ev["query"] = "" if qpos == -1 else path[qpos + 1:]
    ev["country_known"] = bool(ev.get("country"))
    if (ev.get("ip") in _verified_crawler_ips(dataset_id) and not (ds or {}).get("show_fp")
            and ev.get("action_type") not in triage_columnar.ColStore.FP_KEEP_ACTIONS
            and ev.get("severity") != "INFO"):
        ev["severity_original"] = ev.get("severity")
        ev["severity"] = "INFO"
        ev["fp_note"] = ("Crawler verificat prin DNS (PTR + forward-confirm): evenimentul e tratat ca fals "
                         "pozitiv si retrogradat la INFO.")
    return JSONResponse(ev)


@app.get("/api/dataset/{dataset_id}/histogram")
def api_triage_histogram(dataset_id: str,
                          ts_from: int = Query(...),
                          ts_to: int = Query(...),
                          bucket_seconds: int = Query(default=300),
                          country: List[str] = Query(default=[]),
                          severity: List[str] = Query(default=[]),
                          status: List[int] = Query(default=[]),
                          action: List[str] = Query(default=[]),
                          ip: str = Query(default=""), method: str = Query(default=""),
                          path_contains: str = Query(default=""), ua_contains: str = Query(default=""),
                          day: str = Query(default=""), gf: str = Query(default="")):
    filters, err = _gf_checked(None, None, country, severity, status, action, ip, method,
                               path_contains, ua_contains, day, gf_raw=gf)
    if err:
        return err
    # intervalul histogramei e cel cerut; selectia globala il poate restrange
    filters = dict(filters)
    if filters.get("ts_from") is not None:
        ts_from = max(ts_from, int(filters["ts_from"]))
    if filters.get("ts_to") is not None:
        ts_to = min(ts_to, int(filters["ts_to"]))
    filters["ts_from"] = filters["ts_to"] = None
    if err:
        return err
    conn, err = _get_triage_conn(dataset_id)
    if err:
        return err
    try:
        # TOATE filtrele globale (v43.1 ignora ip/path/ua/metoda aici, deci
        # histograma nu urma selectia -- incoerenta fata de tabel).
        store = _col_store(_get_dataset(dataset_id))
        if store is not None:
            buckets = store.histogram(ts_from, ts_to, bucket_seconds, filters)
        else:
            buckets = triage_engine.build_histogram(conn, ts_from, ts_to, bucket_seconds, filters)
        return JSONResponse({"buckets": buckets, "bucket_seconds": max(60, int(bucket_seconds))})
    finally:
        conn.close()


@app.get("/api/dataset/{dataset_id}/alerts/top")
def api_triage_top_alerts(dataset_id: str, limit: int = Query(default=30), gf: str = Query(default="")):
    """Alertele CRITICAL/HIGH (dedup IP + actiune). v45: DOAR din selectia
    globala curenta (perioada + filtre) -- inainte erau mereu din tot logul."""
    f, err = _gf_checked(gf_raw=gf)
    if err:
        return err
    conn, err = _get_triage_conn(dataset_id)
    if err:
        return err
    try:
        store = _col_store(_get_dataset(dataset_id))
        raw_limit = max(60, int(limit) * 4)
        if _gf_is_empty(f):
            alerts = store.top_alerts(limit=raw_limit) if store is not None else triage_engine.top_alerts(conn, limit=raw_limit)
        else:
            alerts = store.alerts_in(f, raw_limit) if store is not None else triage_engine.alerts_in_sql(conn, f, raw_limit)
        moved = 0
        if store is not None:
            ds = _get_dataset(dataset_id) or {}
            alerts, moved = _reconcile_alerts(ds, store, store.mask(f), alerts)
        total_ips = len(alerts)
        return JSONResponse({"alerts": alerts[:max(1, int(limit))], "total_ips": total_ips,
                             "moved_unconfirmed": moved, "filtered": not _gf_is_empty(f)})
    finally:
        conn.close()


@app.get("/api/dataset/{dataset_id}/admin_session")
def api_triage_admin_session(dataset_id: str, ip: str = Query(...),
                              ts: Optional[int] = Query(default=None),
                              window_minutes: int = Query(default=30), gf: str = Query(default="")):
    """Audit trail: cererile IP-ului in jurul autentificarii. v45: limitat la
    perioada selectata (ancora = ultimul login DIN perioada)."""
    f, err = _gf_checked(gf_raw=gf)
    if err:
        return err
    tf, tt = f.get("ts_from"), f.get("ts_to")
    conn, err = _get_triage_conn(dataset_id)
    if err:
        return err
    try:
        store = _col_store(_get_dataset(dataset_id))
        if store is None:
            out = triage_engine.admin_session(conn, ip, around_ts=ts, window_minutes=window_minutes)
            out["events"] = [e for e in out["events"] if (tf is None or e["ts"] >= tf) and (tt is None or e["ts"] <= tt)]
            return JSONResponse(out)
        if ts is None and (tf is not None or tt is not None):
            # ancora = ultima autentificare din perioada selectata
            mm = store.mask({"ts_from": tf, "ts_to": tt, "ip": ip,
                             "action_types": ["admin_login_success", "admin_login_post"]})
            cand: Any = np.flatnonzero(mm) if mm is not None else []
            if len(cand):
                ts = int(store.ts[cand].max())
            else:
                return JSONResponse({"ip": ip, "anchor_ts": None, "events": [], "duration_seconds": 0,
                                     "note": "Nicio autentificare a acestui IP in perioada selectata."})
        anchor, idx = store.admin_session_rows(ip, around_ts=ts, window_minutes=window_minutes)
        if anchor is not None and (tf is not None or tt is not None):
            keep = np.ones(len(idx), bool)
            if tf is not None:
                keep &= store.ts[idx] >= tf
            if tt is not None:
                keep &= store.ts[idx] <= tt
            idx = idx[keep]
        events = _fetch_events_by_ids(conn, store.ids_of(idx).tolist()) if anchor is not None else []
        duration = (events[-1]["ts"] - events[0]["ts"]) if len(events) >= 2 else 0
        return JSONResponse({"ip": ip, "anchor_ts": anchor, "events": events, "duration_seconds": duration})
    finally:
        conn.close()


@app.get("/api/dataset/{dataset_id}/filters")
def api_triage_filters(dataset_id: str):
    conn, err = _get_triage_conn(dataset_id)
    if err:
        return err
    try:
        store = _col_store(_get_dataset(dataset_id))
        dv = store.distinct if store is not None else (lambda c: triage_engine.distinct_values(conn, c))
        return JSONResponse({
            "countries": dv("country"),
            "action_types": dv("action_type"),
            "severities": dv("severity"),
            "statuses": dv("http_status"),
            "geoip": geoip_status(),
        })
    finally:
        conn.close()



# ==========================================================================
# v43.2 -- FILTRE GLOBALE (spec §6): acelasi set de filtre pentru TOATA
# aplicatia. Definitia unui filtru e cea din indexul de triaj (aceeasi ca in
# tabelul RAW), deci tabelul, histograma, sinteza si analiza completa a
# taburilor v42 arata EXACT aceeasi submultime de linii.
# ==========================================================================
def _gf_from_params(ts_from=None, ts_to=None, country=(), severity=(), status=(), action=(),
                    ip="", method="", path_contains="", ua_contains="", day=""):
    countries = []
    for c in (country or []):
        n = normalize_country_value(c)
        if n is None:
            raise ValueError(f"tara nerecunoscuta: {c!r}")
        if n not in countries:
            countries.append(n)
    return {
        "ts_str_day": (day or "").strip() or None,
        "ts_from": ts_from, "ts_to": ts_to, "countries": countries,
        "severities": [s.strip().upper() for s in (severity or []) if s and s.strip()],
        "statuses": [int(x) for x in (status or [])],
        "action_types": [a.strip() for a in (action or []) if a and a.strip()],
        "ip": (ip or "").strip() or None, "method": (method or "").strip().upper() or None,
        "path_contains": path_contains or None, "ua_contains": ua_contains or None,
    }


_WP_CAT_NAMES = ("wp_admin", "admin_ajax", "xmlrpc", "wp_json", "wp_cron", "wp_login_get", "wp_login_post", "wp_any")
_STATUS_CLASS_NAMES = ("1xx", "2xx", "3xx", "4xx", "5xx")


def _gf_parse_json(raw):
    """Selectia globala trimisa de UI ca JSON (aceleasi chei ca filtrele
    indexului) -> (filtre validate, None) sau (None, raspuns 400)."""
    def bad(msg):
        return None, JSONResponse({"error": "Filtru invalid: " + msg}, status_code=400)
    try:
        d = json.loads(raw) if isinstance(raw, str) else dict(raw or {})
    except (ValueError, TypeError):
        return bad("parametrul gf nu e JSON valid")
    if not isinstance(d, dict):
        return bad("parametrul gf trebuie sa fie un obiect")
    lst = lambda k: [x for x in (d.get(k) or []) if x not in (None, "")] if isinstance(d.get(k) or [], list) else None
    for k in ("countries", "severities", "statuses", "action_types", "status_class", "x_ips", "x_countries",
              "x_statuses", "x_paths", "x_uas"):
        if lst(k) is None:
            return bad(f"{k} trebuie sa fie o lista")
    countries = d.get("countries") or []
    badc = [c for c in countries + (d.get("x_countries") or []) if normalize_country_value(c) is None]
    if badc:
        return None, JSONResponse({"error": "Tara nerecunoscuta: " + ", ".join(repr(b) for b in badc) +
                                            " -- foloseste codul ISO din 2 litere (ex. RO, DE), '??' pentru "
                                            "tara nedeterminata sau __non_ro__.", "bad_country": badc},
                                  status_code=400)
    try:
        tf = d.get("ts_from"); tt = d.get("ts_to")
        f = _gf_from_params(int(tf) if tf not in (None, "") else None, int(tt) if tt not in (None, "") else None,
                            countries, d.get("severities") or [], d.get("statuses") or [],
                            d.get("action_types") or [], d.get("ip") or "", d.get("method") or "",
                            d.get("path_contains") or "", d.get("ua_contains") or "", d.get("ts_str_day") or "")
        pe = d.get("path_exact")
        f["path_exact"] = pe if isinstance(pe, str) and pe != "" else None
        sc = [c for c in (d.get("status_class") or []) if c in _STATUS_CLASS_NAMES]
        f["status_class"] = sc
        wc = d.get("wp_cat") or None
        if wc is not None and wc not in _WP_CAT_NAMES:
            return bad(f"categorie WordPress necunoscuta: {wc!r}")
        f["wp_cat"] = wc
        if d.get("ua"):
            f["ua"] = str(d["ua"])
        f["x_ips"] = [str(x).strip() for x in (d.get("x_ips") or []) if str(x).strip()]
        xc = []
        for c in (d.get("x_countries") or []):
            n = normalize_country_value(c)
            if n not in xc:
                xc.append(n)
        f["x_countries"] = xc
        f["x_statuses"] = [int(x) for x in (d.get("x_statuses") or [])]
        f["x_paths"] = [str(x) for x in (d.get("x_paths") or []) if str(x)]
        f["x_uas"] = [str(x) for x in (d.get("x_uas") or []) if str(x)]
    except (TypeError, ValueError) as e:
        return bad(str(e))
    return f, None


def _gf_merge(base, extra):
    """Selectia globala SI filtrul entitatii dintr-un drilldown (AND). Listele
    de excludere se reunesc; restul cheilor entitatii se adauga peste."""
    f = dict(base or {})
    for k, v in (extra or {}).items():
        if v in (None, "", []):
            continue
        if k.startswith("x_"):
            f[k] = list(dict.fromkeys(list(f.get(k) or []) + list(v)))
        elif k in ("countries", "statuses", "severities", "action_types", "status_class") and f.get(k):
            # AND intre doua multimi = intersectia (lista goala => nimic nu trece)
            inter = [x for x in v if x in f[k]]
            if inter:
                f[k] = inter
            else:
                f["_empty"] = True
        elif k == "ts_from" and f.get("ts_from") is not None:
            f[k] = max(int(f[k]), int(v))
        elif k == "ts_to" and f.get("ts_to") is not None:
            f[k] = min(int(f[k]), int(v))
        elif k in ("ip", "path_exact", "method", "ua", "wp_cat", "ts_str_day") and f.get(k) not in (None, "") and f[k] != v:
            f["_empty"] = True   # doua valori exacte diferite pentru acelasi camp => selectie vida
        elif k in ("path_contains", "ua_contains") and f.get(k):
            f["_and_" + k] = list(f.get("_and_" + k) or []) + [v]
        else:
            f[k] = v
    return f


def _ds_tz(ds):
    """Fusul orar al logului (secunde), din primul timestamp indexat --
    per dataset (doua fisiere cu fusuri diferite nu se incurca)."""
    if ds is None:
        return _LOG_TZ_OFFSET[0]
    if ds.get("tz_offset") is None:
        off = None
        try:
            c = triage_engine.connect(triage_engine.db_path_for(ds["workdir"]))
            try:
                r = c.execute("SELECT ts_str FROM events LIMIT 1").fetchone()
            finally:
                c.close()
            m = re.search(r"([+-])(\d\d)(\d\d)$", r[0] if r else "")
            if m:
                off = (1 if m.group(1) == "+" else -1) * (int(m.group(2)) * 3600 + int(m.group(3)) * 60)
        except Exception:
            off = None
        if off is None:
            return _LOG_TZ_OFFSET[0]
        ds["tz_offset"] = off
    return ds["tz_offset"]


def _gf_label(f, ds=None):
    bits = []
    if f.get("ts_from") is not None or f.get("ts_to") is not None:
        tz = _ds_tz(ds)
        fmt = lambda e: datetime.utcfromtimestamp(int(e) + tz).strftime("%d %b %H:%M:%S") if e is not None else "..."
        bits.append(f"interval {fmt(f.get('ts_from'))} - {fmt(f.get('ts_to'))}")
    for k, lbl in (("countries", "tara"), ("ip", "IP"), ("statuses", "status"), ("path_contains", "URL contine"),
                   ("path_exact", "URL"), ("severities", "severitate"), ("method", "metoda"), ("ts_str_day", "ziua")):
        v = f.get(k)
        if v not in (None, "", []):
            bits.append(f"{lbl} {'/'.join(map(str, v)) if isinstance(v, list) else v}")
    return ", ".join(bits)


_LOG_TZ_OFFSET = [0]   # fusul orar al logului (din primul timestamp), doar pentru etichete


def _gf_key(f):
    """Cheie canonica (ordinea valorilor nu conteaza) pentru memoizare."""
    norm = {k: (sorted(map(str, v)) if isinstance(v, list) else v) for k, v in f.items() if v not in (None, [], "")}
    return json.dumps(norm, sort_keys=True)


def _gf_is_empty(f):
    return _gf_key(f) == "{}"


def _overview_from_summary(summ, conn):
    """Sinteza pentru TOT datasetul, in aceeasi forma ca triage_engine.overview,
    construita din sumarul v42 (aceleasi definitii) + meta precalculata.
    Folosita doar pe calea SQL (fara index columnar)."""
    st = summ.get("status") or {}
    filt = triage_engine.get_meta(conn, "filters") or {}
    bounds = triage_engine.get_meta(conn, "bounds") or {}
    countries = filt.get("countries") or []
    return {
        "requests": summ.get("total", 0), "unique_ips": summ.get("unique_ips", 0),
        "unique_paths": summ.get("unique_paths", 0), "bandwidth": summ.get("bandwidth", 0),
        "ts_min": bounds.get("ts_min"), "ts_max": bounds.get("ts_max"),
        "err_4xx": st.get("4xx", 0), "err_5xx": st.get("5xx", 0),
        "unknown_country": sum(c["count"] for c in countries if not c["value"]),
        "statuses": [{"status": c["value"], "n": c["count"]} for c in (filt.get("statuses") or [])],
        "methods": [{"method": k, "n": v} for k, v in sorted((summ.get("methods") or {}).items(), key=lambda x: -x[1])],
        "top_paths": [{"path": p["path"], "n": p["requests"], "ips": p.get("unique_ips")}
                      for p in (summ.get("top_paths") or [])[:15]],
        "top_ips": [{"ip": p["ip"], "country": p.get("country", ""), "n": p["requests"]}
                    for p in (summ.get("top_ips") or [])[:15]],
        "countries": [{"country": "" if c["country"] == "??" else c["country"], "n": c["requests"],
                       "ips": c.get("unique_ips")} for c in (summ.get("country_totals") or [])[:60]],
        "severities": [{"severity": c["value"], "n": c["count"]} for c in (filt.get("severities") or [])],
        "wordpress": triage_engine.get_meta(conn, "wordpress_all") or {},
        "error_paths": triage_engine.get_meta(conn, "error_paths_all") or [],
        "source": "summary",
    }


@app.get("/api/dataset/{dataset_id}/overview")
def api_overview(dataset_id: str,
                 ts_from: Optional[int] = Query(default=None), ts_to: Optional[int] = Query(default=None),
                 country: List[str] = Query(default=[]), severity: List[str] = Query(default=[]),
                 status: List[int] = Query(default=[]), action: List[str] = Query(default=[]),
                 ip: str = Query(default=""), method: str = Query(default=""),
                 path_contains: str = Query(default=""), ua_contains: str = Query(default=""),
                 day: str = Query(default=""), gf: str = Query(default="")):
    """Sinteza selectiei curente pentru panoul inferior: cereri, IP-uri unice,
    URL-uri distincte, erori, WordPress pe categorii, top IP/path/tara.
    Memoizata per dataset + set de filtre."""
    ds = _get_dataset(dataset_id)
    f, err = _gf_checked(ts_from, ts_to, country, severity, status, action, ip, method, path_contains,
                         ua_contains, day, gf_raw=gf)
    if err:
        return err
    key = _gf_key(f)
    cache = ds.setdefault("_overview_cache", {}) if ds else {}
    if key in cache:
        out = dict(cache[key])
        out["cached"] = True
        return JSONResponse(out)
    conn, err = _get_triage_conn(dataset_id)
    if err:
        return err
    try:
        t = time.time()
        store = _col_store(ds)
        if store is not None:
            out = store.overview(f)
        elif _gf_is_empty(f):
            # Fara filtre: aceleasi cifre exista deja in sumarul complet v42 +
            # blocurile precalculate la indexare -- nimic de rescanat.
            out = _overview_from_summary(ds["summary_cache"]["ALL"], conn)
        else:
            out = triage_engine.overview(conn, f)
        out["elapsed_ms"] = int((time.time() - t) * 1000)
        if len(cache) > 64:
            cache.pop(next(iter(cache)))
        cache[key] = out
        return JSONResponse(out)
    finally:
        conn.close()


@app.get("/api/dataset/{dataset_id}/ip_profile")
def api_ip_profile(dataset_id: str, ip: str = Query(...),
                   ts_from: Optional[int] = Query(default=None), ts_to: Optional[int] = Query(default=None),
                   gf: str = Query(default="")):
    """Profil interactiv al unui IP (spec §5) pe selectia globala curenta
    (perioada + toate filtrele active, v45)."""
    base, err = _gf_checked(ts_from, ts_to, gf_raw=gf)
    if err:
        return err
    conn, err = _get_triage_conn(dataset_id)
    if err:
        return err
    try:
        ip = (ip or "").strip()
        f = _gf_merge(base, {})
        f.pop("ip", None) if f.get("ip") == ip else None
        store = _col_store(_get_dataset(dataset_id))
        if store is not None:
            prof = store.ip_profile(ip, f)
        else:
            prof = triage_engine.ip_profile(conn, ip, f)
        prof["country"] = country_of(ip) or ""
        prof["signals"] = _ip_signals(prof)
        return JSONResponse(prof)
    finally:
        conn.close()


def _ip_signals(p):
    """Comportamente neobisnuite ale unui IP, fiecare cu JUSTIFICAREA si un
    nivel de incredere (spec §5: indicatori, nu certitudini). Doar praguri
    simple, explicate in text -- nimic nu e etichetat drept atac confirmat."""
    out = []
    n = p.get("requests") or 0
    if not n:
        return out
    w = p.get("wordpress") or {}
    rpm = p.get("req_per_min") or 0
    peak = (p.get("peak_minute") or {}).get("n") or 0
    e4 = p.get("err_4xx") or 0
    lp = w.get("wp_login_post") or 0
    xr = w.get("xmlrpc") or 0
    if lp >= 20:
        out.append({"level": "high" if lp >= 100 else "medium", "label": "Posibil brute force wp-login",
                    "why": f"{lp} cereri POST catre wp-login.php de la acest IP. Un utilizator real se "
                           f"autentifica de cateva ori; zeci/sute de POST-uri indica incercari automate."})
    elif lp >= 5:
        out.append({"level": "low", "label": "Mai multe incercari de autentificare",
                    "why": f"{lp} POST-uri catre wp-login.php -- poate fi o parola uitata sau inceputul unei incercari automate."})
    if xr >= 10:
        out.append({"level": "medium" if xr < 100 else "high", "label": "Activitate xmlrpc.php",
                    "why": f"{xr} cereri catre xmlrpc.php -- endpoint folosit des pentru brute force (system.multicall) "
                           f"sau pingback; legitim doar pentru Jetpack/aplicatii mobile WordPress."})
    if n >= 50 and e4 / n >= 0.5:
        out.append({"level": "medium", "label": "Rata mare de erori 4xx",
                    "why": f"{e4} din {n} cereri ({round(100 * e4 / n)}%) au primit 4xx -- tipic pentru scanare de "
                           f"fisiere/endpoint-uri inexistente. Un 404 izolat NU e un atac."})
    if peak >= 120 or rpm >= 60:
        out.append({"level": "medium", "label": "Frecventa ridicata",
                    "why": f"varf de {peak} cereri intr-un minut, medie {rpm}/min -- ritm de automatizare (crawler, "
                           f"script, monitorizare); verifica User-Agent-ul si daca e un crawler verificat."})
    crit = sum(a.get("n", 0) for a in (p.get("actions") or []) if a.get("severity") in ("CRITICAL", "HIGH"))
    if crit:
        out.append({"level": "high", "label": "Evenimente CRITICAL/HIGH",
                    "why": f"{crit} cereri clasificate CRITICAL/HIGH de reguli concrete (vezi lista de clasificari)."})
    return out


# --------------------------------------------------------------------------
# v44 -- subset de linii pentru o selectie globala (offset-uri din index ->
# fisier mic), refolosit de pagina Prezentare. Cache LRU mic per dataset;
# fisierele se sterg la evacuare si odata cu datasetul (workdir).
# --------------------------------------------------------------------------
_SUBSET_MAX = 8


def _gf_ranges(ds, f):
    store = _col_store(ds)
    if store is not None:
        return store.offsets(f)
    conn = triage_engine.connect(triage_engine.db_path_for(ds["workdir"]), for_write=False)
    try:
        return list(_coalesce_ranges(triage_engine.candidate_offsets(conn, f)))
    finally:
        conn.close()


def _subset_for_filters(ds, f):
    key = _gf_key(f)
    lock = ds.setdefault("_subset_lock", threading.Lock())
    with lock:
        cache = ds.setdefault("_subsets", {})
        hit = cache.pop(key, None)
        if hit and os.path.exists(hit[0]):
            cache[key] = hit
            return hit
        path = os.path.join(ds["workdir"], f"gfsubset_{hashlib.sha1(key.encode()).hexdigest()[:16]}.log")
        n_bytes = 0
        with open(ds["plain_path"], "rb") as src, open(path, "wb") as dst:
            for a, b in _gf_ranges(ds, f):
                src.seek(a)
                dst.write(src.read(b - a))
                n_bytes += b - a
        while len(cache) >= _SUBSET_MAX:
            old = cache.pop(next(iter(cache)))
            try:
                os.unlink(old[0])
            except OSError:
                pass
        cache[key] = (path, n_bytes)
        return cache[key]


def _gf_for_scan(ds, gf_raw):
    """Selectia globala pentru un drilldown care rescaneaza fisierul:
    (filtre sau None, raspuns-de-eroare sau None)."""
    if not gf_raw:
        return None, None
    f, err = _gf_parse_json(gf_raw)
    if err is not None:
        return None, err
    if _gf_is_empty(f):
        return None, None
    if not ds.get("triage_ready"):
        return None, JSONResponse({"error": "Selectia globala (perioada/filtre) se poate aplica aici dupa "
                                            "indexare -- reincearca in cateva secunde.", "indexing": True},
                                  status_code=202)
    return f, None


def _scan_plan(ds, day_filter, gf=None):
    """Fisierul + chunk-urile de scanat pentru un drilldown. v45: cu o
    selectie globala activa (perioada, tara, IP, ...) scanarea ruleaza DOAR pe
    liniile selectiei (extrase prin index intr-un fisier-subset, cache LRU) --
    inainte, fiecare drilldown citea fisierul intreg (sau ziua) si arata
    linii din afara perioadei selectate. Ziua (day_filter) ramane aplicata
    per linie de scanner, deci rezultatul e intersectia."""
    if gf:
        path, _nb = _subset_for_filters(ds, gf)
        region = None
    else:
        path = ds["plain_path"]
        region = _region_for_day(ds, day_filter)
    scan_size = (region[1] - region[0]) if region is not None else os.path.getsize(path)
    n_workers = _safe_worker_count(scan_size, _default_worker_count())
    if region is not None:
        chunks = find_chunk_offsets(path, n_workers, region_start=region[0], region_end=region[1])
    else:
        chunks = find_chunk_offsets(path, n_workers)
    return path, chunks


_FSUM_LOCK = threading.Lock()
# Executor dedicat (1 thread) pentru re-analiza v42 a selectiilor: threadul lui
# ruleaza la prioritate scazuta (nice +10), la fel si workerii pool-ului
# pornit din el (vezi _pool_map) -- tabelul, sinteza si upload-urile au
# intotdeauna prioritate la CPU. Un singur job odata; selectiile depasite sunt
# abandonate (vezi _fsum_latest).
_FSUM_EXECUTOR = ThreadPoolExecutor(max_workers=1, thread_name_prefix="fsum")


def _run_filtered_summary(dataset_id, key, f):
    """Recalculeaza analiza COMPLETA v42 (toate taburile) doar pentru liniile
    care trec filtrele globale: indexul da offset-urile liniilor, le copiem
    intr-un fisier-subset si rulam pe el EXACT acelasi motor (run_engine +
    build_summary) -- deci fiecare grafic/tabel/finding din taburile vechi
    reflecta selectia, cu aceleasi reguli ca analiza intreaga."""
    try:
        os.setpriority(os.PRIO_PROCESS, threading.get_native_id(), 10)
    except (OSError, AttributeError):
        pass
    ds = _get_dataset(dataset_id)
    if not ds:
        return
    jobs = ds.setdefault("_fsum_jobs", {})
    if ds.get("_fsum_latest") != key:
        # intre timp utilizatorul a ales alta selectie -- nu mai ocupam un
        # worker cu o analiza pe care nu o mai asteapta nimeni
        jobs[key] = {"status": "superseded"}
        return
    try:
        jobs[key] = {"status": "selecting", "progress": 5}
        sub_path = os.path.join(ds["workdir"], f"subset_{abs(hash(key)) % 10**10}.log")
        n_lines = 0
        t0 = time.time()
        with open(ds["plain_path"], "rb") as src, open(sub_path, "wb") as dst:
            for a, b in _gf_ranges(ds, f):
                src.seek(a)
                dst.write(src.read(b - a))
                n_lines += 1
        jobs[key] = {"status": "analyzing", "progress": 35}
        t1 = time.time()
        prog_dir = sub_path + ".prog"
        os.makedirs(prog_dir, exist_ok=True)
        sub_size = max(1, os.path.getsize(sub_path))
        stop = threading.Event()

        def _mon():
            # progres real (35% -> 95%) din fisierele scrise de workeri
            while not stop.wait(1.0):
                done = 0
                try:
                    for fn in os.listdir(prog_dir):
                        try:
                            done += int(open(os.path.join(prog_dir, fn)).read().split()[1])
                        except (OSError, ValueError, IndexError):
                            pass
                except OSError:
                    pass
                if jobs.get(key, {}).get("status") == "analyzing":
                    jobs[key] = {"status": "analyzing", "progress": 35 + int(60 * min(1.0, done / sub_size))}

        threading.Thread(target=_mon, daemon=True).start()
        try:
            merged = run_engine(sub_path, n_workers=None, progress_dir=prog_dir)
        finally:
            stop.set()
            shutil.rmtree(prog_dir, ignore_errors=True)
        summary = build_summary(merged, days_all=ds.get("days_available"))
        summary["_filtered"] = {"filters": json.loads(key), "extract_s": round(t1 - t0, 2),
                                "analyze_s": round(time.time() - t1, 2)}
        with _FSUM_LOCK:
            fc = ds.setdefault("_fsum_cache", {})
            if len(fc) >= 6:  # memoizare limitata: pastram ultimele selectii
                fc.pop(next(iter(fc)))
            fc[key] = summary
        jobs[key] = {"status": "done", "progress": 100}
        print(f"[timing] summary_filtrat extract={t1-t0:.1f}s analiza={time.time()-t1:.1f}s "
              f"linii={merged.get('total', 0)}", flush=True)
        try:
            os.unlink(sub_path)
        except OSError:
            pass
    except Exception as e:
        jobs[key] = {"status": "error", "error": str(e)}


@app.get("/api/dataset/{dataset_id}/summary_filtered")
def api_summary_filtered(dataset_id: str,
                         ts_from: Optional[int] = Query(default=None), ts_to: Optional[int] = Query(default=None),
                         country: List[str] = Query(default=[]), severity: List[str] = Query(default=[]),
                         status: List[int] = Query(default=[]), action: List[str] = Query(default=[]),
                         ip: str = Query(default=""), method: str = Query(default=""),
                         path_contains: str = Query(default=""), ua_contains: str = Query(default=""),
                         day: str = Query(default=""), gf: str = Query(default="")):
    """Sumarul complet (forma identica cu /summary) pentru selectia globala.
    Fara filtre -> sumarul intreg deja calculat. Cu filtre -> din cache, sau
    porneste un job de fundal si raspunde cu progresul (frontend-ul revine)."""
    ds = _get_dataset(dataset_id)
    if not ds:
        return JSONResponse({"error": "Dataset expirat sau inexistent."}, status_code=404)
    f, err = _gf_checked(ts_from, ts_to, country, severity, status, action, ip, method, path_contains,
                         ua_contains, day, gf_raw=gf)
    if err:
        return err
    if _gf_is_empty(f):
        return JSONResponse({"status": "done", "summary": _summary_without_fp(dataset_id, ds["summary_cache"]["ALL"])})
    if not ds.get("triage_ready"):
        return JSONResponse({"status": "waiting_index", "progress": 0})
    key = _gf_key(f)
    ds["_fsum_latest"] = key
    cached = ds.get("_fsum_cache", {}).get(key)
    if cached is not None:
        return JSONResponse({"status": "done", "summary": _summary_without_fp(dataset_id, cached)})
    job = ds.setdefault("_fsum_jobs", {}).get(key)
    if job and job.get("status") == "error":
        return JSONResponse({"status": "error", "error": job.get("error")}, status_code=500)
    if not job or job.get("status") in ("done", "superseded"):
        ds["_fsum_jobs"][key] = {"status": "queued", "progress": 1}
        _FSUM_EXECUTOR.submit(_run_filtered_summary, dataset_id, key, f)
        job = ds["_fsum_jobs"][key]
    return JSONResponse({"status": job.get("status"), "progress": job.get("progress", 0)})


# ==========================================================================
# v45 -- PANOUL DE EXPLORARE (drilldown unitar): orice entitate (IP, URL,
# prefix, tara, cod HTTP, clasa de cod, categorie WordPress, User-Agent,
# actiune, severitate, alerta) SAU selectia curenta, intotdeauna in
# intersectie cu selectia globala (perioada + toate filtrele active).
# Un singur mecanism (gf JSON + _gf_merge) pentru toate vederile.
# ==========================================================================
_EXPLORE_KINDS = ("sel", "ip", "path", "prefix", "country", "status", "sclass", "wp", "ua", "action",
                  "severity", "alert", "method")


def _entity_filter(kind, value):
    """(filtru pentru entitate, None) sau (None, mesaj de eroare)."""
    v = (value or "").strip() if kind not in ("path", "prefix", "ua") else (value or "")
    if kind == "sel":
        return {}, None
    if kind not in _EXPLORE_KINDS:
        return None, f"tip de entitate necunoscut: {kind!r}"
    if v == "" and kind != "country":
        return None, "valoarea entitatii lipseste"
    if kind == "ip":
        return {"ip": v}, None
    if kind == "path":
        return {"path_exact": v.split("?", 1)[0]}, None
    if kind == "prefix":
        return {"path_contains": v}, None
    if kind == "country":
        n = normalize_country_value(v)
        if n is None:
            return None, f"tara nerecunoscuta: {v!r} (cod ISO din 2 litere, '??' sau __non_ro__)"
        return {"countries": [n]}, None
    if kind == "status":
        try:
            return {"statuses": [int(v)]}, None
        except ValueError:
            return None, f"cod HTTP invalid: {v!r}"
    if kind == "sclass":
        if v not in _STATUS_CLASS_NAMES:
            return None, f"clasa de cod invalida: {v!r} (2xx, 3xx, 4xx, 5xx)"
        return {"status_class": [v]}, None
    if kind == "wp":
        if v not in _WP_CAT_NAMES:
            return None, f"categorie WordPress necunoscuta: {v!r}"
        return {"wp_cat": v}, None
    if kind == "ua":
        return {"ua": v}, None
    if kind == "method":
        return {"method": v.upper()}, None
    if kind == "action":
        return {"action_types": [v]}, None
    if kind == "severity":
        return {"severities": [v.upper()]}, None
    if kind == "alert":
        ip, _, act = v.partition("|")
        if not ip or not act:
            return None, "alerta trebuie data ca 'ip|actiune'"
        return {"ip": ip, "action_types": [act]}, None
    return None, "tip necunoscut"


def _explore_filters(ds, kind, value, gf):
    base, err = _gf_checked(gf_raw=gf)
    if err:
        return None, None, err
    ent, emsg = _entity_filter(kind, value)
    if emsg:
        return None, None, JSONResponse({"error": emsg}, status_code=400)
    return base, _gf_merge(base, ent), None


def _empty_reason(base, ent_f, total_in_selection):
    if ent_f.get("_empty"):
        return ("Entitatea intra in conflict cu un filtru global activ (ex. alt IP / alta tara / alt cod deja "
                "selectat) -- intersectia e vida. Elimina filtrul global respectiv ca sa vezi entitatea.")
    if not total_in_selection:
        return "Selectia globala curenta (perioada + filtre) nu contine nicio cerere."
    return "Entitatea nu are nicio cerere in selectia globala curenta (perioada + filtre)."


@app.get("/api/dataset/{dataset_id}/explore")
def api_explore(dataset_id: str, kind: str = Query(default="sel"), value: str = Query(default=""),
                gf: str = Query(default=""), cmp_from: Optional[int] = Query(default=None),
                cmp_to: Optional[int] = Query(default=None), top_n: int = Query(default=15)):
    """Datele panoului de explorare pentru o entitate, DOAR in selectia
    globala: sinteza, UA-uri, IP-uri (cu erori si ritm), rute de plugin/tema,
    alerte, varf, sesiuni estimate; optional comparatie cu alt interval
    (aceleasi filtre, alta perioada)."""
    ds = _get_dataset(dataset_id)
    if not ds:
        return JSONResponse({"error": "Dataset expirat sau inexistent."}, status_code=404)
    base, f, err = _explore_filters(ds, kind, value, gf)
    if err:
        return err
    conn, err = _get_triage_conn(dataset_id)
    if err:
        return err
    try:
        t = time.time()
        top_n = max(5, min(int(top_n), 100))
        store = _col_store(ds)
        if store is not None:
            out = store.explore(f, top_n=top_n)
            total_sel = store.count(base)
        else:
            out = triage_engine.explore_sql(conn, f, top_n=top_n)
            total_sel = triage_engine.count_events(conn, base)
        out["kind"], out["value"] = kind, value
        out["selection_requests"] = total_sel
        out["share_of_selection"] = round(100.0 * out["requests"] / total_sel, 2) if total_sel else 0
        out["selection_label"] = _gf_label(base, ds) or "tot logul"
        if not out["requests"]:
            out["empty_reason"] = _empty_reason(base, f, total_sel)
        if kind == "ip":
            out["country"] = country_of(value.strip()) or ""
            out["signals"] = _ip_signals(out)
        if kind == "country" and out["requests"]:
            out["signals"] = []
        if cmp_from is not None and cmp_to is not None and cmp_to >= cmp_from:
            fb = dict(f)
            fb["ts_from"], fb["ts_to"] = int(cmp_from), int(cmp_to)
            b = store.overview(fb, top_n=8) if store is not None else triage_engine.overview_sql(conn, fb, top_n=8)
            span = max(60.0, (int(cmp_to) - int(cmp_from) + 1))
            b["req_per_min"] = round(b["requests"] * 60.0 / span, 2) if b["requests"] else 0
            out["compare"] = {k: b.get(k) for k in ("requests", "unique_ips", "unique_paths", "err_4xx", "err_5xx",
                                                    "req_per_min", "top_paths", "top_ips", "statuses", "countries",
                                                    "ts_min", "ts_max")}
            out["compare"]["wordpress"] = {k: (b.get("wordpress") or {}).get(k, 0)
                                           for k in ("wp_login_post", "xmlrpc", "wp_admin", "wp_json")}
            out["compare"]["range"] = [int(cmp_from), int(cmp_to)]
        out["elapsed_ms"] = int((time.time() - t) * 1000)
        return JSONResponse(out)
    finally:
        conn.close()


def _auto_bucket(span):
    for b in (60, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 172800, 604800):
        if span / b <= 240:
            return b
    return 604800


@app.get("/api/dataset/{dataset_id}/timeline")
def api_timeline(dataset_id: str, kind: str = Query(default="sel"), value: str = Query(default=""),
                 gf: str = Query(default=""), bucket_seconds: int = Query(default=0)):
    """Distributia in timp (clase de cod + CRITICAL/HIGH/MEDIUM) pentru o
    entitate in selectia globala. Intervalul graficului = perioada selectata
    (sau tot logul), deci golurile se vad ca atare."""
    ds = _get_dataset(dataset_id)
    if not ds:
        return JSONResponse({"error": "Dataset expirat sau inexistent."}, status_code=404)
    base, f, err = _explore_filters(ds, kind, value, gf)
    if err:
        return err
    conn, err = _get_triage_conn(dataset_id)
    if err:
        return err
    try:
        store = _col_store(ds)
        if store is not None:
            bd = store.bounds()
        else:
            bd = triage_engine.get_meta(conn, "bounds") or {}
        lo = base.get("ts_from") if base.get("ts_from") is not None else bd.get("ts_min")
        hi = base.get("ts_to") if base.get("ts_to") is not None else bd.get("ts_max")
        if lo is None or hi is None:
            return JSONResponse({"buckets": [], "bucket_seconds": 60, "range": [lo, hi]})
        b = int(bucket_seconds) if bucket_seconds and bucket_seconds >= 60 else _auto_bucket(max(1, hi - lo))
        if store is not None:
            buckets = store.timeline(f, lo, hi, b)
        else:
            buckets = triage_engine.timeline_sql(conn, f, lo, hi, b)
        return JSONResponse({"buckets": buckets, "bucket_seconds": b, "range": [int(lo), int(hi)]})
    finally:
        conn.close()


@app.get("/api/dataset/{dataset_id}/security_timeline")
def api_security_timeline(dataset_id: str, gf: str = Query(default=""), min_severity: str = Query(default="MEDIUM"),
                          gap: int = Query(default=600), limit: int = Query(default=300),
                          kind: str = Query(default="sel"), value: str = Query(default="")):
    """Cronologia de securitate a selectiei: evenimentele cu severitate >=
    prag, grupate (acelasi IP + aceeasi actiune, pauza <= gap secunde)."""
    ds = _get_dataset(dataset_id)
    if not ds:
        return JSONResponse({"error": "Dataset expirat sau inexistent."}, status_code=404)
    base, f, err = _explore_filters(ds, kind, value, gf)
    if err:
        return err
    min_severity = (min_severity or "MEDIUM").upper()
    if min_severity not in triage_engine.SEVERITY_RANK:
        return JSONResponse({"error": "prag de severitate invalid"}, status_code=400)
    conn, err = _get_triage_conn(dataset_id)
    if err:
        return err
    try:
        t = time.time()
        gap = max(10, min(int(gap), 86400))
        limit = max(10, min(int(limit), 2000))
        store = _col_store(ds)
        if store is not None:
            out = store.security_groups(f, min_severity, gap, limit)
        else:
            out = triage_engine.security_groups_sql(conn, f, min_severity, gap, limit)
        out["elapsed_ms"] = int((time.time() - t) * 1000)
        out["selection_label"] = _gf_label(base, ds) or "tot logul"
        return JSONResponse(out)
    finally:
        conn.close()


_EXPORT_MAX = 500_000


@app.get("/api/dataset/{dataset_id}/export_events")
def api_export_events(dataset_id: str, gf: str = Query(default=""), kind: str = Query(default="sel"),
                      value: str = Query(default=""), format: str = Query(default="csv"),
                      limit: int = Query(default=_EXPORT_MAX)):
    """Export al cererilor din selectia globala (+ entitate): CSV cu campurile
    indexului sau .log cu liniile ORIGINALE (exact cum apar in fisier)."""
    ds = _get_dataset(dataset_id)
    if not ds:
        return JSONResponse({"error": "Dataset expirat sau inexistent."}, status_code=404)
    base, f, err = _explore_filters(ds, kind, value, gf)
    if err:
        return err
    if not ds.get("triage_ready"):
        return JSONResponse({"error": "Indexarea e inca in curs."}, status_code=202)
    limit = max(1, min(int(limit), _EXPORT_MAX))
    store = _col_store(ds)
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", f"logscan_{kind}_{value}")[:80] or "logscan"
    # v49: exportul spune explicit cat contine -- TOATA selectia sau un subset
    try:
        total = int(store.count(f)) if store is not None else None
    except Exception:
        total = None
    if total is not None:
        stem += f"_{min(total, limit)}cereri" + ("" if total <= limit else f"_PRIMELE_din_{total}")
    xh = {"X-Total-Matched": str(total if total is not None else ""), "X-Exported": str(min(total, limit) if total is not None else ""),
          "Access-Control-Expose-Headers": "X-Total-Matched, X-Exported"}
    if format == "log":
        if store is not None:
            ranges = store.offsets(f)
        else:
            c = triage_engine.connect(triage_engine.db_path_for(ds["workdir"]))
            try:
                ranges = list(_coalesce_ranges(triage_engine.candidate_offsets(c, f)))
            finally:
                c.close()

        def gen():
            sent = 0
            with open(ds["plain_path"], "rb") as src:
                for a, b in ranges:
                    src.seek(a)
                    chunk = src.read(b - a)
                    lines = chunk.splitlines(keepends=True)
                    if sent + len(lines) > limit:
                        lines = lines[:limit - sent]
                    yield b"".join(lines)
                    sent += len(lines)
                    if sent >= limit:
                        break
        return StreamingResponse(gen(), media_type="text/plain; charset=utf-8",
                                 headers={"Content-Disposition": f'attachment; filename="{stem}.log"', **xh})
    cols = ["ts_str", "ip", "country", "method", "path", "http_status", "size", "referer", "ua", "severity",
            "action_type", "label"]

    def gen_csv():
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(cols)
        yield buf.getvalue().encode("utf-8-sig")
        conn = triage_engine.connect(triage_engine.db_path_for(ds["workdir"]))
        try:
            if store is not None:
                m = store.mask(f)
                order = store.order_asc
                sel = order if m is None else order[np.flatnonzero(m[order])]
                ids = store.ids_of(sel[:limit]).tolist()
                batches = (ids[i:i + 900] for i in range(0, len(ids), 900))
                for batch in batches:
                    buf.seek(0); buf.truncate()
                    for r in _fetch_events_by_ids(conn, batch):
                        w.writerow([r.get(c, "") for c in cols])
                    yield buf.getvalue().encode("utf-8")
            else:
                where, params = triage_engine._build_where(f, "e")
                cur = conn.execute(f"SELECT {triage_engine._EVENT_COLS} FROM events e LEFT JOIN uas u ON u.id = e.ua_id"
                                   f"{where} ORDER BY e.ts, e.id LIMIT ?", list(params) + [limit])
                while True:
                    rows = cur.fetchmany(2000)
                    if not rows:
                        break
                    buf.seek(0); buf.truncate()
                    for r in rows:
                        r = dict(r)
                        w.writerow([r.get(c, "") for c in cols])
                    yield buf.getvalue().encode("utf-8")
        finally:
            conn.close()
    return StreamingResponse(gen_csv(), media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="{stem}.csv"', **xh})



def main():
    # IMPORTANT: schimbam metoda de pornire a workerilor multiprocessing de
    # la 'fork' (default pe Linux) la 'forkserver', ATATA TIMP CAT se face
    # inainte de a porni orice thread (sweeper) sau serverul uvicorn (care
    # isi porneste propriile thread-uri interne).
    #
    # De ce: 'fork' clonează procesul curent exact cum e in acel moment --
    # daca alt thread tine un lock C-level (ex: logging._lock, folosit
    # implicit de orice logging.info() din uvicorn/Starlette) chiar in
    # clipa fork-ului, procesul-copil mosteneste acel lock PERMANENT blocat
    # (doar thread-ul care a facut fork-ul supravietuieste, nu si cel care
    # tinea lock-ul) -- un worker de multiprocessing.Pool poate ramane
    # blocat definitiv (deadlock), fara nicio eroare vizibila, exact ce s-a
    # intamplat la incarcarea unui log real pe VPS (procesul copil ramanea
    # in starea "sleeping" cu 0 CPU folosit, la nesfarsit).
    # 'forkserver' porneste un proces-server curat, cu un singur thread,
    # INAINTE sa existe alte thread-uri in aplicatie, si toti workerii
    # ulteriori sunt fork-uiti din acel proces curat -- elimina complet
    # riscul de deadlock de mai sus.
    mp.set_start_method("forkserver", force=True)

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    t = threading.Thread(target=sweeper, daemon=True)
    t.start()

    # Wordfence: incarcam instant orice cache existent pe disc (dintr-o
    # rulare anterioara), apoi lansam in fundal o (re)descarcare daca a
    # trecut TTL-ul -- niciuna din cele doua nu blocheaza pornirea
    # serverului sau vreo cerere HTTP.
    _wordfence_load_disk_cache()
    wt = threading.Thread(target=wordfence_refresh, daemon=True)
    wt.start()

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


# ==========================================================================
# v47 -- WORKPLACE: filtrare combinata pe orice camp (vezi workplace.py)
# ==========================================================================
_TZ_RX = re.compile(rb"\[[^\]]*?([+-])(\d{2})(\d{2})\]")


def _log_tz_offset(ds):
    try:
        with open(ds["plain_path"], "rb") as f:
            m = _TZ_RX.search(f.read(16384))
        if m:
            sec = int(m.group(2)) * 3600 + int(m.group(3)) * 60
            return sec if m.group(1) == b"+" else -sec
    except (OSError, KeyError):
        pass
    return 0


def _workplace_for(dataset_id):
    ds = _get_dataset(dataset_id)
    if not ds:
        return None, None, JSONResponse({"error": "Dataset expirat sau inexistent."}, status_code=404)
    store = _col_store(ds)
    if store is None:
        msg = ("Indexul inca se construieste -- reincearca in cateva secunde." if not ds.get("triage_ready")
               else "Workplace necesita indexul columnar (numpy).")
        return None, None, JSONResponse({"error": msg}, status_code=409)
    wp = ds.get("_workplace")
    if wp is None or wp.s is not store:
        wp = workplace.Workplace(store, classify_ua, classify_composition, classify_crawler_claim,
                                 _log_tz_offset(ds))
        wp.asn_name_of = lambda ip: _asn_lookup(ip)[0]   # v50: conditia 'Furnizor (ASN)' (baza se incarca la prima folosire)
        ds["_workplace"] = wp
    return ds, wp, None


def _workplace_ctx(dataset_id):
    return {"verified": _verified_crawler_ips(dataset_id), "fake": _fake_crawler_ips(dataset_id)}


@app.get("/api/dataset/{dataset_id}/workplace/meta")
def api_workplace_meta(dataset_id: str):
    ds, wp, err = _workplace_for(dataset_id)
    if err:
        return err
    s = wp.s
    _, ext_names = wp.ext_codes()
    with _CRAWLER_JOBS_LOCK:
        job = dict(_CRAWLER_JOBS.get(dataset_id) or {})
    job.pop("results", None)
    return JSONResponse({
        "fields": {k: {"label": v[0], "ops": list(v[1])} for k, v in workplace.FIELDS.items()},
        "values": {
            "country": [d["value"] or "??" for d in s.distinct("country", 400)],
            "method": list(s.v_me),
            "status": [d["value"] for d in s.distinct("http_status", 100)],
            "severity": [v for v in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if v in s.d_sev],
            "action": [d["value"] for d in s.distinct("action_type", 200)],
            "ua_cat": list(workplace.UA_CATS), "crawler": list(workplace.CRAWLER_STATES),
            "ext": ext_names, "weekday": list(workplace.WEEKDAYS),
            "wp": ["wp_any"] + list(triage_columnar.WP_NAMES),
        },
        "bounds": s.bounds(), "tz_offset_sec": wp.tz, "crawler_job": job,
        "fp_suppressed": {"ips": len(getattr(s, "suppressed_ips", ())),
                          "events": getattr(s, "suppressed_events", 0)},
    })


@app.post("/api/dataset/{dataset_id}/workplace")
def api_workplace(dataset_id: str, body: dict = Body(...)):
    ds, wp, err = _workplace_for(dataset_id)
    if err:
        return err
    t = time.time()
    try:
        res = wp.run(body.get("q") or {}, _workplace_ctx(dataset_id), ds["plain_path"],
                     limit=int(body.get("limit") or 100), offset=int(body.get("offset") or 0),
                     sort=str(body.get("sort") or "ts_desc"))
    except (workplace.QueryError, TypeError, ValueError) as e:
        return JSONResponse({"error": f"Filtru invalid: {e}"}, status_code=400)
    res["elapsed_ms"] = int((time.time() - t) * 1000)
    return JSONResponse(res)


@app.get("/api/dataset/{dataset_id}/automation")
def api_automation(dataset_id: str, gf: str = Query(default="")):
    """v50: activitate automata (boti, scanari, scraping) pe perioada selectiei
    globale -- aceleasi conditii ca preseturile din Workplace."""
    ds, wp, err = _workplace_for(dataset_id)
    if err:
        return err
    f, err = _gf_checked(gf_raw=gf)
    if err:
        return err
    t = time.time()
    try:
        cats = wp.automation(f.get("ts_from"), f.get("ts_to"), _workplace_ctx(dataset_id))
    except (workplace.QueryError, TypeError, ValueError) as e:
        return JSONResponse({"error": f"Calcul esuat: {e}"}, status_code=400)
    return JSONResponse({"categories": cats, "ts_from": f.get("ts_from"), "ts_to": f.get("ts_to"),
                         "elapsed_ms": int((time.time() - t) * 1000)})


@app.post("/api/dataset/{dataset_id}/workplace/raw")
def api_workplace_raw(dataset_id: str, body: dict = Body(...)):
    """Liniile BRUTE (exact cum sunt in fisier) pentru selectia Workplace."""
    ds, wp, err = _workplace_for(dataset_id)
    if err:
        return err
    try:
        limit = body.get("limit")
        ranges, n = wp.raw_ranges(body.get("q") or {}, _workplace_ctx(dataset_id),
                                  limit=int(limit) if limit else None)
    except (workplace.QueryError, TypeError, ValueError) as e:
        return JSONResponse({"error": f"Filtru invalid: {e}"}, status_code=400)
    path = ds["plain_path"]

    def gen():
        with open(path, "rb") as f:
            for a, b in ranges:
                f.seek(a)
                left = b - a
                while left > 0:
                    chunk = f.read(min(left, 1 << 20))
                    if not chunk:
                        break
                    left -= len(chunk)
                    yield chunk

    name = re.sub(r"[^A-Za-z0-9._-]+", "_", str(body.get("filename") or "workplace")) + ".log"
    return StreamingResponse(gen(), media_type="text/plain; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="{name}"',
                                      "X-Lines": str(n)})



# ==========================================================================
# v47.2 -- "Incidente - traseu cronologic" (Security & Triaj). NU introduce
# reguli noi: regrupeaza pe IP ce exista deja (compromise_trail din analiza,
# severitatea / action_type / label din index). Doar indexul columnar.
# ==========================================================================
_SIG_SEVS = ("CRITICAL", "HIGH")
_STATUS_CLS = ("2xx", "3xx", "4xx", "5xx")


def _incident_ctx(dataset_id, gf):
    """(ds, store, mask, err) -- selectia globala aplicata pe ColStore."""
    ds = _get_dataset(dataset_id)
    if not ds:
        return None, None, None, JSONResponse({"error": "Dataset expirat sau inexistent. Reincarca fisierul."},
                                              status_code=404)
    store = _col_store(ds)
    if store is None:
        msg = ("Indexul inca se construieste -- reincearca in cateva secunde." if not ds.get("triage_ready")
               else "Rubrica Incidente necesita indexul columnar (numpy). Instaleaza numpy in venv-ul aplicatiei.")
        return ds, None, None, JSONResponse({"error": msg}, status_code=409)
    f, err = _gf_checked(gf_raw=gf)
    if err:
        return ds, store, None, err
    return ds, store, store.mask(f), None


def _sev_codes(store, names):
    return [store.d_sev[s] for s in names if s in store.d_sev]


def _ip_rows(store, mask, ipc):
    """Randurile IP-ului din selectie, crescator dupa (timp, id) -- aceeasi
    ordine ca restul aplicatiei (ORDER BY ts, id)."""
    rows = np.flatnonzero(store.ip == ipc)
    if mask is not None and rows.size:
        rows = rows[mask[rows]]
    if rows.size:
        rows = rows[np.lexsort((store.ids_of(rows), store.ts[rows]))]
    return rows


def _first_significant(store, rows, sig_codes):
    """Pozitia (in rows) a celui mai vechi eveniment CRITICAL/HIGH, sau None."""
    if not rows.size or not sig_codes:
        return None
    hit = np.flatnonzero(np.isin(store.sev[rows], sig_codes))
    return int(hit[0]) if hit.size else None


def _status_cls(st):
    return f"{int(st) // 100}xx"


def _trail_by_ip(ds):
    s = ((ds.get("summary_cache") or {}).get("ALL") or {})
    return {t["ip"]: t for t in (s.get("compromise_trail") or []) if t.get("ip")}


@app.get("/api/dataset/{dataset_id}/incidents")
def api_incidents(dataset_id: str, gf: str = Query(default=""), limit: int = Query(default=300)):
    """IP-urile din compromise_trail + IP-urile cu cel putin un eveniment
    CRITICAL/HIGH in selectie, cu primul eveniment semnificativ si ce a urmat."""
    ds, store, m, err = _incident_ctx(dataset_id, gf)
    if err:
        return err
    sig = _sev_codes(store, _SIG_SEVS)
    trail = _trail_by_ip(ds)
    sel = np.arange(store.n) if m is None else np.flatnonzero(m)
    cand = set()
    if sel.size and sig:
        cand.update(np.unique(store.ip[sel[np.isin(store.sev[sel], sig)]]).tolist())
    present = set(np.unique(store.ip[sel]).tolist()) if sel.size else set()
    for ip in trail:
        c = store.d_ip.get(ip, -1)
        if c >= 0 and c in present:
            cand.add(c)
    post_c = store.d_me.get("POST", -1)
    out = []
    for ipc in cand:
        rows = _ip_rows(store, m, ipc)
        if not rows.size:
            continue
        ip = store.v_ip[ipc]
        t = trail.get(ip) or {}
        sev_names = [store.v_sev[x] for x in store.sev[rows].tolist()]
        sev_counts: Dict[str, int] = {}
        for s in sev_names:
            sev_counts[s] = sev_counts.get(s, 0) + 1
        max_rank = min(triage_columnar.SEVERITY_RANK.get(s, 4) for s in sev_counts)
        p = _first_significant(store, rows, sig)
        first = None
        after = rows[p + 1:] if p is not None else rows[:0]
        posts = {k: 0 for k in _STATUS_CLS}
        if p is not None:
            r = int(rows[p])
            first = {"ts": int(store.ts[r]), "action_type": store.v_act[store.act[r]],
                     "label": store.v_lbl[store.lbl[r]], "url": store.v_fp[store.fp[r]],
                     "status": int(store.st[r]), "method": store.v_me[store.me[r]],
                     "severity": store.v_sev[store.sev[r]]}
            if post_c >= 0 and after.size:
                for st in store.st[after[store.me[after] == post_c]].tolist():
                    k = _status_cls(st)
                    if k in posts:
                        posts[k] += 1
        cc = store.v_cc[store.cc[rows[0]]] if store.v_cc else ""
        out.append({
            "ip": ip, "country": cc or t.get("country") or "",
            "dominant_category": t.get("dominant_category"),
            "dominant_category_label": t.get("dominant_category_label"),
            "risk_score": t.get("risk_score") or 0, "in_trail": bool(t),
            "first_significant": first,
            "requests": int(rows.size),
            "before": int(p) if p is not None else int(rows.size),
            "after": int(after.size),
            "posts_after": posts,
            "severity_counts": sev_counts,
            "max_severity": next(k for k, v in triage_columnar.SEVERITY_RANK.items() if v == max_rank),
            "first_ts": int(store.ts[rows[0]]), "last_ts": int(store.ts[rows[-1]]),
            # v47.3: action_type-urile evenimentelor CRITICAL/HIGH ale IP-ului
            "sig_actions": sorted({store.v_act[a] for a in
                                   store.act[rows[np.isin(store.sev[rows], sig)]].tolist()}) if sig else [],
        })
    out.sort(key=lambda x: (-float(x["risk_score"]), triage_columnar.SEVERITY_RANK.get(x["max_severity"], 4),
                            -x["severity_counts"].get("CRITICAL", 0), -x["severity_counts"].get("HIGH", 0), x["ip"]))
    # v47.6: separarea atac / doar-admin se face AICI (o singura sursa de adevar,
    # aceeasi clasificare ca "Acces WP admin"). Un IP e ascuns din Incidente doar
    # daca NU are niciun semnal de atac SI apare efectiv in rubrica admin.
    try:
        adm_status = _admin_compute(ds, store, m)["status"]
    except Exception:
        adm_status = {}
    attack_cats = {"attack_attempt", "confirmed_compromise"}
    admin_only = {"login": 0, "sesiune": 0, "neconfirmat": 0, "incercari": 0}
    attacks = []
    for x in out:
        x["admin_status"] = adm_status.get(x["ip"])
        x["is_attack"] = bool(any(a not in _ADMIN_ACTIONS for a in x["sig_actions"])
                              or x.get("dominant_category") in attack_cats or not x["admin_status"])
        if x["is_attack"]:
            attacks.append(x)
        else:
            admin_only[x["admin_status"]] = admin_only.get(x["admin_status"], 0) + 1
    total = len(out)
    return JSONResponse({"incidents": attacks[:max(1, min(int(limit), 2000))], "total": len(attacks),
                         "candidates_total": total, "admin_only": admin_only,
                         "admin_only_total": sum(admin_only.values()),
                         "tz_offset_sec": _log_tz_offset(ds)})


@app.get("/api/dataset/{dataset_id}/ip_trail")
def api_ip_trail(dataset_id: str, ip: str = Query(...), gf: str = Query(default=""),
                 only: str = Query(default="all"), limit: int = Query(default=5000)):
    """TOATE cererile IP-ului din selectie, crescator dupa timp, cu linia
    bruta din fisier (off/ln) si faza fata de primul eveniment semnificativ."""
    ds, store, m, err = _incident_ctx(dataset_id, gf)
    if err:
        return err
    if only not in ("all", "significant"):
        return JSONResponse({"error": "only trebuie sa fie 'all' sau 'significant'."}, status_code=400)
    limit = max(1, min(int(limit), 20000))
    ipc = store.d_ip.get(ip, -1)
    rows = _ip_rows(store, m, ipc) if ipc >= 0 else np.zeros(0, np.int64)
    sig = _sev_codes(store, _SIG_SEVS)
    p = _first_significant(store, rows, sig)
    pos = np.arange(rows.size)
    keep = np.ones(rows.size, bool)
    if only == "significant" and rows.size:
        med = _sev_codes(store, ("CRITICAL", "HIGH", "MEDIUM"))
        keep = np.isin(store.sev[rows], med) | (store.me[rows] == store.d_me.get("POST", -1))
    sel, sel_pos = rows[keep], pos[keep]
    truncated = int(sel.size) > limit
    sel, sel_pos = sel[:limit], sel_pos[:limit]
    # liniile brute, citite in ordinea din fisier (seek-uri crescatoare)
    raw = {}
    if sel.size:
        o = np.argsort(store.off[sel], kind="stable")
        with open(ds["plain_path"], "rb") as fh:
            for r in sel[o].tolist():
                fh.seek(int(store.off[r]))
                raw[r] = fh.read(int(store.ln[r])).decode("utf-8", errors="replace").rstrip("\r\n")
    events, prev_ts, prev_ua = [], None, None
    for r, k in zip(sel.tolist(), sel_pos.tolist()):
        ts = int(store.ts[r])
        ua = store.v_ua[store.ua[r]] if store.v_ua else ""
        events.append({
            "ts": ts, "dt": (ts - prev_ts) if prev_ts is not None else None,
            "method": store.v_me[store.me[r]], "url": store.v_fp[store.fp[r]], "status": int(store.st[r]),
            "size": int(store.sz[r]), "ua": ua, "ua_changed": prev_ua is not None and ua != prev_ua,
            "severity": store.v_sev[store.sev[r]], "action_type": store.v_act[store.act[r]],
            "label": store.v_lbl[store.lbl[r]], "raw": raw.get(r, ""),
            "phase": "inainte" if (p is None or k < p) else "dupa", "first_significant": p is not None and k == p,
        })
        prev_ts, prev_ua = ts, ua
    t = _trail_by_ip(ds).get(ip) or {}
    uas: Dict[str, int] = {}
    for x in store.ua[rows].tolist():
        u = store.v_ua[x]
        uas[u] = uas.get(u, 0) + 1
    return JSONResponse({
        "ip": ip, "country": (store.v_cc[store.cc[rows[0]]] if rows.size else "") or t.get("country") or "",
        "total": int(rows.size), "shown": len(events), "truncated": truncated, "only": only,
        "first_ts": int(store.ts[rows[0]]) if rows.size else None,
        "last_ts": int(store.ts[rows[-1]]) if rows.size else None,
        "first_significant_index": p,
        "user_agents": sorted(({"ua": u, "n": n} for u, n in uas.items()), key=lambda x: -x["n"]),
        "dominant_category": t.get("dominant_category"), "dominant_category_label": t.get("dominant_category_label"),
        "risk_score": t.get("risk_score"), "trail_summary": t.get("summary"),
        "tz_offset_sec": _log_tz_offset(ds), "events": events,
    })



# ==========================================================================
# v47.3 -- "Acces WP admin": autentificari reusite + ce a facut IP-ul in admin,
# separat de incercarile de autentificare. Actiunile se deduc DOAR din ce se
# vede in access log (URL, metoda, cod) -- corpul POST-urilor nu e logat, deci
# de ex. admin-ajax arata doar ca "actiune AJAX" (numele actiunii e in corp).
# ==========================================================================
# (cheie, eticheta, grup, critic) -- critic = poate modifica cod/conturi/fisiere
_ADM_RULES = (
    # cheie, test(po_low, q_low, method), eticheta, grup, critic
    ("plugin_upload", lambda p, q, m: p.endswith("/update.php") and "action=upload-plugin" in q and m == "POST",
     "Upload plugin (fisier .zip)", "plugin", True),
    ("theme_upload", lambda p, q, m: p.endswith("/update.php") and "action=upload-theme" in q and m == "POST",
     "Upload tema (fisier .zip)", "tema", True),
    ("plugin_install", lambda p, q, m: p.endswith("/update.php") and "action=install-plugin" in q,
     "Instalare plugin din repository", "plugin", True),
    ("theme_install", lambda p, q, m: p.endswith("/update.php") and "action=install-theme" in q,
     "Instalare tema din repository", "tema", True),
    ("plugin_update", lambda p, q, m: (p.endswith("/update.php") and "action=upgrade-plugin" in q)
     or p.endswith("/update-core.php") and "action=do-plugin-upgrade" in q, "Actualizare plugin", "plugin", False),
    ("plugin_activate", lambda p, q, m: p.endswith("/plugins.php") and "action=activate" in q,
     "Activare plugin", "plugin", True),
    ("plugin_deactivate", lambda p, q, m: p.endswith("/plugins.php") and "action=deactivate" in q,
     "Dezactivare plugin", "plugin", True),
    ("plugin_delete", lambda p, q, m: p.endswith("/plugins.php") and "action=delete-selected" in q,
     "Stergere plugin", "plugin", True),
    ("plugin_editor_save", lambda p, q, m: p.endswith("/plugin-editor.php") and m == "POST",
     "Salvare in editorul de plugin-uri (cod PHP)", "cod", True),
    ("theme_editor_save", lambda p, q, m: p.endswith("/theme-editor.php") and m == "POST",
     "Salvare in editorul de teme (cod PHP)", "cod", True),
    ("plugin_editor", lambda p, q, m: p.endswith("/plugin-editor.php"),
     "Deschis editorul de plugin-uri (doar vizualizare)", "cod", False),
    ("theme_editor", lambda p, q, m: p.endswith("/theme-editor.php"),
     "Deschis editorul de teme (doar vizualizare)", "cod", False),
    ("theme_switch", lambda p, q, m: p.endswith("/themes.php") and "action=activate" in q,
     "Schimbare tema activa", "tema", True),
    ("plugin_upload_page", lambda p, q, m: p.endswith("/plugin-install.php") and "tab=upload" in q,
     "Deschis formularul de upload plugin", "plugin", False),
    ("theme_upload_page", lambda p, q, m: p.endswith("/theme-install.php") and "tab=upload" in q,
     "Deschis formularul de upload tema", "tema", False),
    ("plugin_install_page", lambda p, q, m: p.endswith("/plugin-install.php"),
     "Rasfoire plugin-uri de instalat", "plugin", False),
    ("theme_install_page", lambda p, q, m: p.endswith("/theme-install.php"),
     "Rasfoire teme de instalat", "tema", False),
    ("plugins_list", lambda p, q, m: p.endswith("/plugins.php"), "Lista plugin-uri", "plugin", False),
    ("themes_list", lambda p, q, m: p.endswith("/themes.php"), "Lista teme", "tema", False),
    ("user_create", lambda p, q, m: p.endswith("/user-new.php") and m == "POST",
     "Creare utilizator nou", "utilizatori", True),
    ("user_new_page", lambda p, q, m: p.endswith("/user-new.php"), "Deschis formularul de utilizator nou",
     "utilizatori", False),
    ("user_edit_save", lambda p, q, m: (p.endswith("/user-edit.php") or p.endswith("/profile.php")) and m == "POST",
     "Modificare utilizator / profil (parola, email, rol)", "utilizatori", True),
    ("users_action", lambda p, q, m: p.endswith("/users.php") and m == "POST",
     "Stergere / schimbare rol utilizatori (POST)", "utilizatori", True),
    ("users_confirm_page", lambda p, q, m: p.endswith("/users.php") and ("action=delete" in q or "action=remove" in q),
     "Pagina de confirmare stergere utilizator (fara efect)", "utilizatori", False),
    ("users_promote", lambda p, q, m: p.endswith("/users.php") and "action=promote" in q or "changeit=" in q and p.endswith("/users.php"),
     "Schimbare rol utilizatori", "utilizatori", True),
    ("users_list", lambda p, q, m: p.endswith("/users.php") or p.endswith("/user-edit.php") or p.endswith("/profile.php"),
     "Vizualizare utilizatori / profil", "utilizatori", False),
    ("app_password", lambda p, q, m: p.endswith("/authorize-application.php"),
     "Autorizare application password (acces API persistent)", "utilizatori", True),
    ("media_upload", lambda p, q, m: p.endswith("/async-upload.php") or (p.endswith("/media-new.php") and m == "POST"),
     "Upload fisier in Media", "fisiere", True),
    ("media_page", lambda p, q, m: p.endswith("/media-new.php") or p.endswith("/upload.php"),
     "Pagina Media / upload", "fisiere", False),
    ("options_save", lambda p, q, m: p.endswith("/options.php") and m == "POST",
     "Salvare setari", "setari", True),
    ("options_page", lambda p, q, m: "/options-" in p or p.endswith("/options.php"),
     "Pagina de setari", "setari", False),
    ("import_export", lambda p, q, m: p.endswith("/import.php") or p.endswith("/export.php") or "/admin.php" in p and "import=" in q,
     "Import / export continut", "continut", True),
    ("content_save", lambda p, q, m: (p.endswith("/post.php") or p.endswith("/post-new.php")) and m == "POST",
     "Salvare articol / pagina", "continut", False),
    ("content_page", lambda p, q, m: p.endswith("/post.php") or p.endswith("/post-new.php") or p.endswith("/edit.php"),
     "Editare / lista continut", "continut", False),
    ("core_update", lambda p, q, m: p.endswith("/update-core.php"), "Actualizari WordPress", "setari", False),
    ("ajax_post", lambda p, q, m: p.endswith("/admin-ajax.php") and m == "POST",
     "Actiune AJAX (numele actiunii e in corpul POST, nelogat)", "ajax", False),
    ("plugin_page", lambda p, q, m: p.endswith("/admin.php") and "page=" in q,
     "Pagina unui plugin (admin.php?page=...)", "plugin", False),
    ("logout", lambda p, q, m: _is_login_ep(p) and "action=logout" in q, "Logout", "sesiune", False),
    ("login_post", lambda p, q, m: (_is_login_ep(p) or _is_xmlrpc_ep(p)) and m == "POST",
     "Autentificare (POST login)", "sesiune", False),
    ("login_page", lambda p, q, m: _is_login_ep(p), "Pagina de login", "sesiune", False),
    ("dashboard", lambda p, q, m: p.endswith("/wp-admin/") or p.endswith("/wp-admin/index.php") or p.endswith("/wp-admin"),
     "Dashboard wp-admin", "sesiune", False),
)
_ADM_SCOPE = ("/wp-admin", "wp-login.php", "xmlrpc.php")


def classify_admin_action(method, path, status):
    """-> (cheie, eticheta, grup, critic, rezultat) sau None daca cererea nu
    tine de admin. rezultat: executat / blocat / eroare / redirect / inexistent."""
    qpos = path.find("?")
    po = (path[:qpos] if qpos != -1 else path).lower()
    q = path[qpos + 1:].lower() if qpos != -1 else ""
    if not any(s in po for s in _ADM_SCOPE):
        return None
    if po.endswith((".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ico", ".map")):
        return None
    key = lab = grp = None
    crit = False
    for k, test, lb, g, c in _ADM_RULES:
        try:
            if test(po, q, method):
                key, lab, grp, crit = k, lb, g, c
                break
        except Exception:
            continue
    if key is None:
        if "/wp-admin" not in po:
            return None
        if not _is_admin_page(po):
            return None   # v47.5: fisier public din /wp-admin/ (load-styles.php etc.) -- nu e activitate admin
        page = po.rsplit("/", 1)[-1] or "wp-admin"
        key, lab, grp, crit = "other_admin", f"Alta pagina admin ({page})", "altele", m_is_post(method)
    if status in (401, 403):
        res = "blocat"
    elif status == 404:
        res = "inexistent"
    elif status >= 500:
        res = "eroare"
    elif 300 <= status < 400:
        res = "redirect"
    else:
        res = "executat"
    return key, lab, grp, crit, res


def m_is_post(method):
    return method == "POST"


_RES_TXT = {"executat": "raspuns 2xx", "blocat": "BLOCAT", "eroare": "eroare server",
            "redirect": "raspuns 302", "inexistent": "inexistent (404)"}

# v47.6: dovezi DIN LOG ca o operatie chiar a reusit -- WordPress redirectioneaza
# dupa succes pe o pagina cu parametru de confirmare (?update=del&delete_count=N,
# ?settings-updated=true, ?activate=true ...). Fara un asemenea marker, un 2xx/302
# NU e considerat confirmare (302 poate fi si redirect spre login).
def _adm_confirm_marker(po, q):
    """-> (cheie_actiune, unitati) sau None."""
    if po.endswith("/users.php"):
        if "update=del" in q:
            mm = re.search(r"delete_count=(\d+)", q)
            return "users_action", int(mm.group(1)) if mm else 1
        if "update=promote" in q:
            return "users_promote", 1
        if "update=add" in q or "update=newuseradded" in q:
            return "user_create", 1
    if (po.endswith("/profile.php") or po.endswith("/user-edit.php")) and "updated=1" in q:
        return "user_edit_save", 1
    if "settings-updated=true" in q:
        return "options_save", 1
    if po.endswith("/plugins.php"):
        if "activate=true" in q or "activate-multi=true" in q:
            return "plugin_activate", 1
        if "deactivate=true" in q or "deactivate-multi=true" in q:
            return "plugin_deactivate", 1
        if "deleted=true" in q or "deleted=1" in q:
            return "plugin_delete", 1
    if po.endswith("/themes.php") and "activated=true" in q:
        return "theme_switch", 1
    if (po.endswith("/post.php") or po.endswith("/edit.php")) and ("message=1" in q or "message=6" in q):
        return "content_save", 1
    return None


_CONFIRM_UNITS = {"users_action": ("utilizator sters", "utilizatori stersi"),
                  "options_save": ("salvare de setari", "salvari de setari"),
                  "user_edit_save": ("profil modificat", "profiluri modificate"),
                  "plugin_activate": ("plugin activat", "plugin-uri activate"),
                  "plugin_deactivate": ("plugin dezactivat", "plugin-uri dezactivate"),
                  "plugin_delete": ("plugin sters", "plugin-uri sterse"),
                  "theme_switch": ("tema activata", "teme activate"),
                  "user_create": ("utilizator creat", "utilizatori creati"),
                  "users_promote": ("rol schimbat", "roluri schimbate"),
                  "content_save": ("articol salvat", "articole salvate")}


class _UnitMap(dict):
    """_CONFIRM_UNIT.get(k) -> forma de plural (compat); unit_txt(k, n) -> corect gramatical."""
    def get(self, k, default=None):
        v = _CONFIRM_UNITS.get(k)
        return v[1] if v else default


_CONFIRM_UNIT = _UnitMap()


def unit_txt(key, n):
    v = _CONFIRM_UNITS.get(key, ("operatie", "operatii"))
    return f"{n} {v[0] if n == 1 else v[1]}"


def _adm_target(key, po, q):
    """Tinta actiunii, daca apare in URL (plugin, ID utilizator, pagina de setari)."""
    try:
        from urllib.parse import unquote
    except Exception:
        return None
    if key in ("plugin_activate", "plugin_deactivate", "plugin_delete"):
        mm = re.search(r"(?:^|&)plugin=([^&]+)", q)
        return unquote(mm.group(1)).split("/")[0] if mm else None
    if key in ("users_action", "users_confirm_page", "users_promote"):
        mm = re.search(r"(?:^|&)user=(\d+)", q)
        return ("ID " + mm.group(1)) if mm else ("bulk" if "bulk_action" in q or "users%5b%5d" in q else None)
    if key == "options_page":
        return po.rsplit("/", 1)[-1]
    return None


# Endpoint-uri care raspund 200 DOAR unui utilizator autentificat (anonim -> 401).
_AUTH_PROOF_RE = re.compile(r"(/wp-json/wp/v2/users/me|rest_route=/?wp/v2/users/me|[?&]context=edit)")


def _admin_narrative(ip, cc, login_ts_list, session_mode, groups, fmt, proof):
    parts = []
    if session_mode == "login":
        parts.append(f"IP-ul {ip} ({cc or '??'}) s-a autentificat CU SUCCES in WP admin la {fmt(login_ts_list[0])}"
                     + (f" (de {len(login_ts_list)} ori)" if len(login_ts_list) > 1 else "") + ".")
    elif session_mode == "sesiune":
        parts.append(f"IP-ul {ip} ({cc or '??'}) a folosit o sesiune WP admin deja autentificata (cookie); "
                     f"login-ul nu apare in log.")
    else:
        parts.append(f"IP-ul {ip} ({cc or '??'}) are doar {proof.get('admin_pages', 0)} pagina(i) /wp-admin/ cu 200, "
                     f"fara login si fara alta dovada de autentificare -- acces NECONFIRMAT.")
    crit = [g for g in groups if g["critical"]]
    if crit:
        bits = []
        for g in crit:
            r = g["results"]
            det = ", ".join(f"{n} {_RES_TXT.get(k, k)}" for k, n in r.items())
            if g.get("confirmed_units"):
                det += f"; CONFIRMAT de WordPress: {unit_txt(g['key'], g['confirmed_units'])}"
            elif not r.get("blocat") or len(r) > 1:
                det += "; fara confirmare in log"
            tg = [t for t in g.get("targets", []) if t != "bulk"]
            if tg:
                det += " -- " + ", ".join(tg[:6])
            if "bulk" in g.get("targets", []):
                det += (" + o operatie in bulk" if tg else " -- operatie in bulk") + " (ID-urile sunt in corpul POST, nelogat)"
            bits.append(f"{g['label'].lower()} x{g['n']} ({det})")
        parts.append("Actiuni care modifica site-ul: " + "; ".join(bits) + ".")
    else:
        parts.append("Nu apar actiuni care modifica plugin-uri, teme, cod, utilizatori sau setari -- doar navigare.")
    sens = [g for g in groups if g.get("sensitive")]
    if sens:
        parts.append("Pagini sensibile deschise (fara salvare vazuta): " +
                     ", ".join(f"{g['label'].lower()} x{g['n']}" for g in sens) + ".")
    blocked = sum(g["results"].get("blocat", 0) for g in crit)
    if blocked:
        parts.append(f"{blocked} actiuni au fost BLOCATE (401/403, probabil WAF).")
    return " ".join(parts)


def _generic_sizes(store):
    """v47.6: dimensiunile de raspuns 200 servite pe >=10 cai diferite (pagina
    generica / soft-404 / pagina din cache). Un 200 cu o asemenea dimensiune pe
    un endpoint REST sau admin NU dovedeste nimic -- e acelasi continut generic."""
    g = getattr(store, "_generic_sz", None)
    if g is not None:
        return g
    ok = np.flatnonzero((store.st == 200) & (store.sz > 1000))
    g = set()
    if ok.size:
        pair = np.unique(store.sz[ok].astype(np.int64) * (1 << 24) + store.fp[ok].astype(np.int64) % (1 << 24))
        szs, cnt = np.unique(pair >> 24, return_counts=True)
        g = {int(x) for x in szs[cnt >= 10].tolist()}
    store._generic_sz = g
    return g


_SENSITIVE_KEYS = {"theme_editor", "plugin_editor", "plugin_upload_page", "theme_upload_page", "user_new_page"}
_ADMIN_CACHE_MAX = 16


def _admin_compute(ds, store, m, timeline_limit=400):
    """Clasificarea unica (folosita de rubrica "Acces WP admin", de alerte si de
    incidente) -> dict cu successes / unconfirmed / attempts + status pe IP."""
    cache = ds.setdefault("_admin_cache", {})
    ck = (id(store), None if m is None else hash(np.packbits(m).tobytes()), timeline_limit)
    if ck in cache:
        return cache[ck]
    tz = _log_tz_offset(ds) or 0

    def fmt(ts):
        return datetime.utcfromtimestamp(ts + tz).strftime("%d %b %H:%M:%S")

    sel = np.arange(store.n) if m is None else np.flatnonzero(m)
    real_pfx = set(getattr(store, "wp_real_prefixes", None) or [""])
    act_c = {a: store.d_act.get(a, -1) for a in ("admin_login_success", "admin_login_post", "admin_get")}
    ips_ok, ips_try = set(), set()
    if sel.size:
        acts = store.act[sel]
        for k in ("admin_login_success", "admin_get"):
            if act_c[k] >= 0:
                ips_ok.update(np.unique(store.ip[sel[acts == act_c[k]]]).tolist())
        if act_c["admin_login_post"] >= 0:
            ips_try.update(np.unique(store.ip[sel[acts == act_c["admin_login_post"]]]).tolist())
    trail = _trail_by_ip(ds)
    gen_sz = _generic_sizes(store)
    successes, unconfirmed = [], []
    for ipc in ips_ok:
        rows = _ip_rows(store, m, ipc)
        if not rows.size:
            continue
        ip = store.v_ip[ipc]
        cc = store.v_cc[store.cc[rows[0]]] if store.v_cc else ""
        acts = store.act[rows]
        login_mask = (acts == act_c["admin_login_success"]) if act_c["admin_login_success"] >= 0 else np.zeros(rows.size, bool)
        login_ts = [int(t) for t in store.ts[rows[login_mask]].tolist()]
        tl, groups, uas = [], {}, {}
        real_pages, auth_proof, generic_hits, page_sizes = set(), [], [], {}
        ajax_n = admin_assets = 0
        pending = {}   # cheie -> grupul care asteapta markerul de confirmare
        for r in rows.tolist():
            me = store.v_me[store.me[r]]
            url = store.v_fp[store.fp[r]]
            st = int(store.st[r])
            qpos = url.find("?")
            po = (url[:qpos] if qpos != -1 else url).lower()
            q = url[qpos + 1:].lower() if qpos != -1 else ""
            sz = int(store.sz[r])
            if st == 200 and _AUTH_PROOF_RE.search(url.lower()):
                if sz in gen_sz:
                    generic_hits.append(url)      # 200 cu pagina generica a site-ului -- nu e dovada
                elif sz > 0 and len(auth_proof) < 5:
                    auth_proof.append({"ts": int(store.ts[r]), "method": me, "url": url, "status": st, "size": sz})
            if me == "POST" and po.endswith("/admin-ajax.php") and st == 200:
                ajax_n += 1
            if me == "GET" and st == 200 and "/wp-admin/" in po and po.endswith((".js", ".css")):
                admin_assets += 1
            c = classify_admin_action(me, url, st)
            if c is None:
                continue
            pfx = triage_columnar.ColStore.wp_prefix(url)
            if pfx is not None and pfx not in real_pfx:
                continue   # sondare pe o cale fara WordPress (raspuns generic), nu actiune in admin
            key, lab, grp, crit, res = c
            if me == "GET" and st == 200 and _is_admin_page(po):
                if sz not in gen_sz:
                    real_pages.add(po)
                    page_sizes.setdefault(po, sz)
            g = groups.setdefault(key, {"key": key, "label": lab, "group": grp, "critical": crit,
                                        "sensitive": key in _SENSITIVE_KEYS, "n": 0, "results": {},
                                        "first_ts": int(store.ts[r]), "confirmed": 0, "confirmed_units": 0,
                                        "targets": []})
            g["n"] += 1
            g["results"][res] = g["results"].get(res, 0) + 1
            tg = _adm_target(key, po, q)
            if tg and tg not in g["targets"]:
                g["targets"].append(tg)
            if crit and res in ("executat", "redirect"):
                pending[key] = (g, int(store.ts[r]))
            confirm = None
            if me == "GET" and st == 200:
                mk = _adm_confirm_marker(po, q)
                if mk:
                    tk, units = mk
                    pg = pending.get(tk)
                    if pg and int(store.ts[r]) - pg[1] <= 60:
                        pg[0]["confirmed"] += 1
                        pg[0]["confirmed_units"] += units
                        pending.pop(tk, None)
                        confirm = f"confirmare WordPress: {unit_txt(tk, units)}"
                        if tk == "options_save":
                            pgn = po.rsplit("/", 1)[-1]
                            if pgn not in pg[0]["targets"]:
                                pg[0]["targets"].append(pgn)
            ua = store.v_ua[store.ua[r]]
            uas[ua] = uas.get(ua, 0) + 1
            if len(tl) < timeline_limit:
                tl.append({"ts": int(store.ts[r]), "method": me, "url": url, "status": st, "key": key,
                           "label": lab, "group": grp, "critical": crit, "result": res, "confirm": confirm,
                           "login_ok": bool(login_mask.size and act_c["admin_login_success"] >= 0
                                            and store.act[r] == act_c["admin_login_success"])})
        glist = sorted(groups.values(), key=lambda g: (not g["critical"], not g["sensitive"], g["first_ts"]))
        nav = [g for g in glist if g["key"] not in ("login_post", "login_page")]
        if not nav and not login_ts:
            continue
        crit_n = sum(g["n"] for g in glist if g["critical"])
        crit_conf = sum(g["confirmed"] for g in glist if g["critical"])
        crit_blk = sum(g["results"].get("blocat", 0) for g in glist if g["critical"])
        if login_ts:
            mode = "login"
        elif auth_proof or len(real_pages) >= 3 or crit_conf > 0:
            mode = "sesiune"
        else:
            mode = "neconfirmat"
        evidence = []
        if login_ts:
            evidence.append(f"POST login cu 302 urmat de /wp-admin/ cu 200 ({len(login_ts)}x)")
        if auth_proof:
            evidence.append(f"{auth_proof[0]['url'][:90]} -> 200 (raspunde doar utilizatorilor autentificati)")
        if len(real_pages) >= 3:
            evidence.append(f"{len(real_pages)} pagini /wp-admin/ distincte cu 200")
        if crit_conf:
            evidence.append(f"{crit_conf} operatii confirmate de WordPress prin mesajul de succes")
        hints = []
        if mode == "neconfirmat":
            for pg, z in list(page_sizes.items())[:3]:
                hints.append(f"{pg} -> 200, " + f"{z:,}".replace(",", ".") + " octeti (diferit de pagina generica a site-ului)")
            if ajax_n:
                hints.append(f"{ajax_n} POST admin-ajax.php cu 200 (endpoint public -- nu dovedeste login)")
            if admin_assets:
                hints.append(f"{admin_assets} resurse /wp-admin/ (js/css) incarcate")
            if generic_hits:
                hints.append(f"{len(generic_hits)} cerere(i) REST de tip 'utilizator curent' cu 200, dar cu continutul generic "
                             f"al site-ului (aceeasi dimensiune ca paginile publice) -- NU sunt dovada de autentificare")
        t = trail.get(ip) or {}
        proof = {"admin_pages": len(real_pages)}
        item = {
            "ip": ip, "country": cc, "is_non_ro": bool(cc) and cc != "RO", "session_mode": mode,
            "confirmed": mode != "neconfirmat", "evidence": evidence, "hints": hints, "auth_proof": auth_proof,
            "login_ts": login_ts, "first_ts": int(store.ts[rows[0]]), "last_ts": int(store.ts[rows[-1]]),
            "admin_requests": sum(g["n"] for g in nav), "distinct_admin_pages": len(real_pages),
            "critical_actions": crit_n, "critical_confirmed": crit_conf, "critical_blocked": crit_blk,
            "critical_executed": crit_conf,   # compat v47.5: = confirmate, nu doar 2xx/3xx
            "groups": glist, "timeline": tl,
            "timeline_truncated": sum(g["n"] for g in glist) > len(tl),
            "user_agents": sorted(({"ua": u, "n": n} for u, n in uas.items()), key=lambda x: -x["n"])[:6],
            "narrative": _admin_narrative(ip, cc, login_ts, mode, glist, fmt, proof),
            "dominant_category_label": t.get("dominant_category_label"),
        }
        (successes if item["confirmed"] else unconfirmed).append(item)
    successes.sort(key=lambda x: (not x["is_non_ro"], -x["critical_confirmed"], -x["critical_actions"],
                                  x["session_mode"] != "login", x["first_ts"]))
    unconfirmed.sort(key=lambda x: (not x["is_non_ro"], x["first_ts"]))
    covered = {x["ip"] for x in successes} | {x["ip"] for x in unconfirmed}
    attempts = []
    for ipc in ips_try:
        ip = store.v_ip[ipc]
        if ip in covered:
            continue
        rows = _ip_rows(store, m, ipc)
        if not rows.size:
            continue
        lp = rows[store.act[rows] == act_c["admin_login_post"]]
        if not lp.size:
            continue
        cc = store.v_cc[store.cc[rows[0]]] if store.v_cc else ""
        st = {}
        for x in store.st[lp].tolist():
            st[str(x)] = st.get(str(x), 0) + 1
        via = {"wp-login": 0, "xmlrpc": 0}
        for f in store.fp[lp].tolist():
            via["xmlrpc" if "xmlrpc.php" in store.v_fp[f] else "wp-login"] += 1
        t0, t1 = int(store.ts[lp[0]]), int(store.ts[lp[-1]])
        attempts.append({
            "ip": ip, "country": cc, "is_non_ro": bool(cc) and cc != "RO", "attempts": int(lp.size),
            "via": via, "statuses": st, "first_ts": t0, "last_ts": t1,
            "per_min": round(lp.size / max(1.0, (t1 - t0) / 60.0), 1),
            "n_302": st.get("302", 0),
            "user_agents": len({int(u) for u in store.ua[lp].tolist()}),
        })
    attempts.sort(key=lambda x: (-x["attempts"], x["ip"]))
    status = {}
    for x in attempts:
        status[x["ip"]] = "incercari"
    for x in unconfirmed:
        status[x["ip"]] = "neconfirmat"
    for x in successes:
        status[x["ip"]] = x["session_mode"]   # login / sesiune
    out = {"successes": successes, "unconfirmed": unconfirmed, "attempts": attempts, "status": status,
           "tz_offset_sec": tz, "wp_real_prefixes": sorted(real_pfx),
           "wp_fake_prefixes": getattr(store, "wp_fake_prefixes", []),
           "wp_probe_events": getattr(store, "wp_probe_events", 0),
           "note": "Actiunile sunt deduse din URL, metoda si cod HTTP (corpul POST nu apare in access log). "
                   "Un raspuns 2xx/302 NU inseamna ca operatia a reusit; 'CONFIRMAT' apare doar cand WordPress "
                   "a redirectionat pe pagina de succes (ex. ?update=del&delete_count=N, ?settings-updated=true)."}
    if len(cache) >= _ADMIN_CACHE_MAX:
        cache.clear()
    cache[ck] = out
    return out


@app.get("/api/dataset/{dataset_id}/admin_access")
def api_admin_access(dataset_id: str, gf: str = Query(default=""), timeline_limit: int = Query(default=400)):
    """Rubrica "Acces WP admin": acces reusit (login confirmat / sesiune
    autentificata), acces neconfirmat si incercari de autentificare."""
    ds, store, m, err = _incident_ctx(dataset_id, gf)
    if err:
        return err
    d = dict(_admin_compute(ds, store, m, timeline_limit))
    d.pop("status", None)
    return JSONResponse(d)


_ADMIN_ACTIONS = ("admin_login_success", "admin_get", "admin_login_post")
_ADMIN_ALERT_LABEL = {
    "login": "Login WP Admin confirmat (POST 302 + /wp-admin/ 200)",
    "sesiune": "Sesiune WP admin autentificata, fara login in log (cookie existent)",
}


def _reconcile_alerts(ds, store, m, alerts):
    """v47.6: alertele urmeaza EXACT clasificarea din "Acces WP admin" si se
    grupeaza pe IP (un singur card / IP, severitatea maxima)."""
    try:
        st = _admin_compute(ds, store, m)["status"]
    except Exception:
        st = {}
    rank = triage_columnar.SEVERITY_RANK
    by_ip, order, moved = {}, [], 0
    for a in alerts:
        a = dict(a)
        s = st.get(a["ip"])
        if a["action_type"] == "admin_get":
            if s == "neconfirmat":
                moved += 1
                continue                      # e in tab-ul "Acces neconfirmat", nu alerta
            if s in ("login", "sesiune") and a["ip"] in by_ip:
                pass                          # acelasi episod cu login-ul -> se lipeste la cardul IP-ului
            if s == "sesiune":
                a["label"] = _ADMIN_ALERT_LABEL["sesiune"] + (" -- IP non-RO" if a.get("is_non_ro") else "")
        a["admin_status"] = s
        cur = by_ip.get(a["ip"])
        if cur is None:
            a["related"] = []
            by_ip[a["ip"]] = a
            order.append(a["ip"])
            continue
        better = (rank.get(a["severity"], 4), -a["risk_score"]) < (rank.get(cur["severity"], 4), -cur["risk_score"])
        main, other = (a, cur) if better else (cur, a)
        rel = cur["related"]
        main = dict(main)
        main["related"] = rel + [{"action_type": other["action_type"], "label": other["label"],
                                  "severity": other["severity"], "hits": other["hits"]}]
        main["first_ts"] = min(a["first_ts"], cur["first_ts"])
        main["last_ts"] = max(a["last_ts"], cur["last_ts"])
        by_ip[a["ip"]] = main
    out = [by_ip[ip] for ip in order]
    out.sort(key=lambda x: (rank.get(x["severity"], 4), -x["risk_score"], -x["last_ts"]))
    return out, moved




# ==========================================================================
# v47.6 -- RECONCILIERE: analiza detaliata (v42: findings, traseu de
# compromitere, activitate admin, coada de investigare) e adusa la ACEEASI
# clasificare ca rubrica "Acces WP admin" (indexul columnar), ca o pagina sa nu
# spuna doua lucruri diferite despre acelasi IP. Nu se elimina evenimente --
# se corecteaza etichete, severitati gresite si dublurile aceleiasi cereri.
# ==========================================================================
_REQ_RE = re.compile(r"\b(GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS)\s+(\S+)\s+->\s+(\d{3})")
_SEV_RANK_R = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "": 5}


def _adm_context(ds):
    store = _col_store(ds) if ds else None
    if store is None:
        return None
    try:
        a = _admin_compute(ds, store, None)
    except Exception as e:
        print("[v47.6] reconciliere: admin indisponibil:", e)
        return None
    return {"status": a["status"], "succ": {x["ip"]: x for x in a["successes"]},
            "unc": {x["ip"]: x for x in a["unconfirmed"]}, "att": {x["ip"]: x for x in a["attempts"]},
            "fake": a.get("wp_fake_prefixes") or [], "real": set(a.get("wp_real_prefixes") or [""])}


def _fix_finding(f, ctx):
    f = dict(f)
    rule = f.get("rule") or ""
    ip = f.get("ip") or ""
    st = ctx["status"].get(ip)
    ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
    if rule == "Posibil login reusit dupa brute force":
        if st == "login":
            f["reason"] = (f.get("reason") or "") + " CONFIRMAT: IP-ul are login cu 302 urmat de /wp-admin/ cu 200 (vezi 'Acces WP admin')."
            f["confidence"] = "high"
        else:
            f["severity"] = "LOW"
            f["confidence"] = "high"
            f["rule"] = "Raspuns 200/302 dupa incercari esuate -- verificat: NU e login reusit"
            f["detail"] = (f.get("detail") or "").replace("Successful login cannot be confirmed from access logs alone.",
                                                          "Verificat: niciun login confirmat pentru acest IP.")
            fk = ", ".join((p or "/") for p in ctx["fake"][:6])
            f["reason"] = ("Verificat in log: pentru acest IP nu exista niciun POST de login cu 302 urmat de /wp-admin/ cu 200. "
                           "Pe wp-login.php 200 inseamna parola respinsa, xmlrpc.php raspunde 200 la orice cerere, iar pe "
                           "caile fara WordPress" + (f" ({fk})" if fk else "") + " site-ul raspunde generic. Ramane incercare de brute force.")
    elif rule == "Brute force wp-login/xmlrpc":
        n = int(ev.get("requests") or 0)
        real = (ctx["att"].get(ip) or {}).get("attempts")
        if real is not None and n:
            sts = (ctx["att"][ip].get("statuses") or {})
            f["reason"] = (f.get("reason") or "") + (
                f" Din cele {n}: {real} pe WordPress real (coduri {', '.join(f'{k}x{v}' for k, v in sts.items())} -- vezi "
                f"'Acces WP admin' > 'Incercari de autentificare'), {n - real} pe cai unde nu exista WordPress (raspuns generic, "
                f"fara efect).")
            if ev:
                ev = dict(ev); ev["real_wordpress_attempts"] = real; ev["no_wordpress_path_attempts"] = n - real
                f["evidence"] = ev
    elif rule.startswith("Acces admin sensibil"):
        me = (ev.get("method") or "").upper()
        try:
            code = int(ev.get("status"))
        except (TypeError, ValueError):
            code = 0
        if me == "GET" and 200 <= code < 300:
            f["severity"] = "LOW" if st in ("login", "sesiune") else f.get("severity")
            ctxs = {"login": "dupa un login confirmat", "sesiune": "intr-o sesiune autentificata"}.get(st, "fara login confirmat")
            f["reason"] = (f"Pagina (editor plugin/tema sau formular de upload) a fost DOAR afisata (GET {code}), {ctxs}. "
                           f"Afisarea nu instaleaza si nu modifica nimic -- o instalare/salvare reala ar fi un POST; "
                           f"vezi 'Acces WP admin' pentru ce a urmat.")
        elif me == "POST" and code in (401, 403):
            f["reason"] = (f"Upload/salvare (POST) BLOCAT de server (status {code}) -- nimic instalat sau modificat.")
    return f


def _norm_admin_label(lbl, me, code, st, path=None, real=None):
    if path and real is not None:
        pfx = triage_columnar.ColStore.wp_prefix(path)
        if pfx is not None and pfx not in real:
            return "Sondare pe o cale fara WordPress (raspuns generic al site-ului)"
    if lbl == "Plugin/tema: instalare sau editare":
        if me == "POST":
            return ("Plugin/tema: upload/salvare BLOCAT" if code in (401, 403)
                    else f"Plugin/tema: upload/salvare (POST {code}, rezultat neconfirmat)")
        return "Plugin/tema: pagina editor/upload afisata (fara modificare)"
    if lbl == "Acces /wp-admin/ (200)":
        if st in ("login", "sesiune"):
            return "Navigare wp-admin (sesiune autentificata)"
        if st == "neconfirmat":
            return "Acces /wp-admin/ (200) -- NECONFIRMAT"
    if lbl == "Login POST wp-login.php":
        return f"Login POST wp-login.php ({code})"
    return lbl


_LBL_PRIO = ("Login confirmat", "Sondare pe o cale", "Plugin/tema: upload/salvare", "Plugin/tema: pagina", "Acces admin sensibil",
             "Login POST", "Navigare wp-admin", "Acces /wp-admin/")


def _lbl_prio(lbl):
    for i, p in enumerate(_LBL_PRIO):
        if lbl.startswith(p):
            return i
    return len(_LBL_PRIO)


def _fix_admin_activity(items, ctx):
    out = []
    for it in items or []:
        st = ctx["status"].get(it.get("ip"))
        groups = {}
        order = []
        for e in it.get("events") or []:
            if e.get("label") == "Login reusit (302)":
                continue          # aceeasi cerere ca "Login POST wp-login.php" (302) -- nu se numara de 2 ori
            k = (e.get("time"), e.get("method"), e.get("path"), e.get("status"))
            e2 = dict(e)
            e2["label"] = _norm_admin_label(e.get("label") or "", (e.get("method") or "").upper(), e.get("status"), st,
                                            e.get("path"), ctx["real"])
            if k in groups:
                if _lbl_prio(e2["label"]) < _lbl_prio(groups[k]["label"]):
                    groups[k] = e2
                continue
            groups[k] = e2
            order.append(k)
        evs = [groups[k] for k in order]
        acts = Counter(e["label"] for e in evs)
        x = dict(it)
        x["events"] = evs
        x["actions"] = dict(acts)
        x["total_actions"] = max(len(evs), int(it.get("total_actions") or 0) - (len(it.get("events") or []) - len(evs)))
        x["admin_status"] = st
        out.append(x)
    return out


def _fix_trail_item(t, ctx):
    ip = t.get("ip")
    st = ctx["status"].get(ip)
    succ = ctx["succ"].get(ip) or ctx["unc"].get(ip)
    groups, order = {}, []
    for e in t.get("events") or []:
        e = dict(e)
        lbl = e.get("label") or ""
        m = _REQ_RE.search(e.get("detail") or "")
        me, path, code = (m.group(1), m.group(2), int(m.group(3))) if m else ("", "", e.get("status"))
        if e.get("type") == "login":
            k = (e.get("time"), "LOGIN")
            ok = (e.get("detail") or "").startswith("confirmat")
            e["label"] = "Login confirmat (POST 302 + /wp-admin/ 200)" if ok else "POST login 302 fara acces confirmat"
            e["category"] = "successful_login" if ok else "login_attempt"
        elif lbl in ("Login POST wp-login.php", "Login reusit (302)"):
            k = (e.get("time"), "LOGIN")
            e["label"] = f"Login POST wp-login.php ({code})"
            e["category"] = "login_attempt"
            e["category_reason"] = ("POST pe wp-login.php: 200 = parola respinsa; 302 singur nu e dovada -- "
                                    "loginul e confirmat doar de un /wp-admin/ cu 200 imediat dupa.")
        else:
            k = (e.get("time"), me, path, code) if m else (e.get("time"), lbl, id(e))
            nl = _norm_admin_label(lbl, me, code, st, path, ctx["real"]) if e.get("type") == "admin" else lbl
            if lbl.startswith("Acces admin sensibil") and me == "GET" and isinstance(code, int) and 200 <= code < 300:
                nl = "Plugin/tema: pagina editor/upload afisata (fara modificare)"
            if lbl.startswith("Acces admin sensibil") and me == "POST" and code in (401, 403):
                nl = "Plugin/tema: upload/salvare BLOCAT"
            e["label"] = nl
            if nl.startswith("Plugin/tema: upload/salvare BLOCAT"):
                e["category"] = "attack_attempt"
                e["category_reason"] = f"Upload/salvare respins de server (status {code}) -- nimic instalat sau modificat."
            elif nl.startswith("Plugin/tema: pagina") or nl.startswith("Navigare wp-admin"):
                e["category"] = "confirmed_admin_activity" if st in ("login", "sesiune") else "suspicious_request"
                e["category_reason"] = ("Pagina din admin afisata intr-o sesiune autentificata (login confirmat in log); "
                                        "afisarea singura nu modifica nimic." if st in ("login", "sesiune") else
                                        "Pagina din admin cu 200, fara login confirmat in log.")
            elif nl.startswith("Sondare pe o cale fara WordPress"):
                e["category"] = "attack_attempt"
                e["category_reason"] = "Cerere de scanner pe o cale unde nu exista WordPress; 200 = pagina generica, fara efect."
            elif nl.endswith("NECONFIRMAT"):
                e["category"] = "suspicious_request"
                e["category_reason"] = "200 pe /wp-admin/ fara login si fara dovada de autentificare -- vezi 'Acces WP admin' > 'Acces neconfirmat'."
        e["category_label"] = _TRAIL_CATEGORY_LABELS.get(e.get("category"), e.get("category"))
        if k in groups:
            cur = groups[k]
            # aceeasi cerere vazuta de mai multe reguli -> UN eveniment, cel mai specific
            keep_new = (e.get("type") == "login" and cur.get("type") != "login") or \
                       (cur.get("type") != "login" and _lbl_prio(e["label"]) < _lbl_prio(cur["label"]))
            sev = min(cur.get("severity") or "", e.get("severity") or "", key=lambda s: _SEV_RANK_R.get(s, 5))
            if keep_new:
                e["also"] = (cur.get("also") or []) + [cur["label"]]
                groups[k] = e
            else:
                cur.setdefault("also", []).append(e["label"])
                e = cur
            groups[k]["severity"] = sev
            continue
        groups[k] = e
        order.append(k)
    evs = [groups[k] for k in order]
    cat_counts = Counter(e.get("category") for e in evs)
    _CAT = ("confirmed_compromise", "successful_login", "attack_attempt", "confirmed_admin_activity",
            "login_attempt", "suspicious_request")
    dom = next((c for c in _CAT if cat_counts.get(c)), "suspicious_request")
    x = dict(t)
    x["events"] = evs
    x["total_events"] = max(len(evs), int(t.get("total_events") or 0) - (len(t.get("events") or []) - len(evs)))
    x["category_counts"] = dict(cat_counts)
    x["dominant_category"] = dom
    x["dominant_category_label"] = _TRAIL_CATEGORY_LABELS.get(dom, dom)
    x["admin_status"] = st
    # rezumatul in cuvinte -- din aceeasi sursa ca "Acces WP admin"
    lines = []
    old = list(t.get("summary") or [])
    has_login = st == "login"
    if succ:
        if st == "login":
            lines.append(f"Login CONFIRMAT in WP-Admin ({len(succ['login_ts'])}x) -- POST login cu 302 urmat de /wp-admin/ cu 200.")
        elif st == "sesiune":
            lines.append("Sesiune WP admin autentificata, fara login in log (cookie existent).")
        else:
            lines.append("Acces /wp-admin/ cu 200 fara login si fara dovada de autentificare -- NECONFIRMAT.")
        for g in succ["groups"]:
            if not g["critical"]:
                continue
            r = g["results"]
            if g.get("confirmed_units"):
                s2 = f"CONFIRMAT de WordPress: {unit_txt(g['key'], g['confirmed_units'])}"
            elif set(r) == {"blocat"}:
                s2 = "toate BLOCATE (401/403)"
            else:
                s2 = ", ".join(f"{n} {_RES_TXT.get(k, k)}" for k, n in r.items()) + ", fara confirmare in log"
            tg = [z for z in g.get("targets", []) if z != "bulk"]
            lines.append(f"{g['label']} x{g['n']} -- {s2}" + (f" ({', '.join(tg[:5])})" if tg else "") + ".")
        sens = [g for g in succ["groups"] if g.get("sensitive")]
        if sens:
            lines.append("Pagini sensibile doar afisate: " + ", ".join(f"{g['label'].lower()} x{g['n']}" for g in sens) + ".")
    elif ip in ctx["att"]:
        a = ctx["att"][ip]
        lines.append(f"{a['attempts']} incercari de login pe WordPress real, niciuna reusita "
                     f"(coduri: {', '.join(f'{k}x{v}' for k, v in a['statuses'].items())}).")
    for l in old:
        if l.startswith(("S-a logat cu succes", "A accesat editor de plugin", "A activat un plugin",
                         "Activitate inregistrata, fara un tipar clar")):
            continue
        if l.startswith("A facut brute-force"):
            l = "A facut brute-force pe wp-login/xmlrpc" + (" inainte de login." if has_login else " (fara login reusit).")
        lines.append(l)
    if not lines:
        lines.append("Activitate inregistrata, fara un tipar clar -- verifica evenimentele de mai jos.")
    x["summary"] = lines
    return x


def _group_findings(fs, gap=1800):
    """v48: findings cu acelasi IP + regula + severitate + motiv, la cel mult 30
    min unul de altul = ACEEASI secventa -> un singur rand, cu toate cererile
    originale pastrate in evidence ("cererea 1..N"). Nu se combina evenimente
    independente (alt IP, alta regula sau pauza > 30 min)."""
    out, open_ = [], {}
    def ts(f):
        d = parse_apache_time(f.get("time") or "")
        return d.timestamp() if d else None
    for f in fs:
        t = ts(f)
        k = (f.get("ip"), f.get("rule"), f.get("severity"), f.get("reason"))
        g = open_.get(k)
        if f.get("ip") and t is not None and g is not None and t - g["_t1"] <= gap and t >= g["_t0"] - gap:
            g["_items"].append(f)
            g["_t0"], g["_t1"] = min(g["_t0"], t), max(g["_t1"], t)
            continue
        g = {"_items": [f], "_t0": t or 0, "_t1": t or 0}
        open_[k] = g
        out.append(g)
    res = []
    for g in out:
        items = g["_items"]
        if len(items) == 1:
            res.append(items[0])
            continue
        items.sort(key=lambda f: ts(f) or 0)
        f0 = dict(items[0])
        reqs = []
        for f in items:
            mm = _REQ_RE.search(f.get("detail") or "")
            r = f"{mm.group(1)} {mm.group(2)} -> {mm.group(3)}" if mm else (f.get("detail") or "")
            if r not in reqs:
                reqs.append(r)
        f0["detail"] = (f"IP {f0.get('ip')}: {len(items)} cereri din aceeasi secventa, {items[0].get('time')} - "
                        f"{items[-1].get('time')}: " + "; ".join(reqs[:3]) + (f"; +{len(reqs) - 3} altele" if len(reqs) > 3 else ""))
        ev = {"cereri_grupate": len(items), "regula_de_grupare": "acelasi IP, aceeasi regula si severitate, pauza <= 30 min"}
        for i, f in enumerate(items, 1):
            ev[f"cererea {i}"] = f.get("detail")
        f0["evidence"] = ev
        f0["occurrences"] = len(items)
        f0["time"] = items[0].get("time")
        res.append(f0)
    return res


def _reconcile_summary(dataset_id, summary):
    ds = _get_dataset(dataset_id) or {}
    ctx = _adm_context(ds)
    if ctx is None or not isinstance(summary, dict):
        return summary
    out = dict(summary)
    try:
        fs = [_fix_finding(f, ctx) for f in (summary.get("findings") or [])]
        fs.sort(key=lambda f: SEVERITY_ORDER.get(f.get("severity", ""), 9))
        fs = _group_findings(fs)
        out["findings"] = fs
        out["findings_signals"] = sum(int(f.get("occurrences") or 1) for f in fs)
        out["findings_count"] = len(fs)
        iq = summary.get("investigation_queue")
        if isinstance(iq, dict):
            n_extra = max(0, int(iq.get("total") or 0) - len(fs) - len(summary.get("anomalies") or []))
            q = _build_investigation_queue(fs, summary.get("anomalies") or [])
            q["total"] += n_extra
            q["more"] = max(0, q["total"] - len(q["items"]))
            out["investigation_queue"] = q
        if summary.get("compromise_trail"):
            out["compromise_trail"] = [_fix_trail_item(t, ctx) for t in summary["compromise_trail"]]
        if summary.get("admin_activity"):
            out["admin_activity"] = _fix_admin_activity(summary["admin_activity"], ctx)
        # IP-uri suspecte: motivele si riscul urmeaza findingurile reconciliate si alertele
        if summary.get("suspicious_ips"):
            store = _col_store(ds)
            alert_sev = {}
            try:
                for al in _reconcile_alerts(ds, store, None, store.top_alerts(200))[0]:
                    alert_sev[al["ip"]] = (al["severity"], al["label"])
            except Exception:
                pass
            ren = {"Posibil login reusit dupa brute force": None}
            for f in fs:
                if f.get("rule", "").startswith("Raspuns 200/302 dupa incercari esuate"):
                    ren["Posibil login reusit dupa brute force"] = f["rule"]
            fsev = {}
            for f in fs:
                ipf = f.get("ip")
                if ipf:
                    cur = fsev.get(ipf)
                    if cur is None or _SEV_RANK_R.get(f.get("severity", ""), 5) < _SEV_RANK_R.get(cur, 5):
                        fsev[ipf] = f.get("severity", "")
            frules = {f.get("rule") for f in summary.get("findings") or []} | {f.get("rule") for f in fs}
            sips = []
            for x in summary["suspicious_ips"]:
                x = dict(x)
                reasons = [ren.get(r) or r for r in (x.get("reasons") or [])]
                other = [r for r in reasons if r not in frules]
                cands = [fsev.get(x["ip"], "LOW")] + (["MEDIUM"] if other else [])
                if x["ip"] in alert_sev:
                    cands.append(alert_sev[x["ip"]][0])
                    if alert_sev[x["ip"]][1] not in reasons:
                        reasons.insert(0, alert_sev[x["ip"]][1])
                new = min(cands, key=lambda z: _SEV_RANK_R.get(z, 5))
                x["risk_original"] = x.get("risk")
                x["risk"] = new
                x["reasons"] = reasons
                x["admin_status"] = ctx["status"].get(x["ip"])
                sips.append(x)
            sips.sort(key=lambda z: (_SEV_RANK_R.get(z.get("risk", ""), 5), -int(z.get("requests") or 0)))
            out["suspicious_ips"] = sips
        wp = summary.get("wp")
        if isinstance(wp, dict) and wp.get("successful_logins") is not None:
            wp = dict(wp)
            conf = [l for l in wp["successful_logins"] if l.get("confidence") == "HIGH"]
            wp["successful_logins_confirmed"] = len(conf)
            wp["successful_logins_confirmed_ips"] = len({l["ip"] for l in conf})
            wp["successful_logins_unconfirmed"] = len(wp["successful_logins"]) - len(conf)
            out["wp"] = wp
        out["reconciled"] = "v47.6"
    except Exception as e:
        import traceback
        traceback.print_exc()
        print("[v47.6] reconciliere esuata:", e)
        return summary
    return out




# ==========================================================================
# v48 -- "SIGNAL FIRST": rezumatul executiv, incidentele prioritare,
# evenimentele importante si pasii urmatori, construite EXCLUSIV din
# clasificarile deja existente (Acces WP admin, Incidente/atacuri, alerte).
# Nu adauga reguli noi de detectie si nu inventeaza scoruri: severitatea si
# starea fiecarui incident au reguli explicite, documentate mai jos.
# ==========================================================================
ST_CONF = "Confirmat din loguri"
ST_SUSP = "Suspect"
ST_BLOCK = "Blocat conform raspunsului HTTP"
ST_UNC = "Neconfirmat"
ST_VERIFY = "Necesita verificare suplimentara"

# operatiile care schimba conturi / cod / configurare -- folosite la prioritizare
_HIGH_IMPACT = {"plugin_upload", "theme_upload", "plugin_install", "theme_install", "plugin_editor_save",
                "theme_editor_save", "user_create", "user_edit_save", "users_action", "users_promote",
                "app_password", "plugin_activate", "theme_switch", "options_save", "plugin_delete",
                "plugin_deactivate", "media_upload", "import_export"}


def _ts_fmt(tz):
    def f(ts):
        return datetime.utcfromtimestamp(int(ts) + tz).strftime("%d %b %H:%M")
    return f


def _brief_admin_incident(x, fmt, alert_by_ip):
    ip, cc = x["ip"], x["country"] or "??"
    crit = [g for g in x["groups"] if g["critical"]]
    conf_groups = [g for g in crit if g.get("confirmed_units")]
    blocked_groups = [g for g in crit if set(g["results"]) == {"blocat"}]
    open_groups = [g for g in crit if g not in conf_groups and g not in blocked_groups]
    observed, affected, evidence, actions = [], [], list(x.get("evidence") or []), []
    mode = x["session_mode"]
    if mode == "login":
        n = len(x['login_ts'])
        observed.append(f"Login in WP admin confirmat {'o data' if n == 1 else f'de {n} ori'} ({'la' if n == 1 else 'primul la'} {fmt(x['login_ts'][0])}).")
    elif mode == "sesiune":
        observed.append("Sesiune WP admin autentificata, fara login in perioada analizata.")
    else:
        observed.append(f"{x['distinct_admin_pages']} pagina(i) /wp-admin/ cu 200, fara login si fara dovada de autentificare.")
    for g in conf_groups:
        tg = [t for t in g.get("targets", []) if t != "bulk"]
        observed.append(f"{g['label']}: {unit_txt(g['key'], g['confirmed_units'])}, confirmat de WordPress"
                        + (f" ({', '.join(tg[:6])})" if tg else "") + ".")
        affected += [f"{g['group']}: {t}" for t in tg[:6]]
    for g in blocked_groups:
        observed.append(f"{g['label']} x{g['n']}: toate respinse cu 401/403.")
    for g in open_groups:
        observed.append(f"{g['label']} x{g['n']}: " + ", ".join(f"{n} {_RES_TXT.get(k, k)}" for k, n in g["results"].items())
                        + " -- rezultatul nu se vede in log.")
    sens = [g for g in x["groups"] if g.get("sensitive")]
    if sens:
        observed.append("Pagini sensibile doar afisate: " + ", ".join(f"{g['label'].lower()} x{g['n']}" for g in sens) + ".")
    al = alert_by_ip.get(ip)
    # --- stare + severitate (reguli explicite) ---
    impact_conf = any(g["key"] in _HIGH_IMPACT for g in conf_groups)
    if mode == "neconfirmat":
        status, sev = [ST_UNC, ST_VERIFY], "MEDIUM"
    elif conf_groups:
        status = [ST_CONF, ST_VERIFY]
        sev = "CRITICAL" if x["is_non_ro"] else "HIGH"
    elif blocked_groups and not open_groups:
        status = [ST_CONF, ST_BLOCK, ST_VERIFY] if mode == "login" else [ST_BLOCK]
        sev = "CRITICAL" if (x["is_non_ro"] and mode == "login") else "HIGH"
    else:
        status = [ST_CONF, ST_VERIFY] if mode in ("login", "sesiune") else [ST_SUSP]
        sev = "HIGH" if x["is_non_ro"] else "MEDIUM"
    if al and _SEV_RANK_R.get(al["severity"], 5) < _SEV_RANK_R.get(sev, 5):
        sev = al["severity"]
    # --- interpretare + actiuni ---
    if mode == "neconfirmat":
        interp = ("Poate fi o sesiune reala (cookie deja existent) sau un raspuns din cache / generic; "
                  "logul nu permite o concluzie.")
        actions.append(f"Verifica in WordPress daca exista sesiuni active / ultimul login pentru conturile admin la {fmt(x['first_ts'])}.")
    else:
        who = "dintr-un IP din afara Romaniei" if x["is_non_ro"] else "dintr-un IP din Romania"
        interp = f"Acces administrativ real {who}. Logul arata CE s-a cerut, nu CINE a fost (contul nu apare in access log)."
        if blocked_groups:
            interp += " Incercarile de upload/salvare au fost respinse de server; nu e dovada ca nu au existat alte cai."
        t0 = x["login_ts"][0] if x["login_ts"] else x["first_ts"]
        actions.append("Confirma cu proprietarul site-ului daca accesul din " + f"{ip} ({cc}) la {fmt(t0)} a fost al lui.")
        if any(g["key"] in ("users_action", "user_edit_save", "user_create", "users_promote") for g in conf_groups):
            actions.append("Verifica lista de utilizatori si rolurile (Utilizatori > Toti) si jurnalul de modificari al conturilor.")
        if any(g["key"] == "options_save" for g in conf_groups):
            actions.append("Verifica setarile modificate (" + ", ".join(t for g in conf_groups if g["key"] == "options_save" for t in g.get("targets", []) if t != "bulk") + ").")
        if any(g["key"] in ("plugin_activate", "plugin_deactivate", "plugin_delete", "theme_switch") for g in conf_groups):
            actions.append("Verifica lista de plugin-uri / teme active si data ultimei modificari a fisierelor lor.")
        if blocked_groups or any(g["key"] in ("plugin_upload_page", "theme_upload_page", "theme_editor", "plugin_editor") for g in sens):
            actions.append("Cauta pe disc fisiere noi in wp-content/plugins, wp-content/themes si wp-content/uploads din intervalul sesiunii.")
        if x["is_non_ro"] and mode == "login":
            actions.append("Daca accesul nu e recunoscut: schimba parolele conturilor admin si invalideaza sesiunile (dupa confirmare, nu inainte).")
    why = []
    if x["is_non_ro"] and mode in ("login", "sesiune"):
        why.append(f"acces admin dintr-un IP din afara Romaniei ({cc})")
    if conf_groups:
        why.append("modificari confirmate asupra " + ", ".join(sorted({g["group"] for g in conf_groups})))
    if blocked_groups:
        why.append("incercari de a urca cod (plugin/tema) -- blocate")
    if mode == "neconfirmat":
        why.append("acces in zona de administrare fara dovada de autentificare")
    title = {"login": "Acces WP admin cu login confirmat", "sesiune": "Sesiune WP admin autentificata",
             "neconfirmat": "Acces /wp-admin/ neconfirmat"}[mode]
    if conf_groups:
        title += " + modificari confirmate"
    elif blocked_groups:
        title += " + upload-uri blocate"
    return {
        "id": f"adm:{ip}", "kind": "admin", "ip": ip, "country": cc, "severity": sev, "status": status,
        "title": title, "first_ts": x["first_ts"], "last_ts": x["last_ts"],
        "observed": observed, "interpretation": interp,
        "certainty": status[0] + (" -- pe baza: " + "; ".join(evidence) if evidence else ""),
        "affected": affected, "why": why, "actions": actions, "evidence": evidence,
        "hints": x.get("hints") or [],
        "sort": (_SEV_RANK_R.get(sev, 5), 0 if conf_groups else (1 if mode == "login" else 2),
                 0 if impact_conf else 1, -x["last_ts"]),
        "links": {"admin": ip, "trail": ip},
        "signals": {"alert": al["severity"] if al else None, "admin_requests": x["admin_requests"],
                    "critical_confirmed": x["critical_confirmed"], "critical_blocked": x["critical_blocked"]},
        "_groups": x["groups"], "_login_ts": x["login_ts"],
    }


def _brief_attack_incident(i, att, fmt, findings_by_ip):
    ip = i["ip"]
    a = att.get(ip)
    observed = []
    status = [ST_SUSP]
    if a:
        sts = a["statuses"]
        observed.append(f"{a['attempts']} incercari de login pe WordPress real (" +
                        ", ".join(f"{k}: {v}" for k, v in sts.items()) + "), niciuna reusita.")
        if set(sts) <= {"401", "403"}:
            status = [ST_BLOCK]
    f = i.get("first_significant")
    if f:
        observed.append(f"Primul eveniment semnificativ: {f.get('label')} ({f.get('method')} {f.get('url')} -> {f.get('status')}) la {fmt(f['ts'])}.")
    fl = findings_by_ip.get(ip) or []
    for r in sorted({x.get("rule") for x in fl}):
        observed.append(f"Finding: {r}.")
    if i.get("dominant_category_label"):
        observed.append(f"Categoria traseului: {i['dominant_category_label']}.")
    sev = i.get("max_severity") or "MEDIUM"
    return {
        "id": f"atk:{ip}", "kind": "attack", "ip": ip, "country": i.get("country") or "??", "severity": sev,
        "status": status, "title": "Incercare de atac" + (" -- autentificare blocata" if ST_BLOCK in status else ""),
        "first_ts": i["first_ts"], "last_ts": i["last_ts"], "observed": observed,
        "interpretation": "Activitate automata de atac/scanare. Nu exista nicio dovada de acces reusit pentru acest IP.",
        "certainty": status[0] + " -- pe baza codurilor HTTP din log; un 403 arata ca cererea a fost respinsa, nu ca atacul s-a oprit.",
        "affected": [], "why": ["incercari repetate de autentificare / scanare"],
        "actions": [f"Verifica daca {ip} e deja blocat (CSF / Imunify360); daca nu, blocheaza-l sau limiteaza xmlrpc.php / wp-login.php."],
        "evidence": [], "hints": [],
        "sort": (_SEV_RANK_R.get(sev, 5), 3, 1, -i["last_ts"]),
        "links": {"trail": ip}, "signals": {"requests": i["requests"]},
    }


def _brief_events(incs, fmt):
    """Evenimente importante: o linie pe SECVENTA (login, grup de operatii de
    acelasi tip), nu pe cerere HTTP."""
    ev = []
    for x in incs:
        if x["kind"] == "admin":
            if x["_login_ts"]:
                ev.append({"ts": x["_login_ts"][0], "ip": x["ip"], "severity": x["severity"],
                           "status": ST_CONF, "text": f"Login WP admin confirmat"
                           + (f" (+{len(x['_login_ts']) - 1} ulterior)" if len(x["_login_ts"]) > 1 else ""),
                           "incident": x["id"]})
            elif x["kind"] == "admin":
                ev.append({"ts": x["first_ts"], "ip": x["ip"], "severity": x["severity"], "status": x["status"][0],
                           "text": x["title"], "incident": x["id"]})
            for g in x["_groups"]:
                if not g["critical"]:
                    continue
                if g.get("confirmed_units"):
                    st, txt = ST_CONF, f"{g['label']}: {unit_txt(g['key'], g['confirmed_units'])}"
                elif set(g["results"]) == {"blocat"}:
                    st, txt = ST_BLOCK, f"{g['label']} x{g['n']} -- blocat (401/403)"
                else:
                    st, txt = ST_UNC, f"{g['label']} x{g['n']} -- rezultat neconfirmat"
                tg = [t for t in g.get("targets", []) if t != "bulk"]
                ev.append({"ts": g["first_ts"], "ip": x["ip"], "severity": x["severity"], "status": st,
                           "text": txt + (f" ({', '.join(tg[:4])})" if tg else ""), "incident": x["id"]})
        elif x["kind"] == "filter_attack":
            ev.append({"ts": x["first_ts"], "ip": x["ip"], "severity": x["severity"], "status": x["status"][0],
                       "text": x["title"] + " (" + str(x["signals"]["requests"]) + " cereri)", "incident": x["id"]})
        else:
            ev.append({"ts": x["first_ts"], "ip": x["ip"], "severity": x["severity"], "status": x["status"][0],
                       "text": x["title"], "incident": x["id"]})
    # prioritate (severitatea incidentului), apoi cele mai recente
    ev.sort(key=lambda e: (_SEV_RANK_R.get(e["severity"], 5), -e["ts"]))
    for e in ev:
        e["when"] = fmt(e["ts"])
    return ev


@app.get("/api/dataset/{dataset_id}/brief")
def api_brief(dataset_id: str, gf: str = Query(default="")):
    ds, store, m, err = _incident_ctx(dataset_id, gf)
    if err:
        return err
    tz = _log_tz_offset(ds) or 0
    fmt = _ts_fmt(tz)
    sel = np.arange(store.n) if m is None else np.flatnonzero(m)
    adm = _admin_compute(ds, store, m)
    f, _e = _gf_checked(gf_raw=gf)
    try:
        raw_alerts = store.alerts_in(f, 240) if not _gf_is_empty(f) else store.top_alerts(240)
        alerts, _mv = _reconcile_alerts(ds, store, m, raw_alerts)
    except Exception:
        alerts = []
    alert_by_ip = {a["ip"]: a for a in alerts}
    try:
        inc = json.loads(api_incidents(dataset_id, gf=gf, limit=2000).body)
    except Exception:
        inc = {"incidents": [], "admin_only": {}}
    summ = _summary_without_fp(dataset_id, (ds.get("summary_cache") or {}).get("ALL") or {}) if _gf_is_empty(f) else {}
    findings_by_ip: Dict[str, List[Dict[str, Any]]] = {}
    for x in (summ.get("findings") or []):
        if x.get("ip"):
            findings_by_ip.setdefault(x["ip"], []).append(x)
    att = {x["ip"]: x for x in adm["attempts"]}
    incs = [_brief_admin_incident(x, fmt, alert_by_ip) for x in adm["successes"] + adm["unconfirmed"]]
    incs += [_brief_attack_incident(i, att, fmt, findings_by_ip) for i in inc.get("incidents") or []]
    # v49.1: atac pe filtre = incident propriu (nu e legat de un singur IP)
    fa = None
    try:
        fa = _filter_attack_compute(ds, store, m, top=10)
    except Exception as e:
        print("[v49.1] filter attacks:", e)
    if fa and fa.get("detected"):
        st5 = fa["status"]["5xx"]
        obs = [f"{fa['filter_requests']:,} cereri cu parametri de filtrare ({round(100 * fa['share'], 1)}% din selectie) de la {fa['unique_ips']:,} IP-uri unice; {fa['ips_with_1_request']:,} IP-uri au facut o singura cerere.".replace(",", "."),
               "Tinte principale: " + "; ".join(f"{t['target']} ({t['requests']:,} cereri / {t['unique_ips']:,} IP-uri, parametri: {', '.join(t['params'][:3])})".replace(",", ".") for t in fa["targets"][:3]) + ".",
               f"Coduri: 2xx {fa['status']['2xx']}, 3xx {fa['status']['3xx']}, 4xx {fa['status']['4xx']}, 5xx {st5}. Varf: {fa['peak_minute']['requests']} cereri intr-un minut ({fmt(fa['peak_minute']['ts'])})."]
        tp = fa.get("top_param") or "filter_"
        incs.insert(0, {
            "id": "fa:selection", "kind": "filter_attack", "ip": f"{fa['unique_ips']} IP-uri", "country": "",
            "severity": fa["severity"], "status": [ST_CONF] + ([ST_VERIFY] if st5 else []),
            "title": "ATAC PE FILTRE -- " + "; ".join(fa["kinds"]),
            "first_ts": fa["first_ts"], "last_ts": fa["last_ts"], "observed": obs,
            "interpretation": "Enumerare automata a combinatiilor de filtre (scraping / incarcare a serverului), de obicei prin rotatie de IP-uri. Fiecare combinatie e o pagina necache-uita, generata de PHP + MySQL.",
            "certainty": ST_CONF + " -- tiparul de trafic e observat direct (reguli: " + "; ".join(FA_RULES[k] for k in ("distribuit", "concentrat")) + ")",
            "affected": [t["target"] for t in fa["targets"][:5]],
            "why": ["volum mare de pagini dinamice" + (f"; {st5} raspunsuri 5xx (serverul a cedat)" if st5 else "")],
            "actions": [f"Cloudflare: regula WAF -- Managed Challenge pentru cererile cu '{tp}' in query, exceptand boti verificati.",
                        "Rate limiting pe URL-urile tinta; robots.txt: Disallow: /*?*" + tp + " (pentru crawlerele legitime).",
                        "Verifica logurile PHP-FPM / MySQL pentru incarcarea din interval (max_children, slow queries)."],
            "evidence": [], "hints": [], "links": {"filter": True}, "signals": {"requests": fa["filter_requests"]},
            "sort": (_SEV_RANK_R.get(fa["severity"], 5), 0, 0, -fa["last_ts"]),
        })
    incs.sort(key=lambda x: x["sort"])
    events = _brief_events(incs, fmt)
    for x in incs:
        x.pop("sort", None); x.pop("_groups", None); x.pop("_login_ts", None)
    steps, seen = [], set()
    for x in incs:
        for a in x["actions"]:
            if a not in seen:
                seen.add(a)
                steps.append({"text": a, "ip": x["ip"], "incident": x["id"], "severity": x["severity"]})
    blocked_admin = sum(x["critical_blocked"] for x in adm["successes"] + adm["unconfirmed"])
    blocked_login = sum(int(v) for x in adm["attempts"] for k, v in x["statuses"].items() if k in ("401", "403"))
    conf_ops = sum(x["critical_confirmed"] for x in adm["successes"])
    exec_ = {
        "requests": int(sel.size), "unique_ips": int(np.unique(store.ip[sel]).size) if sel.size else 0,
        "ts_min": int(store.ts[sel].min()) if sel.size else None, "ts_max": int(store.ts[sel].max()) if sel.size else None,
        "incidents": len(incs),
        "incidents_by_severity": dict(Counter(x["severity"] for x in incs)),
        "admin_sessions_confirmed": len(adm["successes"]),
        "admin_ops_confirmed": conf_ops,
        "admin_unconfirmed": len(adm["unconfirmed"]),
        "blocked_admin_actions": blocked_admin,
        "blocked_login_requests": blocked_login,
        "login_attempt_ips": len(adm["attempts"]),
        "needs_verification": sum(1 for x in incs if ST_VERIFY in x["status"] or ST_UNC in x["status"]),
        "alerts_ips": len(alerts),
        "filter_attack": bool(fa and fa.get("detected")),
        "filter_requests": (fa or {}).get("filter_requests", 0),
        "filter_unique_ips": (fa or {}).get("unique_ips", 0),
        "filtered": not _gf_is_empty(f),
    }
    wf = (summ.get("wordfence_status") if summ else None)
    return JSONResponse({"exec": exec_, "incidents": incs, "events": events, "steps": steps,
                         "wordfence_status": wf, "tz_offset_sec": tz,
                         "definitions": {
                             ST_CONF: "Exista dovezi directe in log pentru evenimentul respectiv.",
                             ST_SUSP: "Activitatea justifica investigatie, concluzia nu e demonstrata.",
                             ST_BLOCK: "Serverul a raspuns 401/403 -- cererea a fost respinsa; nu inseamna ca tot atacul a fost neutralizat.",
                             ST_UNC: "Datele din log nu permit stabilirea rezultatului.",
                             ST_VERIFY: "Concluzia cere alte surse (WordPress, fisiere, baza de date)."}})




# ==========================================================================
# v49 -- TIMPUL: o singura definitie, folosita de toata aplicatia.
#  * Intern: epoch UTC (secunde intregi), parsat din linia de log CU offsetul
#    ei (ex. "+0300") -- nu se presupune nici UTC, nici ora Romaniei.
#  * Afisare / selectie: ORA LOGULUI ("wall clock" din fisier). Daca logul
#    contine mai multe offseturi (ex. trecerea la ora de iarna +0300 -> +0200),
#    fiecare moment foloseste offsetul segmentului lui.
#  * Interval = [ts_from, ts_to], AMBELE CAPETE INCLUSE, la secunda.
#    "O ora" 14:00 = 14:00:00 .. 14:59:59; "o zi" = 00:00:00 .. 23:59:59.
# ==========================================================================
_MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
_TZ_OFF_RX = re.compile(r"([+-])(\d{2})(\d{2})$")


def _tz_segments(ds):
    """[(offset_sec, ts_min, ts_max, n)] -- din indexul SQL (ts_str pastreaza
    offsetul original al fiecarei linii). Cache pe dataset."""
    seg = ds.get("_tz_segments")
    if seg is not None:
        return seg
    seg = []
    try:
        conn = triage_engine.connect(triage_engine.db_path_for(ds["workdir"]))
        try:
            rows = conn.execute("SELECT substr(ts_str, -5), MIN(ts), MAX(ts), COUNT(*) FROM events "
                                "GROUP BY 1 ORDER BY 2").fetchall()
        finally:
            conn.close()
        for off, a, b, n in rows:
            m = _TZ_OFF_RX.search(off or "")
            if not m:
                continue
            sec = int(m.group(2)) * 3600 + int(m.group(3)) * 60
            seg.append((sec if m.group(1) == "+" else -sec, int(a), int(b), int(n)))
    except Exception as e:
        print("[v49] tz segments:", e)
    if not seg:
        seg = [(_log_tz_offset(ds) or 0, 0, 2 ** 40, 0)]
    ds["_tz_segments"] = seg
    return seg


def offset_at(seg, epoch):
    """Offsetul logului valabil la momentul `epoch`."""
    best = seg[0][0]
    for off, a, b, _n in seg:
        if epoch >= a:
            best = off
    return best


def wall_to_epoch(seg, y, mo, d, h=0, mi=0, s=0):
    """Ora din log -> epoch UTC. Pentru o ora care exista in doua segmente
    (ora repetata la trecerea la ora de iarna) se alege prima aparitie."""
    naive = calendar.timegm((y, mo, d, h, mi, s, 0, 0, 0))
    cands = []
    for off, a, b, _n in seg:
        e = naive - off
        cands.append((0 if a - 3600 <= e <= b + 3600 else 1, e))
    cands.sort()
    return cands[0][1]


def epoch_to_wall(seg, epoch):
    off = offset_at(seg, epoch)
    t = time.gmtime(epoch + off)
    sign = "+" if off >= 0 else "-"
    return {"day": f"{t.tm_mday:02d}/{_MON[t.tm_mon - 1]}/{t.tm_year}", "h": t.tm_hour, "m": t.tm_min, "s": t.tm_sec,
            "offset": f"{sign}{abs(off) // 3600:02d}{abs(off) % 3600 // 60:02d}",
            "text": f"{t.tm_mday:02d} {_MON[t.tm_mon - 1]} {t.tm_year} {t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d}"}


def _parse_day(day):
    m = re.fullmatch(r"(\d{1,2})/([A-Za-z]{3})/(\d{4})", (day or "").strip())
    if not m or m.group(2).title() not in _MON:
        raise ValueError(f"zi invalida: {day!r} (format asteptat 30/Sep/2026)")
    y, mo, d = int(m.group(3)), _MON.index(m.group(2).title()) + 1, int(m.group(1))
    import datetime as _dt
    try:
        _dt.date(y, mo, d)
    except ValueError:
        raise ValueError(f"zi inexistenta: {day!r}")
    return y, mo, d


PERIOD_MODES = ("all", "day", "hour", "min30", "min10", "minute", "moment", "custom")


def compute_period(seg, mode, day=None, h=0, m=0, s=0, day2=None, h2=23, m2=59, s2=59, win=30,
                   bounds=None):
    """-> dict(ts_from, ts_to, label) cu AMBELE capete incluse. ValueError la
    intrari invalide (ora 24, interval inversat, mod necunoscut...)."""
    if mode not in PERIOD_MODES:
        raise ValueError(f"mod necunoscut: {mode!r}")
    for v, hi, name in ((h, 23, "ora"), (m, 59, "minutul"), (s, 59, "secunda"), (h2, 23, "ora finala"),
                        (m2, 59, "minutul final"), (s2, 59, "secunda finala")):
        if not isinstance(v, int) or not 0 <= v <= hi:
            raise ValueError(f"{name} invalid(a): {v!r}")
    if mode == "all":
        if not bounds:
            raise ValueError("limitele logului nu sunt cunoscute")
        a, b = bounds
        return {"ts_from": a, "ts_to": b, "label": "tot logul"}
    y, mo, d = _parse_day(day)
    if mode == "day":
        a = wall_to_epoch(seg, y, mo, d, 0, 0, 0)
        b = wall_to_epoch(seg, y, mo, d, 23, 59, 59)
        lab = f"ziua {day}"
    elif mode == "hour":
        a = wall_to_epoch(seg, y, mo, d, h, 0, 0); b = wall_to_epoch(seg, y, mo, d, h, 59, 59)
        lab = f"{day} {h:02d}:00:00 - {h:02d}:59:59"
    elif mode in ("min30", "min10"):
        step = 30 if mode == "min30" else 10
        m0 = m - m % step
        a = wall_to_epoch(seg, y, mo, d, h, m0, 0); b = wall_to_epoch(seg, y, mo, d, h, m0 + step - 1, 59)
        lab = f"{day} {h:02d}:{m0:02d}:00 - {h:02d}:{m0 + step - 1:02d}:59"
    elif mode == "minute":
        a = wall_to_epoch(seg, y, mo, d, h, m, 0); b = wall_to_epoch(seg, y, mo, d, h, m, 59)
        lab = f"{day} {h:02d}:{m:02d}:00 - {h:02d}:{m:02d}:59"
    elif mode == "moment":
        if not isinstance(win, int) or not 0 <= win <= 86400:
            raise ValueError(f"fereastra invalida: {win!r}")
        t = wall_to_epoch(seg, y, mo, d, h, m, s)
        a, b = t - win, t + win
        lab = f"{day} {h:02d}:{m:02d}:{s:02d} ± {win} s"
    else:  # custom
        y2, mo2, d2 = _parse_day(day2 or day)
        a = wall_to_epoch(seg, y, mo, d, h, m, s)
        b = wall_to_epoch(seg, y2, mo2, d2, h2, m2, s2)
        if b < a:
            raise ValueError("sfarsitul intervalului e inaintea inceputului")
        lab = f"{day} {h:02d}:{m:02d}:{s:02d} - {day2 or day} {h2:02d}:{m2:02d}:{s2:02d}"
    return {"ts_from": int(a), "ts_to": int(b), "label": lab}


def _time_bounds(ds, store):
    if store is not None and store.n:
        return int(store.ts.min()), int(store.ts.max())
    conn = triage_engine.connect(triage_engine.db_path_for(ds["workdir"]))
    try:
        a, b = conn.execute("SELECT MIN(ts), MAX(ts) FROM events").fetchone()
    finally:
        conn.close()
    return (int(a), int(b)) if a is not None else None


@app.get("/api/dataset/{dataset_id}/time_info")
def api_time_info(dataset_id: str):
    """Fusul orar al logului (segmentele de offset), prima / ultima cerere si
    zilele disponibile (in ora logului) -- sursa selectorului de perioada."""
    ds = _get_dataset(dataset_id)
    if not ds:
        return JSONResponse({"error": "Dataset expirat sau inexistent."}, status_code=404)
    if not ds.get("triage_ready"):
        return JSONResponse({"error": "Indexarea e inca in curs.", "indexing": True}, status_code=202)
    store = _col_store(ds)
    seg = _tz_segments(ds)
    bounds = _time_bounds(ds, store)
    days: List[str] = []
    if bounds:
        import datetime as _dt
        y, mo, d = _parse_day(epoch_to_wall(seg, bounds[0])["day"])
        y2, mo2, d2 = _parse_day(epoch_to_wall(seg, bounds[1])["day"])
        cur, end = _dt.date(y, mo, d), _dt.date(y2, mo2, d2)
        while cur <= end and len(days) < 3660:
            days.append(f"{cur.day:02d}/{_MON[cur.month - 1]}/{cur.year}")
            cur += _dt.timedelta(days=1)
    return JSONResponse({
        "segments": [{"offset_sec": o, "ts_min": a, "ts_max": b, "requests": n} for o, a, b, n in seg],
        "multi_offset": len(seg) > 1,
        "first": {"ts": bounds[0], **epoch_to_wall(seg, bounds[0])} if bounds else None,
        "last": {"ts": bounds[1], **epoch_to_wall(seg, bounds[1])} if bounds else None,
        "days": days, "modes": list(PERIOD_MODES),
        "semantics": "Interval inchis [de la, pana la], ambele capete incluse, la secunda; ora = ora din log (offsetul din fiecare linie).",
    })


@app.get("/api/dataset/{dataset_id}/period")
def api_period(dataset_id: str, mode: str = Query(...), day: str = Query(default=""),
               h: int = Query(default=0), m: int = Query(default=0), s: int = Query(default=0),
               day2: str = Query(default=""), h2: int = Query(default=23), m2: int = Query(default=59),
               s2: int = Query(default=59), win: int = Query(default=30), gf: str = Query(default="")):
    """Calculeaza intervalul [ts_from, ts_to] pentru o selectie facuta din
    dropdown-uri (o singura implementare, folosita de selectorul global, de
    selectorul de zi si de testele automate) + cate cereri contine, cu
    celelalte filtre globale active."""
    ds = _get_dataset(dataset_id)
    if not ds:
        return JSONResponse({"error": "Dataset expirat sau inexistent."}, status_code=404)
    if not ds.get("triage_ready"):
        return JSONResponse({"error": "Indexarea e inca in curs.", "indexing": True}, status_code=202)
    store = _col_store(ds)
    seg = _tz_segments(ds)
    try:
        p = compute_period(seg, mode, day or None, h, m, s, day2 or None, h2, m2, s2, win,
                           bounds=_time_bounds(ds, store))
    except ValueError as e:
        return JSONResponse({"error": f"Perioada invalida: {e}"}, status_code=400)
    f, err = _gf_checked(gf_raw=gf) if gf else (_gf_from_params(None, None, [], [], [], [], "", "", "", "", ""), None)
    if err:
        return err
    f = dict(f); f["ts_from"], f["ts_to"] = p["ts_from"], p["ts_to"]; f["ts_str_day"] = None
    try:
        n = store.count(f) if store is not None else None
    except Exception:
        n = None
    p.update({"requests": n, "from_wall": epoch_to_wall(seg, p["ts_from"]), "to_wall": epoch_to_wall(seg, p["ts_to"]),
              "inclusive": True})
    return JSONResponse(p)




# ==========================================================================
# v49.1 -- ATACURI PE FILTRE (enumerare de filtre de magazin: WooCommerce
# filter_*, PrestaShop/Magento layered-nav, ?filtru=, orderby, min/max_price,
# add_to_wishlist, fatete codate in path cu '&' / '*').
# Calculat EXACT din indexul columnar (nu din esantioane), pe selectia globala
# curenta. Regulile de detectie sunt explicite (FA_RULES) si apar in raspuns.
# ==========================================================================
_FA_KEY_EXACT = {"filtru", "filtre", "filter", "add_to_wishlist", "orderby", "min_price", "max_price",
                 "rating_filter", "query_type", "layered"}
_FA_KEY_PREFIX = ("filter_", "pa_", "filtru_", "attribute_")
FA_RULES = {
    "distribuit": "un URL tinta cu >= 200 cereri cu parametri de filtrare din >= 30 IP-uri, cu raport IP/cereri >= 0.3 (multe IP-uri, putine cereri fiecare -- rotatie de proxy)",
    "concentrat": "un singur IP cu >= 300 cereri cu parametri de filtrare",
    "impact": "HIGH daca >= 2000 cereri de filtrare SAU >= 10% dintre ele primesc 5xx (serverul cedeaza); altfel MEDIUM",
}


# v50: PrestaShop 1.7+ (ps_facetedsearch) -- filtrele vin in ?q= ca
# "Fateta-valoare-valoare/Fateta2-valoare" (ex. q=Categorii-BATERII/Marca-Tenax),
# sortarea in ?order=product.<camp>.<asc|desc>; 1.6 (blocklayered) foloseste
# selected_filters. q= simplu (cautare: ?q=cuvant) NU e filtru.
_FA_PS_FACET_RE = re.compile(r"^(?!https?%3a|https?:)[^-/=&]{2,60}-[^&]+$", re.I)


def _fa_keys(url):
    """-> (lista cheilor de filtrare, e_fateta_in_path)"""
    q = url.split("?", 1)
    po = q[0]
    keys = []
    if len(q) > 1:
        for tok in q[1].split("&"):
            k, _, v = tok.partition("=")
            k = k.lower().replace("%5b", "[").split("[", 1)[0]
            if k in _FA_KEY_EXACT or k.startswith(_FA_KEY_PREFIX) or k == "selected_filters":
                pass
            elif k == "q" and _FA_PS_FACET_RE.match(v):
                k = "q="                 # fragment din URL: folosit si ca filtru "path contine" in UI
            elif k == "order" and v.lower().startswith("product."):
                k = "order=product."
            else:
                continue
            if k not in keys:
                keys.append(k)
    facet = ("&" in po or "*" in po) and not po.lower().endswith((".js", ".css", ".png", ".jpg", ".svg", ".woff2"))
    return keys, facet


def _fa_vocab(store):
    """Per cod de URL: e cerere de filtrare? + URL-ul tinta (fara query) + cheile. Cache pe store."""
    c = getattr(store, "_fa_vocab", None)
    if c is not None and c[0] == len(store.v_fp):
        return c[1]
    n = len(store.v_fp)
    flag = np.zeros(n, bool)
    target = np.full(n, -1, np.int32)
    keys_of = {}
    tgt_names, tgt_idx = [], {}
    for i, url in enumerate(store.v_fp):
        k, facet = _fa_keys(url)
        if not k and not facet:
            continue
        flag[i] = True
        po = url.split("?", 1)[0]
        if facet:
            sl = po.find("/", 1)
            po = (po[:sl] if sl > 0 else po) + "/*fatete*"
            k = k + ["(fatete in path)"]
        t = tgt_idx.get(po)
        if t is None:
            t = tgt_idx[po] = len(tgt_names)
            tgt_names.append(po)
        target[i] = t
        keys_of[i] = k
    v = {"flag": flag, "target": target, "targets": tgt_names, "keys": keys_of}
    store._fa_vocab = (n, v)
    return v


def _filter_attack_compute(ds, store, m, top=50):
    V = _fa_vocab(store)
    sel = np.arange(store.n) if m is None else np.flatnonzero(m)
    total_sel = int(sel.size)
    rows = sel[V["flag"][store.fp[sel]]] if sel.size else sel
    out = {"rules": FA_RULES, "selection_requests": total_sel, "filter_requests": int(rows.size)}
    if not rows.size:
        out.update({"detected": False, "unique_ips": 0, "targets": [], "ips": [], "verdict": "Nicio cerere cu parametri de filtrare in selectie."})
        return out
    tz = _log_tz_offset(ds) or 0
    ips = store.ip[rows]
    st = store.st[rows]
    tg = V["target"][store.fp[rows]]
    uniq_ips, ip_cnt = np.unique(ips, return_counts=True)
    s5 = int(np.count_nonzero(st >= 500)); s4 = int(np.count_nonzero((st >= 400) & (st < 500)))
    s3 = int(np.count_nonzero((st >= 300) & (st < 400))); s2 = int(np.count_nonzero((st >= 200) & (st < 300)))
    targets = []
    for t in np.unique(tg).tolist():
        mt = tg == t
        r = rows[mt]
        u = np.unique(store.ip[r])
        kc = Counter()
        for f in np.unique(store.fp[r]).tolist():
            for k in V["keys"].get(f, []):
                kc[k] += 1
        stt = store.st[r]
        cc = Counter(store.v_cc[c] if c >= 0 else "" for c in store.cc[r].tolist())
        targets.append({"target": V["targets"][t], "requests": int(r.size), "unique_ips": int(u.size),
                        "ratio": round(u.size / r.size, 2), "distinct_urls": int(np.unique(store.fp[r]).size),
                        "params": [k for k, _ in kc.most_common(6)],
                        "status": {"2xx": int(np.count_nonzero((stt >= 200) & (stt < 300))), "3xx": int(np.count_nonzero((stt >= 300) & (stt < 400))),
                                   "4xx": int(np.count_nonzero((stt >= 400) & (stt < 500))), "5xx": int(np.count_nonzero(stt >= 500))},
                        "countries": len(cc), "top_countries": [{"cc": k or "??", "n": v} for k, v in cc.most_common(5)],
                        "first_ts": int(store.ts[r].min()), "last_ts": int(store.ts[r].max())})
    targets.sort(key=lambda x: -x["requests"])
    dist = [t for t in targets if t["requests"] >= 200 and t["unique_ips"] >= 30 and t["ratio"] >= 0.3]
    order = np.argsort(-ip_cnt)
    conc = [int(i) for i in order if ip_cnt[i] >= 300]
    ip_list = []
    for i in order[:max(1, top)].tolist():
        ipc = int(uniq_ips[i])
        r = rows[ips == ipc]
        c = store.ip_cc[ipc] if hasattr(store, "ip_cc") else -1
        stt = store.st[r]
        ip_list.append({"ip": store.v_ip[ipc], "country": store.v_cc[c] if c >= 0 else "", "requests": int(r.size),
                        "targets": int(np.unique(V["target"][store.fp[r]]).size),
                        "5xx": int(np.count_nonzero(stt >= 500)), "4xx": int(np.count_nonzero((stt >= 400) & (stt < 500))),
                        "first_ts": int(store.ts[r].min()), "last_ts": int(store.ts[r].max()),
                        "ua": store.v_ua[int(np.bincount(store.ua[r]).argmax())] if r.size else ""})
    # varf pe minut
    mins = (store.ts[rows] // 60).astype(np.int64)
    um, mc = np.unique(mins, return_counts=True)
    pk = int(np.argmax(mc))
    detected = bool(dist or conc)
    sev = "HIGH" if (rows.size >= 2000 or (s5 and s5 / rows.size >= 0.1)) else "MEDIUM"
    kinds = []
    if dist:
        kinds.append(f"distribuit pe {len(dist)} URL-uri tinta")
    if conc:
        kinds.append(f"concentrat: {len(conc)} IP-uri cu >= 300 cereri")
    out.update({
        "detected": detected, "severity": sev if detected else None, "kinds": kinds,
        "unique_ips": int(uniq_ips.size), "share": round(rows.size / total_sel, 4) if total_sel else 0,
        "status": {"2xx": s2, "3xx": s3, "4xx": s4, "5xx": s5},
        "first_ts": int(store.ts[rows].min()), "last_ts": int(store.ts[rows].max()),
        "peak_minute": {"ts": int(um[pk]) * 60, "requests": int(mc[pk])},
        "ips_with_1_request": int(np.count_nonzero(ip_cnt == 1)),
        "targets": targets[:200], "targets_total": len(targets),
        "distributed_targets": [t["target"] for t in dist], "ips": ip_list, "ips_total": int(uniq_ips.size),
        "top_param": (targets[0]["params"][0] if targets and targets[0]["params"] else None),
        "verdict": (f"ATAC PE FILTRE detectat ({'; '.join(kinds)}): {int(rows.size)} cereri de filtrare din "
                    f"{int(uniq_ips.size)} IP-uri unice ({round(100 * rows.size / total_sel, 1) if total_sel else 0}% din selectie)"
                    if detected else
                    f"Nu e atac pe filtre dupa reguli: {int(rows.size)} cereri cu parametri de filtrare din {int(uniq_ips.size)} IP-uri (sub praguri)."),
    })
    return out


@app.get("/api/dataset/{dataset_id}/filter_attacks")
def api_filter_attacks(dataset_id: str, gf: str = Query(default=""), top: int = Query(default=50)):
    ds, store, m, err = _incident_ctx(dataset_id, gf)
    if err:
        return err
    return JSONResponse(_filter_attack_compute(ds, store, m, max(1, min(int(top), 5000))))


# ==========================================================================
# v50 -- RETELE: IP-urile (de obicei cele cu foarte putine cereri -- rotatie de
# proxy / botnet) grupate pe furnizor (ASN), bloc de retea, /24 sau /16.
# Baza ASN (geoip2fast-asn-ipv6.dat.gz, GeoLite2 ASN, IPv4 + IPv6) se incarca
# DOAR la prima cerere a acestei rute (~0.8 s, ~190 MB) -- uploadul si
# parsarea nu o folosesc.
# ==========================================================================
_ASN_FILE = os.path.join(_GEOIP_DIR, "geoip2fast-asn-ipv6.dat.gz")
_asn_db = None
_asn_tried = False
_ASN_LOCK = threading.Lock()
_ASN_MEMO: Dict[str, Any] = {}   # ip -> (asn_name, asn_cidr)
_ASN_MEMO_CAP = 600_000


def _asn_lookup(ip):
    global _asn_db, _asn_tried
    if not _asn_tried:
        with _ASN_LOCK:
            if not _asn_tried:
                if _geoip is not None and os.path.exists(_ASN_FILE):
                    try:
                        _asn_db = _geoip_isolated("asn")(geoip2fast_data_file=_ASN_FILE, verbose=False)
                    except (Exception, SystemExit) as e:
                        print(f"[asn] baza ASN indisponibila: {e}", flush=True)
                        _asn_db = None
                _asn_tried = True
    hit = _ASN_MEMO.get(ip)
    if hit is not None:
        return hit
    name, cidr = "", ""
    if _asn_db is not None and ip:
        try:
            r = _asn_db.lookup(ip)
            name = (getattr(r, "asn_name", "") or "").strip()
            cidr = getattr(r, "asn_cidr", "") or getattr(r, "cidr", "") or ""
        except Exception:
            pass
    out = (name, cidr)
    if len(_ASN_MEMO) < _ASN_MEMO_CAP:
        _ASN_MEMO[ip] = out
    return out


def _net_prefix(ip, bits4, bits6):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    n = ipaddress.ip_network(f"{ip}/{bits4 if a.version == 4 else bits6}", strict=False)
    return str(n)


# furnizori de cloud / gazduire (dupa numele ASN) -- restul sunt, in mare,
# operatori de acces (internet fix / mobil): IP-uri "rezidentiale"
_CLOUD_ASN_RE = re.compile(
    r"amazon|\baws\b|google|microsoft|azure|oracle|alibaba|tencent|huawei cloud|digitalocean|linode|akamai|ovh|hetzner|"
    r"contabo|vultr|choopa|leaseweb|m247|scaleway|online s\.a\.s|ionos|1&1|hostinger|godaddy|cloudflare|fastly|"
    r"datacamp|cdn77|psychz|quadranet|colocrossing|hostwinds|interserver|liquid web|rackspace|servers\.com|"
    r"zenlayer|g-core|gcore|kamatera|netcup|hosteurope|strato|aruba|ukfast|worldstream|serverius|nforce|"
    r"hivelocity|limestone|sharktech|frantech|buyvm|ponynet|packet|equinix|cogent|hurricane electric|"
    r"data ?cent|hosting|\bservers?\b|cloud|\bvps\b|colocation", re.I)


def _asn_kind(name):
    if not name:
        return ""
    return "cloud" if _CLOUD_ASN_RE.search(name) else "isp"


NET_GROUPS = {"asn": "furnizor (ASN)", "block": "bloc de retea (ASN)", "s24": "subnet /24 (IPv6 /48)", "s16": "retea /16 (IPv6 /32)"}


def _net_verdict(o):
    """Concluzie scurta, cu cifrele pe care se bazeaza."""
    n, sel = o.get("matched_ips", 0), o.get("selection_ips", 0)
    if not n:
        return ""
    single = o.get("single_hit_ips", 0)
    parts = []
    if o.get("max_hits") == 1 and sel and single / sel >= 0.5 and n >= 500:
        parts.append(f"{single:,} din {sel:,} IP-uri ({100 * single // sel}%) au facut o singura cerere".replace(",", "."))
    cloud = o.get("cloud_ips")
    if cloud is not None:
        pc = round(100 * cloud / n)
        parts.append(f"{100 - pc}% vin de la operatori de internet (rezidential / mobil), {pc}% din cloud / gazduire")
    if o["group"] in ("asn", "block") and o.get("n_groups", 0) >= 50 and o.get("top10_ips_pct", 100) < 30:
        parts.append(f"sunt imprastiate pe {o['n_groups']:,} retele".replace(",", ".")
                     + f", primele 10 acopera doar {str(o['top10_ips_pct']).replace('.', ',')}%"
                     + " -- tipic unei retele de proxy-uri rezidentiale / botnet: blocarea pe IP sau subnet nu ajuta, "
                       "blocheaza dupa tiparul cererii (WAF / challenge pe URL-ul tinta, rate limiting)")
    elif cloud is not None and n >= 50 and cloud / n >= 0.6:
        parts.append("majoritatea din cloud: se pot bloca sau limita furnizorii de mai jos (ASN)")
    return "; ".join(parts) + "." if parts else ""


@app.get("/api/dataset/{dataset_id}/networks")
def api_networks(dataset_id: str, gf: str = Query(default=""), group: str = Query(default="asn"),
                 max_hits: int = Query(default=1), top: int = Query(default=100)):
    """IP-urile selectiei cu <= max_hits cereri (0 = toate), grupate pe retea.
    Per grup: IP-uri unice, cereri, tari, URL-ul dominant, interval, CIDR-uri."""
    if group not in NET_GROUPS:
        return JSONResponse({"error": "grupare necunoscuta"}, status_code=400)
    ds, store, m, err = _incident_ctx(dataset_id, gf)
    if err:
        return err
    t = time.time()
    sel = np.arange(store.n) if m is None else np.flatnonzero(m)
    nip = len(store.v_ip)
    per_ip = np.bincount(store.ip[sel], minlength=nip) if sel.size else np.zeros(nip, np.int64)
    seen = np.flatnonzero(per_ip)
    max_hits = max(0, int(max_hits))
    want = seen if max_hits == 0 else seen[per_ip[seen] <= max_hits]
    out: Dict[str, Any] = {"group": group, "group_label": NET_GROUPS[group], "max_hits": max_hits,
           "selection_requests": int(sel.size), "selection_ips": int(seen.size),
           "single_hit_ips": int(np.count_nonzero(per_ip[seen] == 1)),
           "matched_ips": int(want.size), "matched_requests": int(per_ip[want].sum()) if want.size else 0,
           "asn_available": None, "groups": []}
    if not want.size:
        out["elapsed_ms"] = int((time.time() - t) * 1000)
        return JSONResponse(out)
    # cheia de grup pentru fiecare IP ales (calculata o data pe IP unic)
    gkey: Dict[str, int] = {}
    gidx = np.full(nip, -1, np.int64)
    names: List[str] = []
    cidrs_of: List[Set[str]] = []
    for code in want.tolist():
        ip = store.v_ip[code]
        if group in ("asn", "block"):
            name, cidr = _asn_lookup(ip)
            k = (name or "(furnizor necunoscut)") if group == "asn" else (cidr or "(bloc necunoscut)")
            c = cidr
        elif group == "s24":
            k = c = _net_prefix(ip, 24, 48)
        else:
            k = c = _net_prefix(ip, 16, 32)
        k = k or "(nedeterminat)"
        g = gkey.get(k)
        if g is None:
            g = gkey[k] = len(names)
            names.append(k)
            cidrs_of.append(set())
        if c and len(cidrs_of[g]) < 200:
            cidrs_of[g].add(c)
        gidx[code] = g
    out["asn_available"] = _asn_db is not None
    ng = len(names)
    g_ips = np.bincount(gidx[want], minlength=ng)
    g_req = np.bincount(gidx[want], weights=per_ip[want], minlength=ng).astype(np.int64)
    rows = sel[gidx[store.ip[sel]] >= 0]
    rg = gidx[store.ip[rows]]
    order = np.argsort(-g_ips, kind="stable")[:max(1, min(int(top), 1000))]
    # URL dominant per grup + interval + 5xx
    npo = len(store.v_po) + 1
    key, cnt = np.unique(rg * npo + store.po[rows], return_counts=True)
    kg = key // npo
    best: Dict[int, Any] = {}
    for g_, k_, c_ in zip(kg.tolist(), (key % npo).tolist(), cnt.tolist()):
        if c_ > best.get(g_, (0, 0))[0]:
            best[g_] = (c_, k_)
    tmin = np.full(ng, np.iinfo(np.int64).max, np.int64); np.minimum.at(tmin, rg, store.ts[rows])
    tmax = np.full(ng, np.iinfo(np.int64).min, np.int64); np.maximum.at(tmax, rg, store.ts[rows])
    e5 = np.bincount(rg, weights=(store.st[rows] >= 500), minlength=ng).astype(np.int64)
    ip_cc = getattr(store, "ip_cc", None)
    for g in order.tolist():
        members = want[gidx[want] == g]
        cc: Counter[str] = Counter()
        if ip_cc is not None:
            for c in ip_cc[members].tolist():
                cc[(store.v_cc[c] if c >= 0 else "") or "??"] += 1
        bc, bp = best.get(g, (0, 0))
        kind = _asn_kind(names[g]) if group == "asn" else ""
        out["groups"].append({
            "key": names[g], "kind": kind, "ips": int(g_ips[g]), "requests": int(g_req[g]),
            "countries": [{"cc": k, "ips": v} for k, v in cc.most_common(4)], "n_countries": len(cc),
            "top_path": store.v_po[bp] if bc else "", "top_path_requests": int(bc),
            "ts_min": int(tmin[g]), "ts_max": int(tmax[g]), "e5": int(e5[g]),
            "cidrs": sorted(cidrs_of[g])[:200], "sample_ips": [store.v_ip[c] for c in members[:5].tolist()],
        })
    out["n_groups"] = ng
    top10 = np.sort(g_ips)[::-1][:10]
    out["top10_ips_pct"] = round(100.0 * float(top10.sum()) / max(1, int(want.size)), 1)
    # cloud vs rezidential pe TOATE IP-urile alese (nu doar pe grupurile afisate)
    if _asn_db is not None or group in ("asn", "block"):
        n_cloud = sum(1 for code in want.tolist() if _asn_kind(_asn_lookup(store.v_ip[code])[0]) == "cloud")
        out["cloud_ips"] = n_cloud
        out["isp_ips"] = int(want.size) - n_cloud
    out["verdict"] = _net_verdict(out)
    out["elapsed_ms"] = int((time.time() - t) * 1000)
    return JSONResponse(out)


@app.get("/api/dataset/{dataset_id}/filter_attacks/requests")
def api_filter_attack_requests(dataset_id: str, gf: str = Query(default=""), target: str = Query(default=""),
                               ip: str = Query(default=""), param: str = Query(default=""),
                               status_class: str = Query(default=""), mode: str = Query(default="unique"),
                               min_requests: int = Query(default=1), sort: str = Query(default="requests"),
                               limit: int = Query(default=200), offset: int = Query(default=0)):
    """Lista atacului, cu filtre: mode=unique -> un rand per IP (IP-uri UNICE,
    cu numarul de cereri); mode=all -> fiecare cerere (toate aparitiile)."""
    ds, store, m, err = _incident_ctx(dataset_id, gf)
    if err:
        return err
    V = _fa_vocab(store)
    sel = np.arange(store.n) if m is None else np.flatnonzero(m)
    rows = sel[V["flag"][store.fp[sel]]] if sel.size else sel
    if target:
        t = V["targets"].index(target) if target in V["targets"] else -2
        rows = rows[V["target"][store.fp[rows]] == t]
    if param:
        okf = np.array([param in V["keys"].get(int(f), []) for f in range(len(store.v_fp))], bool) if rows.size else None
        rows = rows[okf[store.fp[rows]]] if okf is not None else rows
    if ip:
        c = store.d_ip.get(ip, -1)
        rows = rows[store.ip[rows] == c]
    if status_class in ("2xx", "3xx", "4xx", "5xx"):
        lo = int(status_class[0]) * 100
        s = store.st[rows]
        rows = rows[(s >= lo) & (s < lo + 100)]
    limit = max(1, min(int(limit), 5000)); offset = max(0, int(offset))
    if mode == "all":
        o = np.argsort(store.ts[rows], kind="stable")
        if sort == "ts_desc":
            o = o[::-1]
        page = rows[o][offset:offset + limit]
        items = [{"ts": int(store.ts[r]), "ip": store.v_ip[store.ip[r]], "method": store.v_me[store.me[r]],
                  "url": store.v_fp[store.fp[r]], "status": int(store.st[r]),
                  "country": store.v_cc[store.cc[r]] if store.cc[r] >= 0 else ""} for r in page.tolist()]
        return JSONResponse({"mode": "all", "total": int(rows.size), "unique_ips": int(np.unique(store.ip[rows]).size),
                             "items": items, "offset": offset, "limit": limit})
    u, cnt = np.unique(store.ip[rows], return_counts=True)
    keep = cnt >= max(1, int(min_requests))
    u, cnt = u[keep], cnt[keep]
    o = np.argsort(-cnt, kind="stable") if sort != "ip" else np.argsort([store.v_ip[x] for x in u.tolist()])
    page = o[offset:offset + limit]
    items = []
    for i in page.tolist():
        ipc = int(u[i]); r = rows[store.ip[rows] == ipc]; s = store.st[r]
        c = store.ip_cc[ipc] if hasattr(store, "ip_cc") else -1
        items.append({"ip": store.v_ip[ipc], "country": store.v_cc[c] if c >= 0 else "", "requests": int(cnt[i]),
                      "first_ts": int(store.ts[r].min()), "last_ts": int(store.ts[r].max()),
                      "5xx": int(np.count_nonzero(s >= 500)), "4xx": int(np.count_nonzero((s >= 400) & (s < 500))),
                      "distinct_urls": int(np.unique(store.fp[r]).size)})
    return JSONResponse({"mode": "unique", "total_requests": int(cnt.sum()), "total": int(u.size),
                         "unique_ips": int(u.size), "items": items, "offset": offset, "limit": limit})



# --------------------------------------------------------------------------
# v51 -- REGULI DE BLOCARE gata de copiat (Cloudflare / CSF / .htaccess),
# pentru orice selectie: incident (atac pe filtre), categorie automata,
# interogare Workplace, retea sau un IP. Strategia (IP / subnet / tipar /
# limitare de rata) se alege in blockrules.build() din forma traficului.
# --------------------------------------------------------------------------
def _fa_pattern(store: Any, rows: Any) -> List[Dict[str, Any]]:
    """Tiparul atacului pe filtre: URL-urile tinta principale + parametrii."""
    V = _fa_vocab(store)
    tg, cnt = np.unique(V["target"][store.fp[rows]], return_counts=True)
    tot = max(1, int(cnt.sum()))
    exact: List[str] = []
    prefix: List[str] = []
    for t, c in sorted(zip(tg.tolist(), cnt.tolist()), key=lambda x: -x[1]):
        if t < 0 or c < 0.05 * tot or len(exact) + len(prefix) >= 8:
            continue
        name = V["targets"][t]
        if name.endswith("/*fatete*"):
            prefix.append(name[:-len("/*fatete*")] + "/")
        else:
            exact.append(name)
    params: Counter[str] = Counter()
    for f in np.unique(store.fp[rows]).tolist():
        for k in V["keys"].get(int(f), []):
            if not k.startswith("("):
                params[re.split(r"[=\[]", k, 1)[0]] += 1
    pat: List[Dict[str, Any]] = []
    if exact:
        pat.append({"field": "path_only", "op": "exact", "values": exact})
    elif prefix:
        pat.append({"field": "path_only", "op": "prefix", "values": prefix})
    names = [k for k, _ in params.most_common(6) if k]
    if names:
        pat.append({"field": "query", "op": "param", "values": names})
    return pat


@app.post("/api/dataset/{dataset_id}/block_rules")
def api_block_rules(dataset_id: str, body: dict = Body(...)):
    """body: gf (selectia globala) + una dintre: kind="filter_attack", q
    (interogare Workplace), conds (conditii Workplace aplicate peste gf),
    ip. pattern = conditii explicite pentru regula pe tipar (optional)."""
    ds, store, m, err = _incident_ctx(dataset_id, str(body.get("gf") or ""))
    if err:
        return err
    t = time.time()
    label = str(body.get("label") or "selectie")[:120]
    kind = str(body.get("kind") or "")
    q = body.get("q") if isinstance(body.get("q"), dict) else None
    conds = list(body.get("conds") or [])
    if body.get("ip"):
        conds = [{"field": "ip", "op": "in", "values": [str(body["ip"])]}]
    pattern = body.get("pattern") or None
    sel = np.arange(store.n) if m is None else np.flatnonzero(m)
    try:
        if q is not None or conds:
            _, wp, werr = _workplace_for(dataset_id)
            if werr:
                return werr
            qq = q if q is not None else {"conds": conds}
            wm, _, _ = wp.build(qq, _workplace_ctx(dataset_id))
            if q is not None:
                sel = np.arange(store.n) if wm is None else np.flatnonzero(wm)   # Workplace are propria perioada
                conds = list(q.get("conds") or [])
            elif wm is not None:
                sel = sel[wm[sel]]
    except (workplace.QueryError, TypeError, ValueError) as e:
        return JSONResponse({"error": f"Filtru invalid: {e}"}, status_code=400)
    if kind == "filter_attack":
        V = _fa_vocab(store)
        sel = sel[V["flag"][store.fp[sel]]] if sel.size else sel
        if not pattern and sel.size:
            pattern = _fa_pattern(store, sel)
    nip = len(store.v_ip)
    per_ip = np.bincount(store.ip[sel], minlength=nip) if sel.size else np.zeros(nip, np.int64)
    seen = np.flatnonzero(per_ip)
    seen = seen[np.argsort(-per_ip[seen], kind="stable")]
    ips = [(store.v_ip[c], int(per_ip[c])) for c in seen.tolist()]
    info: Dict[str, Any] = {"requests": int(sel.size), "ips": ips}
    if len(ips) > blockrules.IP_MAX:
        sub: Dict[str, List[int]] = {}
        for ip, n in ips:
            k = _net_prefix(ip, 24, 48)
            if k:
                a = sub.setdefault(k, [0, 0]); a[0] += 1; a[1] += n
        info["subnets"] = sorted(((k, v[0], v[1]) for k, v in sub.items()), key=lambda x: -x[2])
    asn_cidrs = None
    want_asn = any((c or {}).get("field") == "asn" for c in (pattern or conds))
    if want_asn or len(ips) <= 30000:
        cl, cidrs = 0, set()
        for ip, _ in ips[:30000]:
            name, cidr = _asn_lookup(ip)
            cl += _asn_kind(name) == "cloud"
            if want_asn and cidr:
                cidrs.add(cidr)
        info["cloud_ips"] = cl
        asn_cidrs = sorted(cidrs) if want_asn else None
    out = blockrules.build(label, info, conds, pattern=pattern, asn_cidrs=asn_cidrs)
    out["top_ips"] = [{"ip": ip, "n": n} for ip, n in ips[:10]]
    out["pattern"] = pattern or [c for c in conds if not c.get("off")]
    out["elapsed_ms"] = int((time.time() - t) * 1000)
    return JSONResponse(out)


@app.get("/api/dataset/{dataset_id}/ip_identity")
def api_ip_identity(dataset_id: str, ip: str = Query(...), gf: str = Query(default="")):
    """v51: identitatea unui IP pentru panoul lateral -- furnizor, bloc, tip
    (cloud / rezidential), crawler verificat, vecinii din aceeasi retea /24 si
    de la acelasi furnizor, in selectie."""
    ds, store, m, err = _incident_ctx(dataset_id, gf)
    if err:
        return err
    _, wp, werr = _workplace_for(dataset_id)
    if werr:
        return werr
    name, cidr = _asn_lookup(ip)
    out: Dict[str, Any] = {"ip": ip, "asn": name, "cidr": cidr, "kind": _asn_kind(name),
                           "subnet": _net_prefix(ip, 24, 64)}
    out["crawler"] = ("verified" if ip in _verified_crawler_ips(dataset_id)
                      else "fake" if ip in _fake_crawler_ips(dataset_id) else "")
    code = store.d_ip.get(ip)
    if code is None:
        return JSONResponse(out)
    sel = np.arange(store.n) if m is None else np.flatnonzero(m)
    per_ip = np.bincount(store.ip[sel], minlength=len(store.v_ip)) if sel.size else np.zeros(len(store.v_ip), np.int64)
    seen = per_ip > 0
    sc, _ = wp.subnet_codes()
    same = seen & (sc == sc[code])
    out["subnet_ips"], out["subnet_requests"] = int(np.count_nonzero(same)), int(per_ip[same].sum())
    if name:
        names = wp.asn_names()
        same_a = seen & np.fromiter((x == name for x in names), dtype=bool, count=len(names))
        out["asn_ips"], out["asn_requests"] = int(np.count_nonzero(same_a)), int(per_ip[same_a].sum())
    return JSONResponse(out)


@app.get("/api/dataset/{dataset_id}/reopen")
def api_reopen(dataset_id: str):
    """v51: datele de la upload, pentru un link copiat (?d=<id>) -- fara
    reincarcare, cat timp analiza e inca in memorie."""
    ds = _get_dataset(dataset_id)
    if not ds:
        return JSONResponse({"error": "Analiza nu mai e in memorie (aplicatia a fost repornita sau a expirat)."},
                            status_code=404)
    summary = (ds.get("summary_cache") or {}).get("ALL")
    if summary is None:
        return JSONResponse({"error": "Sumarul nu e disponibil."}, status_code=404)
    return JSONResponse({"dataset_id": dataset_id, "filename": ds.get("filename"),
                         "source_files": ds.get("source_files"), "days": ds.get("days_available"),
                         "summary": _summary_without_fp(dataset_id, summary)})


DIFF_DIMS = {"ip": "IP-uri", "country": "Tari", "path": "URL-uri", "asn": "Furnizori"}


@app.get("/api/dataset/{dataset_id}/diff")
def api_diff(dataset_id: str, a_from: int = Query(...), a_to: int = Query(...),
             b_from: int = Query(...), b_to: int = Query(...), gf: str = Query(default=""),
             top: int = Query(default=12)):
    """v51: comparatie intre doua perioade A (referinta) si B, pe aceleasi
    filtre de continut: ce e NOU in B, ce a CRESCUT (rata pe ora, ca perioadele
    pot avea lungimi diferite) si ce a DISPARUT."""
    ds, store, _m, err = _incident_ctx(dataset_id, "")
    if err:
        return err
    f, err = _gf_checked(gf_raw=gf)
    if err:
        return err
    f = {k: v for k, v in (f or {}).items() if k not in ("ts_from", "ts_to")}
    t = time.time()
    base = store.mask(f) if f else None
    ts = store.ts
    ma = (ts >= a_from) & (ts <= a_to)
    mb = (ts >= b_from) & (ts <= b_to)
    if base is not None:
        ma &= base
        mb &= base
    da, db = max(1, a_to - a_from + 1), max(1, b_to - b_from + 1)
    top = max(3, min(int(top), 50))

    def totals(m, dur):
        n = int(np.count_nonzero(m))
        st = store.st[m]
        return {"requests": n, "per_min": round(n * 60.0 / dur, 2), "duration_sec": int(dur),
                "unique_ips": int(np.unique(store.ip[m]).size) if n else 0,
                "pct_4xx": round(100.0 * np.count_nonzero((st >= 400) & (st < 500)) / n, 1) if n else 0.0,
                "pct_5xx": round(100.0 * np.count_nonzero(st >= 500) / n, 1) if n else 0.0}

    out: Dict[str, Any] = {"a": totals(ma, da), "b": totals(mb, db), "dims": {}}
    ia, ib = store.ip[ma], store.ip[mb]
    if ib.size:
        seen_a = np.zeros(len(store.v_ip), bool)
        seen_a[ia] = True
        new_rows = ~seen_a[ib]
        out["b"]["new_ip_requests"] = int(np.count_nonzero(new_rows))
        out["b"]["new_ips"] = int(np.unique(ib[new_rows]).size)
    scale = db / da          # cat ar fi facut A in durata lui B
    dims: Dict[str, Tuple[Any, List[str]]] = {"ip": (store.ip, store.v_ip), "country": (store.cc, store.v_cc),
                                              "path": (store.po, store.v_po)}
    _, wp, werr = _workplace_for(dataset_id)
    if werr is None and os.path.exists(_ASN_FILE):
        try:
            names = wp.asn_names()
            d_asn: Dict[str, int] = {}
            ip_asn = np.fromiter((d_asn.setdefault(x or "(necunoscut)", len(d_asn)) for x in names), dtype=np.int32, count=len(names))
            dims["asn"] = (ip_asn[store.ip], list(d_asn))
        except Exception:
            pass
    for key, (col, labels) in dims.items():
        K = len(labels)
        ca = np.bincount(col[ma], minlength=K).astype(np.float64)
        cb = np.bincount(col[mb], minlength=K).astype(np.float64)
        exp_b = ca * scale
        lab = lambda i: labels[i] if labels[i] != "" else ("??" if key == "country" else "(gol)")
        row = lambda i: {"key": lab(i), "a": int(ca[i]), "b": int(cb[i]), "a_scaled": round(float(exp_b[i]), 1)}
        min_n = max(3.0, 0.001 * float(cb.sum()))
        nw = np.flatnonzero((ca == 0) & (cb >= min_n))
        nw = nw[np.argsort(-cb[nw], kind="stable")]
        grow = np.flatnonzero((ca > 0) & (cb >= 2 * exp_b) & (cb - exp_b >= min_n))
        grow = grow[np.argsort(-(cb[grow] - exp_b[grow]), kind="stable")]
        gone = np.flatnonzero((cb == 0) & (exp_b >= min_n))
        gone = gone[np.argsort(-ca[gone], kind="stable")]
        drop = np.flatnonzero((cb > 0) & (cb * 2 <= exp_b) & (exp_b - cb >= min_n))
        drop = drop[np.argsort(-(exp_b[drop] - cb[drop]), kind="stable")]
        out["dims"][key] = {"label": DIFF_DIMS[key],
                            "new": [row(i) for i in nw[:top].tolist()], "n_new": int(nw.size),
                            "new_requests": int(cb[nw].sum()),
                            "grew": [row(i) for i in grow[:top].tolist()], "n_grew": int(grow.size),
                            "gone": [row(i) for i in gone[:top].tolist()], "n_gone": int(gone.size),
                            "dropped": [row(i) for i in drop[:top].tolist()], "n_dropped": int(drop.size)}
    out["elapsed_ms"] = int((time.time() - t) * 1000)
    return JSONResponse(out)

if __name__ == "__main__":
    main()


