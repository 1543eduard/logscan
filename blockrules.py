"""v51 -- reguli de blocare gata de copiat (Cloudflare WAF, CSF, .htaccess)
pentru o selectie: un incident, o categorie automata, o interogare Workplace
sau un IP.

Strategia se alege din forma traficului, nu din preferinte:
  * putine IP-uri (<= IP_MAX)            -> blocare pe IP
  * multe IP-uri, concentrate in putine /24 -> blocare pe subnet
  * multe IP-uri imprastiate (rotatie de proxy) -> regula pe TIPARUL cererii
    (URL / query / User-Agent) -- blocarea pe IP nu ajuta, fiecare IP revine
    o singura data.

Conditiile Workplace sunt traduse camp cu camp; ce nu are echivalent (cod
HTTP, severitate, statistici per IP) e raportat in `unmapped`, nu ignorat
in tacere."""
import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple

IP_MAX = 100            # peste atat, o lista de IP-uri nu mai e o solutie practica
CF_IP_MAX = 250         # expresia Cloudflare are o limita de 4096 caractere
SUBNET_MAX = 25
SUBNET_COVER = 0.8      # subneturile alese trebuie sa acopere >= 80% din cereri

EXT_GROUPS = {
    "php": ("php", "phtml", "php5", "php7"), "js": ("js", "mjs"), "css": ("css",),
    "img": ("png", "jpg", "jpeg", "gif", "webp", "svg", "ico", "avif", "bmp"),
    "font": ("woff", "woff2", "ttf", "otf", "eot"), "html": ("html", "htm"), "xml": ("xml",),
    "json": ("json",), "txt": ("txt",), "arhiva": ("zip", "gz", "tar", "rar", "7z", "sql", "bak", "old", "tgz"),
    "media": ("mp4", "webm", "mp3", "pdf"),
}
FIELD_LABEL = {
    "status": "cod HTTP", "severity": "severitate", "action": "actiune", "wp": "categorie WordPress",
    "size": "marime raspuns", "hour": "ora", "weekday": "zi din saptamana", "ua_cat": "categorie User-Agent",
    "ip_hits": "cereri / IP", "ip_paths": "URL-uri / IP", "ip_rpm": "cereri / minut / IP",
    "ip_err": "% erori / IP", "ip_uas": "User-Agent-uri / IP", "subnet_hits": "cereri / subnet",
    "crawler": "verificare crawler", "country": "tara", "asn": "furnizor",
}


def _cf(s: str) -> str:
    """Literal de sir pentru expresiile Cloudflare (ghilimele duble, escape \\ si ")."""
    return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _cf_set(vals) -> str:
    return "{" + " ".join(_cf(v) for v in vals) + "}"


def _rx(s: str) -> str:
    """Escape pentru regex-urile mod_rewrite (PCRE)."""
    return re.sub(r"([.^$|()\[\]{}*+?\\])", r"\\\1", str(s))


def _n(x: int) -> str:
    return f"{int(x):,}".replace(",", ".")


def _cnt(n: int, one: str, many: str) -> str:
    return f"{_n(n)} {one if n == 1 else many}"


def _meaningful(cf: List[str]) -> bool:
    """Regula pe tipar are sens doar daca prinde altceva decat IP-ul / crawlerul."""
    return any("cf.client.bot" not in x and not x.startswith("ip.src in") for x in cf)


def _vals(c) -> List[str]:
    return [str(v).strip() for v in (c.get("values") or []) if str(v).strip() != ""]


def _or(parts: List[str]) -> str:
    return parts[0] if len(parts) == 1 else "(" + " or ".join(parts) + ")"


def _ip_net(v: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_network(v, strict=False)) if "/" in v else str(ipaddress.ip_address(v))
    except ValueError:
        return None


def translate(conds, asn_cidrs=None) -> Tuple[List[str], List[str], List[str]]:
    """Conditii Workplace -> (parti Cloudflare, linii RewriteCond, nemapate)."""
    cf: List[str] = []
    ht: List[str] = []
    unmapped: List[str] = []
    for c in conds or []:
        if c.get("off"):
            continue
        field, op, neg = c.get("field"), c.get("op") or "in", bool(c.get("not"))
        vals = _vals(c)
        e: Optional[str] = None          # expresia Cloudflare
        h: Optional[str] = None          # RewriteCond (fara flag-ul de negatie)
        if field in ("path", "path_only") and vals:
            var = "http.request.uri" if field == "path" else "http.request.uri.path"
            if op == "exact":
                e = f"{var} eq {_cf(vals[0])}" if len(vals) == 1 else f"{var} in {_cf_set(vals)}"
            elif op == "contains":
                e = _or([f"lower({var}) contains {_cf(v.lower())}" for v in vals])
            elif op == "prefix":
                e = _or([f"starts_with(lower({var}), {_cf(v.lower())})" for v in vals])
            elif op == "suffix":
                e = _or([f"ends_with(lower({var}), {_cf(v.lower())})" for v in vals])
            elif op == "regex":
                e = _or([f"{var} matches {_cf('(?i)' + v)}" for v in vals])
            alt = "|".join(v if op == "regex" else _rx(v) for v in vals)
            if field == "path_only":
                pat = {"exact": f"^({alt})$", "prefix": f"^({alt})", "suffix": f"({alt})$"}.get(op, f"({alt})")
                h = f"%{{REQUEST_URI}} {pat} [NC]"
            else:
                # URL complet (cu query): THE_REQUEST = "GET /cale?query HTTP/1.1"
                pat = {"exact": rf"^\S+\s({alt})\s", "prefix": rf"^\S+\s({alt})",
                       "suffix": rf"({alt})\s\S+$"}.get(op, f"({alt})")
                h = f"%{{THE_REQUEST}} {pat} [NC]"
        elif field == "query":
            if op == "has":
                want = not (vals and vals[0].lower() in ("0", "nu", "false", "no"))
                e = 'http.request.uri.query ne ""' if want else 'http.request.uri.query eq ""'
                h = "%{QUERY_STRING} ." if want else "%{QUERY_STRING} ^$"
            elif vals:
                e = _or([f'any(lower(http.request.uri.args.names[*])[*] eq {_cf(v.lower())})' for v in vals])
                h = "%{QUERY_STRING} (^|&)(" + "|".join(_rx(v) for v in vals) + ")(=|&|$) [NC]"
        elif field == "ua":
            if op == "empty":
                e = '(http.user_agent eq "" or http.user_agent eq "-")'
                h = "%{HTTP_USER_AGENT} ^-?$"
            elif vals:
                if op == "exact":
                    e = f"http.user_agent eq {_cf(vals[0])}" if len(vals) == 1 else f"http.user_agent in {_cf_set(vals)}"
                elif op == "regex":
                    e = _or([f"http.user_agent matches {_cf('(?i)' + v)}" for v in vals])
                elif op == "prefix":
                    e = _or([f"starts_with(lower(http.user_agent), {_cf(v.lower())})" for v in vals])
                else:
                    e = _or([f"lower(http.user_agent) contains {_cf(v.lower())}" for v in vals])
                alt = "|".join(v if op == "regex" else _rx(v) for v in vals)
                pat = {"exact": f"^({alt})$", "prefix": f"^({alt})"}.get(op, f"({alt})")
                h = f"%{{HTTP_USER_AGENT}} {pat} [NC]"
        elif field == "method" and vals:
            ms = [v.upper() for v in vals]
            e = f"http.request.method eq {_cf(ms[0])}" if len(ms) == 1 else f"http.request.method in {_cf_set(ms)}"
            h = "%{REQUEST_METHOD} ^(" + "|".join(ms) + ")$"
        elif field == "ip" and vals:
            if op in ("in", "cidr"):
                nets = [n for n in (_ip_net(v) for v in vals) if n]
                if nets:
                    e = "ip.src in {" + " ".join(nets) + "}"
                    if op == "in":
                        h = "%{REMOTE_ADDR} ^(" + "|".join(_rx(v) for v in nets) + ")$"
            elif op == "prefix":
                h = "%{REMOTE_ADDR} ^(" + "|".join(_rx(v) for v in vals) + ")"
        elif field == "country" and vals:
            cc = [v.upper() for v in vals]
            if cc == ["__NON_RO__"]:
                e = 'ip.src.country ne "RO"'
            elif all(len(x) == 2 and x.isalpha() for x in cc):
                e = f"ip.src.country eq {_cf(cc[0])}" if len(cc) == 1 else f"ip.src.country in {_cf_set(cc)}"
            if e:
                unmapped.append("tara (doar Cloudflare; .htaccess nu stie tara vizitatorului)")
        elif field == "ext" and vals:
            exts = [x for v in vals for x in EXT_GROUPS.get(v, ())]
            if "none" in vals:
                exts.append("")
            if exts:
                e = f"http.request.uri.path.extension in {_cf_set(exts)}"
                ex = [x for x in exts if x]
                if ex:
                    h = r"%{REQUEST_URI} \.(" + "|".join(ex) + ")$ [NC]"
        elif field == "crawler" and vals == ["verified"]:
            e = "cf.client.bot"            # tipic negat: "exceptand crawlerele verificate"
        elif field == "asn" and asn_cidrs:
            e = "ip.src in {" + " ".join(asn_cidrs[:CF_IP_MAX]) + "}"
        if e is None and h is None:
            if field in FIELD_LABEL or field:
                unmapped.append(FIELD_LABEL.get(field, str(field)))
            continue
        if e is not None:
            cf.append(("not " + (e if e.startswith("(") else "(" + e + ")")) if neg else e)
        if h is not None:
            var, _, rest = h.partition(" ")
            ht.append(f"RewriteCond {var} {'!' if neg else ''}{rest}")
    # deduplicare cu ordinea pastrata
    return cf, ht, list(dict.fromkeys(unmapped))


def _csf(items: List[str], label: str) -> str:
    note = re.sub(r"[^\w .:/-]", "", label)[:60] or "logscan"
    lines = [f'csf -td {x} 86400 "logscan: {note}"' for x in items]
    return "\n".join(lines)


def _ht_ips(items: List[str]) -> str:
    rows = [" ".join(items[i:i + 8]) for i in range(0, len(items), 8)]
    return "<RequireAll>\n  Require all granted\n" + "".join(f"  Require not ip {r}\n" for r in rows) + "</RequireAll>"


def build(label: str, sel: Dict[str, Any], conds, pattern=None, asn_cidrs=None) -> Dict[str, Any]:
    """sel: requests, ips [(ip, n)], subnets [(cidr, ips, requests)], cloud_ips,
    verified_bot_requests. Intoarce strategia recomandata + toate variantele."""
    ips: List[Tuple[str, int]] = sel["ips"]
    n_ips, req = len(ips), int(sel["requests"])
    single = sum(1 for _, n in ips if n == 1)
    subnets: List[Tuple[str, int, int]] = sel.get("subnets") or []
    cf, ht, unmapped = translate(pattern if pattern else conds, asn_cidrs)
    # crawlerele verificate nu trebuie blocate niciodata implicit
    if cf and not any("cf.client.bot" in x for x in cf):
        cf.append("not cf.client.bot")
    out: Dict[str, Any] = {"label": label, "requests": req, "ips": n_ips, "single_hit_ips": single,
                           "cloud_ips": int(sel.get("cloud_ips") or 0), "unmapped": unmapped, "options": []}
    if not req:
        out.update(strategy="none", why="Selecția nu are cereri -- nu e nimic de blocat.")
        return out
    sub_cover = 0
    chosen: List[Tuple[str, int, int]] = []
    for s in subnets:
        if len(chosen) >= SUBNET_MAX:
            break
        chosen.append(s)
        sub_cover += s[2]
        if sub_cover >= SUBNET_COVER * req:
            break
    subnet_ok = n_ips > IP_MAX and chosen and sub_cover >= SUBNET_COVER * req
    pattern_ok = _meaningful(cf)
    if n_ips <= IP_MAX:
        strategy = "ip"
        why = (f"{_cnt(n_ips, 'IP face', 'IP-uri fac')} toate cele {_n(req)} cereri -- o listă scurtă, deci blocarea pe IP "
               "e cea mai sigură (nu afectează alți vizitatori). Verifică lista înainte: să nu fie IP-ul tău sau al clientului.")
    elif subnet_ok:
        strategy = "subnet"
        why = (f"{_n(n_ips)} IP-uri, dar {_cnt(len(chosen), 'subrețea /24 acoperă', 'subrețele /24 acoperă')} "
               f"{round(100 * sub_cover / req)}% din cereri -- blochezi rețelele, nu fiecare adresă.")
    elif pattern_ok:
        strategy = "pattern"
        why = (f"{_n(n_ips)} IP-uri, {round(100 * single / max(1, n_ips))}% cu o singură cerere -- rotație de IP-uri. "
               "O listă de IP-uri nu ajută (fiecare adresă nu mai revine); regula trebuie să prindă tiparul cererii.")
    else:
        strategy = "ratelimit"
        why = (f"{_n(n_ips)} IP-uri împrăștiate și niciun tipar de URL / User-Agent care să poată fi tradus într-o regulă. "
               "Soluția practică e limitarea ratei.")
    out.update(strategy=strategy, why=why)
    O = out["options"]

    if pattern_ok:
        residential = n_ips > IP_MAX and out["cloud_ips"] < 0.5 * n_ips
        action = "Managed Challenge" if residential or strategy != "ip" else "Block"
        expr = " and ".join(cf)
        O.append({"key": "cf_pattern", "target": "Cloudflare", "title": f"Cloudflare WAF -- regulă pe tipar ({action})",
                  "recommended": strategy == "pattern",
                  "where": "Security → WAF → Custom rules → Create rule → Edit expression",
                  "text": expr, "action": action,
                  "note": ("Managed Challenge lasă oamenii să treacă (verificare automată, de obicei invizibilă) și oprește "
                           "scripturile. Crawlerele verificate (Google, Bing) sunt exceptate prin «not cf.client.bot».")
                          + (" «matches» (regex) necesită plan Pro sau mai mare." if " matches " in expr else "")})
        O.append({"key": "cf_rate", "target": "Cloudflare", "title": "Cloudflare -- limitare de rată pe același tipar",
                  "recommended": False, "where": "Security → WAF → Rate limiting rules → Create rule",
                  "text": expr, "action": "Block 10 min, peste 20 cereri / 10 s per IP",
                  "note": "Alternativă blândă: vizitatorii normali nu ating pragul, scripturile care insistă de pe același IP da."})
    if strategy in ("ip", "subnet") or n_ips <= CF_IP_MAX:
        items = [c for c, _, _ in chosen] if strategy == "subnet" else [ip for ip, _ in ips[:CF_IP_MAX]]
        what = _cnt(len(items), "subrețea", "subrețele") if strategy == "subnet" else _cnt(len(items), "IP", "IP-uri")
        O.append({"key": "cf_ip", "target": "Cloudflare", "title": f"Cloudflare WAF -- blocare {what}",
                  "recommended": strategy in ("ip", "subnet"),
                  "where": "Security → WAF → Custom rules → Create rule → Edit expression",
                  "text": "ip.src in {" + " ".join(items) + "}", "action": "Block",
                  "note": "Dacă site-ul trece prin Cloudflare, blochează aici: serverul vede adresele Cloudflare, nu pe ale vizitatorilor."})
        O.append({"key": "csf", "target": "CSF", "title": f"CSF (firewall server) -- {what}, 24 de ore",
                  "recommended": False, "where": "SSH pe server, ca root",
                  "text": _csf(items, label), "action": "Blocare temporară 24 h",
                  "note": "Pentru blocare permanentă înlocuiește «-td <adresă> 86400» cu «-d <adresă>». Nu funcționează dacă "
                          "site-ul e în spatele Cloudflare (în log apar atunci IP-urile reale doar dacă mod_remoteip e activ)."})
        O.append({"key": "ht_ip", "target": ".htaccess", "title": f".htaccess -- interzice {what}",
                  "recommended": False, "where": "public_html/.htaccess, la început",
                  "text": _ht_ips(items), "action": "403 Forbidden",
                  "note": "Doar pentru acest site; restul conturilor de pe server nu sunt afectate."})
    if ht and pattern_ok:
        O.append({"key": "ht_pattern", "target": ".htaccess", "title": ".htaccess -- interzice tiparul (403)",
                  "recommended": False, "where": "public_html/.htaccess, la început (înaintea regulilor CMS-ului)",
                  "text": "RewriteEngine On\n" + "\n".join(ht) + "\nRewriteRule ^ - [F,L]", "action": "403 Forbidden",
                  "note": "Atenție: .htaccess nu poate deosebi oamenii de boți -- îi oprește pe toți cei care fac o astfel de cerere. "
                          "Folosește-l doar dacă tiparul nu e folosit de vizitatori reali."})
    if strategy == "ratelimit":
        O.append({"key": "cf_rate_any", "target": "Cloudflare", "title": "Cloudflare -- limitare de rată generală",
                  "recommended": True, "where": "Security → WAF → Rate limiting rules → Create rule",
                  "text": 'http.request.uri.path ne "" and not cf.client.bot', "action": "Managed Challenge peste 60 cereri / 10 s per IP",
                  "note": "Regulă de siguranță pentru tot site-ul; ajustează pragul după traficul normal."})
    return out
