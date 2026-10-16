#!/usr/bin/env python3
"""Generator determinist de loguri cPanel (Apache combined) realiste, pentru
masuratorile de performanta (inainte/dupa) si testele UI. Contine trafic
RO/strain, IPv6, IP-uri private (tara nedeterminata), crawlere, scanari,
brute force wp-login/xmlrpc, sesiuni admin, UA cu ghilimele scapate si
linii invalide. Uz: genlog.py OUT N_LINES [seed]
Masuratorile din raport: genlog.py big.log 2000000 7 / med.log 300000 3"""
import random
import sys
import time

out, n = sys.argv[1], int(sys.argv[2])
seed = int(sys.argv[3]) if len(sys.argv) > 3 else 42
R = random.Random(seed)

RO_PREFIXES = ["86.120", "86.121", "86.122", "86.123", "86.124", "86.125", "79.112", "79.113", "79.115",
               "188.24", "188.25", "188.26", "188.27", "5.12", "5.13", "89.136", "89.137", "93.114", "109.96",
               "109.97", "82.76", "82.77", "92.80", "92.81", "95.76", "95.77"]
WORLD_PREFIXES = ["66.249", "40.77", "157.55", "52.167", "185.220", "45.155", "194.26", "103.152", "122.10",
                  "61.177", "110.42", "185.191", "91.240", "178.62", "2.56", "45.9", "193.32", "81.161",
                  "212.83", "217.160", "34.80", "35.198", "104.248", "167.99", "138.68", "159.89", "51.15",
                  "51.68", "5.188", "176.9", "136.243", "209.141", "198.51", "200.150", "177.67", "41.216",
                  "102.165", "14.162", "113.160", "1.52", "36.91", "58.187", "117.200"]
PRIVATE = ["10.0.0.5", "192.168.1.10", "127.0.0.1"]
V6 = ["2a02:2f0e:%x::%x", "2a02:2f04:%x::%x", "2001:4860:%x::%x", "2a01:4f8:%x::%x", "2400:cb00:%x::%x"]


def mk_pool(prefixes, k):
    s = set()
    while len(s) < k:
        p = R.choice(prefixes)
        s.add(f"{p}.{R.randint(0, 255)}.{R.randint(1, 254)}")
    return list(s)


RO_IPS = mk_pool(RO_PREFIXES, 9000)
WORLD_IPS = mk_pool(WORLD_PREFIXES, 7000)
V6_IPS = [R.choice(V6) % (R.randint(1, 0xffff), R.randint(1, 0xffff)) for _ in range(400)]
ATTACKERS = R.sample(WORLD_IPS, 40)
BRUTE = R.sample(WORLD_IPS, 12)
GOOGLE = [f"66.249.{R.randint(64, 79)}.{R.randint(1, 254)}" for _ in range(60)]

UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
]
BOT_UAS = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
    "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)",
]
ATTACK_UAS = ["python-requests/2.31.0", "curl/8.4.0", "sqlmap/1.7.2#stable", "Go-http-client/1.1",
              "Mozilla/5.0 zgrab/0.x", "Mozilla/5.0 (X11; Linux x86_64) \\\"quoted\\\" agent"]

PAGES = ["/", "/despre-noi/", "/contact/", "/blog/", "/magazin/", "/cos/", "/checkout/", "/contul-meu/",
         "/categorie-produs/pavaj/", "/categorie-produs/pavaj/gri/", "/produs/dala-beton-40x40/",
         "/produs/bordura-gradina/", "/blog/cum-alegi-pavajul/", "/termeni-si-conditii/", "/?s=pavaj",
         "/categorie-produs/pavaj/?filter_culoare=rosu&orderby=price", "/wp-json/wp/v2/posts?per_page=10",
         "/wp-admin/admin-ajax.php?action=get_cart", "/wp-cron.php?doing_wp_cron=1728900000.1234",
         "/feed/", "/sitemap_index.xml", "/robots.txt", "/produs/%C8%9Bigl%C4%83-ceramic%C4%83/"]
STATIC = ["/wp-content/themes/flatsome/assets/css/flatsome.css?ver=3.18", "/wp-includes/js/jquery/jquery.min.js?ver=3.7.1",
          "/wp-content/uploads/2024/05/pavaj-gri-300x300.jpg", "/wp-content/uploads/2024/03/logo.png",
          "/wp-content/plugins/woocommerce/assets/js/frontend/cart-fragments.min.js?ver=9.1", "/favicon.ico"]
SCANS = ["/.env", "/wp-config.php.bak", "/.git/config", "/phpmyadmin/", "/wp-content/uploads/2024/x.php",
         "/wp-content/plugins/revslider/temp/update_extract/shell.php", "/xmlrpc.php", "/wp-login.php",
         "/?author=1", "/wp-json/wp/v2/users", "/index.php?page=../../../../etc/passwd",
         "/s?q=1%20UNION%20ALL%20SELECT%20NULL,NULL--", "/wp-admin/install.php", "/admin.php",
         "/<script>alert(1)</script>", "/cgi-bin/luci", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"]
REFS = ["-", "-", "https://www.google.com/", "https://www.facebook.com/", "https://exemplu.ro/", "https://exemplu.ro/magazin/"]
MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

start = int(time.mktime((2026, 10, 6, 0, 0, 0, 0, 0, -1)))
span = 7 * 86400
tz = "+0300"


def ts(e):
    t = time.gmtime(e + 3 * 3600)
    return f"{t.tm_mday:02d}/{MON[t.tm_mon - 1]}/{t.tm_year}:{t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d} {tz}"


lines = []
t = start
step = span / n
bad = 0
with open(out, "w", encoding="utf-8") as f:
    for i in range(n):
        t += R.expovariate(1.0 / step)
        e = int(t)
        r = R.random()
        st, size = 200, R.randint(300, 90000)
        ref = R.choice(REFS)
        meth = "GET"
        if r < 0.62:
            ip = R.choice(RO_IPS) if R.random() < 0.8 else R.choice(WORLD_IPS)
            ua = R.choice(UAS)
            path = R.choice(PAGES) if R.random() < 0.45 else R.choice(STATIC)
            if R.random() < 0.02:
                st = 404
            elif R.random() < 0.05:
                st = 304; size = 0
            elif R.random() < 0.004:
                st = R.choice([500, 502, 503])
        elif r < 0.72:
            ip = R.choice(GOOGLE) if R.random() < 0.5 else R.choice(WORLD_IPS)
            ua = R.choice(BOT_UAS)
            path = R.choice(PAGES)
        elif r < 0.78:
            ip = R.choice(V6_IPS)
            ua = R.choice(UAS)
            path = R.choice(PAGES)
        elif r < 0.86:
            ip = R.choice(ATTACKERS)
            ua = R.choice(ATTACK_UAS)
            path = R.choice(SCANS)
            st = R.choice([404, 404, 403, 200, 301, 429])
            if path in ("/xmlrpc.php",):
                meth = "POST"
        elif r < 0.93:
            ip = R.choice(BRUTE)
            ua = R.choice(UAS + ATTACK_UAS)
            meth = "POST" if R.random() < 0.8 else "GET"
            path = "/wp-login.php" if R.random() < 0.85 else "/xmlrpc.php"
            st = 200 if R.random() < 0.97 else 302
        elif r < 0.995:
            ip = R.choice(RO_IPS[:60])  # admini
            ua = UAS[0]
            path = R.choice(["/wp-admin/", "/wp-admin/edit.php", "/wp-admin/admin-ajax.php", "/wp-admin/post.php?post=12&action=edit",
                             "/wp-admin/plugins.php", "/wp-login.php", "/wp-admin/load-scripts.php?c=1&load%5Bchunk_0%5D=jquery-core"])
            meth = "POST" if path.endswith("admin-ajax.php") or (path == "/wp-login.php" and R.random() < 0.5) else "GET"
            st = 302 if (path == "/wp-login.php" and meth == "POST") else 200
        else:
            ip = R.choice(PRIVATE)
            ua = "Wget/1.21"
            path = "/wp-cron.php"
        if R.random() < 0.0003:
            f.write(f'{ip} - - [{ts(e)}] "GET /trunchiat\n')
            bad += 1
            continue
        if R.random() < 0.0001:
            f.write("linie corupta fara format\n")
            bad += 1
            continue
        f.write(f'{ip} - - [{ts(e)}] "{meth} {path} HTTP/1.1" {st} {size} "{ref}" "{ua}"\n')
print("ok", out, n, "invalid", bad)
