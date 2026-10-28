# logscan

Analiză pentru jurnalele de acces Apache / LiteSpeed (Raw Access din cPanel): trafic, țări, atacuri, boți, scraping, reguli de blocare. Rulează complet local și efemer: logurile nu sunt trimise nicăieri, iar datele temporare se șterg la oprirea procesului. Implicit aplicația ascultă doar pe `127.0.0.1` și este în modul offline (fără Wordfence/DNS extern). Singurele apeluri externe posibile (feed Wordfence și verificarea DNS a crawlerelor) sunt oprite implicit și se activează doar cu `LOGSCAN_OFFLINE=0`.

## Pornire rapidă

Cerințe: Python 3.11 sau mai nou (cerut de numpy 2.x) și git. `install.sh` îl găsește singur dacă există (`python3.11`, `python3.12`...); pe AlmaLinux / CentOS 8, unde `python3` e 3.6, instalează-l cu `dnf install python3.11`.

Pe un server (ca root), totul dintr-o comandă -- descarcă, instalează și pornește; după asta aplicația se pornește cu `logscan`:

```bash
git clone https://github.com/1543eduard/logscan.git /opt/logscan && /opt/logscan/install.sh --link && logscan
```

Pas cu pas:

```bash
git clone https://github.com/1543eduard/logscan.git
cd logscan
./install.sh            # o singură dată: creează venv/ și instalează dependențele
bin/logscan             # pornește pe un port aleator și afișează adresa
```

Deschide adresa afișată în browser și încarcă fișierul de log (`.log`, `.txt`, `.gz`, `.zip`).

Pentru comanda scurtă `logscan` de oriunde: `./install.sh --link` (creează `/usr/local/bin/logscan`, cere root / sudo).

## Actualizare

```bash
cd logscan
git pull
```

Atât: `bin/logscan` (și `logscan`, dacă ai folosit `--link`) pornește direct din folderul repo-ului. Dacă `requirements.txt` s-a schimbat, rulează încă o dată `./install.sh`.

## Probleme cunoscute

- **„NumPy was built with baseline optimizations (X86_V2) but your machine doesn't support (X86_V2)”**: numpy 2.4+ cere un procesor x86-64-v2, pe care unele mașini virtuale (model CPU generic, de ex. `qemu64`) nu îl expun. De aceea `requirements.txt` fixează numpy 2.3.5, care merge pe orice procesor x86-64. Dacă ai instalat o versiune mai veche a repo-ului: `git pull && ./install.sh`.
- Fără numpy aplicația pornește oricum (pe indexul SQLite, mai lent, fără Workplace / incidente / rețele / reguli) și afișează la pornire cauza exactă.
- Mesajul lung `KeyboardInterrupt` / `CancelledError` la Ctrl+C e normal (oprirea serverului web), nu o eroare.

## Setări pentru `bin/logscan`

| Variabilă | Implicit | Ce face |
|---|---|---|
| `LOGSCAN_HOST` | `127.0.0.1` | Adresa pe care ascultă. Pentru acces din LAN setează explicit `0.0.0.0` și adaugă hostul în `LOGSCAN_ALLOWED_HOSTS`. |
| `LOGSCAN_PORT` | aleator | Port fix. |
| `LOGSCAN_PORT_MIN` / `LOGSCAN_PORT_MAX` | `21000` / `21099` | Intervalul portului aleator (pe serverul cPanel e intervalul deschis în CSF). |
| `LOGSCAN_MAXTIME` | `0` | Oprire automată opțională (`0` = fără limită; oprirea se face cu Ctrl+C). |
| `LOGSCAN_MAX_WORKERS` | după CPU | Numărul maxim de procese de parsare (detectat automat, inclusiv cota de CPU a containerului). |
| `LOGSCAN_OFFLINE` | `1` | `1` = fără Wordfence/DNS extern; `0` permite feed-ul Wordfence și verificarea DNS. |
| `LOGSCAN_ALLOWED_HOSTS` | gol | Hosturi suplimentare acceptate, separate prin virgulă (necesar doar pentru LAN/revers proxy). |
| `LOGSCAN_MAX_UPLOAD_MB` | `8192` | Limita fișierului (și a conținutului decomprimat). |
| `LOGSCAN_MAX_ACTIVE_DATASETS` | `32` | Numărul maxim de analize păstrate simultan în memorie. |
| `LOGSCAN_MAX_RSS_MB` | auto (70% RAM) | Bugetul de memorie pentru preflight-ul de indexare; `0` = auto. |
| `LOGSCAN_WORK_ROOT` | temp sistem | Directorul workdir-urilor; `/dev/shm/logscan` ține datele în RAM. |

Exemplu, pe laptop: `LOGSCAN_HOST=127.0.0.1 LOGSCAN_MAXTIME=0 bin/logscan`

Dacă pornești cu `LOGSCAN_HOST=0.0.0.0`, `bin/logscan` adaugă automat IP-ul local și numele hostului în lista acceptată. Pentru un revers proxy sau un domeniu, adaugă-le explicit în `LOGSCAN_ALLOWED_HOSTS`.

**Atenție:** aplicația nu are autentificare. Implicit ascultă doar pe loopback, validează headerul Host și nu expune documentația OpenAPI. Dacă o deschizi în LAN, fă-o conștient și limitează accesul prin firewall/revers proxy cu autentificare.

## Windows

```bat
git clone https://github.com/1543eduard/logscan.git
cd logscan
py -3.11 -m venv venv
venv\Scripts\pip install -r requirements.txt
venv\Scripts\python app.py --host 127.0.0.1 --port 8080
```

Apoi deschide `http://127.0.0.1:8080`.

## Ce face, pe scurt

- **Overview → Ce s-a întâmplat**: 3–5 concluzii în limbaj simplu (atacuri, rotație de proxy-uri, erori de server, boți), fiecare cu dovezile și regula de blocare.
- **Regulă de blocare** lângă fiecare lucru detectat: Cloudflare WAF, CSF, `.htaccess`; strategia (IP / subrețea / tipar / limitare de rată) se alege din forma traficului.
- **Security & Triaj**: incidente, atac pe filtre (PrestaShop / WooCommerce), activitate automată (scanere, brute force, scraping, rafale, boți falși).
- **IP Explorer**: IP-uri, subrețele, furnizori (ASN), IP-urile unice grupate pe rețele; profil complet al fiecărui IP în panoul lateral.
- **Workplace**: filtrare liberă cu condiții (inclusiv comportament per IP), preseturi și ghid cu exemple.
- **Raw Logs**: liniile originale, copiere / export, **Live 10s** pentru reîmprospătarea automată a ecranului curent.
- Bara de sus: perioada (tragere pe mini-grafic), filtrele active, **Compară perioade**, **Redactează** (pseudonimizează IP-urile la export/copiere), **Live 10s**, **Copiază link** (linkul deschide exact același ecran cât timp aplicația rulează).

Lista completă a schimbărilor: fișierele `SCHIMBARI_v*.md`.

## Teste

```bash
venv/bin/python tests/test_logscan.py                         # 46 teste unitare (inclusiv redact/share și asset-uri statice)
venv/bin/python app.py --port 8092 &                          # teste de interfață (necesită playwright)
venv/bin/python tests/ui_v51.py http://127.0.0.1:8092 /cale/log.log
```
