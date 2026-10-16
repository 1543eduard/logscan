# logscan

Analiză pentru jurnalele de acces Apache / LiteSpeed (Raw Access din cPanel): trafic, țări, atacuri, boți, scraping, reguli de blocare. Rulează complet local; logurile nu sunt trimise nicăieri (GeoIP și baza de furnizori sunt incluse în repo). Singurul apel extern e al lansatorului `bin/logscan`, care întreabă `ifconfig.me` ca să-ți afișeze IP-ul public al serverului (nu și cu `LOGSCAN_HOST=127.0.0.1`).

## Pornire rapidă

Cerințe: Python 3.11 sau mai nou (cerut de numpy 2.x) și git. `install.sh` îl găsește singur dacă există (`python3.11`, `python3.12`...); pe AlmaLinux / CentOS 8, unde `python3` e 3.6, instalează-l cu `dnf install python3.11`.

```bash
git clone git@github.com:1543eduard/logscan.git
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

## Setări pentru `bin/logscan`

| Variabilă | Implicit | Ce face |
|---|---|---|
| `LOGSCAN_HOST` | `0.0.0.0` | Adresa pe care ascultă. Pe calculatorul propriu folosește `127.0.0.1`, ca aplicația să nu fie accesibilă din rețea. |
| `LOGSCAN_PORT` | aleator | Port fix. |
| `LOGSCAN_PORT_MIN` / `LOGSCAN_PORT_MAX` | `21000` / `21099` | Intervalul portului aleator (pe serverul cPanel e intervalul deschis în CSF). |
| `LOGSCAN_MAXTIME` | `2h` | Oprire automată (`0` = fără limită). |
| `LOGSCAN_MAX_WORKERS` | după CPU | Numărul maxim de procese de parsare (detectat automat, inclusiv cota de CPU a containerului). |

Exemplu, pe laptop: `LOGSCAN_HOST=127.0.0.1 LOGSCAN_MAXTIME=0 bin/logscan`

**Atenție:** aplicația nu are autentificare. Pe un server, oricine ajunge la port vede datele încărcate; de aceea portul e aleator și aplicația se oprește singură.

## Windows

```bat
git clone git@github.com:1543eduard/logscan.git
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
- **Raw Logs**: liniile originale, copiere / export.
- Bara de sus: perioada (tragere pe mini-grafic), filtrele active, **Compară perioade**, **Copiază link** (linkul deschide exact același ecran cât timp aplicația rulează).

Lista completă a schimbărilor: fișierele `SCHIMBARI_v*.md`.

## Teste

```bash
venv/bin/python tests/test_logscan.py                         # teste unitare
venv/bin/python app.py --port 8092 &                          # teste de interfață (necesită playwright)
venv/bin/python tests/ui_v51.py http://127.0.0.1:8092 /cale/log.log
```
