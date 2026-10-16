# logscan v47: fals pozitive eliminate, severitate refacuta, modulul Workplace

## 1. Fals pozitivul LFI (facebookexternalhit pe /.../titlu-al.../)
* `lfi_rfi` cerea doar `../` oriunde in URL. Slug-urile trunchiate in log (`al.../`) il contineau => HIGH/CRITICAL fals.
* Acum traversal = segment complet: `/../`, `=../` sau `\..\`. Raman `php://`, `data://`, `expect://` si RFI (`=http://...txt?`).
* La fel pentru `../../` din familia sqli.

## 2. Severitatea depinde de raspunsul serverului
| Eveniment | v46 | v47 |
|---|---|---|
| SQLi + 2xx/5xx | CRITICAL | CRITICAL |
| SQLi + 3xx/4xx (blocat) | CRITICAL | HIGH |
| LFI/XSS/webshell-name + 2xx | HIGH | HIGH |
| LFI/XSS + 3xx/4xx | HIGH | MEDIUM |
| POST wp-login non-RO / RO | HIGH / MEDIUM | MEDIUM / LOW |
| IP non-RO pe endpoint WP sensibil | HIGH | MEDIUM |
| Brute force >=100 / >=20 | CRITICAL / HIGH | HIGH / MEDIUM |
| Webshell servit, login reusit dupa brute force | CRITICAL | CRITICAL (neschimbat) |

## 3. Crawlere verificate DNS = fals pozitive
* Dupa verificarea PTR + forward-confirm, evenimentele IP-urilor verificate devin INFO in tot indexul: alerte, cronologie, overview, tabele.
* Exceptie: webshell servit si login reusit.
* Findings si IP-urile suspecte ale acestor crawlere sunt scoase din sumar. UI-ul se reincarca singur si afiseaza cate au fost eliminate.

## 4. Workplace (meniu Lucru)
* Constructor de conditii cu 19 campuri: IP / CIDR / prefix, tara, metoda, cod sau clasa HTTP, URL (contine / regex / prefix / exact / sufix), URL fara query, extensie, query string sau parametru, User-Agent (contine / exact / prefix / regex / gol), categorie UA, crawler DNS (verificat / fals / neverificat / nu), severitate, actiune, zona WordPress, marime, ora, zi, cereri per IP, URL-uri unice per IP.
* Conditiile se leaga cu SI. Mai multe valori in aceeasi conditie = SAU. Butonul NU = excludere. Orice conditie se poate dezactiva temporar.
* Pe fiecare rand: numarul exact de cereri pe care conditia le potriveste singura si cate raman dupa ea (vezi imediat ce conditie elimina tot).
* Fatete clicabile (+ include / - exclude), histograma pe ore, top IP / URL / UA.
* Peste 40 de preseturi, 16 dintre ele pe User-Agent, plus o bara rapida in care scrii UA-ul (contine / NU contine / exact / incepe cu / regex). Preseturile proprii se salveaza in browser.
* Liniile brute: vizualizare, copiere pagina, copiere toate (max 20.000), descarcare .log cu toate liniile, export JSON al conditiilor.
* Global: 6 preseturi UA noi in meniul Preseturi (inclusiv UA scris de tine) si un buton „Filtre avansate -> Workplace” in Raw Logs.

API: `GET /workplace/meta`, `POST /workplace`, `POST /workplace/raw`. Teste: 31/31 (2 noi).
