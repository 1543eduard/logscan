# logscan v46: identitate vizuală nouă și restructurare pe module

Se instalează peste v45. Backend-ul, indexurile și testele de date sunt păstrate. Toate funcțiile anterioare sunt păstrate și au fost mutate în noua structură.

```bash
cd /opt/logscan
cp -r <arhiva>/* .              # include static/fonts/ (nou)
venv/bin/python3 tests/test_logscan.py      # 29/29
# restart serviciu, apoi Ctrl+Shift+R în browser
curl -s http://127.0.0.1:8080/api/version   # {"version":"46",...}
```

## 1. Ce s-a schimbat vizual

| | v45 | v46 |
|---|---|---|
| Temă | întunecată, accent cyan neon cu efect de strălucire | **luminoasă**: fundal mineral `#EDF0F3`, suprafețe albe, text ardezie `#15212E`, un singur accent petrol `#0B6E73` |
| Culori semantice | roșu, portocaliu și cyan amestecate cu decorul | roșu, chihlimbar și verde folosite **doar** pentru severitate și coduri HTTP |
| Font | fontul sistemului | **IBM Plex Sans** pentru interfață și **IBM Plex Mono** pentru IP-uri, URL-uri și linii brute, servite local (`/static/fonts`, licență OFL), fără CDN |
| Carduri | umbre, bare colorate la stânga titlurilor, gradiente | bordură fină, fără umbre (umbră doar pe sertar, meniuri și paletă), titluri 15 px semibold |
| Indicatori | „KPI” cu bară gradient și strălucire | tile-uri cu cifră mare 22 px și etichetă mică, clicabile spre modulul relevant |
| Tabele | rânduri întunecate | rânduri aerisite, separatoare fine, bare orizontale petrol pentru pondere, coduri HTTP ca pastile colorate |
| Grafice | tick-uri și grile pe fundal închis | paletă nouă (2xx verde, 3xx albastru, 4xx chihlimbar, 5xx roșu), grile discrete, heatmap pe scală petrol |
| Ecran inițial | dreptunghi punctat | zonă de încărcare cu titlu și explicații, meniu lateral vizibil |

## 2. Restructurarea aplicației

**Meniul lateral nou**, pe grupe, înlocuiește rândul de taburi:

* **Situație:** Overview
* **Trafic:** Traffic Analytics, Countries, Endpoints & URLs, HTTP Errors
* **Securitate:** Security & Triaj, WordPress Security, IP Explorer
* **Lucru:** Raw Logs, Investigations

**Bara de sus** (fixă la derulare) conține:

* titlul și descrierea modulului;
* o pastilă cu selecția curentă (perioadă, numărul de cereri, filtre), care rămâne vizibilă oricât derulezi;
* exporturile.

**Perioada analizată** e sus în fiecare modul:

* perioada scrisă în clar, de exemplu „6 oct 2026, 03:00:00 până la 13 oct 2026, 03:30:38”;
* cereri, IP-uri, durată și numărul de filtre active;
* histograma pe care alegi intervalul;
* câmpurile de dată, „Înapoi” și „Resetează”.

Histograma a fost scoasă din Triaj: e selectorul de perioadă al întregii aplicații, deci acum apare peste tot.

**Module noi:** fiecare are un sumar propriu, calculat din index în 10–470 ms pe 2 milioane de linii, iar sub el analiza detaliată din v42.

| Modul | Conținut |
|---|---|
| **Overview** (nou, pagina implicită) | situația scrisă în cuvinte (perioadă, volum, rata erorilor, evenimente CRITICAL/HIGH, WordPress), 7 indicatori clicabili, trafic în timp (tragere = perioadă), evenimentele de securitate recente, top țări, IP-uri, endpoint-uri, WordPress pe categorii, distribuția codurilor |
| **Traffic Analytics** | ritm mediu și vârf, sesiuni estimate, volum pe clase de cod, User-Agent-uri, metode; dedesubt compoziția, bursturile, crawlerele, heatmap-ul |
| **Countries** (nou) | România / în afara României / fără țară; tabelul tuturor țărilor (cereri, pondere, IP-uri, cereri per IP); dedesubt RO față de restul lumii și tabelul pe țări |
| **Endpoints & URLs** | top 40 de URL-uri cu IP-uri, URL-uri cu erori; dedesubt Path Explorer, prefixe, parametri, rute dinamice |
| **HTTP Errors** (nou) | rata erorilor, 4xx, 5xx, codul cel mai frecvent, erorile în timp, coduri, IP-uri cu 4xx / 5xx, URL-uri care produc erori; dedesubt 404 hotspots și graficele vechi |
| **Security & Triaj** | alerte critice, cronologia de securitate, coada de investigare, findings, traseul de compromitere, anomalii |
| **WordPress Security** (nou ca modul) | cereri WordPress, autentificări, xmlrpc, alerte; tabel pe categorii (cereri, IP-uri, sesiuni, coduri); grafic; IP-uri pe wp-login și xmlrpc; rute de plugin-uri și teme; dedesubt analiza WordPress din v42 |
| **IP Explorer** | fosta pagină Prezentare, plus subrețele, top IP-uri, UA-uri, bandwidth |
| **Raw Logs** | tabelul virtualizat al cererilor (fostul panou de jos), cu sinteza și tab-urile lui, plus „Vezi cererile dintr-un moment” și Exploratorul de loguri |
| **Investigations** | spațiul de investigație afișat ca pagină (elemente, notițe, concluzii, export), plus rapoarte, reguli de blocare și export |

Fiecare modul are propria adresă (`#overview`, `#errors`, …): butonul Înapoi al browserului și link-urile funcționează. Taste noi: **O** = Overview, **R** = Raw Logs. Scurtăturile vechi au rămas: Ctrl+K, E, S, I, ?.

## 3. Bara de jos a fost eliminată

* **Cum era creată:** `gfOnDatasetLoaded()` afișa `#selectionPanel` cu clasa `dock` (`position: fixed; bottom: 0`) și adăuga `hasDock` pe body. `dockApply()` îi calcula înălțimea și rezerva spațiu în pagină, iar `triageSetSingleFilter()` o redeschidea automat la fiecare filtru.
* **Ce s-a schimbat:**
  * panoul nu mai are clasa `dock` și a fost mutat în modulul **Raw Logs**;
  * clasa `hasDock` nu se mai pune;
  * cele 3 redeschideri automate au fost șterse;
  * redimensionarea și butonul „pliază” au fost eliminate;
  * `dockApply()` doar redesenează tabelul.
* **Rezultat:** la pornire și după import apare Overview, fără panou jos. Testul `ui_v46.py` verifică faptul că pe marginea de jos nu există niciun element fix și că panoul nu e vizibil, atât înainte, cât și după import.

## 4. Fișiere modificate

* `dashboard.html`:
  * structură nouă: `#sidebar`, `#appMain`, `#topbar`, panglica perioadei, containerele `.modPage`;
  * router `showPage()` pe module, cu alias-uri pentru cheile vechi;
  * module noi (`renderOverview`, `renderTraffic`, `renderCountries`, `renderEndpoints`, `renderErrors`, `renderWordpress`);
  * tema CSS nouă, culorile graficelor și heatmap-ul.
* `app.py`: ruta `/static/fonts/{name}` (doar `.woff2` din `static/fonts`, cu cache) și versiunea 46.
* `static/fonts/`: IBM Plex Sans (400/500/600/700) și Plex Mono (400/500), latin + latin-ext, cu licența OFL.
* Teste:
  * `tests/ui_v46.py` (nou);
  * `ui_smoke.py`, `ui_v45.py` și `ui_xss.py` adaptate la noua navigare.

## 5. Teste

* `test_logscan.py`: 29/29.
* `ui_v46.py`: 10/10, atât pe 300 de mii, cât și pe 2 milioane de linii:
  1. ecranul inițial e luminos și fără bara de jos;
  2. după import apare Overview, fără panoul de jos;
  3. tema și fonturile sunt efectiv încărcate;
  4. toate cele 10 module funcționează din meniu, prin link și din tastatură;
  5. cifrele din Overview, Countries, HTTP Errors, WordPress, Endpoints și Raw Logs sunt egale cu API-ul pe tot logul;
  6. aceleași cifre, egale cu API-ul, pe o oră + țara RO;
  7. un modul deschis se actualizează la schimbarea perioadei;
  8. o selecție goală afișează mesaj explicit în fiecare modul;
  9. legăturile dintre module și panoul de explorare funcționează;
  10. zero erori JS.
* `ui_smoke.py` 14/14, `ui_v45.py` 15/15, `ui_xss.py` (10 module) și `ui_nogeo.py` trec.
* **Performanță (2 milioane de linii):**
  * prima deschidere a fiecărui modul, pe tot logul: 8–470 ms; Overview 1,1 s;
  * pe o selecție de o oră: 7–190 ms;
  * cel mai lung blocaj al interfeței: 111 ms.

* **Corecție după verificarea finală:**
  * **Problema:** cronologia de securitate putea rămâne cu eroarea „Canvas is already in use” când două randări ale aceluiași card se suprapuneau, de exemplu la intrarea în modul urmată imediat de o schimbare de perioadă.
  * **Reparație:** fiecare card are acum propriul număr de secvență, iar o randare mai veche nu mai scrie peste cea nouă.
  * **Test de regresie:** scenariul 12 din `ui_v45.py` declanșează intenționat trei randări suprapuse.

## Limitări

* Analiza detaliată din v42 de sub sumarul fiecărui modul se recalculează pentru selecție doar când deschizi modulul, ca înainte: câteva secunde pe 2 milioane de linii. Sumarul de sus e instant și e mereu pe selecția curentă.
* Etichetele vechi din cardurile v42 au rămas fără diacritice (textul a fost păstrat neschimbat). Interfața nouă folosește diacritice.
* Sub 900 px lățime, meniul lateral devine o bară orizontală derulabilă.
