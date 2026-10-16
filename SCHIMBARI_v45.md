# logscan v45: perioada respectată în toate drilldown-urile și investigație interactivă

Se instalează peste v44. Folderele `geoip/` și `venv` rămân neschimbate, iar dependențele sunt aceleași (numpy, recomandat).

```bash
cd /opt/logscan
cp -r <arhiva>/* .
venv/bin/python3 tests/test_logscan.py      # 29/29
# restart serviciu
```

## 1. Bugul: drilldown-urile ignorau perioada

**Simptom (captura):** perioada globală era 14.10 10:03–11:15, dar „Drill-down: Țara US” afișa linii din 13/Oct 15:03.

**Cauza exactă.** Patru defecte s-au adunat:

1. `drillDown()` din `dashboard.html` copia din selecția globală doar câteva câmpuri:
   * se păstrau `ip`, o singură țară, `path` și `zi`;
   * se pierdeau intervalul de timp, codurile, severitățile, celelalte țări și acțiunile.
2. Endpoint-urile care rescanează fișierul nu aveau niciun parametru de timp sau de selecție globală, așa că scanau tot fișierul (sau toată ziua). Afectate: `/raw`, `/ip_detail`, `/country_subnets`, `/path_breakdown`, `/windows`, `/window_raw`, `/extract_raw`, `/burst_raw`, export.
   * Cu limita de 2000 de linii și oprirea timpurie, întorceau **primele 2000 de linii din fișier**. De aici apare 13/Oct 15:03.
3. Unele componente aveau propria lor perioadă:
   * `/alerts/top` calcula mereu pe tot logul;
   * profilul IP primea doar timpul;
   * Prezentare avea o perioadă locală separată;
   * „Statistici pe interval” folosea o vedere de interval paralelă, necunoscută drilldown-urilor.
4. Componentele deja deschise (fereastra de drilldown, panourile) nu se actualizau când se schimba perioada.

**Reparația, cu o singură sursă de adevăr:**

* Selecția globală (`TRIAGE.filters` + `tsFrom/tsTo`) e serializată într-un singur parametru, `gf` (JSON). Funcțiile `gfObject`, `gfJSON` și `gfUrl` îl adaugă la **fiecare** cerere: drilldown-uri, alerte, Prezentare, profil, export, explorer.
* Serverul validează `gf` (`_gf_parse_json`) și îl intersectează cu entitatea drilldown-ului (`_gf_merge`, semantică AND):
  * două țări diferite dau „selecție vidă”, **nu tot logul**;
  * perioadele se intersectează;
  * excluderile se reunesc.
* Endpoint-urile care rescanează fișierul folosesc acum doar liniile selecției. Acestea sunt extrase prin index (columnar/SQLite) într-un fișier-subset, păstrat într-un cache LRU de 8 subseturi, după care se aplică logica veche, neschimbată. `/raw` folosește direct intervalele de octeți din index.
* Prezentare și „Statistici pe interval” setează acum perioada **globală**.
* Componentele deschise se abonează la schimbările de selecție (`GF_LISTENERS`). Fereastra de drilldown, panoul de explorare, alertele, cronologia, sertarul de audit, Path Explorer și Explorare se reîncarcă singure.
* Fiecare vedere are un număr de secvență. Un răspuns venit pentru o selecție mai veche e ignorat și nu suprascrie rezultatul nou.
* O selecție fără evenimente afișează un mesaj explicit, cu selecția curentă. Aplicația nu revine niciodată automat la tot logul.
* Eticheta perioadei se afișează în fusul orar al **logului** (+0300), calculat per fișier. Înainte apărea în UTC (de ex. „09:00” în loc de „12:00”).

Bug-uri găsite de testele noi și reparate:

* `security_groups_sql`: un `pop` în generator ducea la KeyError pe calea SQLite.
* `unique_uas` pe SQLite număra id-uri, nu texte. După unirea shard-urilor, același UA putea avea mai multe id-uri.
* `_gf_merge` modifica lista primită ca argument.

## 2. Interactivitate nouă

**Panoul de explorare** este un sertar lateral, **ne-modal**: pagina, bara de filtre și panoul de jos rămân utilizabile.

* Merge pentru orice entitate:
  * IP;
  * endpoint (URL exact);
  * prefix URL;
  * țară;
  * cod HTTP și clasă HTTP;
  * categorie WordPress;
  * User-Agent;
  * metodă;
  * acțiune și severitate;
  * alertă (IP + acțiune);
  * „selecția curentă”.
* Rezultatul e mereu **entitatea ∩ selecția globală**.
* Explorerele cerute (IP, Endpoint, Security Timeline, WordPress, HTTP Response, Țară) sunt vederi ale aceluiași explorer.
* Taburi:
  * **Sumar**: KPI-uri clicabile, cotă din selecție, comportament cu justificare, coduri, metode, WordPress (cereri, IP-uri, sesiuni, coduri), rute plugin/temă, top IP-uri și endpoint-uri;
  * **În timp**: grafic pe clase de cod. Un click pe o bară sau o tragere peste mai multe setează perioada globală. Tot aici e **comparația cu alt interval** (perioada precedentă, aceeași perioadă cu o zi înainte, sau un interval ales);
  * **Cereri RAW**: listă paginată, sortare, comutare pe liniile originale, export;
  * **Corelate**: IP-uri cu etichete pentru comportament neobișnuit (concentrare, erori, ritm), URL-uri, țări, UA-uri, erori pe URL;
  * **Alerte**: alertele din selecție și cronologia grupată.
* Navigare:
  * istoric ◀ ▶ (Alt+← / Alt+→);
  * linia selecției mereu vizibilă, cu legătura „arată tot logul”;
  * bara de acțiuni: filtrează, exclude, investigație, compară, CSV, .log, copiază, ⋯.
* **Detaliul unei cereri:**
  * toate câmpurile și linia originală;
  * cererea anterioară sau următoare cu `[` `]` (sau k/j), cu încărcare automată la capătul listei;
  * cererile aceluiași IP la ±2 minute;
  * butonul „context ±5 min”;
  * deschiderea IP-ului, a endpoint-ului, a țării sau a codului.
* **Comparație între două entități**, pe aceeași selecție.

**Meniu contextual** (click dreapta sau ⋯):

* Disponibil pe IP-uri, URL-uri, țări, coduri, UA-uri, alerte, rânduri RAW, celulele tabelului de jos și tabelele vechi v42.
* Acțiuni: detalii, cererile RAW, alertele asociate, filtrare, excludere, comparare, adăugare la investigație, export CSV și .log, copiere, audit admin.
* Acțiunea veche a tabelelor v42 a rămas ultima opțiune.
* La hover apar butoanele ⊕ / ⊘ / ⋯. Pentru tastatură există Tab și Enter.
* Fiecare acțiune confirmă printr-un toast.

**Excluderi în selecție:** pot fi excluse IP-uri, țări, coduri, fragmente de URL și fragmente de UA. Apar ca chip-uri roșii „≠”, iar „Înapoi” le anulează.

**Cronologia de securitate:**

* E un card în Triaj și o vedere în explorer.
* Evenimentele CRITICAL/HIGH/MEDIUM sunt grupate pe IP + acțiune, cu pragul de pauză ales de tine.
* Graficul pe severități acceptă tragerea pentru a alege perioada.
* Click pe un grup deschide dovezile. Butoanele „⏱” și „±10m” setează perioada pe grup.

**Spațiul de investigație:**

* Conține elemente (entități, cereri, selecții), fiecare cu selecția în care a fost adăugat și cu buton de restaurare. Mai conține note pe element, notițe generale și concluzii.
* **Persistența e locală:** `localStorage`, per fișier (amprenta conținutului), deci doar în acest browser. Pagina o spune explicit.
* Serverul nu are utilizatori sau stocare persistentă: dataset-urile sunt temporare. Pentru păstrare sau partajare există export Markdown/JSON și import JSON.

**Paleta de comenzi** (Ctrl+K sau `/`):

* Recunoaște ce scrii: IP, `/url`, cod de țară, cod HTTP, `5xx`.
* Oferă și pagini, preseturi, vizualizări salvate și acțiuni.
* `?` afișează scurtăturile: E (explorează selecția), S (cronologie), I (investigație), D (panou jos), Esc.

**Bara selecției** conține: Explorează selecția, Cronologie securitate, Investigație (n), Preseturi ▾, Export ▾ și ⌘K.

* **Preseturi:** ultima oră sau 24 h din log, brute-force wp-login, XML-RPC, wp-admin, REST, 5xx, 4xx, 403/429, CRITICAL/HIGH, non-RO, țară nedeterminată, fără boți declarați.
* **Vizualizări salvate:** se păstrează local. Perioada e salvată relativ la sfârșitul logului.

**Graficele vechi (taburile detaliate):**

* Un click pe „Trafic în timp”, pe „Erori în timp” sau pe o celulă din heatmap setează perioada globală.
* Un click pe felia de cod deschide explorerul clasei.

**Fereastra de drilldown veche** nu mai acoperă bara selecției, panoul de jos și explorerul. Butonul Înapoi și câmpurile de perioadă rămân utilizabile, iar fereastra se actualizează pe loc.

**Panoul de jos:**

* Click pe IP → profil (explorer); click pe URL → istoricul endpoint-ului.
* Țara, codul și categoria WordPress filtrează, ca în v44.
* Categoria WordPress folosește acum filtrul exact pe categorie (`wp_cat`).

## 3. Server: rute noi și parametri

| Rută | Ce face |
|---|---|
| `GET /explore?kind&value&gf[&cmp_from&cmp_to]` | sumarul entității în selecție, plus comparația cu alt interval |
| `GET /timeline?kind&value&gf` | seria pe clase de cod și severități; intervalul = perioada selectată |
| `GET /security_timeline?gf&min_severity&gap&kind&value` | evenimentele de securitate grupate |
| `GET /export_events?gf&kind&value&format=csv\|log` | export în flux: CSV sau liniile originale |
| `gf` pe toate drilldown-urile vechi, pe `/events` (+`kind`,`value`,`raw`), `/alerts/top`, `/admin_session`, `/ip_profile`, `/ip_overview`, `/ip_compare`, `/export.*` | selecția globală |

Filtre noi în index, identice pe columnar și SQLite:

* `path_exact`, `status_class`, `wp_cat`;
* excluderi: `x_ips`, `x_countries`, `x_statuses`, `x_paths`, `x_uas`;
* două condiții „conține” pe același câmp.

## 4. Teste

* `tests/test_logscan.py`: **29/29** (24 din v44 + 5 noi):
  * `_gf_merge`: intersecții, contradicții = 0 rezultate, excluderi;
  * filtrele noi și explore/timeline/cronologie/alerte sunt identice între columnar și SQLite, pe 36 de combinații;
  * **fiecare drilldown** e comparat cu un calcul direct pe liniile RAW, pe ambele motoare, pentru 12 selecții:
    * tot logul;
    * două perioade succesive;
    * perioadă goală;
    * o singură secundă;
    * perioadă + țară, IP, cod sau excludere.
    * Drilldown-uri acoperite: `/raw` (țară și IP), `/ip_detail`, `/country_subnets`, `/path_breakdown`, `/windows`, `/extract_raw`, Prezentare, `/events`, `/explore`, `/timeline` (6 entități), export `.log` (linie cu linie), alerte, cronologie, sesiune admin, profil IP;
  * perioade succesive și revenire;
  * comparația de perioade;
  * eticheta în fusul orar al logului.
* `tests/ui_v45.py` (nou, Playwright): **15/15** pe 300k linii. Fiecare valoare din UI e comparată cu API-ul, iar timestamp-ul fiecărei linii afișate cu perioada:
  1. drilldown „Țara X” în perioada restrânsă (cazul din captură);
  2. două intervale succesive cu fereastra deschisă, apoi Înapoi;
  3. explorerul pe țară, actualizat când perioada se schimbă cu el deschis;
  4. cronologia unui IP și comparația cu perioada precedentă;
  5. alertă → dovezi RAW din perioadă;
  6. perioadă goală și combinație fără rezultate, cu mesaj explicit;
  7. timp + țară + cod + IP + severitate;
  8. 7 schimbări de perioadă în rafală, fără rezultate depășite;
  9. click dreapta → exclude IP;
  10. paleta, navigarea între cereri și Alt+←;
  11. investigația;
  12. cronologia de securitate și tragerea pe grafic;
  13. graficele vechi;
  14. UI fără blocaje;
  15. 0 erori JS.
* `tests/ui_smoke.py`: 14/14, adaptat la meniul contextual și la explorer.
* `tests/ui_xss.py`: extins pe explorer (5 taburi), meniu, investigație, cronologie și paletă. Niciun payload executat.
* `tests/ui_nogeo.py`: trece.

## 5. Performanță (2.000.000 de linii, 440 MB, 2 CPU)

| Operație | v44 (tot fișierul) | v45 (selecție 1 h) | v45 (selecție 24 h) |
|---|---|---|---|
| Drilldown țară `/raw` | 0,11 s, **linii greșite** | 0,24 s prima dată, 0,03 s din cache | 0,07 s |
| Detaliu IP (rescanare) | 4,0 s | 0,07 s | 0,59 s |
| Subrețele RO (rescanare) | 12,8 s | 0,17 s | 1,9 s |
| Path Explorer `/` | 6,6 s | 0,08 s | 1,0 s |
| Explorer (sumar entitate) | – | 40–60 ms | 40–160 ms |
| Distribuție în timp / cronologie securitate | – | 13 / 39 ms | 15 / 48 ms |
| Export .log | – | 20 ms (2,6 MB) | 220 ms (63 MB) |

Pe tot logul, explorerul răspunde în 0,86 s, cronologia în 0,1 s, iar seria în timp în 0,09 s. În browser, rezultatele explorerului se țin în cache pe cheia entitate + selecție.

## Limitări

* Investigația și vizualizările salvate trăiesc doar în browserul în care au fost create. Pentru transfer există export/import.
* Taburile detaliate v42 (Securitate, Trafic, …) se recalculează pe selecție doar când sunt deschise, ca în v44. Pe 2M de linii asta ia câteva secunde.
* „Fără boți declarați” e aproximativ: exclude UA-urile care conțin bot/crawl/spider.
* Etichetele „comportament neobișnuit” sunt praguri simple (pondere ≥ 20 %, ≥ 50 % erori, ≥ 30 cereri/min) și sunt explicate la hover. Nu sunt detecții.
