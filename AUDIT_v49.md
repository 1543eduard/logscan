# Logscan v49.0 -- audit: module, functii, filtre, exporturi

## Model unic de selectie (sursa de adevar)
- Stare: `TRIAGE.filters` + `TRIAGE.tsFrom/tsTo` (frontend) -> serializata o singura data de `gfObject()/gfJSON()` -> parametrul `gf` pe TOATE rutele.
- Backend: `_gf_parse_json()` -> filtre validate -> `ColStore.mask(f)` (index columnar) sau `_build_where(f)` (SQL, motor de rezerva; paritate testata). Sumarele filtrate = rescanare doar pe liniile din `mask` (`_gf_ranges`), deci aceleasi cereri.
- Combinare: valori multiple in acelasi filtru = OR; filtre diferite = AND; excluderi (`x_*`) = AND NOT.
- Timp: epoch UTC intern; afisare/selectie in ora logului (offsetul fiecarei linii, segmente pentru logurile cu schimbare de ora). Interval inchis [de la, pana la], ambele capete incluse, la secunda.
- Filtre locale legitime (raman separate, documentate): Workplace (conditii proprii + "perioada proprie" cu buton "aplica in toata aplicatia"), Explorator de ferestre (Raw Logs: ferestre de 30 s / 60 s / 10 min), Compara perioade (are nevoie de doua perioade), cautarea din fiecare tabel.

## Inventar module
| Modul | Date | Selectie globala | Export |
|---|---|---|---|
| Overview | /overview (index) | da | meniul Export |
| Traffic / Countries / Endpoints / HTTP Errors | sumarul (rescanare a selectiei) | da (summary_filtered) | Export > Sumar |
| Security & Triaj | /brief, /admin_access, /incidents, /alerts/top, /security_timeline + sumar | da | Export |
| WordPress Security | sumar reconciliat | da | Export > Sumar |
| IP Explorer | /ip_overview | da | CSV per rubrica (rubrica afisata, etichetat) |
| Workplace | /workplace | perioada globala sau proprie (vizibil) | .log al conditiilor (toate cererile) |
| Raw Logs (lista, explorator ferestre) | /events, /windows | da | Export |
| Investigations / Audit Trail / Investigatie | sumar + ip_trail | da (indicat in banner) | .md / .json investigatie |
| Comenzi si cautare (Ctrl K), Preseturi | -- | aplica valori in selectia globala | -- |

## Probleme reale gasite si reparate
1. **Patru selectoare de timp paralele** (header "zi", campuri datetime-local in format AM/PM al browserului, IP Explorer zi+ore, Raw Logs "moment exact"), fiecare cu logica proprie. Ziua din header era un filtru separat (`ts_str_day`) care se putea combina contradictoriu cu intervalul.
   -> Un singur selector din dropdown-uri (zi / ora / minut / secunda / ±fereastra / de la-pana la), calculat de `/period` (o singura implementare in backend). Header-ul de zi, IP Explorer si "moment exact" folosesc acum acelasi mecanism.
2. **Presetarile "ultimele 10 min / ultima ora" taiau la miezul noptii** (lucrau pe ora din zi, 00:00-23:59). -> calculate in epoch, traverseaza miezul noptii.
3. **Fus orar**: un singur offset (din prima linie) pentru tot logul -- gresit pentru logurile care trec la ora de iarna. -> segmente de offset din index; ziua schimbarii are 25 h; afisat "ora logului: UTC+03:00".
4. **Exporturile de sumar (JSON/CSV) foloseau sumarul NEreconciliat** -- exportul putea contine un finding CRITICAL pe care interfata il aratase corectat (ex. "login dupa brute force" fals). -> exportul trece prin aceeasi reconciliere ca interfata; fisierele se numesc `logscan_sumar_*` (sumar) vs `logscan_sel_*cereri.*` (cereri brute).
5. **Export brut fara indicatie de completitudine** -> numele fisierului contine numarul exact (`_8878cereri`) sau `_PRIMELE_din_N` daca s-ar atinge limita de 500.000; headere X-Total-Matched / X-Exported.
6. **Export cu date vechi**: meniul de export era activ in timp ce selectia se recalcula. -> blocat pana cand sinteza selectiei e actualizata; titlul meniului arata numarul de cereri.
7. **"copy" din tabele copia doar randurile afisate (implicit 50)** -> copiaza toate randurile tabelului (cu mesaj).
8. **Filtrul de metoda exista in model dar nu avea control in interfata** -> dropdown "Metoda" din valorile reale ale selectiei; IP si path au sugestii (datalist, max 300, fara a incarca mii de optiuni).
9. **Selectie fara rezultate** -> mesaj explicit + "Reseteaza doar perioada".

## Functii duplicate si decizii
| Duplicat | Decizie |
|---|---|
| Selector zi (header) vs interval | header -> acelasi /period (zi = 00:00:00-23:59:59); filtrul `ts_str_day` ramane acceptat de backend (compatibilitate preseturi vechi), testat identic cu intervalul |
| datetime-local "de la / pana la" | inlocuit de dropdown-uri; inputurile raman ascunse (folosite intern) |
| IP Explorer: zi + "de la ora / pana la ora" + Analizeaza | ascunse; trimitere la selectorul global; presetarile rapide mutate in selectorul global |
| Raw Logs: "Vezi cererile dintr-un moment exact" (zi/ora/granularitate/minut/secunda ±) | = modurile selectorului global; cardul trimite acolo + buton spre cererile brute (Workplace) |
| Export JSON / Export CSV + tip (antet) vs meniul Export al selectiei | un singur meniu (Export ▾ din bara de filtre) cu toate variantele; butoanele din antet ascunse, aceleasi rute |
| Alerte / Incidente / Findings / Traseu (v47-v48) | prezentate o data (incident), restul restranse cu "Semnale asociate" |

## Ce NU s-a schimbat
Motorul de detectie, formatele de export existente (aceleasi coloane), liniile originale (exportul .log copiaza octetii din fisier).

## Teste (tests/test_logscan.py) -- 38/38
- test_v49_perioada_pura: zi, ora, 30/10 min, minut, moment ±N, peste miezul noptii, mai multe zile, ora 24/minut 60/interval inversat/zi inexistenta -> eroare, log cu doua offseturi (ziua de 25 h).
- test_v49_filtre_timp_export_sincron: capetele orei incluse (21:00:00 si 21:59:59 da, 20:59:59/22:00:00 nu), miezul noptii, moment ±1 s, timp AND IP AND cod, OR in acelasi filtru, perioada AND filtrele active, resetarea unui filtru, ziua veche == perioada "o zi", export .log/CSV = exact cererile selectiei (si peste limita de afisare), limita explicita in nume, export sumar == findings din interfata.
- test_v49_performanta_mask_timp: timp + IP + 2 coduri pe 500.000 randuri ~7 ms.
- Browser (Playwright, log cardiomed 88.715 linii): o ora (219 cereri), moment ±30 s (6), interval peste miezul noptii (0 -- confirmat din fisier), zi din header (1.755), zi 12 Oct = 8.878 in Overview, Traffic, Security si in exportul CSV si .log (8.878 randuri, toate din 12 Oct), navigare prin toate cele 11 module cu selectia pastrata, scoaterea unui singur filtru, reset perioada, reset total, 390 px fara scroll orizontal, 0 erori JS.
