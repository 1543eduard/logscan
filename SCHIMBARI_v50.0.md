# v50.0 -- interfata curatata, activitate automata, linii raw complete, upload comprimat

## Investigations
- Scoasa rubrica "Elemente / Notite / Concluzii" (spatiul de investigatie) si toate intrarile spre ea: butonul "Investigatie" din bara, "Adauga la investigatie" din meniul contextual si din panoul de explorare, paleta de comenzi, tasta I. Pagina pastreaza rapoartele, regulile de blocare si exportul.

## Raw Logs
- Coloana "Actiune / Severitate" -> "Semnal": traficul obisnuit (INFO normal / INFO non_ro) nu mai e afisat pe fiecare rand ("–"); raman severitatile peste INFO, login-urile reusite si actiunile clasificate.
- User-Agent mai lat in tabel; vedere noua "Linii originale": fiecare cerere exact cum e in fisier, rupta pe mai multe randuri (UA intreg), cu derulare care incarca restul.
- "Copiaza liniile afisate", "Copiaza toata selectia" (pana la 50.000 de linii, ordine cronologica), "Descarca .log" (toata selectia).

## Workplace
- Conditii noi, calculate pe selectie: varf cereri / minut / IP (ip_rpm), % erori 4xx / IP (ip_err), User-Agent-uri diferite / IP (ip_uas), cereri / subnet /24 sau /64 (subnet_hits).
- Grup nou de preseturi "Boti, scanari si scraping" (16): scraping, scraping catalog, rafale, scanare automata, rotatie UA, atac distribuit pe subnet, atac pe filtre (si distribuit), scanare plugin-uri, enumerare utilizatori WP, xmlrpc, scanere de vulnerabilitati, unelte de scanare, scripturi, admin-ajax in rafala, boti declarati neverificati.
- Ghid sub conditii: ce face fiecare filtru, cu 38 de exemple concrete aplicabile dintr-un click (Shift+click = adauga).

## Security & Triaj
- Sectiune noua "Activitate automata: boti, scanari, scraping" (vizibila implicit): 11 categorii cu reguli explicite (workplace.AUTOMATION), cereri, IP-uri, top IP-uri cu tara; "Workplace" deschide exact aceleasi conditii. Ruta: /api/dataset/{id}/automation.
- "Incidente prioritare": un rand compact per incident (severitate, IP, tara, tip, stare, nr. semnale, interval), detaliile la click; primele 10 + "Arata toate". Cardul a scazut de la ~39.500 px la ~1.500 px pe logul de test.
- "Urmatorii pasi recomandati": pasii identici pentru IP-uri diferite sunt grupati (o fraza + lista IP-urilor).
- "Alerte brute ale motorului" -> "Detectii pe IP (CRITICAL / HIGH)", cu explicatie.

## Countries
- Steaguri SVG (flag-icons 7.6.0, MIT, static/flags/, servite local de /static/flags/{cc}.svg) in Countries, Overview, Raw, Workplace, panoul de explorare, tabelele vechi si incidente. Emoji-urile de steag nu apar pe Windows, de aceea SVG.

## Viteza
- Upload: browserul comprima fisierul cu gzip, bucata cu bucata (CompressionStream), si comprima bucata urmatoare cat se trimite cea curenta; serverul primeste un gzip multi-membru. Pe logul de test: 66 MB -> 6,2 MB trimisi; la 20 Mbit/s upload-ul scade de la 28,1 s la 3,3 s. Fisierele deja comprimate (.gz/.zip) se trimit ca inainte. Interfata comprima doar daca serverul anunta "upload_gzip" in /api/version.
- Parsarea: serverul (container Virtuozzo) are o cota de 1 nucleu (cpu.cfs_quota_us = 100000 / 100000, masurat: 8 procese = 8x timpul unuia). Motorul paralelizeaza deja automat pe toate nucleele din cota; mai multe nuclee alocate containerului = parsare aproape proportional mai rapida. Profilare: costul e distribuit (parserul de linie ~6 us/linie, ~12% din total), nu exista un punct unic de optimizat.

## Teste
- tests/test_logscan.py: 40/40 (nou: test_v50_comportament_automat).
- tests/ui_v50.py (nou): 6/6. ui_smoke 14/14, ui_v46 10/10, ui_xss trece (si pe vederea "Linii originale"), ui_v45 13/15 -- cele 2 esecuri ("alerta din Triaj", "cronologia de securitate") apar identic si pe v49.1.

## v50.0 (completare) -- Atac pe filtre PrestaShop, Retele in IP Explorer
- Atac pe filtre: recunoaste si filtrele PrestaShop (?q=Fateta-valoare[/Fateta2-valoare], ?order=product.*, selected_filters). q= simplu (cautare) nu conteaza. Pe un log real: 20.748 cereri din 19.849 IP-uri pe /2-acasa, raportate inainte "nu", acum HIGH distribuit.
- IP Explorer -> "Retele: IP-uri unice grupate": IP-urile cu o singura cerere (sau <= 3 / <= 10 / oricate) grupate pe furnizor (ASN), bloc de retea, /24 (IPv6 /48) sau /16 (IPv6 /32); per grup IP-uri, cereri, tari, URL dominant, 5xx, interval, CIDR-uri (copiere); tip cloud / rezidential; concluzie automata (ex. retea de proxy-uri rezidentiale -> blocarea pe IP nu ajuta). Ruta: /api/dataset/{id}/networks.
- Baza ASN: geoip/geoip2fast-asn-ipv6.dat.gz (GeoLite2 ASN prin geoip2fast, release LATEST, IPv4 + IPv6), verificata inainte de folosire: pickle fara niciun opcode de apel (GLOBAL/REDUCE/...), doar date. Incarcata doar la prima folosire (~0,8 s, ~190 MB RAM); uploadul si parsarea nu o folosesc.
- Workplace: conditie noua "Furnizor (ASN)" (este / contine); "Workplace" din Retele deschide exact aceleasi IP-uri (verificat pe 120 de grupuri: 0 diferente).
- Teste: 42/42 unitare (noi: test_v50_atac_pe_filtre_prestashop, test_v50_retele_ip_unice), ui_v50 7/7, ui_xss trece.
