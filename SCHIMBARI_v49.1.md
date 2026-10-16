# v49.1 -- Atacuri pe filtre
- Sectiune noua "Atacuri pe filtre" in Security & Triaj (vizibila implicit) + incident in "Incidente prioritare" + "Atac pe filtre DA/nu" in rezumat.
- Calcul exact din index, pe selectia globala: cereri de filtrare (IP totale = toate aparitiile), IP-uri unice, IP-uri cu o singura cerere, % din selectie, 2xx/4xx/5xx, varf pe minut, URL-uri tinta cu parametri, tari si interval.
- Lista cu doua moduri: "IP-uri unice" (un rand per IP, cu nr. de cereri) / "Toate cererile"; filtre: tinta, parametru, cod, min. cereri/IP, IP, sortare; incarcare progresiva.
- "Filtreaza toata aplicatia pe aceste cereri", "Exporta cererile atacului (.log)".
- Reguli explicite (afisate): distribuit = >=200 cereri pe un URL tinta din >=30 IP-uri, raport IP/cereri >=0.3; concentrat = un IP cu >=300 cereri; HIGH daca >=2000 cereri sau >=10% 5xx.
- Rute: /filter_attacks, /filter_attacks/requests. Teste: 39/39.
