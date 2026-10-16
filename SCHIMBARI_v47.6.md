# v47.6 -- coerenta intre sectiuni (verificat pe cardiomed.clinic-ssl_log-Oct-2026)

## O singura sursa de adevar
- `_admin_compute()` clasifica fiecare IP o singura data (login / sesiune / neconfirmat / incercari);
  "Acces WP admin", Alerte critice, Incidente, Findings, Traseu de compromitere, Activitate admin,
  IP-uri suspecte si Coada de investigare folosesc toate aceasta clasificare.

## Acces WP admin
- Un 200 nu mai e considerat dovada de autentificare daca are dimensiunea paginii generice a site-ului
  (servita pe >=10 cai diferite). Exemplu: 180.243.0.174, unde /wp-json/wp/v2/users/me a intors 200 cu 158.177 octeti,
  adica pagina publica -> ramane NECONFIRMAT, cu "Indicii (nu sunt dovada)".
- Operatiile sunt marcate CONFIRMAT doar cand WordPress redirectioneaza pe pagina de succes
  (?update=del&delete_count=N, ?settings-updated=true, ?activate=true, ?updated=1).
  Un 2xx/302 singur apare ca "raspuns 302", nu ca "acceptat".
- GET users.php?action=delete = pagina de confirmare (fara efect), nu stergere.
- Deschiderea editorului de teme/plugin-uri = pagina sensibila doar afisata, nu actiune critica.
- Tinte vizibile: plugin activat (wordfence), ID-uri utilizatori, pagina de setari.

## Alerte critice
- Un card per IP, cu severitatea maxima; semnalele aceluiasi IP apar in card ("+ ... aceeasi sesiune/IP").
- Accesul neconfirmat e retrogradat la MEDIUM in index (columnar SI SQL), deci nu apare nici in alerte, nici in cronologie ca HIGH.

## Incidente
- Separarea atac / doar-autentificare se face in backend; antetul = numarul de randuri (1).
  Restul de 32 IP-uri sunt mentionate pe categorii sub tabel.

## Analiza detaliata (reconciliata)
- "Posibil login reusit dupa brute force" (149.36.51.165, CRITICAL) era fals: 200 pe /wp/xmlrpc.php (cale fara WordPress)
  -> LOW, "verificat: NU e login reusit".
- Brute force: arata cate incercari au fost pe WordPress real (11) si cate pe cai fara WordPress (73).
- Traseu de compromitere: aceeasi cerere nu mai e numarata de 2-3 ori; loginurile sunt numarate corect (2x / 1x, nu 4x / 2x).
- Activitate admin (WordPress Security): fara dublura "Login reusit (302)"; sondarile pe cai fara WordPress sunt etichetate ca atare.
- IP-uri suspecte: riscul urmeaza findingurile reconciliate si alertele (104.28.245.128 CRITICAL, 149.36.51.165 MEDIUM, 128.127.127.33 MEDIUM).
- Tabelul de loginuri: CONFIRMAT / NECONFIRMAT (doar 302) in loc de HIGH / MEDIUM.

## Teste
- 34/34 (nou: test_v476_coerenta_intre_sectiuni).
