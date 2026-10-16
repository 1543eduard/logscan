# logscan v47.2: Incidente - traseu cronologic

Se instaleaza peste v47. Nu exista reguli sau clasificari noi: rubrica doar
regrupeaza pe IP datele calculate deja (compromise_trail din analiza,
severitate / action_type / label din indexul columnar).

## Backend (app.py)

- `GET /api/dataset/{id}/incidents?gf=...`
  - IP-urile din compromise_trail care au cereri in selectie + IP-urile cu cel
    putin un eveniment CRITICAL/HIGH in selectie.
  - Per IP: tara, categoria dominanta, primul eveniment semnificativ (cel mai
    vechi CRITICAL/HIGH: ora, action_type, label, URL, cod), cereri inainte /
    dupa, POST-uri dupa pe clase de cod (2xx/3xx/4xx/5xx), evenimente pe
    severitate, prima / ultima cerere.
  - Sortare: risk_score, apoi severitatea maxima.
- `GET /api/dataset/{id}/ip_trail?ip=...&gf=...&only=all|significant&limit=5000`
  - Toate cererile IP-ului din selectie, crescator (timp, id).
  - Per cerere: ts, secunde fata de cererea anterioara, metoda, URL, cod,
    marime, UA (+ marcaj "UA nou"), severitate, action_type, label, linia
    bruta citita din fisier prin off/ln, faza "inainte" / "dupa".
  - `significant` = severitate >= MEDIUM + toate POST-urile.
  - `limit` maxim 20000; raspunsul spune `truncated` daca s-a taiat.
- Doar index columnar: fara numpy, ambele rute raspund 409 cu mesaj clar.
- Liniile brute complete ale IP-ului se iau prin `POST /workplace/raw` existent,
  cu `{"field":"ip","op":"in","values":[ip]}`.
- `/api/version` -> `47.2`.

## Frontend (dashboard.html)

- Card nou, primul in "Security & Triaj": tabel cu IP-urile (IP, tara,
  categorie dominanta, primul eveniment semnificativ, cereri dupa, POST-uri
  dupa 2xx/4xx, severitate maxima) + cautare dupa IP.
- Click pe rand -> panou de detaliu sub tabel:
  - antet: IP, tara, interval, cereri, User-Agent-uri, rezumatul existent din
    compromise_trail;
  - cronologie verticala cu fiecare cerere: ora, +delta, metoda, URL, cod
    colorat, severitate, label;
  - separator "Primul eveniment semnificativ" intre fazele "inainte" / "dupa";
  - comutator "Toate cererile / Doar semnificative";
  - click pe o cerere -> linia bruta + "Copiaza linia";
  - "Copiaza toate liniile brute", "Descarca .log", "Deschide in Workplace"
    (filtrat pe IP, sortat crescator).
- Respecta selectia globala (perioada + filtre), se reincarca prin GF_LISTENERS.

## Teste

- Nou: `test_incidente_si_traseu_ip` -- ip_trail intoarce toate cererile
  fiecarui IP, crescator, cu linia bruta identica cu fisierul; /incidents
  contine toate IP-urile cu CRITICAL/HIGH. Total: 32/32.
- Verificat in browser pe logul real ariesul.ro (2.653.601 linii): 67 IP-uri,
  tabel ~1 s, detaliu IP 0,1 s, descarcare = toate liniile IP-ului, filtrul
  tara=RO reincarca lista (67 -> 5), zero erori JS.
