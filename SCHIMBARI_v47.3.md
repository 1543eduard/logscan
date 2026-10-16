# logscan v47.3: rubrica "Acces WP admin" + fix login prin /wp-login.php/

Se instaleaza peste v47.2.

## 1. Fix de clasificare (important)

`POST /wp-login.php/` (cu slash sau alt PATH_INFO) executa tot wp-login.php,
dar aplicatia verifica doar `endswith("wp-login.php")`. Login-urile facute asa
nu erau recunoscute, deci nici corelarea "login reusit" (POST 302 + /wp-admin/
200). Atacatorii folosesc forma asta tocmai ca sa ocoleasca regulile pe
`wp-login.php` exact. Reparat identic in analiza v42 (`app.py`), indexul SQL
(`triage_engine.py`) si indexul columnar (`triage_columnar.py`); la fel pentru
`xmlrpc.php/`. Logurile trebuie reincarcate ca indexul sa fie refacut.

## 2. Rubrica noua "Acces WP admin" (prima in Security & Triaj)

Doua taburi:

- **Acces reusit**: IP-uri cu login confirmat (admin_login_success) sau cu
  /wp-admin/ 200 fara login vazut (sesiune existenta). Pentru fiecare IP:
  - rezumat in cuvinte: "IP-ul X s-a autentificat CU SUCCES la ..., apoi:
    upload plugin x3 (3 BLOCAT), deschis editorul de teme ...";
  - etichete pe tipuri de actiuni (rosu = critica acceptata de server,
    gri = critica blocata);
  - cronologia doar a cererilor de admin, cu separator "Login reusit", eticheta
    actiunii, cod si rezultat (acceptat / blocat / eroare / 404);
  - "Traseu complet al IP-ului" (panoul din v47.2) si "Deschide in Workplace".
  - Ordine: non-RO primele, apoi dupa actiunile critice acceptate.
- **Incercari de autentificare**: IP-uri cu POST pe wp-login/xmlrpc si fara
  niciun acces reusit: numar, wp-login vs xmlrpc, coduri, interval, ritm/min,
  numar de User-Agent-uri. Click = traseul complet.

Actiuni recunoscute (doar din URL + metoda + cod): upload / instalare /
activare / dezactivare / stergere plugin, upload / instalare / schimbare tema,
editor de plugin-uri si teme (deschis / salvat), creare / modificare
utilizatori, application passwords, upload in Media (async-upload), salvare
setari, import / export, continut, pagini de plugin (admin.php?page=...),
actiuni AJAX. Corpul POST-urilor nu e in access log: "acceptat de server" nu
garanteaza ca operatia a reusit.

API: `GET /api/dataset/{id}/admin_access?gf=...`

## 3. Tabelul de incidente

Redenumit "Incidente - atacuri, traseu cronologic". IP-urile ale caror
evenimente CRITICAL/HIGH sunt doar de autentificare / acces admin nu mai apar
aici (sunt in "Acces WP admin"); un mesaj spune cate au fost mutate. Un IP care
s-a logat SI a avut alt atac (ex. webshell) ramane in ambele.
`/incidents` intoarce in plus `sig_actions`.

## Teste

- Nou: `test_acces_admin_reusit_si_incercari` (secventa reala cu
  `/wp-login.php/`, upload de plugin blocat 403, brute-force) -> 33/33.
- Browser: 300k linii reale + secventa 104.28.245.128 -> IP-ul apare cu
  "LOGIN REUSIT", 3 upload-uri de plugin blocate, editor de teme deschis;
  brute-force-ul apare la "Incercari"; zero erori JS.
