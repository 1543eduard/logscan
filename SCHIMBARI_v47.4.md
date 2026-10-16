# logscan v47.4: fara alarme false in "Acces WP admin" si in incidente

Se instaleaza peste v47.3. **Logurile trebuie reincarcate** (clasificarea se
aplica la indexare).

## 1. Sondari pe cai fara WordPress (ex. 149.36.51.165 pe /xml/wp-admin/)
Multe site-uri raspund 200 la orice URL (pagina generica / soft-404). Un
scanner care cere /xml/wp-admin/ primea 200 si aparea ca "acces admin" (HIGH).
Acum WordPress e considerat existent doar la: radacina, prefixele cu login
confirmat si prefixele unde >= 2 IP-uri au primit 302 pe wp-admin/wp-login.
Pe celelalte prefixe, evenimentele devin `wp_probe` (LOW, "Sondare wp-admin/
wp-login pe o cale fara WordPress"). Nu mai apar in "Acces reusit", in alerte
sau in incidente; rubrica spune cate cereri si pe ce cai au fost tratate asa.

## 2. Fisiere publice din /wp-admin/ nu mai inseamna acces in admin
load-styles.php, load-scripts.php, admin-ajax.php, admin-post.php, install.php,
upgrade.php, setup-config.php, repair.php si fisierele statice (.css, .js,
imagini, fonturi) raspund 200 si fara autentificare (le incarca chiar pagina
de login). Un 200 pe ele nu mai e "Acces /wp-admin/ (200)" si nici nu mai
confirma un login. Exemplu eliminat: Googlebot pe /wp-admin/install.php.

## 3. "Activitate admin confirmata" nu mai include incercarile de login
In traseul de compromitere (analiza v42), orice POST pe wp-login.php era
"Activitate admin confirmata". La WordPress, POST cu 200 = parola respinsa.
Categorie noua: **"Incercare de autentificare"** (login_attempt). Un 200 pe
/wp-admin/ fara login confirmat devine "Cerere suspecta".

## 4. Tabelul de incidente = doar atacuri
Raman doar IP-urile cu un eveniment CRITICAL/HIGH care nu tine de
autentificare, sau cu traseu "Incercare de atac" / "Compromitere confirmata".
Login-urile reusite, incercarile si accesele admin sunt doar in "Acces WP admin".
Tabelul "Incercari de autentificare" are coloana noua "302 fara acces".

## Teste
33/33 (testul de acces admin acopera acum si /xml/wp-admin/ si categoria
login_attempt). Browser pe 300k linii reale: "Acces reusit" 15 -> 10 IP-uri
(8 login confirmat + 2 sesiuni reale), incidente 32 -> 2 atacuri reale,
zero erori JS.
