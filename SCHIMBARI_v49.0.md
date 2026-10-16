# v49.0 -- filtrare temporala, functii unice, export sincronizat
Vezi AUDIT_v49.md pentru inventar, probleme si decizii.
- Selector de perioada din dropdown-uri (tot logul / zi / ora / 30 min / 10 min / minut / moment ± fereastra / de la-pana la), prima/ultima cerere, reset doar perioada, presetari rapide.
- Rute noi: /api/dataset/{id}/time_info, /api/dataset/{id}/period.
- Fus orar pe segmente (logurile cu schimbare de ora); interval inchis, capete incluse.
- Un singur meniu de export, blocat cat timp selectia se recalculeaza; numele fisierului spune cate cereri contine.
- Exporturile de sumar = aceeasi reconciliere ca interfata.
- Filtru Metoda; sugestii IP / path; copy tabel = toate randurile.
- Teste: 38/38.
