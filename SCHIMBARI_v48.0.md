# v48.0 -- Signal First

## Vizibil implicit (Security & Triaj)
- Rezumat executiv compact: interval, cereri, IP-uri unice, incidente de investigat (pe severitati),
  sesiuni/operatii admin confirmate, acces neconfirmat, actiuni admin blocate, cereri de login blocate, de verificat.
- Incidente prioritare (Observat / Interpretare / Certitudine / De ce conteaza / Actiune recomandata / Semnale asociate),
  ordonate dupa severitate -> confirmare -> impactul operatiei -> recenta.
- Evenimente importante: max 5 (pe secventa, nu pe cerere), "Vezi toate evenimentele (N)".
- Urmatorii pasi recomandati, deduplicati, derivati din dovezi.

## Restrans implicit (cu numarul real si buton explicit)
Acces WP admin (detalii), Atacuri pe IP, Alerte brute, Toate semnalele de investigare, Findings tehnice,
Traseu de compromitere, Path-uri scanate, Scanare CMS, Wordfence (cu "verificare INDISPONIBILA" cand e cazul),
Anomalii, Analiza temporala (calculata doar la deschidere). Starea deschis/inchis se tine minte per browser.

## Backend
- GET /api/dataset/{id}/brief (respecta filtrul global `gf`) -- compune doar clasificarile existente.
- Stari explicite: Confirmat din loguri / Suspect / Blocat conform raspunsului HTTP / Neconfirmat / Necesita verificare suplimentara.
- Findings din aceeasi secventa (acelasi IP + regula + severitate, pauza <= 30 min) = un rand; cererile originale raman in evidence.
- Motorul de detectie nu a fost schimbat.

## Teste
35/35 (nou: test_v48_brief_signal_first).
