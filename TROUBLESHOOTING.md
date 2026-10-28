# LOGSCAN Upload - Troubleshooting Guide

## Problema: "Analyzing..." dar nimic nu se incarca

### Posibilile cauze si solutii

---

## 1. ✅ Test Upload Endpoint

Incearca **diagnostic script**:

```bash
cd /path/to/logscan
./test_upload_real.sh
```

Aceasta va:
- Verifica daca serverul ruleaza
- Testeaza `/upload` page
- Testeaza `/api/upload` endpoint
- Arata timingul exact
- Arata raspunsul serverului

---

## 2. 🔍 Diagnoza: "Analyzing..." hangs

Daca progresul nu avanseaza:

### Cauza A: Fisier prea mare
- **Simptom:** "Analyzing..." ramane > 30 secunde
- **Solutie:** Spliteaza fisierul
  ```bash
  split -l 50000 access.log access_part_
  # Incarc access_part_aa, access_part_ab, etc
  ```

### Cauza B: Format fisier gresit
- **Simptom:** Incarc, dar nimic nu se apare
- **Solutie:** Verifica formatul log-ului

```bash
# Apache Combined Format (SUPORTAT)
head -1 access.log
# Output trebuie sa arate asa:
# 91.200.123.86 - - [28/Oct/2026:15:10:00 +0000] "GET / HTTP/1.1" 200 4096 "-" "Mozilla/5.0"

# SSL Access Log (SUPORTAT)
head -1 sslaccesslog_stirilebanatului.ro_10_27_2026
# Output trebuie sa arate asa:
# 91.200.123.86 - - [28/Oct/2026:15:10:00 +0000] "GET / HTTP/1.1" 200 4096 "-" "Mozilla/5.0"
```

### Cauza C: Server prea incarcata
- **Simptom:** Timeout la 2 minute
- **Solutie:** Asteapta ca server sa se elibereze sau restart-eaza

```bash
# Verifica CPU/RAM
ps aux | grep app.py

# Restart server
# Apasa Ctrl+C in terminal unde ruleaza logscan
logscan
```

### Cauza D: Browser tab timeout
- **Simptom:** Buton se dezactiveaza dar nimic nu se intampla
- **Solutie:** Verifica server logs
  ```bash
  # Intr-un alt terminal:
  tail -f /tmp/*.log
  ```

---

## 3. 📋 Formate de Fisiere Suportate

### ✅ Suportat
- **Apache Combined Format** (cea mai comuna)
  ```
  IP - - [DATE] "METHOD PATH HTTP/1.1" STATUS SIZE "-" "USERAGENT"
  ```

- **cPanel SSL Access Log**
  ```
  sslaccesslog_stirilebanatului.ro_10_27_2026
  (aceasta are Apache Combined Format inauntru)
  ```

- **Fisiere Comprimate**
  - `.gz` (gzip)
  - `.zip` (archive)
  - Sunt decompresate automat

- **Fisiere Multiple**
  ```
  Poti incarca mai multe fisiere deodata!
  upload.html accepta drag & drop pe mai multe
  ```

### ❌ Nu este suportat (inca)
- Nginx JSON logs
- Apache JSON format
- IIS W3C format

---

## 4. 🧪 Test Manual (Command Line)

Incearca direct cu curl:

```bash
# 1. Gaseste portul serverului
PORT=9142  # sau orice port vei vedea cu 'logscan'

# 2. Testeaza upload
curl -X POST http://127.0.0.1:$PORT/api/upload \
  -F "files=@sslaccesslog_stirilebanatului.ro_10_27_2026"

# Output trebuie sa arate asa:
# {"dataset_id": "abc123...", "filename": "...", "summary": {...}}
```

Daca vei vedea JSON response cu `dataset_id`, **serverul lucreaza corect!**

---

## 5. 🔧 Debug Info

### Verifica ca serverul ruleaza

```bash
# Cauta procesul Python
ps aux | grep logscan

# Sau verifica portul
netstat -tlnp | grep 21
```

### Verifica logs-urile serverului

Cand incarci, ar trebui sa vada ceva similar:

```
[timing] index_columnar=0.001s randuri=100 login_ok=5 ram=50MB merge=0.1s
```

---

## 6. 📊 Cum Sti Ca Lucreaza

### ✅ Semne de Succes

1. **Durante incarcarii:**
   - Buton "Upload & Analyze" devine disabled
   - Apare progress bar animat
   - Vede: "Uploading: filename.log"
   - Vede: "MB - Processing with parallel analysis..."

2. **Dupa incarcare:**
   - Status verde: "✅ Analysis complete in 2.5s!"
   - Apare "Analysis Results" cu metrici:
     - Total Requests: 1000+
     - Unique IPs: 50+
     - Unique Paths: 200+
     - Threat Level: Medium/High
   - Buton: "Go to Dashboard"

### ❌ Semne ca Ceva Nu E OK

1. Status rosu: "❌ Error: ..."
   - Verify format fisier
   - Check server ruleaza

2. Timeout dupa 2 min: "❌ Timeout after 120s..."
   - Fisier prea mare
   - Server prea incarcata

3. Status ramane albastru: "Analyzing..."
   - Check server logs
   - Verifica browser console (F12)

---

## 7. 🚨 Urgent Check: Probleme Frecvente

| Problema | Cauza | Solutie |
|----------|-------|---------|
| "Analyzing" infinit | Server hangs | Ctrl+C, logscan |
| Timeout la 2 min | Fisier mare | Split fisier |
| 404 Not Found | Url gresit | http://ip:port/upload |
| "Error: Server error" | /api/upload nu raspunde | Check server logs |
| JSON error | Format fisier gresit | Verifica format |

---

## 8. 💡 Pro Tips

### Uploaduri Rapide
```bash
# Testeaza cu fisier mic
head -1000 access.log > test_small.log
# Incarc test_small.log
# Verifica ca merge
# Apoi incarc fisierul mare
```

### Compresie
```bash
# Comprima inainte de upload
gzip -k sslaccesslog_stirilebanatului.ro_10_27_2026
# Aceasta creeaza: sslaccesslog_stirilebanatului.ro_10_27_2026.gz
# Upload .gz direct!
```

### Multiple Files
```bash
# Poti incarca multiple fisiere deodata
# Drag & drop mai multe fisiere in zone
# SAU ctrl+click sa selectezi mai multe
```

---

## 9. 📞 Support

Daca nici nimic nu merge:

1. **Rula test script:**
   ```bash
   ./test_upload_real.sh
   ```

2. **Verifica output, noteaza:**
   - Port serverului
   - Eroare specifica
   - Timing

3. **Check server logs:**
   ```bash
   ps aux | grep app.py
   # Verifica daca procesul ruleaza
   ```

---

## 10. ✨ Versiune Actualizata

Upload.html are acum:
- ✅ Progress bar animat
- ✅ Afiseaza file size
- ✅ Afiseaza duration (cate secunde)
- ✅ Timeout dupa 2 minute cu mesaj clar
- ✅ Support pentru .gz si .zip
- ✅ Mesaje error mai bune

**Data Update:** 2026-10-28

---

## Urmatorul Pas

Dupa ce uploadul merge:
1. Mergi pe `/` (root) pentru Dashboard
2. Vei vedea 20 interactive features
3. Poti analiza loguri complet
