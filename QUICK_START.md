# LOGSCAN v3 - Quick Start Guide

## Start the Server

```bash
logscan
```

You'll see:
```
==================================================
 logscan v52.1 pornit
 Deschide in browser:  http://91.200.123.86:21059
 Se opreste cu Ctrl+C
==================================================
```

## Use the New Upload Page (Recommended)

**Go to:** `http://91.200.123.86:21059/upload`

### Steps:
1. **Drag & drop** your log file onto the purple area
   - OR click "Select File" button
2. **Click** "Upload & Analyze" button
3. **Wait** for analysis (usually 1-3 seconds)
4. **View results** - shows total requests, IPs, bandwidth, threat level
5. **Click** "Go to Dashboard" to access all 20 features

## Use the Main Dashboard

**Go to:** `http://91.200.123.86:21059/` (root)

All 20 interactive features available:
- Extract all IPs with threat scoring
- Real paths analysis
- HTTP status distribution
- Attack pattern detection
- Geolocation mapping
- And 15 more...

## Supported Log Formats

- **Apache/cPanel combined format** (most common)
- **Plain text** (.log, .txt)
- **Compressed** (.gz)
- **Archives** (.zip)
- **Multiple files** - combine in one upload

## Supported File Sizes

- Typical: 1 - 500 MB (processes in seconds)
- Large: up to 1 GB (may take 30+ seconds)
- Very large: split into multiple files

## What Gets Analyzed

### Automatic Detection
- HTTP request methods (GET, POST, PUT, etc.)
- Response status codes (200, 404, 401, etc.)
- URLs and paths requested
- Source IP addresses
- Request size/bandwidth

### Security Analysis
- SQL injection attempts
- XSS (cross-site scripting) patterns
- Path traversal attacks
- Shell upload attempts
- Admin login attempts
- Bot/crawler detection

### Geographic Analysis
- Country of origin per IP
- Regional attack distribution
- Legitimate vs suspicious regions

## Results Interpretation

| Metric | Meaning |
|--------|---------|
| **Total Requests** | How many HTTP requests in the log |
| **Unique IPs** | Number of different source addresses |
| **Unique Paths** | Number of different URLs/pages accessed |
| **Bandwidth** | Total data transferred (GB/MB/KB) |
| **Threat Level** | Overall security risk assessment |

## Keyboard Shortcuts

Inside dashboard (after upload):
- **?** - Show all shortcuts
- **/**  - Focus search box
- **n** - Next page
- **p** - Previous page

## Common Tasks

### Upload a Log
1. Open `/upload`
2. Drag and drop access.log
3. Wait for results

### Analyze Security
1. Click "Attack Patterns" feature
2. View SQL injection attempts
3. View XSS attempts
4. View path traversal attempts

### Block Bad IPs
1. Click "Firewall Rules Generator"
2. Select IP address(es)
3. Choose format (Nginx/Apache/iptables/UFW)
4. Copy the generated rules
5. Apply to your firewall

### Export Results
1. Click "Download IPs" feature
2. Select IPs from the list
3. Download as .txt file
4. Use in your firewall/WAF

### View Timeline
1. Click "Attack Timeline" feature
2. Scroll through attack progression
3. See when attacks occurred
4. Identify patterns over time

## Troubleshooting

### Server won't start
```bash
# Check if port is in use
netstat -tlnp | grep 21
# Kill existing process if needed
pkill -f app.py
```

### File upload fails
- Check file size (under 1GB)
- Verify file is valid log format
- Try the upload page instead: `/upload`

### Results show all zeros
- Ensure log file has actual content
- Check if log format is Apache combined
- Try uploading a different log file

### Browser shows 404
- Verify server is running
- Check correct URL with port number
- Try `http://127.0.0.1:21059` if using localhost

## Support

**Documentation:** See `UPLOAD_GUIDE.md` for detailed upload methods

**User Manual:** See `LOGSCAN_USER_MANUAL.md` for all 20 features

**Issues:** Check server logs for error messages

---

**Version:** 52.1  
**Last Updated:** 2026-10-28  
**Status:** Production Ready ✅
