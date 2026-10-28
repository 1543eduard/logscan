# LOGSCAN Upload Guide

## Quick Start

Two upload methods are available:

### Method 1: New Clean Upload Page (RECOMMENDED)
**URL:** `http://your-server:port/upload`

This is a completely separate, simplified upload interface:
- ✅ Clean, modern design
- ✅ Drag & drop support
- ✅ Instant analysis results display
- ✅ No complex dependencies
- ✅ Mobile-friendly responsive layout

**Steps:**
1. Open `/upload` in your browser
2. Drag & drop your log file OR click to select
3. Click "Upload & Analyze"
4. View results immediately
5. Click "Go to Dashboard" to explore all 20 interactive features

---

### Method 2: Dashboard Upload
**URL:** `http://your-server:port/` (root)

The main dashboard includes upload plus all interactive analysis features:
- 20 interactive features in sidebar
- Advanced filtering and analysis tools
- Session management and favorites
- Export functionality

**Steps:**
1. Open the dashboard
2. Use drag & drop area or click upload button
3. Browse interactive features in sidebar

---

## Upload Methods Comparison

| Feature | New Upload Page | Dashboard |
|---------|-----------------|-----------|
| Drag & Drop | ✅ Yes | ✅ Yes |
| Form Upload | ✅ Yes | ✅ Yes |
| Results Display | ✅ Quick Preview | ✅ Full Analysis |
| Sidebar Features | Link to Dashboard | ✅ All 20 Features |
| Mobile-Friendly | ✅ Yes | ✅ Yes |

---

## Supported Formats

All methods support:
- **Plain text:** `.log`, `.txt`
- **Compressed:** `.gz`, `.zip`
- **Archives:** Multiple files in one upload
- **Size limit:** Configurable, typically 1GB

---

## What Happens After Upload

### 1. File Processing
- Log file is parsed once across all CPU cores
- Creates indexed dataset in memory
- Analysis runs in parallel for speed

### 2. Results
- **Total Requests:** Count of all HTTP requests
- **Unique IPs:** Number of distinct source IPs
- **Unique Paths:** Number of different URLs requested
- **Bandwidth:** Total bytes transferred
- **Threat Level:** Quick security assessment

### 3. Interactive Features (20 Total)
Once uploaded, access the full dashboard for:
- Extract all IPs with threat scoring
- Real paths analysis (no domain spam)
- HTTP status code distribution
- Attack pattern detection
- Geolocation mapping
- And 15 more advanced features...

---

## Troubleshooting

**Upload button not responding:**
- Try the new upload page at `/upload`
- Check browser console for errors (F12 → Console)
- Verify file size is under limit

**Results not displaying:**
- Ensure log file is in standard Apache/cPanel format
- Try a different browser
- Check server logs for errors

**Connection refused:**
- Verify server is running: `logscan`
- Check firewall allows the port
- Try localhost if using VPS

---

## Technical Details

- **Backend:** FastAPI with Uvicorn
- **Upload Endpoint:** `POST /api/upload`
- **Response Format:** JSON with dataset_id and summary
- **Processing:** Multicore parallel analysis
- **Storage:** Ephemeral (cleared on server restart)

---

## Examples

### Start Server
```bash
logscan
# Server: http://91.200.123.86:21059
```

### Access Upload Page
```
http://91.200.123.86:21059/upload
```

### Upload via Command Line
```bash
curl -X POST http://localhost:21059/api/upload \
  -F "files=@access.log"
```

---

Last updated: 2026-10-28
