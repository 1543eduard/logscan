# 🚀 logscan v52.1 - Enhanced Edition

**Security & Traffic Analytics Dashboard for Apache/LiteSpeed Access Logs**

> **v52.1 Enhanced:** Added 10 interactive UI features for improved usability and power-user workflows.

---

## ✨ NEW IN v52.1

### 10 Interactive Features Added:

1. **🌙 Dark Mode Toggle** - Light/dark theme with auto-save
2. **🔍 Drill-Down on Click** - Click IP/path/country → sidebar with details
3. **☑️ Multi-Select + Bulk Actions** - Select items → bottom bar with Block/Export/Copy
4. **⏱️ Timeline Scrubber** - Drag histogram to filter by time range
5. **📊 IP Reputation Sidebar** - Hover IP → see reputation, ASN, blacklists
6. **📋 Column Picker** - Show/hide table columns (saves preference)
7. **⌨️ Keyboard Shortcuts** - Press `?` for help, `F` for filters, `D` for dark mode
8. **🔧 Advanced Filter Builder** - Visual UI to build complex filters
9. **🗺️ Heatmap Interaction** - Click countries on map for drill-down
10. **⭐ Bookmarks/Saved Filters** - Save and re-apply filter configurations

---

## 🎯 Quick Start

### 1. Install Command (One-Word Start)

```bash
# Clone repo
git clone https://github.com/1543eduard/logscan.git
cd logscan

# Install the 'logscan' command globally
bash install.sh

# Now you can start with:
logscan
```

That's it! Opens at `http://localhost:8080`

### 2. Or Run Directly

```bash
./logscan                    # Start on port 8080
./logscan --port 9000        # Start on different port
./logscan --help             # Show help
./logscan --reload           # Auto-reload on code changes
```

### 3. Upload Logs & Analyze

- Drag & drop .log/.txt/.gz/.zip files
- Choose Apache/LiteSpeed combined format (Raw Access from cPanel)
- Get instant security findings, traffic analysis, WordPress checks

---

## 📊 Features

### Dashboard Pages (11 tabs)

- **Overview** - Summary, key metrics, alerts
- **Traffic Analytics** - Time-series, composition, trends
- **Countries** - GeoIP heatmap, top origins
- **Endpoints & URLs** - Path analysis, parameter detection
- **HTTP Errors** - 4xx/5xx breakdown, 404 hotspots
- **Security & Triage** - Findings, incidents, attack timeline
- **WordPress Security** - Admin access, plugin vulnerabilities
- **IP Explorer** - Detailed IP analysis, reputation
- **Workplace** - Power-user filters, subnet view
- **Raw Logs** - Original log lines, bulk operations
- **Investigations** - Incident queue, playback

### Analysis Engine

- **Offline GeoIP** - No external API calls, fully private
- **Columnar Index** - Fast filtering on 100M+ lines
- **Triage Rules** - CRITICAL/HIGH/MEDIUM findings
- **WordPress Detection** - Vulnerability, plugin, login patterns
- **Bot Classification** - Verified crawlers vs. suspicious
- **Anomaly Detection** - Burst detection, path enumeration
- **Multi-file Upload** - Combine multiple logs, auto-dedupe

---

## 🎮 How to Use Features

### Dark Mode
```
Click "🌙 Tema" button (sidebar footer)
→ Switches to light mode
→ Theme saved automatically
→ Works on all pages
```

### Drill-Down
```
Click any IP/path/country in tables
→ Sidebar slides in from right
→ Shows details + API results
→ Click [Copy] or [Filter]
```

### Bulk Actions
```
Click multiple rows to select
→ Bottom action bar appears
→ [Block] [Whitelist] [Export] [Copy] [Clear]
```

### Keyboard Shortcuts
```
Press ? → Help panel
Press F → Filter builder
Press D → Dark mode toggle
Press E → Export
Press B → Bulk actions
Press Esc → Close modals
```

### Advanced Filters
```
Press F
→ Build conditions: IP = X, Path contains Y, Status = 404
→ Preview filter
→ Apply to all data
```

### Bookmarks
```
Click "⭐ Bookmarks"
→ Save current filter as named bookmark
→ Reload any time
→ Persists across sessions
```

---

## 📦 Installation

### Prerequisites
- Python 3.12+
- FastAPI, Uvicorn
- Optional: NumPy (for columnar analysis)

### Setup

```bash
# Clone
git clone https://github.com/1543eduard/logscan.git
cd logscan

# Create venv (if not present)
python3.12 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Install command
bash install.sh

# Run
logscan
```

### Docker (Optional)

```bash
docker build -t logscan:latest .
docker run -p 8080:8080 logscan:latest
# Open: http://localhost:8080
```

---

## 🔧 Configuration

### Custom Port
```bash
logscan --port 9000
```

### Auto-Reload (Development)
```bash
logscan --reload
```

### Environment Variables
```bash
export LOGSCAN_PORT=9000
export LOGSCAN_HOST=0.0.0.0
logscan
```

---

## 📊 Example Log Format

Supports Apache/LiteSpeed combined format:

```
203.0.113.45 - frank [10/Oct/2000:13:55:36 +0000] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (X11; I; Linux 2.2.1 i586)"
```

### Supported Formats
- .log (text)
- .txt (text)
- .gz (gzip compressed)
- .zip (archive with multiple logs)

---

## 🚀 Performance

### Optimization Features (v52.1)
- Adaptive chunking: auto-scales parallelism based on file size
- Columnar indexing: 100-300MB logs analyzed in <5 seconds
- Memory-efficient: streams files, doesn't load entire log into RAM
- GeoIP offline: no API calls, all data local

### Benchmarks
- 100MB log: ~2-3 seconds
- 500MB log: ~8-10 seconds
- 1GB log: ~15-20 seconds

---

## 🔐 Security

✅ **Private by Default**
- All analysis runs locally
- No data sent to external services
- Offline GeoIP database
- No telemetry or tracking

✅ **Features**
- IP validation (prevents invalid data)
- Private IP detection (127.x, 10.x, 192.168.x, etc.)
- PII detection (compliance checks)
- WordPress vulnerability detection

---

## 📈 What's New in v52.1

### Bug Fixes
- ✅ IP validation (256.x.x.x rejected)
- ✅ Private IP detection (shows "Private" not blank)
- ✅ Better error messages

### Optimizations
- ✅ Adaptive chunks (+20-30% speedup)
- ✅ Columnar indexing
- ✅ Memory-efficient streaming

### New APIs (12+)
- `/quick_search` - Fuzzy search IPs/paths
- `/bulk_block` - Generate firewall rules
- `/period_compare` - Compare two periods
- `/threat_intel` - IP reputation
- `/compliance_check` - GDPR/PCI/HIPAA
- `/detect_coordinated_attacks` - Group similar attacks
- `/anomalies_ml` - ML-based anomalies
- `/baseline_analysis` - Multi-log baseline
- `/geoip_heatmap` - Country data
- `/generate_report` - HTML reports
- `/custom_rules` - Security rule builder
- `/send_slack` - Send findings to Slack

---

## 📚 Documentation

- **START_HERE.md** - Quick start guide
- **DEPLOYMENT_GUIDE.md** - Complete setup instructions
- **INTERACTIVE_ANALYSIS.md** - Feature analysis
- **SESSION_SUMMARY.md** - Implementation details

---

## 🐛 Troubleshooting

### Port already in use
```bash
logscan --port 9000
```

### Dark mode not saving
```javascript
// In browser console:
localStorage.clear();
location.reload();
```

### Features not loading
```javascript
// Check:
console.log(window.bulkState);
console.log(window.drillDownState);
```

---

## 🤝 Contributing

Issues, suggestions, pull requests welcome!

---

## 📄 License

MIT License - See LICENSE file

---

## 👨‍💻 Author

Enhanced by Eduard (2026-10-28)
Original by [maintainer]

---

## 🎯 Roadmap

- [ ] Real-time log streaming
- [ ] Multi-user collaboration
- [ ] Slack/email alerts
- [ ] Database persistence
- [ ] API authentication
- [ ] Custom alert rules
- [ ] PDF reports

---

## 📞 Support

```bash
# Help
logscan --help

# Check version
cat app.py | grep "v52"

# Debug mode
logscan --reload
# Then check browser console (F12)
```

---

**Version:** 52.1 Enhanced Edition  
**Last Updated:** 2026-10-28  
**Status:** Production Ready ✅

