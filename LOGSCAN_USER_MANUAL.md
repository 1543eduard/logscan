# 📖 LOGSCAN v3 - COMPLETE USER MANUAL

**Version:** 3.0  
**Date:** 2026-10-28  
**Status:** Production Ready ✅

---

## 🎯 OVERVIEW

LOGSCAN is a security and traffic analytics platform for Apache/LiteSpeed access logs. It provides **20 interactive features** for comprehensive log analysis, threat detection, and security management.

### Quick Start
1. Start: `logscan` (or `/tmp/opencode/logscan-git/logscan`)
2. Open: http://localhost:8080 (or http://YOUR_IP:PORT)
3. Upload: Drag & drop your .log, .txt, .gz, or .zip file
4. Analyze: Click buttons in sidebar to analyze

---

## 🌟 ALL 20 FEATURES EXPLAINED

### GROUP 1: IP ANALYSIS (Features 1-3)

#### 1️⃣ Extract All IPs
**What:** Shows every unique IP address in the log.

**Features:**
- 🔍 **Live Search** - Type to filter IPs instantly
- 🎯 **Threat Badges** - Color-coded risk (🔴CRITICAL, 🟠HIGH, 🟡MEDIUM, 🟢LOW)
- 📋 **Copy Button** - Click to copy any IP to clipboard
- 📊 **Request Count** - How many requests from each IP
- 🔗 **Clickable** - Click IP for detailed information

**When to Use:**
- Identify sources of traffic
- Find suspicious IPs
- Build firewall rules
- Investigate traffic patterns

**Example:** 
```
Search "93.119" → Shows all IPs starting with 93.119
Click 93.119.227.190 → See details about this IP
Click Copy → IP is in your clipboard
```

---

#### 2️⃣ Real Paths
**What:** Lists all actual URLs/paths accessed in your logs.

**Features:**
- 🔍 **Sort Options** - By frequency, alphabetical, or admin paths first
- ⚠️ **Admin Highlight** - Paths with /admin, wp-admin, etc shown in red
- 📄 **Type Icons** - 🔧 .php, ⚠️ admin, 🔐 login, 📄 regular
- 📊 **Request Count** - How many times each path was accessed
- **Fixed:** No more domain spam (only real paths with /)

**When to Use:**
- Understand what endpoints are being hit
- Identify WordPress or admin panel attacks
- Find application vulnerabilities
- Monitor parameter injection attempts

**Example:**
```
See: /wp-admin (⚠️ admin path)
See: /api/users (vulnerable endpoint?)
See: /index.php?id=1 (parameter injection?)
```

---

#### 3️⃣ HTTP Status Codes
**What:** Shows distribution of response codes.

**Features:**
- 📊 **Visual Bar Chart** - See distribution at a glance
- 🎨 **Color Coded**:
  - 🟢 2xx = Success (Green)
  - 🔵 3xx = Redirect (Blue)
  - 🟠 4xx = Client Error (Orange)
  - 🔴 5xx = Server Error (Red)
- 📈 **Percentages** - What % of requests got each code
- 🔍 **Interactive** - Hover for details

**When to Use:**
- Monitor application health
- Detect 404 attacks (path enumeration)
- Find configuration issues
- Diagnose server problems

**Example:**
```
200: 1,234 (85%) ← Good
404: 156 (11%) ← Path enumeration attack?
500: 45 (3%) ← Server errors
```

---

### GROUP 2: THREAT DETECTION (Features 4-6)

#### 4️⃣ Attack Patterns
**What:** Automatically detects common attack types.

**Detects:**
- 💉 **SQL Injection** - union, select, drop, where, injection keywords
- 🔓 **XSS** - <script>, onerror, onclick, javascript, onload
- 📂 **Path Traversal** - .., %2e%2e, etc/passwd, ../
- 🔐 **Admin Access** - wp-admin, admin, phpmyadmin
- ⚡ **Shell/RCE** - .php, .sh, shell, exec, system

**Features:**
- 🎯 **Icon Indicators** - Easy to spot attack type
- 📊 **Count** - How many of each attack detected
- 🔍 **Click for Details** - Understand the threat
- ✅ **Green Alert** - If no attacks found

**When to Use:**
- Identify active attacks
- Understand attack vectors
- Prioritize response
- Generate security reports

**Example:**
```
🚨 Found:
💉 SQL Injection: 5 attempts
🔓 XSS: 2 attempts
⚡ Shell access: 1 attempt
→ Action: Block these IPs immediately
```

---

#### 5️⃣ Geolocation Analysis
**What:** Shows which countries traffic is coming from.

**Features:**
- 🌍 **Country Mapping** - Identify geographic sources
- 📊 **Request Distribution** - How much traffic per country
- 🇺🇸 **Flag Context** - Understand source locations
- 🎯 **Top Sources** - Prioritize investigation

**When to Use:**
- Detect unusual geographic patterns
- Identify DDoS origins
- Monitor international traffic
- Compliance geo-restrictions

**Example:**
```
USA: 500 requests (40%)
Russia: 300 requests (25%) ← Suspicious?
Afghanistan: 150 requests (12%) ← Investigate?
```

---

#### 6️⃣ Threat Score
**What:** Assigns risk score (0-100) to each IP based on behavior.

**Risk Levels:**
- 🟢 **0-25: Low** - Minimal threat
- 🟡 **26-50: Medium** - Monitor
- 🟠 **51-75: High** - Review & prepare action
- 🔴 **76-100: Critical** - Block immediately

**Features:**
- 📊 **Visual Progress Bar** - Quick risk assessment
- 🎯 **Top 15** - See most dangerous IPs first
- 🧮 **Score Calculation** - Based on request frequency
- 🎨 **Color Coded** - Green to red by severity

**When to Use:**
- Prioritize which IPs to block
- Make quick security decisions
- Understand overall threat level
- Create action priority

**Example:**
```
🔴 93.119.227.190: Score 95/100 CRITICAL
   └─ 47 requests → BLOCK NOW
🟠 74.125.218.194: Score 58/100 HIGH
   └─ 12 requests → Review
🟡 86.124.204.112: Score 32/100 MEDIUM
   └─ 5 requests → Monitor
```

---

### GROUP 3: EXPORT & RULES (Features 7-8)

#### 7️⃣ Download IPs as Text
**What:** Exports all IPs to a .txt file.

**Features:**
- 📥 **Auto-Download** - Download starts automatically
- 📄 **Plain Text** - One IP per line
- 📊 **Request Counts** - Shows "IP (count)"
- 📅 **Dated Filename** - logscan_ips_2026-10-28.txt

**Format:**
```
93.119.227.190 (47 requests)
74.125.218.194 (12 requests)
86.124.204.112 (5 requests)
...
```

**When to Use:**
- Import to spreadsheet analysis
- Share with team
- Document findings
- Archive for compliance

---

#### 8️⃣ Firewall Rules Generator
**What:** Auto-generates firewall rules to block dangerous IPs.

**Supported Formats:**
- **Nginx** - `deny IP;` format
- **Apache** - `Require not ip IP` format
- **iptables** - Linux firewall rules
- **UFW** - Ubuntu firewall rules

**Features:**
- 🔄 **Format Switcher** - Change output format live
- 🔥 **Auto-Generation** - Copy-paste ready
- ⚙️ **Intelligent Filtering** - Only includes IPs with 5+ requests
- 📋 **Copy Ready** - Paste directly into config

**Example Nginx:**
```
deny 93.119.227.190;
deny 74.125.218.194;
deny 86.124.204.112;
```

**Example iptables:**
```
sudo iptables -A INPUT -s 93.119.227.190 -j DROP
sudo iptables -A INPUT -s 74.125.218.194 -j DROP
```

**When to Use:**
- Quickly block attacks
- Automate security response
- Implement infrastructure rules
- Consistent deployment across servers

---

### GROUP 4: ADVANCED ANALYSIS (Features 9-15)

#### 9️⃣ Bot Detection
**What:** Identifies legitimate bots vs suspicious ones.

**Detects:**
- ✅ **Googlebot** - Google search crawler (trusted)
- ✅ **Bingbot** - Bing search crawler (trusted)
- ✅ **FacebookBot** - Facebook link checker (trusted)
- ⚠️ **curl** - Command-line tool (suspicious)
- ⚠️ **wget** - Download tool (suspicious)
- ⚠️ **Python** - Custom scripts (suspicious)
- 🚫 **Bad Bot** - Generic bots (dangerous)

**When to Use:**
- Distinguish real bots from attacks
- Optimize CDN/caching strategy
- Focus on human attackers
- Understand automation patterns

---

#### 🔟 Time Analysis
**What:** Shows when requests happen (hourly distribution).

**Features:**
- 📈 **Hourly Breakdown** - Traffic per hour
- 🎯 **Peak Hours** - When attacks happen
- 📊 **Visual Chart** - Easy to spot patterns
- 🔍 **Anomaly Detection** - Unusual times

**Example:**
```
09:00 - 234 requests ← Peak
14:00 - 189 requests
23:00 - 12 requests (unusual!)
```

**When to Use:**
- Understand attack timing
- Schedule maintenance windows
- Plan incident response
- Identify coordinated attacks

---

#### 1️⃣1️⃣ Export Filtered Results
**What:** Download only the results you're looking at.

**When to Use:**
- Share specific findings
- Create reports
- Archive analysis
- Import elsewhere

---

#### 1️⃣2️⃣ Bulk Select IPs
**What:** Select multiple IPs for batch operations.

**Features:**
- ☑️ **Checkboxes** - Select multiple
- 🗑️ **Clear All** - Reset selections
- 📊 **Count** - See how many selected
- 🎯 **Batch Actions** - Block, whitelist, etc.

**When to Use:**
- Block multiple IPs at once
- Create whitelists
- Group related threats
- Batch export

---

#### 1️⃣3️⃣ IP Comparison
**What:** Compare top 2 IPs side-by-side.

**Shows:**
- 🆚 **Side-by-side data**
- 📊 **Request counts**
- 🎯 **Risk levels**
- 🔍 **Differences**

**When to Use:**
- Understand similar threats
- See patterns between IPs
- Make blocking decisions
- Document comparisons

---

#### 1️⃣4️⃣ Regex Filter
**What:** Advanced filtering with regular expressions.

**Features:**
- 🔍 **Custom patterns** - Write your own regex
- 📝 **Real-time** - See matches instantly
- 🎯 **Powerful** - Find complex patterns
- 🧪 **Testing** - Build confidence

**Examples:**
```
^93\..* → All IPs starting with 93
.*wp-admin.* → All WordPress admin attempts
(\.php|\.sh)$ → All PHP or shell files
```

**When to Use:**
- Find complex patterns
- Custom threat detection
- Unusual requests
- Advanced investigations

---

#### 1️⃣5️⃣ Whitelist Management
**What:** Mark trusted sources to exclude from alerts.

**Manage:**
- ✅ **Known good bots** - Googlebot, Bingbot
- ✅ **Internal IPs** - Your office, VPN
- ✅ **Business partners** - Trusted APIs
- ✅ **CDN providers** - Cloudflare, Akamai

**When to Use:**
- Reduce false positives
- Focus on real threats
- Maintain trusted services
- Compliance requirements

---

### GROUP 5: SECURITY AUTOMATION (Features 16-20)

#### 1️⃣6️⃣ Attack Timeline
**What:** Visual graph of attacks over time.

**Shows:**
- 📅 **Timestamp** - When attack happened
- 🎯 **Type** - What kind of attack
- 📊 **Count** - How many incidents
- 🎨 **Color coded** - Red for critical

**When to Use:**
- Understand attack progression
- Identify coordinated attacks
- Track incident response
- Generate timelines for reports

---

#### 1️⃣7️⃣ Pre-built Block Rules
**What:** Ready-to-use block lists for common threats.

**Presets:**
- 🤖 **Common Bot Networks** - Known bot sources
- ⚫ **Known Bad Actors** - Documented attackers
- 🕵️ **Suspicious Proxies** - Proxy IP ranges

**When to Use:**
- Quick protection
- Standard threats
- Get started fast
- Best practices

---

#### 1️⃣8️⃣ Session Management
**What:** Save and load previous analyses.

**Features:**
- 💾 **Save** - Current analysis snapshot
- 📂 **Load** - Previous analysis
- 📅 **Dates** - When analysis was done
- 📊 **Metadata** - IP count, findings

**When to Use:**
- Compare over time
- Track improvements
- Compliance audit trail
- Historical analysis

---

#### 1️⃣9️⃣ Pinned Favorites
**What:** Quick access to important IPs.

**Features:**
- ⭐ **Star Icon** - Pin important IPs
- 🏷️ **Labels** - Add notes
- 🎯 **Quick Access** - See at a glance
- 📝 **Annotations** - Remember why important

**When to Use:**
- Track repeat offenders
- Monitor known threats
- Quick reference
- Investigation notes

---

#### 2️⃣0️⃣ User Manual
**What:** This guide! Interactive help system.

**Contains:**
- 📚 **All features** - Full explanation
- 🎯 **Examples** - Real usage
- 💡 **Tips** - Best practices
- 🔗 **Quick links** - Navigate easily

---

## ⌨️ KEYBOARD SHORTCUTS

| Key | Action |
|-----|--------|
| `?` | Open help/manual |
| `D` | Toggle dark mode |
| `Escape` | Close panel |
| `Ctrl+C` | Copy (in search) |

---

## 🎯 COMMON WORKFLOWS

### Workflow 1: Quick Security Check (5 minutes)
1. Click **Extract All IPs**
2. Check **Threat Score** for 🔴 CRITICAL
3. Click **Firewall Rules Generator**
4. Copy rules to your firewall
5. Done!

### Workflow 2: Detailed Investigation (15 minutes)
1. Click **Attack Patterns** - Understand threats
2. Click **Geolocation** - Identify sources
3. Click **Bot Detection** - Filter noise
4. Click **Threat Score** - Prioritize action
5. Click **Firewall Rules** - Implement blocking

### Workflow 3: Compliance Report (30 minutes)
1. Click **Download IPs** - Export data
2. Click **Export Filtered** - CSV version
3. Click **Attack Timeline** - Visual timeline
4. Click **Sessions** - Save for audit
5. Share documentation

### Workflow 4: Track Improvements (Weekly)
1. Click **Sessions** - Load last week's analysis
2. Click **Threat Score** - Compare with today
3. Note improvements
4. Identify new threats
5. Update firewall rules

---

## 💡 BEST PRACTICES

### DO ✅
- ✅ Review **Threat Score** first - Prioritize high risk
- ✅ Use **Firewall Rules Generator** - Automate blocking
- ✅ Create **Whitelists** - Reduce false positives
- ✅ Save **Sessions** - Audit trail & history
- ✅ Check **Time Analysis** - Understand patterns
- ✅ Monitor **Bot Detection** - Know your traffic

### DON'T ❌
- ❌ Block all IPs without review - false positives
- ❌ Ignore **Admin paths** - Common attack vectors
- ❌ Skip **Geolocation** - Understand sources
- ❌ Forget to **Update rules** - Threats evolve
- ❌ Dismiss **Attack Patterns** - Early warning
- ❌ Overload firewall - Use **Threat Score** to prioritize

---

## 🆘 TROUBLESHOOTING

### "No data appears"
→ Upload a log file first  
→ Check file format (Apache combined log)  
→ Try demo file: `/tmp/test.log`

### "Search not working"
→ Clear search box and try again  
→ Type slower to see results  
→ Check for typos in search term

### "Copy button doesn't work"
→ Browser may have clipboard restrictions  
→ Try right-click → Copy instead  
→ Chrome/Firefox recommended

### "Panel takes too long to load"
→ Large log files take time  
→ Close other panels first  
→ Try smaller data subset

---

## 📊 EXAMPLE SESSION

### You upload: access_log (1.2 MB, 50,000 requests)

**1. Click "Extract All IPs"**
```
Result: 128 unique IPs found
You search "93.119" → 5 matches shown
```

**2. Click "Threat Score"**
```
Result: 
🔴 93.119.227.190 - Score 95 CRITICAL
🟠 74.125.218.194 - Score 58 HIGH
🟡 86.124.204.112 - Score 32 MEDIUM
```

**3. Click "Attack Patterns"**
```
Result:
🚨 5 types detected:
💉 SQL Injection: 12 attempts
🔓 XSS: 5 attempts
⚡ Shell: 2 attempts
```

**4. Click "Firewall Rules Generator"**
→ Select "Nginx"
```
deny 93.119.227.190;
deny 74.125.218.194;
```

**5. Copy rules to nginx.conf**
→ Reload Nginx  
→ Done! Traffic blocked.

---

## 🚀 ADVANCED TIPS

### Tip 1: Combine Threat Score + Firewall Rules
High threat score → Auto-generate rules → Deploy

### Tip 2: Use Bot Detection to Focus
Filter out known good bots → Only real threats

### Tip 3: Time Analysis for Patterns
Attacks at 3 AM? Schedule security updates then.

### Tip 4: Session Trends
Compare weekly. Are threats going up or down?

### Tip 5: Whitelist Aggressively
Add your CDN, monitoring, APIs → Reduce noise

---

## 📞 SUPPORT

**Having issues?**
- Check this manual first
- Try different log file
- Review troubleshooting section
- Check browser console (F12) for errors

**Feature requests?**
- All 20 features are fully functional
- Let us know what you'd add

---

## 📄 VERSION HISTORY

| Version | Date | Changes |
|---------|------|---------|
| 3.0 | 2026-10-28 | All 20 features, full UI, interactive panels |
| 2.5 | 2026-10-27 | 8 features, bug fixes |
| 2.0 | 2026-10-26 | Initial release, core analysis |

---

**Status:** ✅ Production Ready  
**Last Updated:** 2026-10-28  
**Tested:** All 20 features verified ✅

EOF

cat /tmp/opencode/LOGSCAN_USER_MANUAL.md | wc -l
echo "✅ Manual created: $(stat -f%z /tmp/opencode/LOGSCAN_USER_MANUAL.md 2>/dev/null || stat -c%s /tmp/opencode/LOGSCAN_USER_MANUAL.md) bytes"
