# SentinelRecon 🛡️📡

**SentinelRecon** is an interactive, fullstack educational simulator and dashboard designed to demonstrate active port scanning, passive OSINT domain footprint analysis, defensive measures (firewalls, IDS, rate limiting, honeypots), and security assessments.

Built using a **zero-dependency Python HTTP server**, **SQLite database**, and raw **vanilla CSS/JS** with glassmorphic visuals, the application supports persistent telemetry logging and role-based login consoles.

---

## 🚀 Key Features

* 🔐 **Role-Based Authentication**: Custom sign-in portal. Access credentials seeded directly:
  * **Standard User** (`user` / `userpass`): Standard dashboard access, quiz modules, active scan engines, and OSINT footprint builders.
  * **Administrator** (`admin` / `adminpass`): Standard access + exclusive **Admin Audit Console** query tools reading real-time SQLite database transaction logs.
* 📡 **Port Scan Engine Simulator**: Interactive live canvas illustrating packet movement between the attacker host, target defenses, web host, databases, and mail systems. Supports TCP SYN Stealth, TCP Connect, and UDP scanning configurations.
* 🔍 **OSINT Footprint Analyzer**: Map active DNS Zone mappings (MX, A, TXT, DMARC) and public WHOIS registries for targets, compiling a list of prioritized security hardening recommendations.
* 🛡️ **Defense Sandbox**: Toggle Firewalls, Intrusion Detection Systems (IDS), Rate Limiters, and Honeypot decoys to analyze their real-time impact on recon efficiency, detection capability, and decoy attraction.
* 📖 **Training & Interactive Assessment Quiz**: Study the key stages of cyber reconnaissance and complete graded knowledge checkups.
* 💾 **SQLite Telemetry Logging**: Persistent SQLite database storage logging transaction history records for port scan telemetry.
* 🔌 **Hybrid Client Fallbacks**: Automatically switches to client-side fallback operations if the server backend is unreachable, allowing local testing.

---

## 🛠️ Technology Stack

* **Frontend**: HTML5, Vanilla HSL CSS3 variables, Canvas animations, FontAwesome icon packs.
* **Backend**: Python 3 (built on native `http.server.BaseHTTPRequestHandler`).
* **Database**: SQLite3 (`sqlite3`) persistent file storage (`sentinel_recon.db`).

---

## 🏃 Getting Started

### 1. Start the Server
Run the native Python backend web server from the project directory:
```bash
python server.py
```
This automatically boots the web server on `http://localhost:8000`, checks the schema configuration, and seeds default user credentials, slides, and assessments.

### 2. Access the Application
Open your web browser and navigate to:
* **Dashboard App**: [http://localhost:8000](http://localhost:8000)
* **Integration Tests Suite**: [http://localhost:8000/tests.html](http://localhost:8000/tests.html)

---

## 🧪 Integration Testing
Verify backend API routing and authentication safety scopes using the automated suite:
```bash
python test_backend.py
```
