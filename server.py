import os
import json
import sqlite3
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime

PORT = 8000
DB_FILE = "sentinel_recon.db"

# Seed Data Configurations
SEED_SLIDES = [
    (
        "Reconnaissance Overview",
        (
            "<p>Reconnaissance is the initial phase of any cybersecurity evaluation. In this phase, "
            "a security auditor or analyst gathers as much information as possible about the target "
            "system before attempting to analyze its vulnerabilities.</p>"
            "<p>Recon is divided into two primary types:</p>"
            "<ul>"
            "<li><strong>Passive Reconnaissance</strong>: Gathering information without directly "
            "interacting with the target systems (e.g. search engines, WHOIS databases, DNS records).</li>"
            "<li><strong>Active Reconnaissance</strong>: Interacting directly with the target to discover "
            "details (e.g. network port scanning, service version identification).</li>"
            "</ul>"
        ),
        0
    ),
    (
        "Understanding Port Scanning",
        (
            "<p>Ports are virtual points where network connections start and end. There are 65,535 TCP "
            "and UDP ports available on every IP address.</p>"
            "<p>Port scanning is an active recon technique used to map out which services (like web servers "
            "on port 80/443, mail systems on port 25, databases on port 3306) are listening for incoming traffic.</p>"
            "<p>By identifying open ports, security auditors can assess the network's attack surface and "
            "recommend which unused services should be turned off.</p>"
        ),
        1
    ),
    (
        "TCP Handshake Mechanics",
        (
            "<p>The Transmission Control Protocol (TCP) relies on a three-way handshake to establish reliable connections:</p>"
            "<ol>"
            "<li><strong>SYN (Synchronize)</strong>: The client sends a packet initiating connection negotiation.</li>"
            "<li><strong>SYN-ACK (Synchronize-Acknowledge)</strong>: The server responds, agreeing to the connection.</li>"
            "<li><strong>ACK (Acknowledge)</strong>: The client acknowledges, establishing the path.</li>"
            "</ol>"
            "<p>Different port scanning methodologies manipulate these flags to determine if a port is open "
            "without necessarily completing the log-triggering connection.</p>"
        ),
        2
    ),
    (
        "Defending Against Reconnaissance",
        (
            "<p>Recon is the foundation of any intrusion attempt. Blocking or complicating this phase "
            "significantly improves security:</p>"
            "<ul>"
            "<li><strong>Firewalls</strong>: Filter out unauthorized requests and drop packets to non-public ports.</li>"
            "<li><strong>Intrusion Detection Systems (IDS)</strong>: Monitor packet frequencies and flag scanning signatures.</li>"
            "<li><strong>Rate Limiting</strong>: Drop traffic from source IPs sending high volumes of connection requests.</li>"
            "<li><strong>Honeypots</strong>: Deploy decoy assets that distract scanner resources and catalog their behaviors.</li>"
            "</ul>"
        ),
        3
    )
]

SEED_QUESTIONS = [
    (
        1,
        "Which type of reconnaissance does NOT involve direct interaction with the target systems?",
        json.dumps([
            "Active Reconnaissance",
            "Passive Reconnaissance",
            "Exploitation",
            "Port Scanning"
        ]),
        1
    ),
    (
        2,
        "What is the final packet sent by a scanner to complete a full TCP Connect Scan handshake?",
        json.dumps([
            "SYN",
            "SYN-ACK",
            "RST",
            "ACK"
        ]),
        3
    ),
    (
        3,
        "How does a target operating system typically respond to a UDP scan on a CLOSED port?",
        json.dumps([
            "SYN-ACK",
            "ICMP Port Unreachable",
            "No response",
            "TCP Reset (RST)"
        ]),
        1
    ),
    (
        4,
        "Which defensive mechanism is specifically designed to act as a decoy and capture intelligence?",
        json.dumps([
            "Honeypot",
            "Firewall ruleset",
            "Rate limiter",
            "DNSSEC validation"
        ]),
        0
    )
]

SEED_USERS = [
    ("admin", "adminpass", "admin"),
    ("user", "userpass", "user")
]

SCAN_METHODOLOGIES = {
    "syn": {
        "title": "TCP SYN Stealth Scan (Half-Open)",
        "packets": [
            {"from": "attacker", "to": "firewall", "label": "SYN", "type": "req"},
            {"from": "firewall", "to": "web", "label": "SYN", "type": "req"},
            {"from": "web", "to": "firewall", "label": "SYN-ACK", "type": "resp-open"},
            {"from": "firewall", "to": "attacker", "label": "SYN-ACK", "type": "resp-open"},
            {"from": "attacker", "to": "firewall", "label": "RST", "type": "reset"}
        ]
    },
    "connect": {
        "title": "TCP Connect Full Handshake Scan",
        "packets": [
            {"from": "attacker", "to": "firewall", "label": "SYN", "type": "req"},
            {"from": "firewall", "to": "web", "label": "SYN", "type": "req"},
            {"from": "web", "to": "firewall", "label": "SYN-ACK", "type": "resp-open"},
            {"from": "firewall", "to": "attacker", "label": "SYN-ACK", "type": "resp-open"},
            {"from": "attacker", "to": "firewall", "label": "ACK", "type": "req"},
            {"from": "attacker", "to": "firewall", "label": "RST/ACK", "type": "reset"}
        ]
    },
    "udp": {
        "title": "UDP Port Scan",
        "packets": [
            {"from": "attacker", "to": "firewall", "label": "UDP Probe", "type": "req"},
            {"from": "firewall", "to": "web", "label": "UDP Probe", "type": "req"},
            {"from": "web", "to": "firewall", "label": "ICMP Unreachable", "type": "error"},
            {"from": "firewall", "to": "attacker", "label": "ICMP Unreachable", "type": "error"}
        ]
    }
}

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Create tables
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS slides (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        order_index INTEGER NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS quiz_questions (
        id INTEGER PRIMARY KEY,
        question TEXT NOT NULL,
        options TEXT NOT NULL,
        correct INTEGER NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        scan_type TEXT NOT NULL,
        packets_count INTEGER NOT NULL,
        alerts_triggered INTEGER NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL
    )
    """)
    conn.commit()

    # Seeds
    cursor.execute("SELECT COUNT(*) FROM slides")
    if cursor.fetchone()[0] == 0:
        cursor.executemany("INSERT INTO slides (title, content, order_index) VALUES (?, ?, ?)", SEED_SLIDES)

    cursor.execute("SELECT COUNT(*) FROM quiz_questions")
    if cursor.fetchone()[0] == 0:
        cursor.executemany("INSERT INTO quiz_questions (id, question, options, correct) VALUES (?, ?, ?, ?)", SEED_QUESTIONS)

    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.executemany("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", SEED_USERS)
        print("Database: Seeded user credential profiles.")

    conn.commit()
    conn.close()

class FullstackReconHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass

    def send_json(self, data, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query = urllib.parse.parse_qs(parsed_url.query)

        if path == '/api/slides':
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT title, content FROM slides ORDER BY order_index")
            rows = cursor.fetchall()
            conn.close()
            slides = [{"title": r[0], "content": r[1]} for r in rows]
            self.send_json(slides)
            return

        elif path == '/api/quiz':
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT id, question, options FROM quiz_questions ORDER BY id")
            rows = cursor.fetchall()
            conn.close()
            questions = [{"id": r[0], "question": r[1], "options": json.loads(r[2])} for r in rows]
            self.send_json(questions)
            return

        elif path == '/api/history':
            # Role Protection check
            role = query.get('role', [None])[0]
            if role != 'admin':
                self.send_json({"error": "Unauthorized. Admin role required."}, 403)
                return

            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT timestamp, scan_type, packets_count, alerts_triggered FROM scan_history ORDER BY id DESC LIMIT 20")
            rows = cursor.fetchall()
            conn.close()

            history = [{
                "timestamp": r[0],
                "type": r[1],
                "packets": r[2],
                "alerts": r[3]
            } for r in rows]
            self.send_json(history)
            return

        # Static routing
        if path == '/':
            path = '/index.html'

        file_path = os.path.join(os.getcwd(), path.lstrip('/'))
        if os.path.exists(file_path) and os.path.isfile(file_path):
            self.send_response(200)
            if file_path.endswith('.html'):
                self.send_header('Content-Type', 'text/html')
            elif file_path.endswith('.css'):
                self.send_header('Content-Type', 'text/css')
            elif file_path.endswith('.js'):
                self.send_header('Content-Type', 'application/javascript')
            else:
                self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            with open(file_path, 'rb') as f:
                self.wfile.write(f.read())
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 - Resource Not Found")

    def do_POST(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        try:
            body = json.loads(post_data.decode('utf-8')) if post_data else {}
        except json.JSONDecodeError:
            self.send_json({"error": "Invalid JSON body"}, 400)
            return

        if path == '/api/login':
            username = body.get('username')
            password = body.get('password')

            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT username, role FROM users WHERE username = ? AND password = ?", (username, password))
            row = cursor.fetchone()
            conn.close()

            if row:
                self.send_json({
                    "success": True,
                    "username": row[0],
                    "role": row[1]
                })
            else:
                self.send_json({"success": False, "error": "Invalid username or password credentials"}, 401)
            return

        elif path == '/api/quiz/submit':
            question_id = body.get('id')
            selected_option = body.get('selected')

            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT correct FROM quiz_questions WHERE id = ?", (question_id,))
            row = cursor.fetchone()
            conn.close()

            if not row:
                self.send_json({"error": "Question not found"}, 404)
                return

            correct_index = row[0]
            self.send_json({
                "correct": (selected_option == correct_index),
                "correctIndex": correct_index
            })
            return

        elif path == '/api/scan/simulate':
            scan_type = body.get('type', 'syn')
            defenses = body.get('defenses', {})
            
            methodology = SCAN_METHODOLOGIES.get(scan_type)
            if not methodology:
                self.send_json({"error": "Unknown scan type"}, 400)
                return

            firewall_active = defenses.get('firewall', True)
            ids_active = defenses.get('ids', True)

            response_logs = []
            packets = list(methodology["packets"])
            
            if firewall_active and scan_type != 'udp':
                response_logs.append("Firewall: Connection to DB Port 3306 filtered and dropped.")
            
            alerts_triggered = 1 if ids_active else 0

            # Commit logs to persistent history logs
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO scan_history (timestamp, scan_type, packets_count, alerts_triggered) VALUES (?, ?, ?, ?)",
                (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), scan_type.upper(), len(packets), alerts_triggered)
            )
            conn.commit()
            conn.close()
            
            self.send_json({
                "title": methodology["title"],
                "packets": packets,
                "logs": response_logs,
                "alerts": alerts_triggered
            })
            return

        elif path == '/api/osint/analyze':
            domain = body.get('domain', 'company.com')
            
            dns_records = [
                {"type": "A", "value": "192.168.10.45"},
                {"type": "MX", "value": f"mail.{domain}"},
                {"type": "TXT", "value": '"v=spf1 include:_spf.google.com ~all" (SoftFail Configured)', "vulnerable": True},
                {"type": "DMARC", "value": "None found (Vulnerable to email impersonation)", "vulnerable": True}
            ]
            
            whois_data = {
                "registrar": "SafeNames Ltd.",
                "contact": f"admin@{domain} (Private WHOIS Shielding inactive)",
                "location": "Germany, Frankfurt"
            }

            self.send_json({
                "domain": domain,
                "dns": dns_records,
                "whois": whois_data
            })
            return

        self.send_json({"error": "Endpoint not found"}, 404)

def run():
    init_db()
    server_address = ('', PORT)
    httpd = HTTPServer(server_address, FullstackReconHandler)
    print(f"SentinelRecon Server listening on port {PORT}...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()

if __name__ == '__main__':
    run()
