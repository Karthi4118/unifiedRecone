import os
import json
import sqlite3
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime

PORT = 8000
DB_FILE = "sentinel_recon_v2.db"

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
    # Week 1: Passive Recon & OSINT (1 to 20)
    (1, 1, "What is the primary characteristic of passive reconnaissance?", json.dumps(["Direct connection to target", "No direct interaction with target", "Exploiting database tables", "Modifying firewall configurations"]), 1, "Passive reconnaissance gathers target intelligence from public sources without sending any packets directly to target servers."),
    (2, 1, "Which of the following is an OSINT resource?", json.dumps(["Nmap port scan", "SQL injection exploit", "WHOIS domain database", "Metasploit payload"]), 2, "WHOIS registry holds public registration information for domain names, which is a classic passive OSINT asset."),
    (3, 1, "Which DNS record maps a domain name to an IPv4 address?", json.dumps(["MX record", "CNAME record", "TXT record", "A record"]), 3, "The DNS 'A' (Address) record maps hostnames to their corresponding IPv4 addresses."),
    (4, 1, "Which DNS record type specifies the mail server responsible for receiving email?", json.dumps(["A record", "MX record", "NS record", "TXT record"]), 1, "The 'MX' (Mail Exchanger) record directs emails to the appropriate mail servers for the domain."),
    (5, 1, "Which Google Dorking search operator restricts search results to a specific domain?", json.dumps(["site:", "filetype:", "inurl:", "intitle:"]), 0, "The 'site:' operator filters results to match pages indexed only from the specified domain."),
    (6, 1, "Which Google Dorking operator filters search results for specific file extensions?", json.dumps(["site:", "inurl:", "filetype:", "ext:"]), 2, "The 'filetype:' (or 'ext:') operator restricts results to document formats like pdf, docx, or txt."),
    (7, 1, "Which tool collects passive email and subdomain intelligence from public key servers and search engines?", json.dumps(["Metasploit", "theHarvester", "Wireshark", "Nping"]), 1, "'theHarvester' is a passive footprinting tool designed to extract emails, subdomains, and hostnames from public data sources."),
    (8, 1, "Which platform is a public search engine for internet-connected devices and certificates?", json.dumps(["Shodan", "Nessus", "Wireshark", "Burp Suite"]), 0, "Shodan is a search engine that catalogs active public IPs, server banners, and connected IoT devices worldwide."),
    (9, 1, "What type of data does a public WHOIS query return?", json.dumps(["Active port list", "Domain registration and owner contact details", "SQL database backup files", "Internal router routing tables"]), 1, "WHOIS records track domain ownership, registrar history, and administrative contact details."),
    (10, 1, "Which of the following is NOT a passive reconnaissance technique?", json.dumps(["Google Dorking searches", "Banner grabbing via Netcat", "Querying Shodan databases", "WHOIS lookup queries"]), 1, "Banner grabbing requires a direct connection to open ports, making it an active recon technique."),
    (11, 1, "What is the primary security purpose of a Sender Policy Framework (SPF) record?", json.dumps(["Encrypt email payload", "Specify authorized sending mail servers", "Map subdomain routes", "Establish TLS handshakes"]), 1, "SPF is a TXT record that defines which hostnames/IPs are permitted to send outbound emails on behalf of a domain."),
    (12, 1, "What does a DMARC policy of 'p=reject' command receiving mail servers to do?", json.dumps(["Accept the message", "Discard the message immediately", "Flag it as spam but deliver it", "Reroute it to admin mailboxes"]), 1, "A 'reject' policy tells incoming servers to block any emails that fail SPF/DKIM verification checks."),
    (13, 1, "Which utility is used to query DNS servers directly?", json.dumps(["ping", "netstat", "nslookup", "ipconfig"]), 2, "'nslookup' (or 'dig') is a standard command-line utility used to query DNS name servers for specific records."),
    (14, 1, "Which passive analysis tool maps relationships between entities, people, domains, and companies?", json.dumps(["Maltego", "Hydra", "John the Ripper", "Nmap"]), 0, "Maltego is a powerful intelligence tool that gathers public datasets and displays them as graphical relationship maps."),
    (15, 1, "What is analyzed during a passive DNS lookup database query?", json.dumps(["Local hosts file", "Historical domain record change logs", "Router ARP cache tables", "Active port responses"]), 1, "Passive DNS lookups query historical transaction databases mapping DNS changes over time without querying the target name server."),
    (16, 1, "How does the Shodan platform map global IoT devices?", json.dumps(["Background web crawling", "Constant internet-wide scanning of the IPv4 range", "Installing user agents", "Analyzing DNS zone files"]), 1, "Shodan constantly scans public IPv4 addresses, reads response banners, and catalogs open interfaces in its database."),
    (17, 1, "What threat is mitigated by enabling WHOIS privacy shielding?", json.dumps(["SQL injection attacks", "Social engineering targeting exposed registrant emails", "Firewall ruleset bypasses", "ARP spoofing attacks"]), 1, "WHOIS privacy masks personal registrant contact details (email/phone), shielding administrators from phishing and spam."),
    (18, 1, "Which DNS record type maps hostnames to IPv6 addresses?", json.dumps(["A record", "CNAME record", "AAAA record", "TXT record"]), 2, "An 'AAAA' record maps a domain name directly to a 128-bit IPv6 address."),
    (19, 1, "Which of the following is a physical passive reconnaissance strategy?", json.dumps(["Port scan sweeps", "Site mapping and dumpster diving", "SQL injection fuzzing", "Wi-Fi packet deauth injection"]), 1, "Dumpster diving and physical facility mapping gather organization intelligence without network interaction."),
    (20, 1, "Which protocol is utilized when checking registrar details for a domain?", json.dumps(["HTTP", "WHOIS protocol", "DNS query protocol", "FTP"]), 1, "WHOIS protocol (TCP port 43) is used to query registry databases for domain and network identifier information."),

    # Week 2: Active Port Scanning & Banner Grabbing (21 to 40)
    (21, 2, "What defines active reconnaissance?", json.dumps(["Using search engines", "Direct interaction with target ports", "Passive DNS analysis", "Reading public news"]), 1, "Active reconnaissance requires sending traffic directly to the target system to analyze responses."),
    (22, 2, "Which utility is the industry standard for network mapping and port scanning?", json.dumps(["Wireshark", "Nmap", "Metasploit", "Aircrack-ng"]), 1, "Nmap (Network Mapper) is the open-source industry standard tool for scanning ports and mapping network hosts."),
    (23, 2, "What does an 'open' port status indicate in Nmap?", json.dumps(["A firewall is blocking the scan", "An application is actively listening for connections", "The host is offline", "The port is insecurely filtered"]), 1, "An 'open' state means a service is actively accepting TCP connections or UDP packets on that port."),
    (24, 2, "What does a 'filtered' port status mean?", json.dumps(["The service is closed", "A firewall or filter is blocking probes", "The port is vulnerable", "The host is scanning back"]), 1, "A 'filtered' state indicates Nmap cannot determine if the port is open or closed because a firewall is dropping probes."),
    (25, 2, "What standard port is used for secure HTTPS web traffic?", json.dumps(["Port 80", "Port 443", "Port 22", "Port 8080"]), 1, "Port 443 is the default port for HTTP over SSL/TLS (HTTPS)."),
    (26, 2, "What is the standard listening port for Secure Shell (SSH)?", json.dumps(["Port 21", "Port 23", "Port 22", "Port 25"]), 2, "Port 22 is the default port for secure remote shell access (SSH)."),
    (27, 2, "What is 'Banner Grabbing'?", json.dumps(["Cracking passwords", "Reading application header greeting messages", "Sniffing local Wi-Fi", "Modifying website HTML"]), 1, "Banner grabbing reads the welcome message or header sent by services upon connection to identify software names and versions."),
    (28, 2, "Which Nmap parameter flag enables service version detection?", json.dumps(["-O", "-sS", "-sV", "-F"]), 2, "The `-sV` flag probes open ports to determine service protocols, product names, and version strings."),
    (29, 2, "What is the default TCP port for MySQL databases?", json.dumps(["Port 1433", "Port 3306", "Port 5432", "Port 1521"]), 1, "MySQL database servers listen on TCP port 3306 by default."),
    (30, 2, "What port is utilized for unencrypted HTTP web traffic?", json.dumps(["Port 80", "Port 443", "Port 8080", "Port 23"]), 0, "Port 80 is the default TCP port for unencrypted HTTP traffic."),
    (31, 2, "What port is standard for Domain Name System (DNS) queries?", json.dumps(["Port 80", "Port 53", "Port 25", "Port 110"]), 1, "DNS queries use port 53 (most commonly UDP, but TCP for zone transfers)."),
    (32, 2, "What is the primary goal of a network ping sweep?", json.dumps(["Exploit open services", "Discover active hosts on a subnet", "Block firewall responses", "Sniff login passwords"]), 1, "A ping sweep sends ICMP echo requests to a range of IP addresses to identify which host systems are online."),
    (33, 2, "Which TCP port is standard for Simple Mail Transfer Protocol (SMTP)?", json.dumps(["Port 25", "Port 110", "Port 143", "Port 587"]), 0, "SMTP mail servers listen on TCP port 25 for mail routing by default."),
    (34, 2, "Which Nmap flag enables Operating System (OS) fingerprinting?", json.dumps(["-sS", "-sV", "-O", "-sT"]), 2, "The `-O` switch enables OS detection by analyzing packet anomalies in target responses."),
    (35, 2, "How does OS fingerprinting identify operating systems?", json.dumps(["Reading system files", "Analyzing TCP/IP stack response signatures", "Interpreting web headers", "Querying public DNS records"]), 1, "Operating systems implement TCP/IP specifications with slight differences in flag responses. Nmap compares these to a local signature database."),
    (36, 2, "Which Nmap parameter runs a fast scan of the top 100 ports?", json.dumps(["-F", "-p-", "-sV", "-A"]), 0, "The `-F` (Fast) flag runs a quick scan, covering the top 100 most common ports instead of the default 1,000."),
    (37, 2, "What TCP port is assigned to Windows Remote Desktop Protocol (RDP)?", json.dumps(["Port 22", "Port 445", "Port 3389", "Port 5900"]), 2, "Windows Remote Desktop Protocol (RDP) listens on TCP port 3389 by default."),
    (38, 2, "Which Nmap parameter scans the entire range of 65,535 TCP ports?", json.dumps(["-p 1-1000", "-p-", "-F", "-p all"]), 1, "The `-p-` flag directs Nmap to scan all 65,535 possible port numbers."),
    (39, 2, "What is the main operational risk of active reconnaissance?", json.dumps(["Getting incorrect DNS records", "Triggering alerts in firewalls and IDS systems", "Slowing down local networks", "Encrypting target hard drives"]), 1, "Because active scans directly contact ports, security controls like firewalls and IDS are likely to log and alert on this traffic."),
    (40, 2, "Which port is default for File Transfer Protocol (FTP) command connections?", json.dumps(["Port 21", "Port 22", "Port 23", "Port 25"]), 0, "FTP uses port 21 for command/control connection negotiations."),

    # Week 3: TCP Handshake & Packet Flag Manipulation (41 to 60)
    (41, 3, "What packet initiates a TCP three-way handshake?", json.dumps(["ACK", "SYN-ACK", "SYN", "RST"]), 2, "A client starts the three-way handshake by sending a TCP packet with the SYN (Synchronize) flag active."),
    (42, 3, "How does an open port respond to an incoming TCP SYN packet?", json.dumps(["RST", "SYN-ACK", "ACK", "No response"]), 1, "If a port is open, the host responds with a SYN-ACK packet, indicating readiness to establish a connection."),
    (43, 3, "What packet is sent to finalize the TCP three-way handshake?", json.dumps(["SYN", "RST", "FIN", "ACK"]), 3, "The client sends a final ACK (Acknowledge) packet to confirm connection establishment."),
    (44, 3, "Why is a TCP SYN scan referred to as a 'stealth' or 'half-open' scan?", json.dumps(["It uses encrypted VPNs", "It never completes the three-way connection handshake", "It only scans UDP ports", "It sends no packets"]), 1, "A SYN scan terminates connection attempts with an RST packet immediately after receiving the SYN-ACK, leaving the handshake 'half-open' and unlogged by standard apps."),
    (45, 3, "Which Nmap parameter activates a TCP SYN Stealth scan?", json.dumps(["-sT", "-sS", "-sU", "-sN"]), 1, "The `-sS` flag instructs Nmap to run a TCP SYN (Stealth) scan."),
    (46, 3, "How does a closed TCP port respond to a SYN request?", json.dumps(["SYN-ACK", "No response", "RST", "FIN"]), 2, "If a port is closed, the target operating system responds with an RST (Reset) packet to reject the connection."),
    (47, 3, "Which TCP header flag is used to reset a connection immediately?", json.dumps(["SYN", "FIN", "RST", "PSH"]), 2, "The RST (Reset) flag instantly terminates a TCP session or rejects connection requests."),
    (48, 3, "Which Nmap parameter runs a full TCP Connect scan?", json.dumps(["-sS", "-sT", "-sX", "-sN"]), 1, "The `-sT` flag executes a full TCP Connect scan, completing the entire handshake via OS socket APIs."),
    (49, 3, "Which TCP flags are turned on in a NULL scan?", json.dumps(["All flags active", "No flags active", "SYN and ACK flags only", "FIN and RST flags only"]), 1, "A NULL scan sends a TCP packet with all header flags set to 0 (empty flags)."),
    (50, 3, "What defines a TCP FIN scan?", json.dumps(["A packet with only the FIN flag active", "A packet establishing connections", "A scan checking firewall limits", "A packet with SYN active"]), 0, "A FIN scan sends a TCP packet with only the FIN (Finish) flag set."),
    (51, 3, "Which TCP flags are active in an XMAS scan packet?", json.dumps(["SYN, ACK, RST", "FIN, PSH, URG", "None", "FIN only"]), 1, "An XMAS scan turns on the FIN, PSH, and URG flags, making the packet appear 'lit up' like a Christmas tree in analyzers."),
    (52, 3, "According to RFC 793, how should an OPEN port respond to NULL, FIN, or XMAS scans?", json.dumps(["Send an RST packet", "Ignore the packet (no response)", "Send a SYN-ACK packet", "Send an ACK packet"]), 1, "Under RFC 793, open ports must ignore incoming TCP packets that do not have SYN, RST, or ACK flags active."),
    (53, 3, "How does a CLOSED port respond to NULL, FIN, or XMAS scans?", json.dumps(["SYN-ACK", "No response", "RST-ACK", "FIN-ACK"]), 2, "A closed port responds to anomalous packets (like NULL, FIN, XMAS) by sending back an RST-ACK packet."),
    (54, 3, "Why does a SYN scan require administrative/root privileges?", json.dumps(["It uses high ports", "It must construct custom raw TCP sockets", "It records passwords", "It disables local firewalls"]), 1, "Completing raw TCP flag customization (sending SYN and RST manually) requires root/administrative permissions to open raw network sockets."),
    (55, 3, "What is a main advantage of a SYN scan compared to a full Connect scan?", json.dumps(["It is faster and bypasses application-level connection logging", "It works on UDP ports", "It retrieves file listings", "It does not send any packets"]), 0, "Because a SYN scan never completes the handshake, standard application daemons do not register a connection event in their logs."),
    (56, 3, "What protocol error response is parsed to identify a closed UDP port?", json.dumps(["TCP Reset (RST)", "ICMP Port Unreachable", "SYN-ACK", "HTTP 404 Error"]), 1, "If a UDP probe hits a closed port, the target OS typically responds with an ICMP Type 3 Code 3 (Port Unreachable) error."),
    (57, 3, "Why do UDP port scans usually take a very long time?", json.dumps(["UDP is a secure protocol", "Hosts throttle ICMP error responses to rate-limit traffic", "UDP packets are larger", "Firewalls cannot parse UDP"]), 1, "Most operating systems restrict the frequency of ICMP error packets (e.g. max 1 per second) to prevent resource exhaustion, slowing down UDP port sweeps."),
    (58, 3, "What TCP flag requests that buffered data be pushed immediately to the application?", json.dumps(["SYN", "ACK", "PSH", "URG"]), 2, "The PSH (Push) flag forces TCP to transmit data buffers directly to the application layer without waiting for full segments."),
    (59, 3, "What TCP flag indicates that the packet contains urgent data?", json.dumps(["SYN", "URG", "PSH", "FIN"]), 1, "The URG (Urgent) flag flags specific data in the packet as priority, to be processed ahead of other queued data."),
    (60, 3, "What TCP flag is used to gracefully close a connection?", json.dumps(["RST", "FIN", "ACK", "SYN"]), 1, "The FIN (Finish) flag initiates the graceful shutdown of a TCP connection stream."),

    # Week 4: Defense Sandbox & Mitigation Strategies (61 to 80)
    (61, 4, "What is the primary role of an Intrusion Detection System (IDS)?", json.dumps(["Filter website URLs", "Monitor traffic for signatures of malicious scans", "Encrypt local databases", "Reset user passwords"]), 1, "An IDS scans network traffic patterns and flags packets matching known signature patterns of scans or attacks."),
    (62, 4, "How does a stateful firewall differ from a simple packet filter?", json.dumps(["It blocks all incoming traffic", "It tracks active connection states and sessions", "It runs honeypots automatically", "It parses application HTTP codes"]), 1, "Stateful firewalls maintain a state table tracking current open sockets, admitting return packets only for valid active sessions."),
    (63, 4, "What is a 'Honeypot' in network defense?", json.dumps(["A database firewall", "A decoy system designed to attract and analyze attacker scans", "A password cracking utility", "A DNS backup server"]), 1, "A honeypot is a decoy server deployed to lure attackers, log their methodologies, and delay scanner progress."),
    (64, 4, "What defense drops traffic from IP sources that send packet bursts in short intervals?", json.dumps(["Encryption", "Rate Limiting", "Honeypot routing", "Active banners"]), 1, "Rate limiting monitors connection rates per IP and drops traffic exceeding preset limits to mitigate aggressive sweeps."),
    (65, 4, "What is the primary function of a Web Application Firewall (WAF)?", json.dumps(["Filter network port sweeps", "Inspect application-level traffic (e.g., SQLi, XSS)", "Disable external DNS queries", "Configure WHOIS entries"]), 1, "WAFs analyze HTTP/HTTPS application layer data to prevent exploits like SQL Injection, Cross-Site Scripting, and path traversal."),
    (66, 4, "How can administrators prevent banner grabbing from leaking software versions?", json.dumps(["Disable SSH entirely", "Modify configurations to hide or mock service versions", "Allow anonymous logins", "Shut down the database"]), 1, "Editing service configuration files (like Apache, Nginx, or SSH) allows admins to suppress version listings or display custom banners."),
    (67, 4, "Which Nmap timing parameter makes scans extremely slow to avoid threshold limits?", json.dumps(["-T5 (Aggressive)", "-T0 (Paranoid)", "-F (Fast)", "-sV"]), 1, "Nmap's `-T0` (Paranoid) timing inserts long delays between packets, staying below threshold alerts of standard rate limiters."),
    (68, 4, "What firewall policy block strategy drops all unapproved incoming traffic?", json.dumps(["Permissive policy", "Default-Deny (Strict Filtering) policy", "Stateful tracking", "Honeypot forwarding"]), 1, "A 'Default-Deny' ruleset blocks all ports and protocols by default, admitting traffic only to explicitly whitelisted services."),
    (69, 4, "What is a host-based firewall?", json.dumps(["A hardware router firewall", "A software firewall running directly on the host operating system", "A cloud load balancer", "A DNSSEC server"]), 1, "Host-based firewalls protect individual end-user devices or server nodes directly from the OS layer."),
    (70, 4, "What type of honeypot simulates fully functional OS environments to analyze advanced payloads?", json.dumps(["Low-interaction honeypot", "High-interaction honeypot", "DNS redirection", "Stateful IDS"]), 1, "High-interaction honeypots run real operating systems and applications to let analysts study deep shell interactions."),
    (71, 4, "What is a 'False Positive' in intrusion detection logs?", json.dumps(["An attack is missed by the scanner", "Legitimate network traffic is incorrectly flagged as a threat", "A honeypot is successfully attacked", "A firewall blocks database query limits"]), 1, "A false positive occurs when normal connection patterns trigger signature rules and create false alert logs."),
    (72, 4, "What Nmap technique obfuscates the scan source IP using decoy addresses?", json.dumps(["-sV", "-D decoy1,decoy2,ME", "-p-", "-T4"]), 1, "The decoy (`-D`) option tells Nmap to send spoofed scanning packets from multiple fake IPs alongside the real scanner IP, hiding the real source."),
    (73, 4, "How does rate limiting mitigate port scans?", json.dumps(["It blocks all TCP handshakes", "It temporarily throttles or blocks IPs exceeding traffic thresholds", "It randomizes open ports", "It hides DNS records"]), 1, "By throttling IPs that query multiple ports in short periods, rate limiters render sweeps slow and inefficient."),
    (74, 4, "Which active defense system dynamically blocks threat IPs upon detecting scans?", json.dumps(["Intrusion Detection System (IDS)", "Intrusion Prevention System (IPS)", "WHOIS Shield", "Decoy proxy"]), 1, "An IPS monitors traffic (like an IDS) but has inline control capabilities to dynamically update firewall blocks against threat sources."),
    (75, 4, "Which technique splits TCP headers across multiple packets to bypass simple static signature filters?", json.dumps(["IP spoofing", "Packet Fragmentation", "Decoy scanning", "Banner spoofing"]), 1, "Packet fragmentation breaks TCP headers into tiny chunks, making it difficult for simple stateless filters to match alert signatures."),
    (76, 4, "What is a key indicator of a port scan inside firewalls/IDS logs?", json.dumps(["Low response latency", "High frequency of connections to multiple distinct ports from a single IP", "High database write volume", "Expired SSL certificates"]), 1, "Scanning traffic manifests as sudden bursts of connections targeting sequential or random ports from a single origin IP."),
    (77, 4, "What defensive strategy constantly changes network addresses, ports, or layouts to confuse scanners?", json.dumps(["Honeynet", "Moving Target Defense", "Decoy Routing", "Ingress Filtering"]), 1, "Moving Target Defense shifts system surfaces dynamically, making scanned maps obsolete before attackers can exploit them."),
    (78, 4, "What is a network of multiple honeypots deployed together called?", json.dumps(["Moving target", "Honeynet", "IDS cluster", "Decoy pool"]), 1, "A honeynet is a subnet consisting of multiple honeypots configured to resemble a larger operational network segment."),
    (79, 4, "What mechanism blocks incoming packets with source IPs that do not belong to the source network?", json.dumps(["Egress filtering", "Ingress filtering", "Rate limits", "SSL decryption"]), 1, "Ingress filtering checks source addresses against topological routing tables, dropping incoming packets with forged external source IPs."),
    (80, 4, "How does a vulnerability scan differ from a simple port scan?", json.dumps(["It is passive", "It actively probes open ports for known software exploits and vulnerabilities", "It runs on database SQL commands", "It requires no network connection"]), 1, "A port scan simply catalogs listening ports, whereas a vulnerability scanner checks those listening services for specific bugs, misconfigurations, or patch levels.")
]

SEED_USERS = [
    ("admin@sentinel.com", "adminpass", "admin"),
    ("user@sentinel.com", "userpass", "user")
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
        week INTEGER NOT NULL,
        question TEXT NOT NULL,
        options TEXT NOT NULL,
        correct INTEGER NOT NULL,
        explanation TEXT NOT NULL
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
        email TEXT UNIQUE NOT NULL,
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
        cursor.executemany("INSERT INTO quiz_questions (id, week, question, options, correct, explanation) VALUES (?, ?, ?, ?, ?, ?)", SEED_QUESTIONS)

    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.executemany("INSERT INTO users (email, password, role) VALUES (?, ?, ?)", SEED_USERS)
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
            week_param = query.get('week', [None])[0]
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            if week_param:
                cursor.execute("SELECT id, week, question, options, explanation FROM quiz_questions WHERE week = ? ORDER BY id", (week_param,))
            else:
                cursor.execute("SELECT id, week, question, options, explanation FROM quiz_questions ORDER BY id")
            rows = cursor.fetchall()
            conn.close()
            questions = []
            for r in rows:
                questions.append({
                    "id": r[0],
                    "week": r[1],
                    "question": r[2],
                    "options": json.loads(r[3]),
                    "explanation": r[4]
                })
            self.send_json(questions)
            return

        elif path == '/api/history':
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

        elif path == '/api/admin/users':
            role = query.get('role', [None])[0]
            if role != 'admin':
                self.send_json({"error": "Unauthorized. Admin role required."}, 403)
                return

            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT id, email, role FROM users ORDER BY id")
            rows = cursor.fetchall()
            conn.close()

            users_list = [{"id": r[0], "email": r[1], "role": r[2]} for r in rows]
            self.send_json({
                "total": len(users_list),
                "users": users_list
            })
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
            email = body.get('email')
            password = body.get('password')

            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT email, role FROM users WHERE email = ? AND password = ?", (email, password))
            row = cursor.fetchone()
            conn.close()

            if row:
                self.send_json({
                    "success": True,
                    "username": row[0],
                    "role": row[1]
                })
            else:
                self.send_json({"success": False, "error": "Invalid email or password credentials"}, 401)
            return

        elif path == '/api/forgot-password':
            email = body.get('email')
            new_password = body.get('password')

            if not email or not new_password:
                self.send_json({"success": False, "error": "Email and new password are required"}, 400)
                return

            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
            user_exists = cursor.fetchone()

            if not user_exists:
                conn.close()
                self.send_json({"success": False, "error": "User with this email does not exist"}, 404)
                return

            cursor.execute("UPDATE users SET password = ? WHERE email = ?", (new_password, email))
            conn.commit()
            conn.close()

            self.send_json({"success": True, "message": "Password updated successfully"})
            return

        elif path == '/api/quiz/submit':
            question_id = body.get('id')
            selected_option = body.get('selected')

            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT correct, explanation FROM quiz_questions WHERE id = ?", (question_id,))
            row = cursor.fetchone()
            conn.close()

            if not row:
                self.send_json({"error": "Question not found"}, 404)
                return

            correct_index = row[0]
            explanation = row[1]
            self.send_json({
                "correct": (selected_option == correct_index),
                "correctIndex": correct_index,
                "explanation": explanation
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
