/* app.js - Refactored Hybrid Client Controller with User & Admin Authentication */

document.addEventListener('DOMContentLoaded', () => {
  // ================= LIVE DEBUGGER INTERCEPTOR =================
  const debugOutput = document.getElementById('debug-log-output');
  const debugConsole = document.getElementById('debug-console');
  const debugToggle = document.getElementById('debug-toggle-btn');
  const closeDebug = document.getElementById('close-debug-btn');

  if (closeDebug && debugConsole && debugToggle) {
    closeDebug.addEventListener('click', () => {
      debugConsole.style.display = 'none';
      debugToggle.style.display = 'block';
    });
    debugToggle.addEventListener('click', () => {
      debugConsole.style.display = 'flex';
      debugToggle.style.display = 'none';
    });
  }

  function logToDebugConsole(type, args) {
    if (!debugOutput) return;
    const msg = Array.from(args).map(arg => typeof arg === 'object' ? JSON.stringify(arg) : arg).join(' ');
    const line = document.createElement('div');
    line.style.marginBottom = '4px';
    if (type === 'error') {
      line.style.color = 'var(--accent-coral)';
    } else if (type === 'warn') {
      line.style.color = 'var(--accent-amber)';
    } else {
      line.style.color = 'var(--text-secondary)';
    }
    line.textContent = `[${type.toUpperCase()}] ${msg}`;
    debugOutput.appendChild(line);
    debugOutput.scrollTop = debugOutput.scrollHeight;
  }

  const _log = console.log;
  const _error = console.error;
  const _warn = console.warn;

  console.log = function() {
    logToDebugConsole('log', arguments);
    _log.apply(console, arguments);
  };
  console.error = function() {
    logToDebugConsole('error', arguments);
    _error.apply(console, arguments);
  };
  console.warn = function() {
    logToDebugConsole('warn', arguments);
    _warn.apply(console, arguments);
  };

  // ================= STATE & CONFIGURATION =================
  const state = {
    user: null,
    role: null,
    activeTab: 'dashboard',
    alertsDetected: 0,
    quizScore: 0,
    defenses: {
      ids: true,
      firewall: true,
      honeypot: false,
      ratelimit: true
    },
    scanner: {
      active: false,
      type: 'syn',
      speed: 'normal',
      intervalId: null,
      currentStep: 0,
      packetsSent: 0,
      portsScanned: [],
      simulatedPackets: []
    },
    training: {
      slides: [],
      questions: [],
      currentSlide: 0,
      answersSubmitted: {}
    }
  };

  // ================= FALLBACK STATIC DATA =================
  const FALLBACK_SLIDES = [
    {
      title: "Reconnaissance Overview",
      content: `
        <p>Reconnaissance is the initial phase of any cybersecurity evaluation. In this phase, a security auditor or analyst gathers as much information as possible about the target system before attempting to analyze its vulnerabilities.</p>
        <p>Recon is divided into two primary types:</p>
        <ul>
          <li><strong>Passive Reconnaissance</strong>: Gathering information without directly interacting with the target systems (e.g. search engines, WHOIS databases, DNS records).</li>
          <li><strong>Active Reconnaissance</strong>: Interacting directly with the target to discover details (e.g. network port scanning, service version identification).</li>
        </ul>
      `
    },
    {
      title: "Understanding Port Scanning",
      content: `
        <p>Ports are virtual points where network connections start and end. There are 65,535 TCP and UDP ports available on every IP address.</p>
        <p>Port scanning is an active recon technique used to map out which services (like web servers on port 80/443, mail systems on port 25, databases on port 3306) are listening for incoming traffic.</p>
        <p>By identifying open ports, security auditors can assess the network's attack surface and recommend which unused services should be turned off.</p>
      `
    },
    {
      title: "TCP Handshake Mechanics",
      content: `
        <p>The Transmission Control Protocol (TCP) relies on a three-way handshake to establish reliable connections:</p>
        <ol>
          <li><strong>SYN (Synchronize)</strong>: The client sends a packet initiating connection negotiation.</li>
          <li><strong>SYN-ACK (Synchronize-Acknowledge)</strong>: The server responds, agreeing to the connection.</li>
          <li><strong>ACK (Acknowledge)</strong>: The client acknowledges, establishing the path.</li>
        </ol>
        <p>Different port scanning methodologies manipulate these flags to determine if a port is open without necessarily completing the log-triggering connection.</p>
      `
    },
    {
      title: "Defending Against Reconnaissance",
      content: `
        <p>Recon is the foundation of any intrusion attempt. Blocking or complicating this phase significantly improves security:</p>
        <ul>
          <li><strong>Firewalls</strong>: Filter out unauthorized requests and drop packets to non-public ports.</li>
          <li><strong>Intrusion Detection Systems (IDS)</strong>: Monitor packet frequencies and flag scanning signatures.</li>
          <li><strong>Rate Limiting</strong>: Drop traffic from source IPs sending high volumes of connection requests.</li>
          <li><strong>Honeypots</strong>: Deploy decoy assets that distract scanner resources and catalog their behaviors.</li>
        </ul>
      `
    }
  ];

  const FALLBACK_QUESTIONS = [
    {
      id: 1,
      question: "Which type of reconnaissance does NOT involve direct interaction with the target systems?",
      options: [
        "Active Reconnaissance",
        "Passive Reconnaissance",
        "Exploitation",
        "Port Scanning"
      ],
      correct: 1
    },
    {
      id: 2,
      question: "What is the final packet sent by a scanner to complete a full TCP Connect Scan handshake?",
      options: [
        "SYN",
        "SYN-ACK",
        "RST",
        "ACK"
      ],
      correct: 3
    },
    {
      id: 3,
      question: "How does a target operating system typically respond to a UDP scan on a CLOSED port?",
      options: [
        "SYN-ACK",
        "ICMP Port Unreachable",
        "No response",
        "TCP Reset (RST)"
      ],
      correct: 1
    },
    {
      id: 4,
      question: "Which defensive mechanism is specifically designed to act as a decoy and capture intelligence?",
      options: [
        "Honeypot",
        "Firewall ruleset",
        "Rate limiter",
        "DNSSEC validation"
      ],
      correct: 0
    }
  ];

  const FALLBACK_METHODOLOGIES = {
    syn: {
      packets: [
        { from: 'attacker', to: 'firewall', label: 'SYN', type: 'req' },
        { from: 'firewall', to: 'web', label: 'SYN', type: 'req' },
        { from: 'web', to: 'firewall', label: 'SYN-ACK', type: 'resp-open' },
        { from: 'firewall', to: 'attacker', label: 'SYN-ACK', type: 'resp-open' },
        { from: 'attacker', to: 'firewall', label: 'RST', type: 'reset' }
      ]
    },
    connect: {
      packets: [
        { from: 'attacker', to: 'firewall', label: 'SYN', type: 'req' },
        { from: 'firewall', to: 'web', label: 'SYN', type: 'req' },
        { from: 'web', to: 'firewall', label: 'SYN-ACK', type: 'resp-open' },
        { from: 'firewall', to: 'attacker', label: 'SYN-ACK', type: 'resp-open' },
        { from: 'attacker', to: 'firewall', label: 'ACK', type: 'req' },
        { from: 'attacker', to: 'firewall', label: 'RST/ACK', type: 'reset' }
      ]
    },
    udp: {
      packets: [
        { from: 'attacker', to: 'firewall', label: 'UDP Probe', type: 'req' },
        { from: 'firewall', to: 'web', label: 'UDP Probe', type: 'req' },
        { from: 'web', to: 'firewall', label: 'ICMP Unreachable', type: 'error' },
        { from: 'firewall', to: 'attacker', label: 'ICMP Unreachable', type: 'error' }
      ]
    }
  };

  // ================= AUTHENTICATION PORTAL =================
  const loginOverlay = document.getElementById('login-overlay');
  const loginForm = document.getElementById('login-form');
  const loginErrorMsg = document.getElementById('login-error-msg');
  const logoutBtn = document.getElementById('logout-btn');
  const userBadge = document.getElementById('user-role-badge');
  const navAdminConsole = document.getElementById('nav-admin-console');

  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    loginErrorMsg.style.display = 'none';

    try {
      let loggedIn = false;
      let role = null;

      // Try server-side authentication if not on file protocol
      if (window.location.protocol !== 'file:') {
        try {
          const loginResp = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
          });

          if (loginResp.ok) {
            const authData = await loginResp.json();
            if (authData.success) {
              loggedIn = true;
              role = authData.role;
            }
          }
        } catch (fetchErr) {
          console.warn("Backend server authentication unreachable. Falling back to local verification.");
        }
      }

      // If backend was unreachable or static server returned 404, check locally
      if (!loggedIn) {
        if ((username === 'admin' && password === 'adminpass') || (username === 'user' && password === 'userpass')) {
          loggedIn = true;
          role = (username === 'admin') ? 'admin' : 'user';
        }
      }

      if (loggedIn) {
        handleSuccessfulLogin(username, role);
      } else {
        throw new Error("Invalid credentials");
      }

    } catch (err) {
      loginErrorMsg.style.display = 'block';
    }
  });

  logoutBtn.addEventListener('click', () => {
    state.user = null;
    state.role = null;
    
    // Clear inputs and reset UI
    document.getElementById('username').value = '';
    document.getElementById('password').value = '';
    loginOverlay.style.display = 'flex';
    navAdminConsole.style.display = 'none';
    
    switchTab('dashboard');
  });

  function handleSuccessfulLogin(username, role) {
    state.user = username;
    state.role = role;

    loginOverlay.style.display = 'none';
    userBadge.textContent = `${username.toUpperCase()} (${role.toUpperCase()})`;
    userBadge.style.color = role === 'admin' ? 'var(--accent-amber)' : 'var(--accent-cyan)';
    userBadge.style.borderColor = role === 'admin' ? 'var(--accent-amber)' : 'var(--accent-cyan)';

    if (role === 'admin') {
      navAdminConsole.style.display = 'flex';
    } else {
      navAdminConsole.style.display = 'none';
    }

    fetchTrainingData();
    switchTab('dashboard');
  }

  // ================= UTILITIES & UI NAVIGATION =================
  const navItems = document.querySelectorAll('.nav-item');
  const tabPanels = document.querySelectorAll('.tab-panel');
  const pageTitle = document.getElementById('current-page-title');

  navItems.forEach(item => {
    item.addEventListener('click', () => {
      const tab = item.getAttribute('data-tab');
      switchTab(tab);
    });
  });

  function switchTab(tab) {
    state.activeTab = tab;
    
    navItems.forEach(item => {
      if (item.getAttribute('data-tab') === tab) {
        item.classList.add('active');
      } else {
        item.classList.remove('active');
      }
    });

    tabPanels.forEach(panel => {
      if (panel.id === tab) {
        panel.classList.add('active');
      } else {
        panel.classList.remove('active');
      }
    });

    let titleText = 'Operational Dashboard';
    if (tab === 'scan-simulator') titleText = 'Port Scan Engine Simulator';
    if (tab === 'osint-analyzer') titleText = 'OSINT Footprint Analyzer';
    if (tab === 'defense-sandbox') titleText = 'Security Defense Sandbox';
    if (tab === 'knowledge-base') titleText = 'Cybersecurity Training & Quiz';
    if (tab === 'admin-console') titleText = 'Admin Audit Console';
    pageTitle.textContent = titleText;

    if (tab === 'dashboard') {
      updateDashboardData();
    } else if (tab === 'admin-console') {
      fetchAdminLogs();
    }
  }

  function updateDashboardData() {
    document.getElementById('dashboard-alerts').textContent = state.alertsDetected;
    document.getElementById('dashboard-score').textContent = `${state.quizScore}%`;
  }

  function addTerminalLine(element, text, styleClass = 'line-info') {
    if (!element) return;
    const line = document.createElement('div');
    line.className = `terminal-line ${styleClass}`;
    
    const timestamp = new Date().toLocaleTimeString();
    line.innerHTML = `<span class="line-info">[${timestamp}]</span> ${text}`;
    element.appendChild(line);
    element.scrollTop = element.scrollHeight;
  }

  // ================= ADMIN AUDIT TELEMETRY LOGS =================
  const dbHistoryRows = document.getElementById('db-history-rows');

  async function fetchAdminLogs() {
    dbHistoryRows.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 2rem; color: var(--text-muted);">Querying SQLite tables...</td></tr>';
    
    try {
      if (window.location.protocol === 'file:') {
        throw new Error("Local offline fallback");
      }

      const historyResp = await fetch(`/api/history?role=${state.role}`);
      if (!historyResp.ok) throw new Error("Unauthorized log query request");

      const logs = await historyResp.json();
      renderHistoryTable(logs);

    } catch (err) {
      console.log("Loading offline fallback database transaction records.");
      const mockLogs = [
        { timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19), type: "SYN", packets: 5, alerts: 1 },
        { timestamp: new Date(Date.now() - 3600000).toISOString().replace('T', ' ').substring(0, 19), type: "CONNECT", packets: 6, alerts: 0 }
      ];
      renderHistoryTable(mockLogs);
    }
  }

  function renderHistoryTable(logs) {
    if (logs.length === 0) {
      dbHistoryRows.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 2rem; color: var(--text-muted);">No logs found in SQLite scan_history database table.</td></tr>';
      return;
    }

    let rowsHTML = '';
    logs.forEach(log => {
      const alertColor = log.alerts > 0 ? 'var(--accent-coral)' : 'var(--text-muted)';
      rowsHTML += `
        <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
          <td style="padding: 0.75rem 1rem; font-family: var(--font-mono);">${log.timestamp}</td>
          <td style="padding: 0.75rem 1rem; font-weight: 500; color: var(--accent-cyan);">${log.type}</td>
          <td style="padding: 0.75rem 1rem;">${log.packets} packets</td>
          <td style="padding: 0.75rem 1rem; color: ${alertColor};">${log.alerts > 0 ? 'ALERT COMMITTED' : 'CLEAN'}</td>
        </tr>
      `;
    });
    dbHistoryRows.innerHTML = rowsHTML;
  }

  // ================= DATA FETCHING (BACKEND INTEGRATION) =================
  async function fetchTrainingData() {
    try {
      if (window.location.protocol === 'file:') {
        throw new Error("Local file protocol active");
      }
      
      const slideResp = await fetch('/api/slides');
      if (slideResp.ok) {
        state.training.slides = await slideResp.json();
      } else {
        throw new Error();
      }

      const quizResp = await fetch('/api/quiz');
      if (quizResp.ok) {
        state.training.questions = await quizResp.json();
      } else {
        throw new Error();
      }
    } catch (err) {
      console.log("Loading offline fallback training content.");
      state.training.slides = FALLBACK_SLIDES;
      state.training.questions = FALLBACK_QUESTIONS;
    }
    renderSlide();
    renderQuiz();
  }

  // ================= PORT SCAN SIMULATOR =================
  const startScanBtn = document.getElementById('start-scan-btn');
  const stopScanBtn = document.getElementById('stop-scan-btn');
  const scanConsole = document.getElementById('scan-console-output');
  const scanTypeSelect = document.getElementById('scan-type');
  const scanSpeedSelect = document.getElementById('scan-speed');

  startScanBtn.addEventListener('click', () => {
    if (state.scanner.active) return;
    initiatePortScan();
  });

  stopScanBtn.addEventListener('click', () => {
    stopPortScan('Scan aborted by user operator.');
  });

  async function initiatePortScan() {
    state.scanner.active = true;
    state.scanner.type = scanTypeSelect.value || 'syn';
    state.scanner.speed = scanSpeedSelect.value || 'normal';
    state.scanner.currentStep = 0;
    
    scanConsole.innerHTML = '';
    addTerminalLine(scanConsole, `Initializing Scan Session...`, 'line-info');
    
    try {
      if (window.location.protocol === 'file:') {
        throw new Error("File protocol active");
      }

      const scanResp = await fetch('/api/scan/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: state.scanner.type,
          defenses: state.defenses
        })
      });

      if (!scanResp.ok) throw new Error("Server API response error");
      
      const resultData = await scanResp.json();
      state.scanner.simulatedPackets = resultData.packets || [];
      
      if (resultData.logs && Array.isArray(resultData.logs)) {
        resultData.logs.forEach(log => {
          addTerminalLine(scanConsole, log, 'line-warning');
        });
      }

      if (resultData.alerts > 0) {
        state.alertsDetected += resultData.alerts;
      }

    } catch (err) {
      console.warn("Using client-side scanning simulation fallback:", err.message);
      const methodology = FALLBACK_METHODOLOGIES[state.scanner.type] || FALLBACK_METHODOLOGIES['syn'];
      state.scanner.simulatedPackets = methodology ? (methodology.packets || []) : [];
      
      if (state.defenses.firewall && state.scanner.type !== 'udp') {
        addTerminalLine(scanConsole, "Firewall: Connection to DB Port 3306 filtered and dropped (Local Shield).", 'line-warning');
      }
    }

    let delay = 1000;
    if (state.scanner.speed === 'fast') delay = 400;
    if (state.scanner.speed === 'slow') delay = 2000;

    const attackerNode = document.getElementById('node-attacker');
    if (attackerNode) attackerNode.classList.add('active');

    // Reset interval safely
    if (state.scanner.intervalId) {
      clearInterval(state.scanner.intervalId);
    }
    state.scanner.intervalId = setInterval(runScanStep, delay);
  }

  function runScanStep() {
    try {
      const step = state.scanner.currentStep;
      const packets = state.scanner.simulatedPackets || [];

      if (packets.length === 0) {
        throw new Error("No scanning packets loaded.");
      }

      if (step >= packets.length) {
        addTerminalLine(scanConsole, `Scan execution complete. Port mapping parsed.`, 'line-success');
        
        if (state.scanner.type === 'udp') {
          addTerminalLine(scanConsole, `PORT   STATE        SERVICE\n80/udp  open|filtered http\n3306/udp open|filtered mysql\n25/udp  closed       smtp`, 'line-success');
        } else {
          const dbState = state.defenses.firewall ? 'filtered' : 'open';
          addTerminalLine(scanConsole, `PORT     STATE    SERVICE\n80/tcp   open     http\n3306/tcp ${dbState} mysql\n25/tcp   closed   smtp`, 'line-success');
        }
        
        stopPortScan();
        return;
      }

      const packet = packets[step];
      visualizePacket(packet);

      if (packet.from === 'attacker' && packet.to === 'firewall') {
        addTerminalLine(scanConsole, `Outgoing: Attacker -> Target Port (Sent Flag: ${packet.label})`, 'line-info');
      } else if (packet.from === 'firewall' && packet.to === 'attacker') {
        let outputStyle = 'line-info';
        if (packet.type === 'resp-open') outputStyle = 'line-success';
        if (packet.type === 'error' || packet.type === 'reset') outputStyle = 'line-error';
        addTerminalLine(scanConsole, `Incoming: Attacker <- Target Port (Received Flag: ${packet.label})`, outputStyle);
      }

      if (state.defenses.ids && packet.from === 'attacker') {
        const sandboxConsole = document.getElementById('sandbox-console-output');
        if (sandboxConsole) {
          addTerminalLine(sandboxConsole, `IDS ALERT: Scan attempt detected from source IP (Flag: ${packet.label})`, 'line-warning');
        }
        state.alertsDetected++;
      }

      state.scanner.currentStep++;
    } catch (err) {
      console.error("Scanner execution runtime crash:", err);
      stopPortScan(`Scanner Error: ${err.message}`);
    }
  }

  function visualizePacket(packet) {
    const canvas = document.getElementById('network-canvas');
    const fromEl = document.getElementById(`node-${packet.from}`);
    const toEl = document.getElementById(`node-${packet.to}`);

    if (!fromEl || !toEl) return;

    const fromRect = fromEl.getBoundingClientRect();
    const toRect = toEl.getBoundingClientRect();
    const canvasRect = canvas.getBoundingClientRect();

    const startX = fromRect.left - canvasRect.left + 24;
    const startY = fromRect.top - canvasRect.top + 24;
    const endX = toRect.left - canvasRect.left + 24;
    const endY = toRect.top - canvasRect.top + 24;

    const pkt = document.createElement('div');
    pkt.className = 'packet';
    
    if (packet.type === 'resp-open') pkt.style.backgroundColor = 'var(--accent-emerald)';
    if (packet.type === 'error' || packet.type === 'reset') pkt.style.backgroundColor = 'var(--accent-coral)';
    
    pkt.style.left = `${startX}px`;
    pkt.style.top = `${startY}px`;
    canvas.appendChild(pkt);

    let progress = 0;
    const duration = state.scanner.speed === 'fast' ? 200 : state.scanner.speed === 'slow' ? 1000 : 500;
    const steps = 20;
    const stepTime = duration / steps;
    
    const animInterval = setInterval(() => {
      progress += 1 / steps;
      if (progress >= 1) {
        clearInterval(animInterval);
        pkt.remove();
        toEl.classList.add('active');
        setTimeout(() => toEl.classList.remove('active'), 250);
      } else {
        const currentX = startX + (endX - startX) * progress;
        const currentY = startY + (endY - startY) * progress;
        pkt.style.left = `${currentX}px`;
        pkt.style.top = `${currentY}px`;
      }
    }, stepTime);
  }

  function stopPortScan(abortReason = '') {
    state.scanner.active = false;
    if (state.scanner.intervalId) {
      clearInterval(state.scanner.intervalId);
    }
    document.getElementById('node-attacker').classList.remove('active');
    if (abortReason) {
      addTerminalLine(scanConsole, abortReason, 'line-error');
    }
  }

  // ================= OSINT FOOTPRINT ANALYZER =================
  const startOsintBtn = document.getElementById('start-osint-btn');
  const osintTerminal = document.getElementById('osint-console-output');
  const osintResultsPanel = document.getElementById('osint-results-panel');
  const hardeningCard = document.getElementById('hardening-card');
  const hardeningList = document.getElementById('hardening-list');

  startOsintBtn.addEventListener('click', () => {
    const domain = document.getElementById('osint-domain').value.trim();
    if (!domain) return;
    runOsintSimulation(domain);
  });

  async function runOsintSimulation(domain) {
    osintTerminal.innerHTML = '';
    addTerminalLine(osintTerminal, `Initiating passive intelligence gathering on: ${domain}...`, 'line-info');
    
    try {
      if (window.location.protocol === 'file:') {
        throw new Error("File protocol detected");
      }

      const osintResp = await fetch('/api/osint/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: domain })
      });

      if (!osintResp.ok) throw new Error("OSINT analysis server error.");

      const result = await osintResp.json();
      presentOsintOutputs(result);

    } catch (err) {
      console.log("Using client-side OSINT simulation fallback.");
      const result = {
        domain: domain,
        dns: [
          { type: "A", value: "192.168.10.45" },
          { type: "MX", value: `mail.${domain}` },
          { type: "TXT", value: '"v=spf1 include:_spf.google.com ~all" (SoftFail Configured)', vulnerable: true },
          { type: "DMARC", value: "None found (Vulnerable to email impersonation)", vulnerable: true }
        ],
        whois: {
          registrar: "SafeNames Ltd.",
          contact: `admin@${domain} (Private WHOIS Shielding inactive)`,
          location: "Germany, Frankfurt"
        }
      };
      
      setTimeout(() => {
        addTerminalLine(osintTerminal, `Querying public WHOIS registries for registrar data...`, 'line-info');
      }, 500);

      setTimeout(() => {
        addTerminalLine(osintTerminal, `Extracting active DNS Zone records...`, 'line-info');
      }, 1200);

      setTimeout(() => {
        addTerminalLine(osintTerminal, `OSINT compilation completed successfully.`, 'line-success');
        presentOsintOutputs(result);
      }, 2000);
    }
  }

  function presentOsintOutputs(result) {
    let dnsRows = '';
    result.dns.forEach(record => {
      const colorStyle = record.vulnerable ? 'style="color: var(--accent-coral);"' : '';
      dnsRows += `<div ${colorStyle}>${record.type.padEnd(5)} -> ${record.value}</div>`;
    });

    osintResultsPanel.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: 1rem;">
        <div style="border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.75rem;">
          <span style="color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase;">Domain Target</span>
          <div style="font-weight: 600; color: var(--accent-cyan); font-family: var(--font-display);">${result.domain}</div>
        </div>

        <div>
          <span style="color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase;">DNS Zone Configuration</span>
          <div style="display: flex; flex-direction: column; gap: 0.35rem; margin-top: 0.5rem; font-family: var(--font-mono); font-size: 0.8rem;">
            ${dnsRows}
          </div>
        </div>

        <div>
          <span style="color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase;">WHOIS Registry Data</span>
          <div style="margin-top: 0.25rem; font-size: 0.85rem; color: var(--text-secondary);">
            Registrar: ${result.whois.registrar}<br>
            Tech Contact: ${result.whois.contact}<br>
            Server Location: ${result.whois.location}
          </div>
        </div>
      </div>
    `;

    hardeningCard.style.display = 'block';
    hardeningList.innerHTML = `
      <div class="checklist-item">
        <div class="checklist-icon warning"><i class="fa-solid fa-triangle-exclamation"></i></div>
        <div class="checklist-details">
          <h4>Implement DMARC Records</h4>
          <p>No TXT DMARC record discovered. Add a rule policy (e.g. <code>p=reject</code>) to prevent spoofing.</p>
        </div>
      </div>
      <div class="checklist-item">
        <div class="checklist-icon warning"><i class="fa-solid fa-triangle-exclamation"></i></div>
        <div class="checklist-details">
          <h4>Configure WHOIS Privacy Shielding</h4>
          <p>The administrative contact email is exposed publicly. Activate privacy protection services.</p>
        </div>
      </div>
      <div class="checklist-item">
        <div class="checklist-icon secure"><i class="fa-solid fa-check"></i></div>
        <div class="checklist-details">
          <h4>SPF Policy Check</h4>
          <p>SPF records configured correctly. However, upgrading from ~all (SoftFail) to -all (HardFail) is recommended.</p>
        </div>
      </div>
    `;
  }

  // ================= DEFENSE SANDBOX =================
  const idsToggle = document.getElementById('defense-ids-toggle');
  const firewallToggle = document.getElementById('defense-firewall-toggle');
  const honeypotToggle = document.getElementById('defense-honeypot-toggle');
  const ratelimitToggle = document.getElementById('defense-ratelimit-toggle');

  const reconEfficiency = document.getElementById('sandbox-recon-efficiency');
  const barRecon = document.getElementById('bar-recon-efficiency');
  const detectionCap = document.getElementById('sandbox-detection-cap');
  const barDetection = document.getElementById('bar-detection-cap');
  const decoyScore = document.getElementById('sandbox-decoy-attraction');
  const barDecoy = document.getElementById('bar-decoy-attraction');

  [idsToggle, firewallToggle, honeypotToggle, ratelimitToggle].forEach(toggle => {
    toggle.addEventListener('change', () => {
      state.defenses.ids = idsToggle.checked;
      state.defenses.firewall = firewallToggle.checked;
      state.defenses.honeypot = honeypotToggle.checked;
      state.defenses.ratelimit = ratelimitToggle.checked;

      updateDefenseIndicators();
      updateDashboardSettings();
    });
  });

  function updateDefenseIndicators() {
    let efficiency = 100;
    let detection = 0;
    let decoy = 0;

    if (state.defenses.firewall) efficiency -= 35;
    if (state.defenses.ratelimit) efficiency -= 25;
    if (state.defenses.honeypot) {
      efficiency -= 15;
      decoy = 85;
    }
    
    if (state.defenses.ids) detection += 50;
    if (state.defenses.firewall) detection += 25;
    if (state.defenses.honeypot) detection += 15;

    efficiency = Math.max(10, efficiency);
    detection = Math.min(98, detection);

    reconEfficiency.textContent = `${efficiency}%`;
    barRecon.style.width = `${efficiency}%`;

    detectionCap.textContent = `${detection}%`;
    barDetection.style.width = `${detection}%`;

    decoyScore.textContent = `${decoy}%`;
    barDecoy.style.width = `${decoy}%`;
  }

  function updateDashboardSettings() {
    document.getElementById('summary-ids').textContent = state.defenses.ids ? 'Active Detection' : 'Disabled';
    document.getElementById('summary-ids').style.color = state.defenses.ids ? 'var(--accent-cyan)' : 'var(--text-muted)';
    
    document.getElementById('summary-firewall').textContent = state.defenses.firewall ? 'Strict Filtering' : 'Permissive (Any)';
    document.getElementById('summary-firewall').style.color = state.defenses.firewall ? 'var(--accent-emerald)' : 'var(--accent-coral)';

    document.getElementById('summary-honeypot').textContent = state.defenses.honeypot ? 'Decoys Active' : 'Disabled';
    document.getElementById('summary-honeypot').style.color = state.defenses.honeypot ? 'var(--accent-amber)' : 'var(--text-muted)';

    document.getElementById('summary-ratelimit').textContent = state.defenses.ratelimit ? 'Blocking Bursts' : 'Inactive';
    document.getElementById('summary-ratelimit').style.color = state.defenses.ratelimit ? 'var(--accent-emerald)' : 'var(--accent-coral)';
  }

  // ================= TRAINING & QUIZ =================
  const slideContainer = document.getElementById('training-slides');
  const prevSlideBtn = document.getElementById('prev-slide-btn');
  const nextSlideBtn = document.getElementById('next-slide-btn');
  const slideTracker = document.getElementById('slide-tracker');
  const quizContainer = document.getElementById('quiz-container');

  prevSlideBtn.addEventListener('click', () => {
    if (state.training.currentSlide > 0) {
      state.training.currentSlide--;
      renderSlide();
    }
  });

  nextSlideBtn.addEventListener('click', () => {
    if (state.training.currentSlide < state.training.slides.length - 1) {
      state.training.currentSlide++;
      renderSlide();
    }
  });

  function renderSlide() {
    if (state.training.slides.length === 0) return;
    const slide = state.training.slides[state.training.currentSlide];
    slideContainer.innerHTML = `
      <h3 style="font-family: var(--font-display); font-size: 1.25rem; margin-bottom: 1rem; color: var(--accent-cyan);">${slide.title}</h3>
      <div class="slide-content">${slide.content}</div>
    `;

    prevSlideBtn.disabled = state.training.currentSlide === 0;
    nextSlideBtn.disabled = state.training.currentSlide === state.training.slides.length - 1;
    slideTracker.textContent = `Slide ${state.training.currentSlide + 1} of ${state.training.slides.length}`;
  }

  function renderQuiz() {
    quizContainer.innerHTML = '';
    state.training.questions.forEach((q, idx) => {
      const qDiv = document.createElement('div');
      qDiv.style.marginBottom = '1.5rem';
      
      const qTitle = document.createElement('h4');
      qTitle.style.fontSize = '0.95rem';
      qTitle.style.marginBottom = '0.75rem';
      qTitle.textContent = `${idx + 1}. ${q.question}`;
      qDiv.appendChild(qTitle);

      q.options.forEach((opt, optIdx) => {
        const optDiv = document.createElement('div');
        optDiv.className = 'quiz-option';
        optDiv.innerHTML = `
          <span>${opt}</span>
          <i class="fa-solid fa-circle" style="font-size: 0.65rem; color: rgba(255,255,255,0.1);"></i>
        `;
        
        optDiv.addEventListener('click', () => submitQuizAnswer(q.id, optIdx, optDiv, qDiv));
        qDiv.appendChild(optDiv);
      });

      quizContainer.appendChild(qDiv);
    });
  }

  async function submitQuizAnswer(questionId, selectedIdx, optDiv, qDiv) {
    if (state.training.answersSubmitted[questionId] !== undefined) return;
    
    state.training.answersSubmitted[questionId] = selectedIdx;
    
    try {
      if (window.location.protocol === 'file:') {
        throw new Error();
      }

      const checkResp = await fetch('/api/quiz/submit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: Number(questionId), selected: selectedIdx })
      });

      if (!checkResp.ok) throw new Error();

      const validation = await checkResp.json();
      applyQuizSelectionUI(validation.correct, validation.correctIndex, optDiv, qDiv);

    } catch (err) {
      console.log("Using offline quiz check fallback.");
      const question = FALLBACK_QUESTIONS.find(q => q.id == questionId);
      if (question) {
        const isCorrect = (selectedIdx === question.correct);
        applyQuizSelectionUI(isCorrect, question.correct, optDiv, qDiv);
      } else {
        console.error("Could not find matching fallback question ID:", questionId);
      }
    }
  }

  function applyQuizSelectionUI(isCorrect, correctIndex, optDiv, qDiv) {
    if (isCorrect) {
      optDiv.classList.add('correct');
      optDiv.querySelector('i').className = 'fa-solid fa-circle-check';
      optDiv.querySelector('i').style.color = 'var(--accent-emerald)';
    } else {
      optDiv.classList.add('incorrect');
      optDiv.querySelector('i').className = 'fa-solid fa-circle-xmark';
      optDiv.querySelector('i').style.color = 'var(--accent-coral)';

      const correctOpt = qDiv.querySelectorAll('.quiz-option')[correctIndex];
      if (correctOpt) {
        correctOpt.classList.add('correct');
        correctOpt.querySelector('i').className = 'fa-solid fa-circle-check';
        correctOpt.querySelector('i').style.color = 'var(--accent-emerald)';
      }
    }

    calculateQuizScore();
  }

  function calculateQuizScore() {
    let totalQuestions = state.training.questions.length;
    if (totalQuestions === 0) return;
    
    let uniqueCorrects = 0;
    
    state.training.questions.forEach(q => {
      const submitted = state.training.answersSubmitted[q.id];
      if (submitted !== undefined) {
        const questionData = FALLBACK_QUESTIONS.find(fq => fq.id == q.id);
        if (questionData && submitted === questionData.correct) {
          uniqueCorrects++;
        }
      }
    });

    let score = Math.round((uniqueCorrects / totalQuestions) * 100);
    state.quizScore = Math.min(100, score);
    updateDashboardData();
  }

  // Initial runs (Pre-auth placeholders)
  updateDefenseIndicators();
  updateDashboardSettings();
  updateDashboardData();
});
