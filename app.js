/* app.js - Refactored Client Controller with Email Auth, Recovery Resets, Profiles, and Week-Wise Quizzes */

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
    quizScore: 0, // Cumulative average score
    quizWeekScores: {
      1: null,
      2: null,
      3: null,
      4: null
    },
    currentQuizWeek: 1,
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
      answersSubmitted: {} // Maps questionId to selected option index
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

  // Offline mock questions (20 unique questions per week, matching server database seed)
  const FALLBACK_QUESTIONS = [];
  const TOPICS_BY_WEEK = {
    1: "Passive Recon & OSINT",
    2: "Port Scan Mechanics",
    3: "TCP Flag Manipulation",
    4: "Defenses & Hardening"
  };

  // Generate fallback mock quiz bank structured by week
  for (let w = 1; w <= 4; w++) {
    for (let q = 1; q <= 20; q++) {
      const globalId = (w - 1) * 20 + q;
      FALLBACK_QUESTIONS.push({
        id: globalId,
        week: w,
        question: `[Week ${w} - Question ${q}] This is a fallback query regarding ${TOPICS_BY_WEEK[w]}?`,
        options: ["Option A (Incorrect)", "Option B (Correct Answer)", "Option C (Incorrect)", "Option D (Incorrect)"],
        correct: 1,
        explanation: `Under ${TOPICS_BY_WEEK[w]} guidelines, Option B is correct because it maps directly to standard cybersecurity methodologies.`
      });
    }
  }

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

  // ================= DOM ELEMENT SELECTIONS =================
  const loginOverlay = document.getElementById('login-overlay');
  const loginForm = document.getElementById('login-form');
  const loginEmail = document.getElementById('login-email');
  const loginPassword = document.getElementById('login-password');
  const loginErrorMsg = document.getElementById('login-error-msg');
  
  const forgotForm = document.getElementById('forgot-form');
  const forgotEmail = document.getElementById('forgot-email');
  const forgotNewPassword = document.getElementById('forgot-new-password');
  const forgotMessage = document.getElementById('forgot-message');
  
  const forgotPasswordLink = document.getElementById('forgot-password-link');
  const backToLoginLink = document.getElementById('back-to-login-link');
  
  const logoutBtn = document.getElementById('logout-btn');
  const userBadge = document.getElementById('user-role-badge');
  const navAdminConsole = document.getElementById('nav-admin-console');
  const navKnowledgeBase = document.getElementById('nav-knowledge-base');
  const navMyProfile = document.getElementById('nav-my-profile');

  // ================= AUTHENTICATION & RECOVERY HANDLERS =================
  
  // Toggle forgot password cards
  forgotPasswordLink.addEventListener('click', (e) => {
    e.preventDefault();
    loginForm.style.display = 'none';
    forgotForm.style.display = 'block';
    forgotMessage.style.display = 'none';
  });

  backToLoginLink.addEventListener('click', (e) => {
    e.preventDefault();
    forgotForm.style.display = 'none';
    loginForm.style.display = 'block';
    loginErrorMsg.style.display = 'none';
  });

  // Handle forgot password submission
  forgotForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    forgotMessage.style.display = 'none';
    
    const email = forgotEmail.value.trim();
    const password = forgotNewPassword.value.trim();

    try {
      if (window.location.protocol === 'file:') {
        // Offline Mock Password update
        if (email === 'user@gmail.com' || email === 'admin@gmail.com') {
          forgotMessage.textContent = "Offline Reset Success! Use your new password to log in.";
          forgotMessage.style.color = "var(--accent-emerald)";
          forgotMessage.style.display = "block";
        } else {
          throw new Error("User email not found in local offline storage.");
        }
        return;
      }

      const forgotResp = await fetch('/api/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      const resData = await forgotResp.json();
      if (forgotResp.ok && resData.success) {
        forgotMessage.textContent = "Credentials reset successfully! Return to Login.";
        forgotMessage.style.color = "var(--accent-emerald)";
      } else {
        throw new Error(resData.error || "Reset failed.");
      }
    } catch (err) {
      forgotMessage.textContent = err.message;
      forgotMessage.style.color = "var(--accent-coral)";
    }
    forgotMessage.style.display = 'block';
  });

  // Handle standard Login submission
  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = loginEmail.value.trim();
    const password = loginPassword.value.trim();
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
            body: JSON.stringify({ email, password })
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

      // Offline credentials validation fallback
      if (!loggedIn) {
        if ((email === 'admin@gmail.com' && password === 'adminpass') || 
            (email === 'user@gmail.com' && password === 'userpass')) {
          loggedIn = true;
          role = (email === 'admin@gmail.com') ? 'admin' : 'user';
        }
      }

      if (loggedIn) {
        handleSuccessfulLogin(email, role);
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
    state.quizWeekScores = { 1: null, 2: null, 3: null, 4: null };
    state.quizScore = 0;
    
    // Clear inputs and reset UI
    loginEmail.value = '';
    loginPassword.value = '';
    forgotEmail.value = '';
    forgotNewPassword.value = '';
    
    loginOverlay.style.display = 'flex';
    loginForm.style.display = 'block';
    forgotForm.style.display = 'none';
    navAdminConsole.style.display = 'none';
    navKnowledgeBase.style.display = 'flex';
    
    switchTab('dashboard');
  });

  function handleSuccessfulLogin(email, role) {
    state.user = email;
    state.role = role;

    loginOverlay.style.display = 'none';
    userBadge.textContent = `${email.toUpperCase()} (${role.toUpperCase()})`;
    userBadge.style.color = role === 'admin' ? 'var(--accent-amber)' : 'var(--accent-cyan)';
    userBadge.style.borderColor = role === 'admin' ? 'var(--accent-amber)' : 'var(--accent-cyan)';

    // Dynamic Navigation Visibility depending on credentials role
    if (role === 'admin') {
      navAdminConsole.style.display = 'flex';
      navKnowledgeBase.style.display = 'none'; // Hide quiz section from Admin
    } else {
      navAdminConsole.style.display = 'none';
      navKnowledgeBase.style.display = 'flex'; // Show quiz section to Users
    }

    // Refresh profile card and active stats
    updateProfileUI();
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
    if (tab === 'my-profile') titleText = 'User Profile Console';
    if (tab === 'admin-console') titleText = 'Admin Audit Console';
    pageTitle.textContent = titleText;

    if (tab === 'dashboard') {
      updateDashboardData();
    } else if (tab === 'admin-console') {
      fetchAdminLogs();
      fetchAdminUserStats();
    } else if (tab === 'my-profile') {
      updateProfileUI();
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
  const adminTotalUsersEl = document.getElementById('admin-total-users');
  const adminUserRowsEl = document.getElementById('admin-user-rows');

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

  // Fetch registered user list directory for admin dashboard
  async function fetchAdminUserStats() {
    if (!adminUserRowsEl) return;
    adminUserRowsEl.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 1rem; color: var(--text-muted);">Loading user metrics...</td></tr>';
    
    try {
      if (window.location.protocol === 'file:') throw new Error("Offline mode");

      const statsResp = await fetch(`/api/admin/users?role=${state.role}`);
      if (!statsResp.ok) throw new Error("Unauthorized data call");

      const data = await statsResp.json();
      adminTotalUsersEl.textContent = data.total;
      
      let rows = '';
      data.users.forEach(u => {
        rows += `
          <tr style="border-bottom: 1px solid rgba(255,255,255,0.03);">
            <td style="padding: 0.35rem 0.5rem; font-family: var(--font-mono);">${u.id}</td>
            <td style="padding: 0.35rem 0.5rem; color: var(--accent-cyan);">${u.email}</td>
            <td style="padding: 0.35rem 0.5rem;">${u.role.toUpperCase()}</td>
          </tr>
        `;
      });
      adminUserRowsEl.innerHTML = rows;

    } catch (err) {
      console.log("Loading offline fallback stats directory.");
      adminUserRowsEl.innerHTML = `
        <tr style="border-bottom: 1px solid rgba(255,255,255,0.03);">
          <td style="padding: 0.35rem 0.5rem; font-family: var(--font-mono);">1</td>
          <td style="padding: 0.35rem 0.5rem; color: var(--accent-cyan);">admin@gmail.com</td>
          <td style="padding: 0.35rem 0.5rem;">ADMIN</td>
        </tr>
        <tr style="border-bottom: 1px solid rgba(255,255,255,0.03);">
          <td style="padding: 0.35rem 0.5rem; font-family: var(--font-mono);">2</td>
          <td style="padding: 0.35rem 0.5rem; color: var(--accent-cyan);">user@gmail.com</td>
          <td style="padding: 0.35rem 0.5rem;">USER</td>
        </tr>
      `;
    }
  }

  // ================= USER PROFILE MANAGEMENT =================
  function updateProfileUI() {
    const initialsEl = document.getElementById('profile-initials');
    const emailDisplayEl = document.getElementById('profile-email-display');
    const roleDisplayEl = document.getElementById('profile-role-display');

    if (!emailDisplayEl) return;

    const emailStr = state.user || 'user@gmail.com';
    emailDisplayEl.textContent = emailStr;
    roleDisplayEl.textContent = (state.role || 'USER').toUpperCase();
    
    // Initials parsing
    const initials = emailStr.split('@')[0].substring(0, 2).toUpperCase();
    initialsEl.textContent = initials;

    // Refresh week scores indicators on the profile panel
    for (let w = 1; w <= 4; w++) {
      const scoreVal = state.quizWeekScores[w];
      const scoreLabelEl = document.getElementById(`score-w1` ? `score-w${w}` : null);
      const badgeEl = document.getElementById(`badge-w1` ? `badge-w${w}` : null);

      if (scoreLabelEl && badgeEl) {
        if (scoreVal !== null) {
          scoreLabelEl.textContent = `${scoreVal}%`;
          scoreLabelEl.style.color = scoreVal >= 70 ? 'var(--accent-emerald)' : 'var(--accent-coral)';
          badgeEl.classList.add('completed');
        } else {
          scoreLabelEl.textContent = "Locked";
          scoreLabelEl.style.color = 'var(--text-muted)';
          badgeEl.classList.remove('completed');
        }
      }
    }
  }

  // ================= DATA FETCHING (QUIZ WEEKS MIGRATION) =================
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
    } catch (err) {
      console.log("Loading offline fallback slides.");
      state.training.slides = FALLBACK_SLIDES;
    }
    renderSlide();
    loadWeekQuiz(state.currentQuizWeek);
  }

  // Renders 20 questions for the selected week
  async function loadWeekQuiz(weekNum) {
    state.currentQuizWeek = weekNum;
    state.training.questions = [];
    state.training.answersSubmitted = {};
    
    // Clear and hide submit buttons
    const submitBtn = document.getElementById('submit-quiz-btn');
    if (submitBtn) submitBtn.style.display = 'none';

    // Update Topic label
    const topicEl = document.getElementById('quiz-week-topic');
    if (topicEl) topicEl.textContent = TOPICS_BY_WEEK[weekNum];

    // Refresh score display
    const wScore = state.quizWeekScores[weekNum];
    const scoreValEl = document.getElementById('quiz-week-score');
    if (scoreValEl) {
      scoreValEl.textContent = wScore !== null ? `Graded: ${wScore}%` : "Not Started";
      scoreValEl.style.color = wScore !== null ? 'var(--accent-cyan)' : 'var(--accent-amber)';
    }

    // Update active week selector tab button styles
    document.querySelectorAll('#quiz-week-tabs button').forEach(btn => {
      const btnWeek = parseInt(btn.getAttribute('data-week'));
      if (btnWeek === weekNum) {
        btn.classList.add('active');
      } else {
        btn.classList.remove('active');
      }
    });

    try {
      if (window.location.protocol === 'file:') throw new Error("Offline fetch");
      
      const quizResp = await fetch(`/api/quiz?week=${weekNum}`);
      if (quizResp.ok) {
        state.training.questions = await quizResp.json();
      } else {
        throw new Error();
      }
    } catch (err) {
      console.log("Loading offline fallback quiz questions for week:", weekNum);
      state.training.questions = FALLBACK_QUESTIONS.filter(q => q.week === weekNum);
    }

    renderQuiz();
  }

  // Bind week button triggers
  document.querySelectorAll('#quiz-week-tabs button').forEach(btn => {
    btn.addEventListener('click', () => {
      const week = parseInt(btn.getAttribute('data-week'));
      loadWeekQuiz(week);
    });
  });

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
    try {
      const canvas = document.getElementById('network-canvas');
      if (!canvas) return;
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
    } catch (err) {
      console.warn("Packet visualization animation skipped:", err.message);
    }
  }

  function stopPortScan(abortReason = '') {
    state.scanner.active = false;
    if (state.scanner.intervalId) {
      clearInterval(state.scanner.intervalId);
    }
    const attackerNode = document.getElementById('node-attacker');
    if (attackerNode) attackerNode.classList.remove('active');
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

  // ================= TRAINING & QUIZ (WEEK-WISE SUPPORT) =================
  const slideContainer = document.getElementById('training-slides');
  const prevSlideBtn = document.getElementById('prev-slide-btn');
  const nextSlideBtn = document.getElementById('next-slide-btn');
  const slideTracker = document.getElementById('slide-tracker');
  const quizContainer = document.getElementById('quiz-container');
  const submitQuizBtn = document.getElementById('submit-quiz-btn');

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
    
    const activeWeek = state.currentQuizWeek;
    const isGraded = state.quizWeekScores[activeWeek] !== null;

    if (state.training.questions.length === 0) {
      quizContainer.innerHTML = '<div style="text-align: center; color: var(--text-muted); padding: 1rem;">No questions seeded for this week.</div>';
      submitQuizBtn.style.display = 'none';
      return;
    }

    state.training.questions.forEach((q, idx) => {
      const qDiv = document.createElement('div');
      qDiv.style.marginBottom = '2rem';
      qDiv.style.borderBottom = '1px solid rgba(255,255,255,0.03)';
      qDiv.style.paddingBottom = '1rem';
      qDiv.className = 'quiz-question-block';
      qDiv.setAttribute('data-qid', q.id);
      
      const qTitle = document.createElement('h4');
      qTitle.style.fontSize = '0.9rem';
      qTitle.style.marginBottom = '0.75rem';
      qTitle.textContent = `${idx + 1}. ${q.question}`;
      qDiv.appendChild(qTitle);

      q.options.forEach((opt, optIdx) => {
        const optDiv = document.createElement('div');
        optDiv.className = 'quiz-option';
        
        // Restore submitted state visual styling if graded
        const answersSubmitted = state.training.answersSubmitted[q.id];
        if (isGraded) {
          const isSelected = answersSubmitted === optIdx;
          const isCorrectAnswer = optIdx === q.correct;
          if (isCorrectAnswer) {
            optDiv.classList.add('correct');
          } else if (isSelected) {
            optDiv.classList.add('incorrect');
          }
        } else {
          // If not graded, bind click listener
          optDiv.addEventListener('click', () => selectOption(q.id, optIdx, qDiv));
          
          if (answersSubmitted === optIdx) {
            optDiv.style.borderColor = 'var(--accent-cyan)';
            optDiv.style.background = 'rgba(0, 242, 254, 0.05)';
          }
        }

        optDiv.innerHTML = `
          <span>${opt}</span>
          <i class="fa-solid ${isGraded && optIdx === q.correct ? 'fa-circle-check' : 'fa-circle'}" style="font-size: 0.65rem; color: ${isGraded && optIdx === q.correct ? 'var(--accent-emerald)' : 'rgba(255,255,255,0.1)'}"></i>
        `;
        
        qDiv.appendChild(optDiv);
      });

      // Display explanation text if graded
      if (isGraded) {
        const expDiv = document.createElement('div');
        expDiv.className = 'line-explanation';
        expDiv.innerHTML = `<strong>Explanation:</strong> ${q.explanation}`;
        qDiv.appendChild(expDiv);
      }

      quizContainer.appendChild(qDiv);
    });

    // Control visibility of submit button
    if (isGraded) {
      submitQuizBtn.style.display = 'none';
    } else {
      submitQuizBtn.style.display = 'block';
    }
  }

  function selectOption(questionId, selectedIdx, qDiv) {
    state.training.answersSubmitted[questionId] = selectedIdx;
    
    // Reset border borders for all child options
    qDiv.querySelectorAll('.quiz-option').forEach((opt, idx) => {
      if (idx === selectedIdx) {
        opt.style.borderColor = 'var(--accent-cyan)';
        opt.style.background = 'rgba(0, 242, 254, 0.05)';
      } else {
        opt.style.borderColor = 'var(--border-color)';
        opt.style.background = 'rgba(13, 20, 38, 0.6)';
      }
    });
  }

  // Handle entire Week Quiz grading submission
  submitQuizBtn.addEventListener('click', async () => {
    const activeWeek = state.currentQuizWeek;
    let unansweredCount = 0;
    
    state.training.questions.forEach(q => {
      if (state.training.answersSubmitted[q.id] === undefined) {
        unansweredCount++;
      }
    });

    if (unansweredCount > 0) {
      alert(`Please answer all 20 questions before submitting. (${unansweredCount} remaining)`);
      return;
    }

    // Submit and check answers
    let correctCount = 0;
    
    for (let i = 0; i < state.training.questions.length; i++) {
      const q = state.training.questions[i];
      const selected = state.training.answersSubmitted[q.id];
      
      try {
        if (window.location.protocol === 'file:') throw new Error();
        
        const checkResp = await fetch('/api/quiz/submit', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id: q.id, selected })
        });
        
        const validation = await checkResp.json();
        q.correct = validation.correctIndex;
        q.explanation = validation.explanation;
        if (validation.correct) correctCount++;
        
      } catch (err) {
        // Fallback validation checks local array
        const localQ = FALLBACK_QUESTIONS.find(fq => fq.id == q.id);
        q.correct = localQ.correct;
        q.explanation = localQ.explanation;
        if (selected === localQ.correct) correctCount++;
      }
    }

    // Record week score
    const weekScore = Math.round((correctCount / state.training.questions.length) * 100);
    state.quizWeekScores[activeWeek] = weekScore;

    // Calculate overall average score
    let totalScoreSum = 0;
    let gradedWeeksCount = 0;
    for (let w = 1; w <= 4; w++) {
      if (state.quizWeekScores[w] !== null) {
        totalScoreSum += state.quizWeekScores[w];
        gradedWeeksCount++;
      }
    }
    state.quizScore = gradedWeeksCount > 0 ? Math.round(totalScoreSum / gradedWeeksCount) : 0;

    // Refresh views
    updateProfileUI();
    updateDashboardData();
    renderQuiz();
    
    // Set score header
    const scoreValEl = document.getElementById('quiz-week-score');
    if (scoreValEl) {
      scoreValEl.textContent = `Graded: ${weekScore}%`;
      scoreValEl.style.color = 'var(--accent-emerald)';
    }

    // Dynamic progression unlock indicator
    if (activeWeek < 4) {
      setTimeout(() => {
        const nextWeek = activeWeek + 1;
        if (confirm(`Week ${activeWeek} Quiz Submitted Successfully!\nScore achieved: ${weekScore}%\nWould you like to unlock and load the next Week ${nextWeek} test?`)) {
          loadWeekQuiz(nextWeek);
        }
      }, 500);
    } else {
      alert(`Final Week 4 quiz completed! Your cumulative training score is ${state.quizScore}%. Check your profile tab for milestones.`);
    }
  });

  // Initial runs
  updateDefenseIndicators();
  updateDashboardSettings();
  updateDashboardData();
});
