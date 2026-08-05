/* tests.js - Refactored Integration Test Engine for Fullstack SentinelRecon */

document.addEventListener('DOMContentLoaded', () => {
  const iframe = document.getElementById('app-iframe');
  const runBtn = document.getElementById('run-tests-btn');
  const reloadBtn = document.getElementById('reload-iframe-btn');
  
  const passedCountEl = document.getElementById('passed-count');
  const failedCountEl = document.getElementById('failed-count');
  const durationEl = document.getElementById('test-duration');
  const overallStatus = document.getElementById('overall-status');

  function getAppWindow() {
    return iframe.contentWindow;
  }

  function getAppDocument() {
    return iframe.contentDocument || iframe.contentWindow.document;
  }

  reloadBtn.addEventListener('click', () => {
    iframe.src = 'index.html';
  });

  runBtn.addEventListener('click', runTestSuite);

  async function runTestSuite() {
    runBtn.disabled = true;
    overallStatus.textContent = 'RUNNING FULLSTACK TESTS...';
    overallStatus.style.color = 'var(--accent-cyan)';
    
    // Reset test item styles
    const testItems = document.querySelectorAll('.test-item');
    testItems.forEach(item => {
      item.className = 'test-item';
      item.querySelector('i').className = 'fa-solid fa-circle-question test-status-icon';
      item.querySelector('i').style.color = 'var(--text-muted)';
    });

    passedCountEl.textContent = '0';
    failedCountEl.textContent = '0';
    durationEl.textContent = '0ms';

    const startTime = performance.now();
    let passed = 0;
    let failed = 0;

    // Reload the frame to ensure a clean slate
    iframe.src = 'index.html';
    await delay(1200); // Wait for load and initial fetch calls

    const tests = [
      { id: 'test-tab-switching', fn: testTabSwitching },
      { id: 'test-port-scanner', fn: testPortScanner },
      { id: 'test-osint-analyzer', fn: testOsintAnalyzer },
      { id: 'test-defense-sandbox', fn: testDefenseSandbox },
      { id: 'test-knowledge-quiz', fn: testKnowledgeQuiz }
    ];

    for (let test of tests) {
      updateTestStatus(test.id, 'running');
      try {
        await test.fn();
        updateTestStatus(test.id, 'passed');
        passed++;
        passedCountEl.textContent = passed;
      } catch (err) {
        console.error(`Test ${test.id} failed:`, err);
        updateTestStatus(test.id, 'failed');
        failed++;
        failedCountEl.textContent = failed;
      }
      await delay(500); // Brief visual pause between tests
    }

    const endTime = performance.now();
    durationEl.textContent = `${Math.round(endTime - startTime)}ms`;
    
    runBtn.disabled = false;
    if (failed === 0) {
      overallStatus.textContent = 'ALL FULLSTACK TESTS PASSED';
      overallStatus.style.color = 'var(--accent-emerald)';
    } else {
      overallStatus.textContent = `${failed} TESTS FAILED`;
      overallStatus.style.color = 'var(--accent-coral)';
    }
  }

  function updateTestStatus(id, status) {
    const el = document.getElementById(id);
    if (!el) return;

    el.className = `test-item ${status}`;
    const icon = el.querySelector('i');
    
    if (status === 'running') {
      icon.className = 'fa-solid fa-spinner test-status-icon running';
    } else if (status === 'passed') {
      icon.className = 'fa-solid fa-circle-check test-status-icon passed';
    } else if (status === 'failed') {
      icon.className = 'fa-solid fa-circle-xmark test-status-icon failed';
    }
  }

  function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // ================= TEST CASE IMPLEMENTATIONS =================

  // 1. Test Tab Switching
  async function testTabSwitching() {
    const doc = getAppDocument();
    
    const scanSimLink = doc.querySelector('.nav-item[data-tab="scan-simulator"]');
    if (!scanSimLink) throw new Error("Could not find Scan Simulator navigation link.");
    
    scanSimLink.click();
    await delay(300);

    const activePanel = doc.querySelector('.tab-panel.active');
    if (!activePanel || activePanel.id !== 'scan-simulator') {
      throw new Error("Scan Simulator panel is not marked active after click.");
    }

    const pageTitle = doc.getElementById('current-page-title');
    if (pageTitle.textContent !== 'Port Scan Engine Simulator') {
      throw new Error("Page title did not update correctly.");
    }
  }

  // 2. Test Port Scanner Simulation (communicates with `/api/scan/simulate`)
  async function testPortScanner() {
    const doc = getAppDocument();
    
    doc.querySelector('.nav-item[data-tab="scan-simulator"]').click();
    await delay(200);

    const startBtn = doc.getElementById('start-scan-btn');
    const scanConsole = doc.getElementById('scan-console-output');

    if (!startBtn || !scanConsole) throw new Error("Simulator controls are missing.");

    // Trigger scan
    startBtn.click();
    await delay(1500); // Allow server request to complete and scan to progress

    const lines = scanConsole.querySelectorAll('.terminal-line');
    if (lines.length < 2) {
      throw new Error("Console log was not appended during scanning.");
    }

    // Verify backend scan initiation statement was printed
    const firstLineText = lines[0].textContent;
    if (!firstLineText.includes("Fullstack Scan Session")) {
      throw new Error("Scanner output does not indicate server-side scan execution.");
    }

    // Abort scan
    const stopBtn = doc.getElementById('stop-scan-btn');
    stopBtn.click();
    await delay(200);
  }

  // 3. Test OSINT Analyzer (communicates with `/api/osint/analyze`)
  async function testOsintAnalyzer() {
    const doc = getAppDocument();

    doc.querySelector('.nav-item[data-tab="osint-analyzer"]').click();
    await delay(200);

    const input = doc.getElementById('osint-domain');
    const btn = doc.getElementById('start-osint-btn');

    if (!input || !btn) throw new Error("OSINT UI inputs not found.");

    input.value = "testdefense.org";
    btn.click();

    // Wait for server OSINT query simulation to complete
    await delay(2500);

    const results = doc.getElementById('osint-results-panel');
    if (!results.innerHTML.includes('testdefense.org') || !results.innerHTML.includes('DNS Zone Configuration')) {
      throw new Error("OSINT results from backend were not displayed correctly.");
    }

    const hardening = doc.getElementById('hardening-card');
    if (hardening.style.display !== 'block') {
      throw new Error("Hardening advisory card was not displayed.");
    }
  }

  // 4. Test Defensive Sandbox Toggles
  async function testDefenseSandbox() {
    const doc = getAppDocument();

    doc.querySelector('.nav-item[data-tab="defense-sandbox"]').click();
    await delay(200);

    const firewallToggle = doc.getElementById('defense-firewall-toggle');
    const efficiencyText = doc.getElementById('sandbox-recon-efficiency');

    if (!firewallToggle || !efficiencyText) throw new Error("Defense controls are missing.");

    const initialEfficiency = parseInt(efficiencyText.textContent);

    // Toggle off
    firewallToggle.click();
    await delay(300);

    const newEfficiency = parseInt(efficiencyText.textContent);
    if (newEfficiency <= initialEfficiency) {
      throw new Error("Toggling firewall off did not increase simulated attacker recon efficiency.");
    }

    // Toggle firewall back on to be nice
    firewallToggle.click();
    await delay(200);
  }

  // 5. Test Quiz Knowledge Module (communicates with `/api/quiz` and `/api/quiz/submit`)
  async function testKnowledgeQuiz() {
    const doc = getAppDocument();

    doc.querySelector('.nav-item[data-tab="knowledge-base"]').click();
    await delay(200);

    const quizOptions = doc.querySelectorAll('.quiz-option');
    if (quizOptions.length === 0) throw new Error("Quiz questions were not loaded from backend API server.");

    // Answer first option
    const firstOption = quizOptions[0];
    firstOption.click();
    await delay(500); // Wait for backend evaluation request

    if (!firstOption.classList.contains('correct') && !firstOption.classList.contains('incorrect')) {
      throw new Error("Clicking option did not trigger correctness highlight classes from backend validation.");
    }

    doc.querySelector('.nav-item[data-tab="dashboard"]').click();
    await delay(200);

    const scoreDiv = doc.getElementById('dashboard-score');
    if (scoreDiv.textContent === '0%') {
      throw new Error("Dashboard training score failed to update after answering quiz.");
    }
  }
});
