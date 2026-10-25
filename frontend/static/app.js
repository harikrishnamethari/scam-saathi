/**
 * Scam Saathi — Frontend Application
 * Handles UI state, API calls, agent activity panel, and result rendering.
 */

'use strict';

/* ============================================================
   SAMPLE MESSAGES (fictional test fixtures)
   ============================================================ */

const SAMPLES = {
  bank: {
    label: 'Bank OTP Scam',
    text: 'URGENT: Aapka bank account aaj block ho jayega. KYC update karne ke liye apna OTP share karein. Bank helpline: 1800-XXX-XXXX',
  },
  parcel: {
    label: 'Parcel Fee Scam',
    text: 'Your parcel is on hold due to an unpaid customs fee. Pay a small redelivery fee at example.invalid/parcel-release to release it immediately. Ref: IN-78423.',
  },
  job: {
    label: 'Fake Job Offer',
    text: 'Congratulations! You have been selected for a work-from-home data entry job. Earn ₹25,000/month. Pay a refundable registration fee of ₹999 today to confirm your position. Limited slots available!',
  },
  upi: {
    label: 'UPI Request',
    text: 'Hello, I want to buy your item listed on OLX. I am sending ₹5000 via UPI. Please enter your UPI PIN to receive the payment. Accept here: upi://pay?amount=5000&note=receive',
  },
  ordinary: {
    label: 'Ordinary Message',
    text: 'Hi, are we still meeting tomorrow at 5 PM? Let me know if you need to reschedule.',
  },
};

/* ============================================================
   UTILITY HELPERS
   ============================================================ */

const $ = (id) => document.getElementById(id);
const MAX_LEN = 4000;
const API_BASE = '';

function escapeHtml(text) {
  const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
  return String(text).replace(/[&<>"']/g, (m) => map[m]);
}

function formatCategoryLabel(cat) {
  const labels = {
    banking: 'Banking / Credential Theft',
    delivery_scam: 'Parcel / Delivery Scam',
    job_scam: 'Fake Job Offer',
    government_impersonation: 'Government Impersonation',
    lottery_prize: 'Lottery / Prize Scam',
    phishing: 'Phishing',
    credential_theft: 'Credential Theft',
    generic: 'General Scam Pattern',
    unknown: 'Unknown / Insufficient Evidence',
  };
  return labels[cat] || cat;
}

function riskHeading(level) {
  const headings = {
    high: '⚠️ High Risk — Serious Warning Signs Found',
    medium: '⚡ Medium Risk — Suspicious Patterns Detected',
    low: '✓ Low Risk — No Obvious Warning Signs',
    uncertain: '? Uncertain — Insufficient Information',
  };
  return headings[level] || 'Analysis Complete';
}

function confidenceLabel(level) {
  const labels = { high: 'High', medium: 'Medium', low: 'Low' };
  return labels[level] || level;
}

/* ============================================================
   STATE
   ============================================================ */

let isAnalyzing = false;
let currentMessage = '';

/* ============================================================
   DOM REFERENCES
   ============================================================ */

const messageInput = $('message-input');
const analyzeBtn = $('analyze-btn');
const clearBtn = $('clear-btn');
const charCounter = $('char-counter');
const inputError = $('input-error');
const agentPanel = $('agent-panel');
const errorPanel = $('error-panel');
const errorMessage = $('error-message');
const retryBtn = $('retry-btn');
const resultsPanel = $('results-panel');
const fallbackWarning = $('fallback-warning');
const newAnalysisBtn = $('new-analysis-btn');
const outputLanguage = $('output-language');
const demoBadge = $('demo-badge');
const liveBadge = $('live-badge');
const demoTag = $('demo-tag');

/* ============================================================
   INIT
   ============================================================ */

document.addEventListener('DOMContentLoaded', () => {
  // Wire up sample chips
  document.querySelectorAll('.chip[data-sample]').forEach((chip) => {
    chip.addEventListener('click', () => {
      const key = chip.dataset.sample;
      if (SAMPLES[key]) {
        messageInput.value = SAMPLES[key].text;
        updateCharCounter();
        showClearButton();
        clearErrors();
        messageInput.focus();
      }
    });
  });

  // Wire up clear button
  clearBtn.addEventListener('click', clearInput);

  // Wire up analyze button
  analyzeBtn.addEventListener('click', runAnalysis);

  // Wire up textarea events
  messageInput.addEventListener('input', () => {
    updateCharCounter();
    showClearButton();
    clearErrors();
  });

  messageInput.addEventListener('keydown', (e) => {
    // Allow Ctrl/Cmd+Enter to analyze
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      runAnalysis();
    }
  });

  // Retry button
  retryBtn.addEventListener('click', () => {
    hideErrorPanel();
    if (currentMessage) {
      runAnalysis();
    }
  });

  // New analysis
  newAnalysisBtn.addEventListener('click', resetForNewAnalysis);

  // Check app status (demo vs live)
  checkAppStatus();

  updateCharCounter();
});

/* ============================================================
   STATUS CHECK
   ============================================================ */

async function checkAppStatus() {
  try {
    const resp = await fetch(`${API_BASE}/api/status`);
    if (resp.ok) {
      const data = await resp.json();
      if (data.demo_mode) {
        demoBadge.classList.remove('hidden');
      } else {
        liveBadge.classList.remove('hidden');
      }
    }
  } catch {
    // Server not reachable — just show nothing for now
  }
}

/* ============================================================
   INPUT MANAGEMENT
   ============================================================ */

function updateCharCounter() {
  const len = messageInput.value.length;
  charCounter.textContent = `${len} / ${MAX_LEN}`;
  charCounter.classList.toggle('warn', len > MAX_LEN * 0.9);
}

function showClearButton() {
  if (messageInput.value.length > 0) {
    clearBtn.classList.remove('hidden');
  } else {
    clearBtn.classList.add('hidden');
  }
}

function clearInput() {
  messageInput.value = '';
  updateCharCounter();
  clearBtn.classList.add('hidden');
  clearErrors();
  messageInput.focus();
}

function clearErrors() {
  inputError.textContent = '';
  messageInput.style.borderColor = '';
}

function showInputError(msg) {
  inputError.textContent = msg;
  messageInput.style.borderColor = 'var(--color-red)';
  messageInput.focus();
}

/* ============================================================
   AGENT PANEL
   ============================================================ */

function setAgentStatus(agentId, status) {
  const el = $(agentId);
  if (!el) return;
  el.dataset.status = status;
  const statusEl = el.querySelector('.agent-step-status');
  if (statusEl) {
    statusEl.setAttribute('aria-label', `Status: ${status}`);
  }
}

function resetAgents() {
  ['agent-1', 'agent-2', 'agent-3', 'agent-4'].forEach((id) => {
    setAgentStatus(id, 'pending');
  });
}

async function animateAgentPipeline(isDemo) {
  // For demo mode, simulate quick sequential progress
  // For live mode, all run concurrently in one API call but we show stages
  const delay = (ms) => new Promise((r) => setTimeout(r, ms));

  setAgentStatus('agent-1', 'running');
  await delay(isDemo ? 400 : 600);
  setAgentStatus('agent-1', 'done');

  setAgentStatus('agent-2', 'running');
  await delay(isDemo ? 500 : 800);
  setAgentStatus('agent-2', 'done');

  setAgentStatus('agent-3', 'running');
  await delay(isDemo ? 400 : 600);
  setAgentStatus('agent-3', 'done');

  setAgentStatus('agent-4', 'running');
  await delay(isDemo ? 300 : 400);
  setAgentStatus('agent-4', 'done');
}

/* ============================================================
   MAIN ANALYSIS FLOW
   ============================================================ */

async function runAnalysis() {
  if (isAnalyzing) return;

  const message = messageInput.value.trim();

  // Validate
  if (!message) {
    showInputError('Please paste a message to analyze.');
    return;
  }

  if (message.length > MAX_LEN) {
    showInputError(`Message is too long. Maximum ${MAX_LEN} characters allowed.`);
    return;
  }

  clearErrors();
  currentMessage = message;
  isAnalyzing = true;

  // Update UI for loading state
  setAnalyzingState(true);
  hideResults();
  hideErrorPanel();

  // Show agent panel
  resetAgents();
  agentPanel.classList.remove('hidden');

  // Kick off agent animation in background (non-blocking)
  const isLikelyDemo = demoBadge && !demoBadge.classList.contains('hidden');
  const animationPromise = animateAgentPipeline(isLikelyDemo);

  try {
    const lang = outputLanguage.value || 'en';

    const response = await fetch(`${API_BASE}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message, output_language: lang }),
    });

    // Wait for animation to complete
    await animationPromise;

    if (!response.ok) {
      let errMsg = 'Analysis failed. Please try again.';
      try {
        const errData = await response.json();
        errMsg = errData.detail || errMsg;
      } catch {}
      throw new Error(errMsg);
    }

    const data = await response.json();
    agentPanel.classList.add('hidden');
    renderResults(data);

  } catch (err) {
    // Ensure animation finishes
    try { await animationPromise; } catch {}

    agentPanel.classList.add('hidden');
    showErrorPanel(err.message || 'Something went wrong. Please try again.');
  } finally {
    isAnalyzing = false;
    setAnalyzingState(false);
  }
}

function setAnalyzingState(analyzing) {
  analyzeBtn.disabled = analyzing;

  const btnIcon = analyzeBtn.querySelector('.btn-icon');
  const btnText = analyzeBtn.querySelector('.btn-text');
  const btnSpinner = analyzeBtn.querySelector('.btn-spinner');

  if (analyzing) {
    btnIcon.classList.add('hidden');
    btnSpinner.classList.remove('hidden');
    btnText.textContent = 'Analyzing…';
  } else {
    btnIcon.classList.remove('hidden');
    btnSpinner.classList.add('hidden');
    btnText.textContent = 'Analyze Message';
  }
}

/* ============================================================
   ERROR PANEL
   ============================================================ */

function showErrorPanel(msg) {
  errorMessage.textContent = msg;
  errorPanel.classList.remove('hidden');
}

function hideErrorPanel() {
  errorPanel.classList.add('hidden');
}

/* ============================================================
   RESULTS RENDERING
   ============================================================ */

function hideResults() {
  resultsPanel.classList.add('hidden');
}

function renderResults(data) {
  // Validate data minimally
  const validRisk = ['high', 'medium', 'low', 'uncertain'];
  const risk = validRisk.includes(data.riskLevel) ? data.riskLevel : 'uncertain';

  // Fallback warning
  if (data.fallbackWarning) {
    fallbackWarning.textContent = data.fallbackWarning;
    fallbackWarning.classList.remove('hidden');
  } else {
    fallbackWarning.classList.add('hidden');
  }

  // -- Risk header --
  const headerCard = $('result-header');
  headerCard.className = 'result-header-card risk-' + risk;

  // Risk badge
  const riskBadge = $('risk-badge');
  riskBadge.className = 'risk-badge badge-' + risk;
  const icons = { high: '🔴', medium: '🟠', low: '🟢', uncertain: '❓' };
  riskBadge.querySelector('.risk-badge-icon').textContent = icons[risk] || '';
  $('risk-label').textContent =
    risk === 'high' ? 'High Risk' :
    risk === 'medium' ? 'Medium Risk' :
    risk === 'low' ? 'Low Risk' : 'Uncertain';

  // Demo tag
  if (data.demoMode) {
    demoTag.style.display = 'inline-flex';
  } else {
    demoTag.style.display = 'none';
  }

  // Heading & summary
  $('result-heading').textContent = riskHeading(risk);
  $('result-summary').textContent = data.summary || '';

  // Info chips
  $('detected-lang-text').textContent = `Detected: ${escapeHtml(data.detectedLanguage || 'Unknown')}`;
  $('scam-category-text').textContent = formatCategoryLabel(data.scamCategory);
  $('confidence-text').textContent = confidenceLabel(data.assessmentConfidence);

  // Confidence explanation
  $('confidence-explanation').textContent = data.confidenceExplanation || '';

  // -- Red flags --
  const redFlagsList = $('red-flags-list');
  const noFlagsMsg = $('no-flags-msg');
  redFlagsList.innerHTML = '';

  const flags = Array.isArray(data.redFlags) ? data.redFlags : [];

  if (flags.length === 0) {
    noFlagsMsg.classList.remove('hidden');
    redFlagsList.classList.add('hidden');
  } else {
    noFlagsMsg.classList.add('hidden');
    redFlagsList.classList.remove('hidden');
    flags.forEach((flag, idx) => {
      const sev = flag.severity || 'medium';
      const card = document.createElement('div');
      card.className = `red-flag-card sev-${sev}`;
      card.innerHTML = `
        <div class="red-flag-header">
          <span class="flag-num">${idx + 1}</span>
          <span class="flag-quote">&ldquo;${escapeHtml(flag.quote)}&rdquo;</span>
          <span class="flag-severity-badge">${escapeHtml(sev)}</span>
        </div>
        <p class="flag-reason">${escapeHtml(flag.reason || '')}</p>
      `;
      redFlagsList.appendChild(card);
    });
  }

  // -- Recommended actions --
  const actionsList = $('actions-list');
  actionsList.innerHTML = '';
  const actions = Array.isArray(data.recommendedActions) ? data.recommendedActions : [];
  actions.forEach((action, idx) => {
    const li = document.createElement('li');
    li.className = 'action-item';
    li.innerHTML = `<span class="action-num">${idx + 1}</span><span>${escapeHtml(action)}</span>`;
    actionsList.appendChild(li);
  });

  // -- Recovery advice --
  const recoverySection = $('recovery-section');
  const alreadyActed = data.alreadyActedAdvice;
  if (alreadyActed && alreadyActed.isRelevant && alreadyActed.steps && alreadyActed.steps.length > 0) {
    recoverySection.classList.remove('hidden');
    $('recovery-message').textContent = alreadyActed.message || 'If you have already responded to this message, take these steps immediately:';
    const recoverySteps = $('recovery-steps');
    recoverySteps.innerHTML = '';
    alreadyActed.steps.forEach((step, idx) => {
      const li = document.createElement('li');
      li.className = 'recovery-step-item';
      li.innerHTML = `<span class="recovery-step-num">${idx + 1}</span><span>${escapeHtml(step)}</span>`;
      recoverySteps.appendChild(li);
    });
  } else {
    recoverySection.classList.add('hidden');
  }

  // -- Limitations --
  $('limitations-text').textContent = data.limitations || 'This analysis is based on the text of the message only.';

  // Update mode badges from result
  if (data.demoMode) {
    demoBadge.classList.remove('hidden');
    liveBadge.classList.add('hidden');
  } else {
    liveBadge.classList.remove('hidden');
    demoBadge.classList.add('hidden');
  }

  // Show results
  resultsPanel.classList.remove('hidden');

  // Scroll to results
  setTimeout(() => {
    resultsPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, 100);
}

/* ============================================================
   RESET FOR NEW ANALYSIS
   ============================================================ */

function resetForNewAnalysis() {
  hideResults();
  hideErrorPanel();
  agentPanel.classList.add('hidden');
  clearInput();
  document.getElementById('analysis-card').scrollIntoView({ behavior: 'smooth', block: 'center' });
  messageInput.focus();
}
