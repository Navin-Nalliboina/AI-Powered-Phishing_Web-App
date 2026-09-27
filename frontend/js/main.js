/**
 * CyberShield AI - Scanner & Home Page Controller
 * Features:
 * - Real-time AI threat scanning
 * - Complete Database History viewer with live search & filters
 * - Light/Dark Cybersecurity Theme Switcher
 * - Admin Profile Dropdown
 */

const SAMPLES = {
  phish_email: "URGENT: Your PayPal account has been restricted due to unauthorized login attempts! Click here to verify your identity within 24 hours at http://paypal-account-center.top/restricted/login.php or your funds will be permanently frozen.",
  malicious_url: "http://wellsfargo-verify-security.top/login.php?cmd=reauth_token_8392",
  fake_sms: "FedEx Delivery Alert: Parcel #48291 failed delivery due to missing address info. Pay $1.99 redelivery fee immediately to avoid return: http://fedx-package-tracking.tk/track",
  safe_email: "Hi team, please find attached the minutes and slides from today's product design sync. Let me know if you have any questions before Monday's release.",
  safe_url: "https://www.google.com/search?q=cybersecurity+best+practices"
};

let currentInputMode = "text";
let lastScanResult = null;
let allSubmissionsHistory = [];

document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  initInputTabs();
  initFormSubmit();
  loadAllDatabaseHistory();
  initAdminStatus();

  // Check if directed directly to scanner
  if (window.location.hash === "#scanner" || window.location.search.includes("start=true")) {
    openScanner();
  }
});

/* ================== ENTRY HOME & SCANNER SWITCHER ================== */
function openScanner() {
  const entryScreen = document.getElementById("entry-home-screen");
  const scannerWorkspace = document.getElementById("scanner-workspace");
  if (entryScreen && scannerWorkspace) {
    entryScreen.style.display = "none";
    scannerWorkspace.classList.add("active");
    window.location.hash = "scanner";
    const textarea = document.getElementById("scan-input");
    if (textarea) textarea.focus();
  }
}

function showHomeScreen() {
  const entryScreen = document.getElementById("entry-home-screen");
  const scannerWorkspace = document.getElementById("scanner-workspace");
  if (entryScreen && scannerWorkspace) {
    scannerWorkspace.classList.remove("active");
    entryScreen.style.display = "flex";
    if (window.location.hash === "#scanner") {
      history.replaceState(null, null, ' ');
    }
  }
}

/* ================== THEME CONTROLLER ================== */
function initTheme() {
  const savedTheme = localStorage.getItem("cybershield_theme") || "light";
  if (savedTheme === "dark") {
    document.body.classList.add("dark-theme");
  } else {
    document.body.classList.remove("dark-theme");
  }
  updateThemeButton(savedTheme);
}

function toggleTheme() {
  const isDark = document.body.classList.toggle("dark-theme");
  const newTheme = isDark ? "dark" : "light";
  localStorage.setItem("cybershield_theme", newTheme);
  updateThemeButton(newTheme);
}

function updateThemeButton(theme) {
  const btn = document.getElementById("theme-toggle");
  if (btn) {
    btn.innerHTML = (theme === "dark") ? "☀️" : "🌙";
    btn.title = (theme === "dark") ? "Switch to Light Cyber Theme" : "Switch to Dark Cyber Theme";
  }
}

/* ================== ADMIN DROPDOWN & STATUS ================== */
function toggleAdminDropdown(e) {
  if (e) e.stopPropagation();
  const menu = document.getElementById("admin-dropdown-menu");
  if (menu) {
    menu.classList.toggle("show");
  }
}

document.addEventListener("click", (e) => {
  const menu = document.getElementById("admin-dropdown-menu");
  if (menu && !e.target.closest(".admin-profile-wrapper")) {
    menu.classList.remove("show");
  }
});

async function initAdminStatus() {
  try {
    const res = await fetch("/api/admin/status");
    if (!res.ok) return;
    const status = await res.json();

    const statusEl = document.getElementById("admin-lock-status");
    if (statusEl) {
      if (status.is_owner_laptop) {
        statusEl.innerHTML = `🛡️ Owner Laptop Verified (<code style="font-size:0.75rem;">${status.laptop_name}</code>)`;
        statusEl.className = "admin-dropdown-status";
      } else {
        statusEl.innerHTML = `🔒 Protected (Read-Only Mode)`;
        statusEl.className = "admin-dropdown-status locked";
      }
    }
  } catch (err) {
    console.warn("Could not check admin status:", err);
  }
}

/* ================== INPUT TABS & SAMPLES ================== */
function initInputTabs() {
  const tabs = document.querySelectorAll(".tab-btn");
  const textarea = document.getElementById("scan-input");

  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      currentInputMode = tab.dataset.mode;
      
      if (currentInputMode === "url") {
        textarea.placeholder = "Enter or paste website URL (e.g. http://paypal-verify.top/login or https://example.com)...";
      } else {
        textarea.placeholder = "Paste suspicious email body, SMS text message, or customer notice...";
      }
    });
  });
}

function loadSample(key) {
  const textarea = document.getElementById("scan-input");
  if (SAMPLES[key]) {
    textarea.value = SAMPLES[key];
    textarea.focus();

    if (key.includes("url")) {
      const urlTab = document.querySelector('[data-mode="url"]');
      if (urlTab) urlTab.click();
    } else {
      const textTab = document.querySelector('[data-mode="text"]');
      if (textTab) textTab.click();
    }
  }
}

/* ================== SCANNER EXECUTION ================== */
function initFormSubmit() {
  const form = document.getElementById("scan-form");
  const textarea = document.getElementById("scan-input");
  const submitBtn = document.getElementById("btn-submit-scan");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const content = textarea.value.trim();

    if (!content) {
      alert("Please enter or paste text/URL to scan.");
      return;
    }

    submitBtn.disabled = true;
    submitBtn.innerHTML = `<span>⚡</span> Scanning with AI...`;

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          content: content,
          input_type: currentInputMode
        })
      });

      if (!response.ok) {
        const errorData = await response.json();
        alert(`Scan Alert: ${errorData.detail || "Error analyzing content."}`);
        return;
      }

      const data = await response.json();
      lastScanResult = data;
      renderScanResult(data);
      loadAllDatabaseHistory(); // Refresh complete history

    } catch (err) {
      console.error("Scan error:", err);
      alert("Network error: unable to connect to the backend scanner.");
    } finally {
      submitBtn.disabled = false;
      submitBtn.innerHTML = `<span>🛡️</span> Analyze Threat`;
    }
  });
}

function renderScanResult(data) {
  const resultCard = document.getElementById("result-card");
  const badge = document.getElementById("result-badge");
  const scoreVal = document.getElementById("result-score-val");
  const progressFill = document.getElementById("result-progress-fill");
  const confVal = document.getElementById("result-conf-val");
  const typeVal = document.getElementById("result-type-val");
  const explanationList = document.getElementById("result-explanations");
  const indicatorsGrid = document.getElementById("result-indicators");

  resultCard.style.display = "block";
  resultCard.scrollIntoView({ behavior: "smooth", block: "nearest" });

  badge.className = `risk-badge ${data.risk_level}`;
  let icon = "🛡️";
  if (data.risk_level === "Malicious") icon = "🚨";
  else if (data.risk_level === "Suspicious") icon = "⚠️";
  badge.innerHTML = `${icon} ${data.risk_level.toUpperCase()} THREAT`;

  scoreVal.textContent = `${data.risk_score}%`;
  confVal.textContent = `${data.confidence}%`;
  typeVal.textContent = data.input_type.toUpperCase();

  progressFill.style.width = `${Math.max(5, data.risk_score)}%`;
  if (data.risk_level === "Malicious") {
    progressFill.style.background = "linear-gradient(90deg, #dc2626, #b91c1c)";
    scoreVal.style.color = "var(--threat-malicious)";
  } else if (data.risk_level === "Suspicious") {
    progressFill.style.background = "linear-gradient(90deg, #d97706, #b45309)";
    scoreVal.style.color = "var(--threat-suspicious)";
  } else {
    progressFill.style.background = "linear-gradient(90deg, #16a34a, #15803d)";
    scoreVal.style.color = "var(--threat-safe)";
  }

  explanationList.innerHTML = "";
  data.explanation.forEach(exp => {
    const li = document.createElement("li");
    li.textContent = exp;
    explanationList.appendChild(li);
  });

  indicatorsGrid.innerHTML = "";
  if (data.indicators && data.indicators.length > 0) {
    data.indicators.forEach(ind => {
      const card = document.createElement("div");
      card.className = "indicator-card";
      card.innerHTML = `
        <div class="indicator-title">⚠️ ${ind.label}</div>
        <div class="indicator-desc">${ind.desc}</div>
      `;
      indicatorsGrid.appendChild(card);
    });
  } else {
    indicatorsGrid.innerHTML = `<div style="color:var(--text-muted); font-size:0.88rem;">No critical technical threat markers identified.</div>`;
  }
}

function askBotAboutLastScan() {
  if (typeof toggleFloatingChat === "function") {
    const chatBox = document.getElementById("floating-chat-box");
    if (chatBox && chatBox.style.display !== "block") {
      toggleFloatingChat();
    }
  }
  if (window.chatInstance) {
    window.chatInstance.sendMessage("Why was this flagged?");
  }
}

/* ================== COMPLETE DATABASE HISTORY ================== */
async function loadAllDatabaseHistory() {
  const tbody = document.getElementById("recent-scans-tbody");
  if (!tbody) return;

  try {
    // Request all records from database without arbitrary limit
    const res = await fetch("/api/scans/recent?all_records=true");
    const data = await res.json();
    allSubmissionsHistory = data;
    renderFilteredHistory();

  } catch (err) {
    console.error("Failed to load history:", err);
  }
}

function renderFilteredHistory() {
  const tbody = document.getElementById("recent-scans-tbody");
  const countBadge = document.getElementById("history-count");
  if (!tbody) return;

  const searchInput = document.getElementById("history-search");
  const filterSelect = document.getElementById("history-filter");

  const query = searchInput ? searchInput.value.toLowerCase().trim() : "";
  const filter = filterSelect ? filterSelect.value : "ALL";

  let filtered = allSubmissionsHistory.filter(item => {
    const matchesSearch = !query || item.raw_content.toLowerCase().includes(query) || item.input_type.toLowerCase().includes(query) || String(item.id).includes(query);
    const matchesFilter = (filter === "ALL") || (item.risk_level.toUpperCase() === filter.toUpperCase());
    return matchesSearch && matchesFilter;
  });

  if (countBadge) {
    countBadge.textContent = `Showing all ${filtered.length} of ${allSubmissionsHistory.length} recorded scans`;
  }

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--text-dim); padding:1.5rem;">No matching scan records found in database.</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(item => `
    <tr>
      <td style="font-weight:700;">#${item.id}</td>
      <td><span class="sample-pill" style="font-size:0.75rem;">${item.input_type.toUpperCase()}</span></td>
      <td style="max-width:320px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-family:var(--font-mono); font-size:0.82rem;">
        ${escapeHtml(item.raw_content)}
      </td>
      <td>
        <span class="risk-badge ${item.risk_level}" style="padding:0.2rem 0.65rem; font-size:0.75rem;">
          ${item.risk_level} (${item.risk_score}%)
        </span>
      </td>
      <td style="font-size:0.8rem; color:var(--text-dim);">${item.created_at || "Just now"}</td>
    </tr>
  `).join("");
}

function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
