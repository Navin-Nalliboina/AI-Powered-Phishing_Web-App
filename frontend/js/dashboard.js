/**
 * CyberShield AI - Threat Analytics Dashboard Controller
 */

let distributionChart = null;
let categoryChart = null;

document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  initAdminStatus();
  fetchDashboardMetrics();
  loadAllDashboardFeed();
  // Auto refresh every 15 seconds
  setInterval(() => {
    fetchDashboardMetrics();
    loadAllDashboardFeed();
  }, 15000);
});

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

async function fetchDashboardMetrics() {
  try {
    const res = await fetch("/api/stats");
    if (!res.ok) throw new Error("Failed to fetch stats");
    const data = await res.json();

    // Update Counters
    document.getElementById("stat-total-scans").textContent = data.total_scans;
    document.getElementById("stat-threats-blocked").textContent = data.malicious_count;
    document.getElementById("stat-suspicious").textContent = data.suspicious_count;
    document.getElementById("stat-anomalies").textContent = data.total_anomalies;
    document.getElementById("stat-avg-score").textContent = `${data.avg_risk_score}%`;
    document.getElementById("stat-chat-queries").textContent = data.chat_queries;

    // Render Charts
    renderDistributionChart(data.distribution);
    renderCategoryChart(data.by_type);

  } catch (err) {
    console.error("Dashboard error:", err);
  }
}

async function loadAllDashboardFeed() {
  const feedTbody = document.getElementById("dashboard-feed-tbody");
  const countEl = document.getElementById("dashboard-feed-count");
  if (!feedTbody) return;

  try {
    const res = await fetch("/api/scans/recent?all_records=true");
    const scans = await res.json();

    if (countEl) {
      countEl.textContent = `Showing all ${scans.length} database detections`;
    }

    if (!scans || scans.length === 0) {
      feedTbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--text-dim); padding:1.5rem;">No detections recorded yet.</td></tr>`;
      return;
    }

    feedTbody.innerHTML = scans.map(item => `
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

  } catch (err) {
    console.error("Feed error:", err);
  }
}

function renderDistributionChart(dist) {
  const ctx = document.getElementById("threatDistChart");
  if (!ctx) return;

  const chartData = {
    labels: ["Safe", "Suspicious", "Malicious"],
    datasets: [{
      data: [dist.safe || 0, dist.suspicious || 0, dist.malicious || 0],
      backgroundColor: ["#16a34a", "#d97706", "#dc2626"],
      borderWidth: 2,
      borderColor: "#ffffff"
    }]
  };

  if (distributionChart) {
    distributionChart.data = chartData;
    distributionChart.update();
  } else {
    distributionChart = new Chart(ctx, {
      type: "doughnut",
      data: chartData,
      options: {
        responsive: true,
        plugins: {
          legend: {
            position: "bottom",
            labels: { color: "#475569", font: { family: "Inter", size: 12, weight: 600 } }
          }
        },
        cutout: "68%"
      }
    });
  }
}

function renderCategoryChart(byType) {
  const ctx = document.getElementById("categoryChart");
  if (!ctx) return;

  const chartData = {
    labels: ["URLs / Websites", "Email Messages", "SMS / Text"],
    datasets: [{
      label: "Submissions",
      data: [byType.url || 0, byType.email || 0, byType.text || 0],
      backgroundColor: ["#0284c7", "#2563eb", "#8b5cf6"],
      borderRadius: 6
    }]
  };

  if (categoryChart) {
    categoryChart.data = chartData;
    categoryChart.update();
  } else {
    categoryChart = new Chart(ctx, {
      type: "bar",
      data: chartData,
      options: {
        responsive: true,
        scales: {
          x: { ticks: { color: "#475569", font: { weight: 600 } }, grid: { display: false } },
          y: { ticks: { color: "#475569", stepSize: 1 }, grid: { color: "rgba(0,0,0,0.05)" } }
        },
        plugins: {
          legend: { display: false }
        }
      }
    });
  }
}

function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
