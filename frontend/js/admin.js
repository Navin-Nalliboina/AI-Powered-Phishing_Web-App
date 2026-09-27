/**
 * CyberShield AI - Admin & Anomaly Center Controller
 * Enforces Laptop-Owner Lock & Displays Telemetry
 */

let isOwnerAuthorized = false;

document.addEventListener("DOMContentLoaded", () => {
  initAdminVerification();
  loadAnomalies();
  loadProfileData();
  initProfileForm();
});

async function initAdminVerification() {
  const banner = document.getElementById("admin-lock-banner");
  const saveBtn = document.getElementById("btn-save-profile");
  const inputs = document.querySelectorAll("#profile-form input, #profile-form textarea");

  try {
    const res = await fetch("/api/admin/status");
    if (!res.ok) throw new Error("Status check failed");
    const status = await res.json();

    isOwnerAuthorized = status.is_owner_laptop;

    if (banner) {
      if (isOwnerAuthorized) {
        banner.style.display = "flex";
        banner.className = "sample-pill safe";
        banner.style.padding = "0.6rem 1rem";
        banner.style.borderRadius = "var(--radius-sm)";
        banner.style.marginBottom = "1rem";
        banner.innerHTML = `<span>🛡️</span> <strong>Verified Owner Laptop (${status.laptop_name}):</strong> Full administrative profile editing access granted.`;
      } else {
        banner.style.display = "flex";
        banner.className = "sample-pill malicious";
        banner.style.padding = "0.6rem 1rem";
        banner.style.borderRadius = "var(--radius-sm)";
        banner.style.marginBottom = "1rem";
        banner.innerHTML = `<span>🔒</span> <strong>Security Restriction:</strong> This admin profile is locked to owner laptop (${status.owner_target}). Editing is restricted.`;
        
        // Lock inputs for non-owner
        inputs.forEach(inp => {
          inp.disabled = true;
          inp.style.opacity = "0.7";
          inp.style.cursor = "not-allowed";
        });
        if (saveBtn) {
          saveBtn.disabled = true;
          saveBtn.style.opacity = "0.5";
          saveBtn.style.cursor = "not-allowed";
          saveBtn.innerHTML = `<span>🔒</span> Locked to Owner Laptop`;
        }
      }
    }
  } catch (err) {
    console.error("Admin verification error:", err);
  }
}

async function loadAnomalies() {
  const tbody = document.getElementById("anomalies-tbody");
  if (!tbody) return;

  try {
    const res = await fetch("/api/anomalies");
    const anomalies = await res.json();

    if (anomalies.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--threat-safe); padding:1.5rem;">✅ System Healthy: No security anomalies or abuse attempts flagged!</td></tr>`;
      return;
    }

    tbody.innerHTML = anomalies.map(item => {
      let sevClass = "Safe";
      if (item.severity === "Critical" || item.severity === "High") sevClass = "Malicious";
      else if (item.severity === "Medium") sevClass = "Suspicious";

      return `
        <tr>
          <td>#${item.id}</td>
          <td><span class="sample-pill">${item.anomaly_type}</span></td>
          <td><span class="risk-badge ${sevClass}" style="padding:0.2rem 0.5rem; font-size:0.75rem;">${item.severity}</span></td>
          <td style="max-width:300px; font-size:0.85rem;">${escapeHtml(item.details)}</td>
          <td><code style="font-size:0.8rem; font-family:var(--font-mono);">${item.client_ip}</code></td>
          <td>
            ${item.is_resolved 
              ? `<span style="color:var(--threat-safe); font-size:0.8rem;">✓ Resolved</span>` 
              : `<span style="color:var(--threat-suspicious); font-size:0.8rem;">● Needs Review</span>`}
          </td>
          <td>
            ${!item.is_resolved 
              ? `<button class="sample-pill" style="border-color:var(--accent-cyan); color:var(--accent-cyan);" onclick="resolveAnomaly(${item.id})">Mark Resolved</button>` 
              : `<span style="color:var(--text-dim); font-size:0.8rem;">Completed</span>`}
          </td>
        </tr>
      `;
    }).join("");

  } catch (err) {
    console.error("Failed to load anomalies:", err);
  }
}

async function resolveAnomaly(id) {
  try {
    const res = await fetch(`/api/anomalies/${id}/resolve`, { method: "POST" });
    if (res.ok) {
      loadAnomalies();
    }
  } catch (err) {
    alert("Error resolving anomaly.");
  }
}

async function loadProfileData() {
  try {
    const res = await fetch("/api/profile");
    if (!res.ok) return;
    const profile = await res.json();

    document.getElementById("edit-name").value = profile.name || "";
    document.getElementById("edit-title").value = profile.title || "";
    document.getElementById("edit-bio").value = profile.bio || "";
    document.getElementById("edit-skills").value = (profile.skills || []).join(", ");
    document.getElementById("edit-email").value = profile.email || "";
    document.getElementById("edit-github").value = profile.github || "";
    document.getElementById("edit-linkedin").value = profile.linkedin || "";
  } catch (err) {
    console.error("Error loading profile:", err);
  }
}

function initProfileForm() {
  const form = document.getElementById("profile-form");
  if (!form) return;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();

    if (!isOwnerAuthorized) {
      alert("Security Block: Profile can only be edited on the authorized owner laptop.");
      return;
    }

    const skillsRaw = document.getElementById("edit-skills").value;
    const skillsArray = skillsRaw.split(",").map(s => s.trim()).filter(s => s.length > 0);

    const payload = {
      name: document.getElementById("edit-name").value.trim(),
      title: document.getElementById("edit-title").value.trim(),
      bio: document.getElementById("edit-bio").value.trim(),
      skills: skillsArray,
      email: document.getElementById("edit-email").value.trim(),
      github: document.getElementById("edit-github").value.trim(),
      linkedin: document.getElementById("edit-linkedin").value.trim()
    };

    try {
      const res = await fetch("/api/profile", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });

      if (res.ok) {
        alert("✅ Profile updated successfully! Ask the chatbot 'tell me yourself' to see the updated profile and hear the voice narration.");
      } else {
        const errData = await res.json();
        alert(`Failed to update profile: ${errData.detail || "Unauthorized"}`);
      }
    } catch (err) {
      console.error("Error saving profile:", err);
      alert("Network error updating profile.");
    }
  });
}

function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
