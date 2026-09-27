/**
 * CyberShield AI - Chatbot Assistant Engine
 * Features:
 * - Web Speech API Voice synthesis (Text-to-Speech)
 * - "Tell me yourself" Creator Profile Showcase & Voice Narration
 * - Real-time scan explanations & Cybersecurity QA
 */

class ChatAssistant {
  constructor(containerId = "chat-messages", inputId = "chat-input", sendBtnId = "btn-send-chat") {
    this.messagesContainer = document.getElementById(containerId);
    this.inputElement = document.getElementById(inputId);
    this.sendBtn = document.getElementById(sendBtnId);
    this.sessionId = this._getOrCreateSessionId();
    this.isVoiceEnabled = true;
    this.currentUtterance = null;

    this._initEvents();
  }

  _getOrCreateSessionId() {
    let sid = sessionStorage.getItem("cybershield_session_id");
    if (!sid) {
      sid = "sess_" + Math.random().toString(36).substring(2, 11) + "_" + Date.now();
      sessionStorage.setItem("cybershield_session_id", sid);
    }
    return sid;
  }

  _initEvents() {
    if (this.sendBtn) {
      this.sendBtn.addEventListener("click", () => this.sendMessage());
    }

    if (this.inputElement) {
      this.inputElement.addEventListener("keydown", (e) => {
        if (e.key === "Enter" && !e.shiftKey) {
          e.preventDefault();
          this.sendMessage();
        }
      });
    }

    // Voice toggle button if present
    const voiceToggle = document.getElementById("voice-toggle-btn");
    if (voiceToggle) {
      voiceToggle.addEventListener("click", () => {
        this.isVoiceEnabled = !this.isVoiceEnabled;
        voiceToggle.innerHTML = this.isVoiceEnabled 
          ? `<span>🔊</span> Voice: ON` 
          : `<span>🔇</span> Voice: OFF`;
        voiceToggle.style.color = this.isVoiceEnabled ? "var(--accent-cyan)" : "var(--text-dim)";
        if (!this.isVoiceEnabled && window.speechSynthesis) {
          window.speechSynthesis.cancel();
        }
      });
    }
  }

  speak(text) {
    if (!('speechSynthesis' in window)) {
      console.warn("Web Speech API not supported in this browser.");
      return;
    }

    window.speechSynthesis.cancel(); // Stop any active speech

    if (!text || !text.trim()) return;

    // Clean markdown and symbols for clean spoken voice
    const cleanSpeech = text
      .replace(/[*#_`>]/g, "")
      .replace(/\[([^\]]+)\]\([^\)]+\)/g, "$1")
      .replace(/http[s]?:\/\/\S+/g, "link")
      .trim();

    const utterance = new SpeechSynthesisUtterance(cleanSpeech);
    utterance.rate = 1.0;
    utterance.pitch = 1.0;

    // Try selecting natural English voice
    const voices = window.speechSynthesis.getVoices();
    const enVoice = voices.find(v => v.lang.startsWith("en") && (v.name.includes("Google") || v.name.includes("Natural") || v.name.includes("David") || v.name.includes("Zira")));
    if (enVoice) {
      utterance.voice = enVoice;
    }

    window.speechSynthesis.speak(utterance);
    this.currentUtterance = utterance;
  }

  stopSpeech() {
    if ('speechSynthesis' in window) {
      window.speechSynthesis.cancel();
    }
  }

  async sendMessage(customText = null) {
    const text = customText || (this.inputElement ? this.inputElement.value.trim() : "");
    if (!text) return;

    if (this.inputElement && !customText) {
      this.inputElement.value = "";
    }

    // Render User Bubble
    this.renderBubble("user", text);

    // Render Loading Bubble
    const loadingId = this.renderLoadingBubble();

    try {
      const response = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: text,
          session_id: this.sessionId
        })
      });

      const data = await response.json();
      this.removeLoadingBubble(loadingId);

      // Render Bot Bubble
      this.renderBubble("bot", data.response, data.voice_text);

      // Trigger Profile Modal if requested
      if (data.action === "SHOW_PROFILE") {
        if (typeof showProfileModal === "function") {
          showProfileModal(data.profile_data);
        }
      }

      // Voice Narration
      if (this.isVoiceEnabled && data.voice_text) {
        this.speak(data.voice_text);
      }

    } catch (err) {
      console.error("Chat error:", err);
      this.removeLoadingBubble(loadingId);
      this.renderBubble("bot", "⚠️ Connection error: unable to reach the AI assistant. Please ensure the backend is running.");
    }
  }

  renderBubble(sender, text, voiceText = null) {
    if (!this.messagesContainer) return;

    const bubble = document.createElement("div");
    bubble.className = `chat-bubble ${sender}`;

    // Simple markdown parsing for bold, code, lists, links
    let formattedText = this._formatMarkdown(text);

    let html = `<div>${formattedText}</div>`;

    if (sender === "bot") {
      const voicePayload = (voiceText || text).replace(/"/g, '&quot;');
      html += `
        <div class="bubble-footer">
          <span>CyberShield AI</span>
          <button class="btn-speak" onclick="window.chatInstance.speak('${voicePayload.replace(/'/g, "\\'")}')">
            🔊 Listen
          </button>
        </div>
      `;
    }

    bubble.innerHTML = html;
    this.messagesContainer.appendChild(bubble);
    this.messagesContainer.scrollTop = this.messagesContainer.scrollHeight;
  }

  renderLoadingBubble() {
    if (!this.messagesContainer) return null;
    const id = "loading_" + Date.now();
    const bubble = document.createElement("div");
    bubble.id = id;
    bubble.className = "chat-bubble bot";
    bubble.innerHTML = `<span style="color: var(--accent-cyan);">⚡ Analyzing and generating response...</span>`;
    this.messagesContainer.appendChild(bubble);
    this.messagesContainer.scrollTop = this.messagesContainer.scrollHeight;
    return id;
  }

  removeLoadingBubble(id) {
    const el = document.getElementById(id);
    if (el) el.remove();
  }

  _formatMarkdown(md) {
    if (!md) return "";
    let html = md
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;") // sanitize HTML
      .replace(/^### (.*$)/gim, '<h4 style="color:var(--accent-cyan); margin:0.5rem 0 0.3rem;">$1</h4>')
      .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
      .replace(/\*([^*]+)\*/g, '<em>$1</em>')
      .replace(/`([^`]+)`/g, '<code style="background:rgba(0,0,0,0.3); color:var(--accent-cyan); padding:2px 5px; border-radius:4px; font-family:var(--font-mono); font-size:0.85em;">$1</code>')
      .replace(/\n\n/g, '<div style="margin-bottom:0.6rem;"></div>')
      .replace(/\n/g, '<br/>');
    return html;
  }
}

// Global initialization
document.addEventListener("DOMContentLoaded", () => {
  window.chatInstance = new ChatAssistant();
});

// Helper for quick question pill clicks
function askQuick(text) {
  if (window.chatInstance) {
    window.chatInstance.sendMessage(text);
  }
}

// Profile Modal Controller
function showProfileModal(profile) {
  const modal = document.getElementById("profile-modal");
  if (!modal) return;

  if (profile) {
    const nameEl = document.getElementById("prof-name");
    const titleEl = document.getElementById("prof-title");
    const bioEl = document.getElementById("prof-bio");
    const skillsEl = document.getElementById("prof-skills");
    const githubEl = document.getElementById("prof-github");
    const linkedinEl = document.getElementById("prof-linkedin");
    const emailEl = document.getElementById("prof-email");

    if (nameEl) nameEl.textContent = profile.name;
    if (titleEl) titleEl.textContent = profile.title;
    if (bioEl) bioEl.textContent = profile.bio;
    if (githubEl) githubEl.href = profile.github;
    if (linkedinEl) linkedinEl.href = profile.linkedin;
    if (emailEl) emailEl.textContent = profile.email;

    if (skillsEl && profile.skills) {
      skillsEl.innerHTML = profile.skills.map(s => `<span class="skill-tag">${s}</span>`).join("");
    }
  }

  modal.style.display = "flex";
}

function closeProfileModal() {
  const modal = document.getElementById("profile-modal");
  if (modal) modal.style.display = "none";
}

// Floating Chat Widget Toggle
function toggleFloatingChat() {
  const chatBox = document.getElementById("floating-chat-box");
  if (chatBox) {
    chatBox.style.display = (chatBox.style.display === "block") ? "none" : "block";
  }
}
