/**
 * popup.js
 * 팝업 UI의 상태 업데이트 및 통계 표시를 담당합니다.
 */

document.addEventListener('DOMContentLoaded', () => {
  const dot = document.getElementById("dot");
  const text = document.getElementById("status-text");

  // 1. 서버(API) 연결 상태 확인
  chrome.runtime.sendMessage({ type: "HEALTH_CHECK" }, (res) => {
    if (res?.ok) {
      dot.className = "dot ok";
      text.textContent = "로컬 분석 엔진 연결됨 ✓";
    } else {
      dot.className = "dot error";
      text.textContent = "분석 엔진 오프라인 (Docker 확인)";
    }
  });

  // 2. background.js로부터 누적된 위협 통계 데이터 가져오기
  chrome.runtime.sendMessage({ type: "GET_STATS" }, (stats) => {
    if (stats) {
      document.getElementById("stat-safe").textContent = stats.safe || 0;
      document.getElementById("stat-agent").textContent = stats.agentic || 0;
      document.getElementById("stat-sus").textContent = stats.suspicious || 0;
      document.getElementById("stat-mal").textContent = stats.malicious || 0;
    }
  });

  // 3. HMAC Secret 관리
  const hmacInput = document.getElementById("hmac-secret");
  const saveBtn = document.getElementById("save-secret");
  const statusEl = document.getElementById("secret-status");

  // 저장된 값 불러오기 (마스킹 표시)
  chrome.storage.sync.get(["hmacSecret"], (cfg) => {
    const s = cfg?.hmacSecret || "";
    statusEl.textContent = s ? `현재: 설정됨 (${s.length}자)` : "현재: 미설정 (인증 안 함)";
    hmacInput.placeholder = s ? "변경하려면 새 값 입력" : "비워두면 인증 안 함";
  });

  saveBtn.addEventListener("click", () => {
    const secret = hmacInput.value.trim();
    chrome.storage.sync.set({ hmacSecret: secret }, () => {
      if (chrome.runtime.lastError) {
        statusEl.style.color = "#c00";
        statusEl.textContent = `저장 실패: ${chrome.runtime.lastError.message}`;
        return;
      }
      statusEl.style.color = "";
      statusEl.textContent = secret
        ? `저장됨 (${secret.length}자) — 어댑터 AISLOP_HMAC_SECRET 와 동일해야 함`
        : "삭제됨 — 인증 비활성화";
      hmacInput.value = "";
    });
  });

  // 4. 대화 히스토리 (FIFO + LRU 하이브리드, 최근 5건)
  const historyListEl = document.getElementById("history-list");
  const historyClearBtn = document.getElementById("history-clear");

  function _relTime(ms) {
    const diff = Date.now() - ms;
    if (diff < 60_000) return "방금";
    if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}분 전`;
    if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}시간 전`;
    return `${Math.floor(diff / 86_400_000)}일 전`;
  }

  function _esc(s) {
    return String(s ?? "").replace(/[&<>"']/g, c => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    }[c]));
  }

  function _levelClass(level) {
    const u = String(level || "").toUpperCase();
    if (u === "CRITICAL") return "critical";
    if (u === "HIGH") return "high";
    if (u === "MEDIUM") return "medium";
    if (u === "LOW") return "low";
    return "unknown";
  }

  function _siteBadge(site) {
    if (site === "claude") return ["badge-claude", "Claude"];
    if (site === "chatgpt") return ["badge-chatgpt", "ChatGPT"];
    if (site === "gemini") return ["badge-gemini", "Gemini"];
    return ["", site || "?"];
  }

  function renderHistory(history) {
    if (!history || !history.length) {
      historyListEl.innerHTML =
        '<div class="history-empty">아직 분석한 대화가 없습니다</div>';
      return;
    }
    // 최근(가장 늦은 lastSeenAt)이 위로
    const sorted = [...history].sort((a, b) => (b.lastSeenAt || 0) - (a.lastSeenAt || 0));
    historyListEl.innerHTML = "";
    sorted.forEach((conv, idx) => {
      const [badgeCls, badgeText] = _siteBadge(conv.site);
      const dangerCnt = (conv.packages || []).filter(
        p => p.level === "CRITICAL" || p.level === "HIGH"
      ).length;
      const topPkgs = (conv.packages || [])
        .slice()
        .sort((a, b) => {
          const order = ["CRITICAL", "HIGH", "MEDIUM", "UNKNOWN", "LOW"];
          return order.indexOf(a.level) - order.indexOf(b.level);
        })
        .slice(0, 3);
      const totalCnt = (conv.packages || []).length;

      const item = document.createElement("div");
      item.className = "conv-item";
      item.dataset.idx = idx;
      item.innerHTML = `
        <div class="conv-head">
          <span class="conv-site-badge ${badgeCls}">${_esc(badgeText)}</span>
          <span class="conv-title" title="${_esc(conv.title)}">${_esc(conv.title)}</span>
          <span class="conv-time">${_relTime(conv.lastSeenAt)}</span>
        </div>
        <div class="conv-summary">
          ${topPkgs.map(p =>
            `<span class="pkg-mini ${_levelClass(p.level)}" title="${_esc(p.name)} · ${_esc(p.level)}">${_esc(p.name)}</span>`
          ).join("")}
          ${totalCnt > 3 ? `<span class="pkg-mini unknown">+${totalCnt - 3}</span>` : ""}
          ${dangerCnt > 0 ? `<span class="pkg-mini critical" style="margin-left:auto;">⚠ ${dangerCnt} 위험</span>` : ""}
        </div>
        <div class="conv-detail" id="detail-${idx}">
          ${(conv.packages || []).map(p => `
            <div class="conv-detail-row">
              <span class="conv-detail-name">${_esc(p.name)}</span>
              <span class="conv-detail-level pkg-mini ${_levelClass(p.level)}">${_esc(p.level)}</span>
            </div>
          `).join("")}
        </div>
      `;
      item.addEventListener("click", (e) => {
        // 배지/타이틀 클릭 시 해당 대화로 이동
        if (e.target.classList.contains("conv-site-badge") ||
            e.target.classList.contains("conv-title")) {
          chrome.tabs.create({ url: conv.url });
          return;
        }
        // 카드 본문 클릭 시 상세 토글
        const detail = item.querySelector(".conv-detail");
        detail.classList.toggle("open");
      });
      historyListEl.appendChild(item);
    });
  }

  chrome.runtime.sendMessage({ type: "GET_HISTORY" }, (history) => {
    renderHistory(history || []);
  });

  historyClearBtn.addEventListener("click", () => {
    if (!confirm("최근 대화 히스토리를 모두 비웁니다. 계속할까요?")) return;
    chrome.runtime.sendMessage({ type: "CLEAR_HISTORY" }, () => {
      renderHistory([]);
    });
  });
});