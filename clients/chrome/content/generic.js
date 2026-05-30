/**
 * generic.js — Perplexity / Copilot / DeepSeek / Grok / Phind / Mistral 등
 * 범용 LLM 채팅 사이트용 컨텐츠 스크립트
 *
 * 전략:
 *  - 코드블록은 표준 `pre code` 셀렉터로 탐지
 *  - 메시지 컨테이너는 휴리스틱 셀렉터 목록으로 탐지
 *  - 사이트별 DOM 차이는 무시하고, 코드/텍스트 위치를 직접 분석
 */

// ── 사이트 식별 (로그 메시지용) ─────────────────────────────────────────────
const SITE_NAME = (() => {
  const h = location.hostname;
  if (h.includes("perplexity"))             return "perplexity";
  if (h.includes("copilot.microsoft.com"))  return "copilot";
  if (h.includes("deepseek"))               return "deepseek";
  if (h.includes("grok.com"))               return "grok";
  if (h.includes("phind"))                  return "phind";
  if (h.includes("mistral"))                return "mistral";
  return h;
})();

// ── 코드블록 셀렉터 (대부분 사이트가 표준 pre code 사용) ────────────────────
const CODE_SELECTORS = ["pre code", "pre"].join(", ");

// ── 메시지 컨테이너 휴리스틱 ─────────────────────────────────────────────────
const MESSAGE_SELECTORS = [
  "[data-message-author-role='assistant']",   // OpenAI-style
  "[data-role='assistant']",                  // 일부
  "[class*='message-content']",
  "[class*='AssistantMessage']",
  "[class*='assistant-message']",
  "[class*='ProseMirror']",                   // Phind
  // 토큰 정확 매칭(~=) — [class*='prose'] 는 print:prose, not-prose(반대 의미)까지
  // 오매칭해서 <main> 전체가 잡혀 패널이 풀폭으로 튀어나옴. 진짜 prose 토큰만 매칭.
  "[class~='prose']:not(input):not(textarea)",
  "article",                                  // Perplexity
  "[role='article']",
].join(", ");

// ── 언어 감지 ─────────────────────────────────────────────────────────────────
function guessFilename(codeEl) {
  // 클래스명에서 언어 추출 (language-python 등)
  const classes = [...(codeEl.classList || []), ...(codeEl.parentElement?.classList || [])];
  for (const cls of classes) {
    const lang = cls.replace(/^(language-|lang-|hljs-)/, "").toLowerCase();
    if (lang === "python")                       return "script.py";
    if (lang === "javascript" || lang === "js")  return "script.js";
    if (lang === "typescript" || lang === "ts")  return "script.ts";
    if (lang === "json")                         return "package.json";
  }
  // 코드블록 헤더(이전 형제)에서 언어 텍스트
  const header = (
    codeEl.closest("pre")?.previousElementSibling?.textContent ||
    codeEl.parentElement?.previousElementSibling?.textContent || ""
  ).trim().toLowerCase();
  if (header.includes("python"))     return "script.py";
  if (header.includes("javascript")) return "script.js";
  if (header.includes("typescript")) return "script.ts";
  if (header.includes("json"))       return "package.json";
  // 코드 내용으로 추측
  const code = (codeEl.innerText || codeEl.textContent) || "";
  if (/^\s*(import |from .+ import|def |class )/.test(code)) return "script.py";
  if (/require\(|import .+ from/.test(code))                  return "script.js";
  if (/"dependencies"\s*:/.test(code))                        return "package.json";
  return "script.py";
}

// ── 패널 삽입: 가장 가까운 pre 또는 메시지 컨테이너 뒤에 ────────────────────
function insertAfterCode(codeEl, newEl) {
  const pre = codeEl.closest("pre") || codeEl;
  // pre 바로 다음에 삽입
  try { pre.insertAdjacentElement("afterend", newEl); return true; } catch {}
  // 실패 시 블록 레벨 부모를 찾아 그 뒤로
  let el = pre;
  for (let i = 0; i < 8; i++) {
    const p = el.parentElement;
    if (!p || p === document.body) break;
    const d = window.getComputedStyle(p).display;
    if (d === "block" || d === "flex" || d === "grid") {
      try { p.insertAdjacentElement("afterend", newEl); return true; } catch {}
    }
    el = p;
  }
  return false;
}

// ── 유저 질문 메시지 식별 ────────────────────────────────────────────────────
// MESSAGE_SELECTORS 가 광범위(message-content/prose/article)해서 유저 질문 말풍선까지
// 매칭됨 → 응답(assistant)만 검사하도록 유저 컨테이너를 제외.
const USER_MESSAGE_SELECTORS = [
  "[data-message-author-role='user']",
  "[data-role='user']",
  "[class*='user-message']", "[class*='UserMessage']",
  "[class*='user-query']",   "[class*='UserQuery']",
  "[class*='user-bubble']",  "[class*='UserBubble']",
  "[class*='message-bubble--user']",
  "[class*='human']",
  "[aria-label*='your message' i]",
].join(", ");

function _isUserMessage(el) {
  try {
    if (el.closest(USER_MESSAGE_SELECTORS)) return true;
    // Grok: 유저 질문은 <p class="break-words" node="[object Object]"> 로 렌더됨.
    // node 속성은 Grok 입력 직렬화 흔적 — AI 응답(마크다운)엔 없음.
    // 스캔 컨테이너가 이 <p>를 감싸므로 descendant 로 검사.
    if (el.matches?.("p.break-words[node]")) return true;
    const q = el.querySelector?.("p.break-words[node]");
    // 코드블록(pre/code)이 없는 컨테이너만 유저 질문으로 판단 — 응답 오제외 방지
    if (q && !el.querySelector("pre, code")) return true;
    return false;
  } catch { return false; }
}

// ── 중복 방지 ─────────────────────────────────────────────────────────────────
let processedKeys = new Set();
const processedTextKeys = new Set();

// ── 코드블록 스캔 ─────────────────────────────────────────────────────────────
function scanCodeBlocks() {
  document.querySelectorAll(CODE_SELECTORS).forEach(el => {
    if (el.hasAttribute("data-slop-scanned")) return;
    // 유저 질문 안의 코드는 제외 — AI 응답만 검사
    if (_isUserMessage(el)) return;
    // pre 안에 code가 있으면 code 우선, 아니면 pre 자체
    if (el.tagName === "PRE" && el.querySelector("code")) return;
    const text = ((el.innerText || el.textContent) || "").trim();
    if (text.length < 80) return;
    const hasImport = /^\s*(import |from .+ import)/m.test(text)
      || /require\(|"dependencies"/.test(text);
    if (!hasImport) return;
    el.setAttribute("data-slop-scanned", "1");
    const filename = guessFilename(el);
    analyzeAndRender(text, filename, (newEl) => insertAfterCode(el, newEl));
  });
}

// ── 텍스트 응답 스캔 ─────────────────────────────────────────────────────────
function scanResponseText() {
  document.querySelectorAll(MESSAGE_SELECTORS).forEach(el => {
    if (el.hasAttribute("data-slop-scanned")) return;
    // 유저 질문은 제외 — AI 응답만 검사
    if (_isUserMessage(el)) return;
    const text = el.innerText || "";
    if (text.length < 20 || text.length > 50000) return;

    const installPackages = extractPackagesFromText(text);
    const nlpPackages = typeof extractPackagesFromNaturalText === "function"
      ? extractPackagesFromNaturalText(text)
      : [];
    const allPackages = [...new Set([...installPackages, ...nlpPackages])]
      .filter(p => ![...processedKeys].some(k => k.includes(p)));

    if (!allPackages.length) return;
    if (el.parentElement?.querySelector("[data-slop-text-panel]")) return;
    if (el.querySelector("[data-slop-text-panel]")) return;

    // 콘텐츠 기반 중복 방지 — 중첩 매칭/재렌더로 같은 패키지 세트가 중복 검사되던 것 방지
    const pkgKey = allPackages.slice().sort().join(",");
    if (processedTextKeys.has(pkgKey)) {
      el.setAttribute("data-slop-scanned", "1");
      return;
    }
    processedTextKeys.add(pkgKey);

    el.setAttribute("data-slop-scanned", "1");
    // 진단용: 검사된 컨테이너의 태그/클래스 출력 — 유저 질문 말풍선 식별에 사용
    const _cls = typeof el.className === "string" ? el.className : "(non-string)";
    console.log(`[Slop Detector] ${SITE_NAME} 텍스트 패키지 감지:`, allPackages,
      `\n  ↳ 컨테이너: <${el.tagName.toLowerCase()} class="${_cls}">`);

    analyzePackagesFromText(allPackages, (newEl) => {
      newEl.setAttribute("data-slop-text-panel", "1");
      const existingPanel = el.nextElementSibling?.hasAttribute("data-slop-panel")
        ? el.nextElementSibling : null;
      const insertTarget = existingPanel || el;
      try { insertTarget.insertAdjacentElement("afterend", newEl); return true; } catch {}
      return false;
    });
  });
}

// ── MutationObserver ──────────────────────────────────────────────────────────
const observer = new MutationObserver(() => {
  clearTimeout(observer._timer);
  observer._timer = setTimeout(() => { scanCodeBlocks(); scanResponseText(); }, 1500);
});

// ── 시작 ──────────────────────────────────────────────────────────────────────
(async () => {
  const serverUp = await checkApiServer();
  console.log(`[Slop Detector] 시작 — 사이트: ${SITE_NAME}, API: ${serverUp ? "✅ 연결됨" : "❌ 오프라인"}`);
  if (!serverUp) return;

  watchNavigation(() => {
    processedKeys = new Set();
    setTimeout(scanCodeBlocks, 1000);
  });

  scanCodeBlocks();
  scanResponseText();
  observer.observe(document.body, { childList: true, subtree: true });
})();
