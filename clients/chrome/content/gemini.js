/**
 * gemini.js — gemini.google.com 전용
 *
 * Gemini DOM 특성:
 * - 코드블록: message-content pre code, .code-block pre code
 * - 언어 레이블: 코드블록 헤더에 "Python" 텍스트
 * - 스트리밍 중 DOM 요소를 새로 만들어 교체함 → 내용 기반 중복 방지
 * - 삽입 위치: pre.insertAdjacentElement("afterend")
 */

// ── 셀렉터 ────────────────────────────────────────────────────────────────────
const SELECTORS = [
  "message-content pre code",
  ".code-block pre code",
  "model-response pre code",
  ".model-response-text pre code",
  ".markdown-main-panel pre code",
  "[data-message-id] pre code",
  "pre code",
].join(", ");

// 응답 컨테이너 셀렉터 (텍스트 스캔용) — model 응답에만 한정.
// .markdown-main-panel, [data-message-id] 는 대화 전체/유저 입력까지 포함하므로 제외.
const RESPONSE_SELECTORS = [
  "message-content",
  "model-response",
  ".model-response-text",
  ".response-container-content",
  "[class*='model-response']",
].join(", ");

// ── 언어 감지 ─────────────────────────────────────────────────────────────────
function guessFilename(codeEl) {
  // 클래스명에서 언어 추출
  const classes = [...(codeEl.classList || []), ...(codeEl.parentElement?.classList || [])];
  for (const cls of classes) {
    const lang = cls.replace(/^(language-|lang-)/, "").toLowerCase();
    if (lang === "python")                       return "script.py";
    if (lang === "javascript" || lang === "js")  return "script.js";
    if (lang === "typescript" || lang === "ts")  return "script.ts";
    if (lang === "json")                         return "package.json";
  }

  // Gemini 코드블록 헤더 텍스트 ("Python", "JavaScript" 등)
  const header =
    codeEl.closest(".code-block, pre")
      ?.previousElementSibling?.textContent?.trim()?.toLowerCase() || "";
  if (header.includes("python"))     return "script.py";
  if (header.includes("javascript")) return "script.js";
  if (header.includes("typescript")) return "script.ts";
  if (header.includes("json"))       return "package.json";

  // 코드 내용으로 추측
  const code = codeEl.textContent || "";
  if (/^\s*(import |from .+ import|def |class )/.test(code)) return "script.py";
  if (/require\(|import .+ from/.test(code))                  return "script.js";
  if (/"dependencies"\s*:/.test(code))                        return "package.json";
  return "script.py";
}

// ── 패널 삽입 ─────────────────────────────────────────────────────────────────
function insertAfterCode(codeEl, newEl) {
  const pre = codeEl.closest("pre");
  if (pre) {
    try { pre.insertAdjacentElement("afterend", newEl); return true; } catch {}
  }
  let el = codeEl;
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

// ── 중복 방지 ─────────────────────────────────────────────────────────────────
// Gemini는 스트리밍 중 DOM을 새로 만들므로 내용 기반으로 추적
let processedKeys = new Set();

function getKey(text) {
  return `${text.length}::${text.slice(0, 60)}::${text.slice(-60)}`;
}

// ── 코드블록 스캔 ─────────────────────────────────────────────────────────────
function scanCodeBlocks() {
  document.querySelectorAll(SELECTORS).forEach(el => {
    if (el.hasAttribute("data-slop-scanned")) return;
    // 응답 단위 dedup — 다양한 컨테이너 셀렉터 시도
    const msg = el.closest(RESPONSE_SELECTORS);
    if (msg && msg.hasAttribute("data-slop-code-scanned")) {
      el.setAttribute("data-slop-scanned", "1");
      return;
    }
    const text = (el.textContent || "").trim();
    if (text.length < 80) return;
    const hasImport = /^\s*(import |from .+ import)/m.test(text)
      || /require\(|"dependencies"/.test(text);
    if (!hasImport) return;
    el.setAttribute("data-slop-scanned", "1");
    if (msg) msg.setAttribute("data-slop-code-scanned", "1");
    const filename = guessFilename(el);
    analyzeAndRender(text, filename, (newEl) => insertAfterCode(el, newEl));
  });
}

// ── MutationObserver ──────────────────────────────────────────────────────────
// Gemini 스트리밍이 완전히 끝난 뒤 스캔하도록 debounce 1500ms
const observer = new MutationObserver(() => {
  clearTimeout(observer._timer);
  observer._timer = setTimeout(() => { scanCodeBlocks(); scanResponseText(); }, 1500);
});

// ── 시작 ──────────────────────────────────────────────────────────────────────
(async () => {
  const serverUp = await checkApiServer();
  console.log(`[Slop Detector] 시작 — 사이트: gemini, API: ${serverUp ? "✅ 연결됨" : "❌ 오프라인"}`);
  if (!serverUp) return;

  watchNavigation(() => {
    processedKeys = new Set();
    setTimeout(scanCodeBlocks, 1000);
  });

  scanCodeBlocks();
  scanResponseText();
  observer.observe(document.body, { childList: true, subtree: true });
})();

// ── 텍스트 응답 스캔 (pip/npm install 패턴) ───────────────────────────────────
const processedTextKeys = new Set();

function scanResponseText() {
  // 다양한 응답 컨테이너 셀렉터 — Gemini가 message-content 빼도 fallback으로 잡힘.
  // 중첩 매치 dedup: model-response를 canonical로 — 없으면 message-content, 둘 다 없으면 자기 자신
  const candidates = document.querySelectorAll(RESPONSE_SELECTORS);
  const seen = new Set();
  for (const raw of candidates) {
    const el = raw.closest("model-response") || raw.closest("message-content") || raw;
    if (seen.has(el)) continue;
    seen.add(el);
    if (el.hasAttribute("data-slop-scanned")) continue;
    if (el.hasAttribute("data-slop-code-scanned")) continue;
    if (el.closest("[data-slop-code-scanned]")) continue;
    if (el.querySelector("[data-slop-text-panel]")) continue;
    const text = el.innerText || "";
    if (text.length < 20) continue;

    // 1단계: pip/npm install 패턴 (고신뢰)
    const installPackages = extractPackagesFromText(text);

    // 2단계: 자연어 감지 — 백틱, import 패턴, 인기 패키지 매칭, **bold**, 하이픈 패키지명
    const nlpPackages = typeof extractPackagesFromNaturalText === "function"
      ? extractPackagesFromNaturalText(text)
      : [];

    // 모두 소문자 정규화 + 합집합
    const allPackages = [...new Set(
      [...installPackages, ...nlpPackages]
        .map(p => (p || "").toString().toLowerCase().trim())
        .filter(Boolean)
    )];

    // 코드블록에서 이미 분석된 패키지 제외
    const newPackages = allPackages.filter(p => {
      return ![...processedKeys].some(k => k.includes(p));
    });
    if (!newPackages.length) continue;

    el.setAttribute("data-slop-scanned", "1");
    console.log(`[Slop Detector] Gemini 패키지 감지:`, newPackages);

    analyzePackagesFromText(newPackages, (newEl) => {
      newEl.setAttribute("data-slop-text-panel", "1");
      const existingPanel = el.nextElementSibling?.hasAttribute("data-slop-panel")
        ? el.nextElementSibling : null;
      const insertTarget = existingPanel || el;
      try { insertTarget.insertAdjacentElement("afterend", newEl); return true; } catch {}
      return false;
    });
  }
}
