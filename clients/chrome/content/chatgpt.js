/**
 * chatgpt.js — chatgpt.com 전용
 *
 * ChatGPT DOM 특성:
 * - 코드블록: pre 없이 div[dir='ltr'] 가 전체 코드를 담음
 * - 언어 레이블: 코드블록 이전 형제 요소에 "Python" 등 텍스트
 * - textContent 사용 시 줄바꿈 사라짐 → innerText 사용
 * - 삽입 위치: border-token-border-light 컨테이너 다음
 */

// ── 언어 감지 ─────────────────────────────────────────────────────────────────
function guessFilename(codeEl) {
  // ChatGPT: 코드블록 헤더가 이전 형제 요소에 있음
  const prevSibling =
    codeEl.previousElementSibling?.textContent?.trim()?.toLowerCase() ||
    codeEl.parentElement?.previousElementSibling?.textContent?.trim()?.toLowerCase() ||
    codeEl.closest("[class*='overflow']")?.previousElementSibling?.textContent?.trim()?.toLowerCase() || "";

  if (prevSibling.includes("python"))     return "script.py";
  if (prevSibling.includes("javascript")) return "script.js";
  if (prevSibling.includes("typescript")) return "script.ts";
  if (prevSibling.includes("json"))       return "package.json";

  const code = (codeEl.innerText || codeEl.textContent) || "";
  if (/^\s*(import |from .+ import|def |class )/.test(code)) return "script.py";
  if (/require\(|import .+ from/.test(code))                  return "script.js";
  if (/"dependencies"\s*:/.test(code))                        return "package.json";
  return "script.py";
}

// ── 패널 삽입 ─────────────────────────────────────────────────────────────────
// div[dir='ltr'] 기준 4단계 위의 border-token-border 컨테이너 다음에 삽입
function insertAfterCodeBlock(codeEl, newEl) {
  let el = codeEl;
  for (let i = 0; i < 12; i++) {
    const p = el.parentElement;
    if (!p || p === document.body) break;
    const cls = p.className || "";
    if (cls.includes("border-token-border") && cls.includes("border-radius")) {
      try { p.insertAdjacentElement("afterend", newEl); return true; } catch {}
    }
    el = p;
  }
  console.warn("[Slop Detector] ChatGPT 패널 삽입 위치 없음");
  return false;
}

// ── 중복 방지 ─────────────────────────────────────────────────────────────────
let processedKeys = new Set();

function getKey(text) {
  return `${text.length}::${text.slice(0, 60)}::${text.slice(-60)}`;
}

// ── 코드블록 스캔 ─────────────────────────────────────────────────────────────
function scanCodeBlocks() {
  const selectors = ["div[dir='ltr']", "pre code"].join(", ");
  document.querySelectorAll(selectors).forEach(el => {
    if (el.hasAttribute("data-slop-scanned")) return;
    const text = ((el.innerText || el.textContent) || "").trim();
    if (text.length < 80) return;
    const hasImport = /^\s*(import |from .+ import)/m.test(text)
      || /require\(|"dependencies"/.test(text);
    if (!hasImport) return;
    // 컨텐츠 해시로 dedup — 한 응답에 코드블록 여러 개 있으면 각각 분석
    // (div[dir='ltr']와 pre code nested 케이스도 같은 텍스트로 dedup됨)
    const key = getKey(text);
    if (processedKeys.has(key)) {
      el.setAttribute("data-slop-scanned", "1");
      return;
    }
    processedKeys.add(key);
    el.setAttribute("data-slop-scanned", "1");
    // text 스캔이 같은 응답에서 nlp/span 추출 안 돌도록 마킹 (pip은 여전히 추출)
    const msg = el.closest("div[data-message-author-role='assistant']");
    if (msg) msg.setAttribute("data-slop-code-scanned", "1");
    const filename = guessFilename(el);
    analyzeAndRender(text, filename, (newEl) => insertAfterCodeBlock(el, newEl));
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
  console.log(`[Slop Detector] 시작 — 사이트: chatgpt, API: ${serverUp ? "✅ 연결됨" : "❌ 오프라인"}`);
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

// ChatGPT 패키지명 매핑 (표시명 → PyPI/npm 패키지명)
const GPT_PACKAGE_ALIASES = {
  "tensorflow": "tensorflow",
  "pytorch": "torch",
  "scikit-learn": "scikit-learn",
  "sklearn": "scikit-learn",
  "keras": "keras",
  "hugging face transformers": "transformers",
  "hugging face": "transformers",
  "huggingface": "transformers",
  "transformers": "transformers",
  "numpy": "numpy",
  "pandas": "pandas",
  "matplotlib": "matplotlib",
  "opencv": "opencv-python",
  "xgboost": "xgboost",
  "lightgbm": "lightgbm",
};

function extractSpanPackages(el) {
  // span.whitespace-normal 태그에서 패키지명 추출 (ChatGPT 특유 렌더링)
  const spans = [...el.querySelectorAll("span.whitespace-normal")]
    .map(s => s.textContent.trim().toLowerCase())
    .filter(t => t.length > 1 && t.length < 50);

  const packages = new Set();
  for (const name of spans) {
    // 알려진 패키지명 직접 매핑
    if (GPT_PACKAGE_ALIASES[name]) {
      packages.add(GPT_PACKAGE_ALIASES[name]);
    }
    // 매핑 없으면 그대로 사용 (소문자, 영문+하이픈만)
    else if (/^[a-z0-9][a-z0-9\-\.]+$/.test(name)) {
      packages.add(name);
    }
  }
  return [...packages];
}

function scanResponseText() {
  document.querySelectorAll("div[data-message-author-role='assistant']").forEach(el => {
    if (el.hasAttribute("data-slop-scanned")) return;
    const text = el.innerText || "";
    if (text.length < 20) return;

    // pip install 패턴은 항상 추출 (고신뢰, 코드블록 import와 안 겹침)
    // 예: 응답 맨 아래 bash 코드블록의 "pip install fastapi-users redis"
    const pipPackages = extractPackagesFromText(text);

    // 코드블록 스캔이 이미 처리했으면 nlp/span 은 스킵 (중복 방지)
    // pip 추출은 그대로 유지 — 코드블록과 패키지가 다름
    const codeAlreadyScanned = el.hasAttribute("data-slop-code-scanned");
    const spanPackages = codeAlreadyScanned ? [] : extractSpanPackages(el);
    const nlpPackages = codeAlreadyScanned ? [] : (typeof extractPackagesFromNaturalText === "function"
      ? extractPackagesFromNaturalText(text)
      : []);

    // 합치고 lowercase 정규화로 dedup
    const allPackages = [...new Set(
      [...pipPackages, ...spanPackages, ...nlpPackages]
        .map(p => (p || "").toString().toLowerCase().trim())
        .filter(Boolean)
    )].filter(p => ![...processedKeys].some(k => k.includes(p)));

    if (!allPackages.length) return;

    // DOM에 이미 텍스트 패널이 삽입되어 있으면 스킵 (타이밍 중복 방지)
    if (el.parentElement?.querySelector("[data-slop-text-panel]")) return;

    el.setAttribute("data-slop-scanned", "1");
    console.log(`[Slop Detector] ChatGPT 텍스트 패키지 감지:`, allPackages);

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
