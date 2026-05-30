/**
 * background.js — Service Worker
 */

const API_BASE = "http://localhost:8001";

// ── HMAC 서명 (선택) ──────────────────────────────────────────────────────────
// chrome.storage.sync 의 hmacSecret 값이 있으면 모든 POST 요청에 서명 헤더 추가.
// 알고리즘: msg = `${ts_ms}.` + body_utf8 ; sig = HMAC_SHA256(secret, msg).hex()
async function _getHmacSecret() {
  try {
    const cfg = await chrome.storage.sync.get(["hmacSecret"]);
    return (cfg?.hmacSecret || "").trim();
  } catch { return ""; }
}

async function _hmacHeaders(bodyString) {
  const secret = await _getHmacSecret();
  if (!secret) return {};
  const enc = new TextEncoder();
  const ts = Date.now();
  const prefix = enc.encode(`${ts}.`);
  const bodyBytes = enc.encode(bodyString);
  const combined = new Uint8Array(prefix.length + bodyBytes.length);
  combined.set(prefix, 0);
  combined.set(bodyBytes, prefix.length);
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sigBuf = await crypto.subtle.sign("HMAC", key, combined);
  const sigHex = Array.from(new Uint8Array(sigBuf))
    .map(b => b.toString(16).padStart(2, "0")).join("");
  return {
    "X-PkgSentinel-Signature": `sha256=${sigHex}`,
    "X-PkgSentinel-Timestamp": String(ts),
    "X-PkgSentinel-Tool": "slop-detector-chrome/0.3.0",
  };
}

// ── 성능 향상: 중복 요청 방지를 위한 메모리 캐시 ──────────────────────────────
const analysisCache = new Map();
const CACHE_TTL = 1000 * 60 * 30; // 30분 유지

function getFromCache(key) {
  const cached = analysisCache.get(key);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.data;
  }
  return null;
}

function setCache(key, data) {
  analysisCache.set(key, { data, timestamp: Date.now() });
}

async function sha256(text) {
  const buf = await crypto.subtle.digest("SHA-256",
    new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, "0")).join("");
}

// ── 위험도 상태 관리 ────────────────────────────────────────────────────────
// API 응답 (V2 어댑터):
//   /analyze            → { results: [PackageResult] }
//   /parse-and-analyze  → { results: [PackageResult] }
// 각 PackageResult.level ∈ { CRITICAL, HIGH, MEDIUM, AGENTIC, LOW, UNKNOWN }
// 매핑:
//   CRITICAL          → malicious
//   HIGH / MEDIUM     → suspicious
//   AGENTIC           → agentic (별도 — langchain 등 AI 라이브러리, opt-in 필요)
//   LOW / UNKNOWN     → safe
async function updateRiskState(analysisResult) {
  const items = Array.isArray(analysisResult)
    ? analysisResult
    : (analysisResult && Array.isArray(analysisResult.results))
      ? analysisResult.results
      : [];

  if (items.length === 0) return;

  chrome.storage.local.get(['scanStats'], (res) => {
    const stats = res.scanStats || { safe: 0, suspicious: 0, malicious: 0, agentic: 0 };
    // 기존 사용자 데이터 호환: agentic 필드가 없으면 추가
    if (stats.agentic === undefined) stats.agentic = 0;

    for (const item of items) {
      const level = (item && item.level) || "LOW";
      if (level === "CRITICAL") stats.malicious++;
      else if (level === "AGENTIC" || item?.is_agentic) stats.agentic++;
      else if (level === "HIGH" || level === "MEDIUM") stats.suspicious++;
      else stats.safe++;
    }

    chrome.storage.local.set({ scanStats: stats });
  });
}

// ── 대화 히스토리 (FIFO + LRU 하이브리드 링버퍼) ───────────────────────────
// chrome.storage.local 의 detectionHistory 키에 최근 5건 저장.
// 새 대화 → push + 6번째면 가장 오래된 거 shift
// 기존 대화 재방문/추가 분석 → 해당 항목을 끝으로 이동 (LRU bump) + 패키지 병합
const HISTORY_MAX = 5;
const PACKAGES_PER_CONV_MAX = 30;

function _extractConvInfo(url, title) {
  if (!url) return null;
  let convId = null, site = null;
  try {
    const u = new URL(url);
    const host = u.hostname.toLowerCase();
    const path = u.pathname;
    if (host.endsWith("claude.ai")) {
      const m = path.match(/\/chat\/([a-zA-Z0-9\-_]+)/);
      if (m) { convId = m[1]; site = "claude"; }
    } else if (host.endsWith("chatgpt.com")) {
      const m = path.match(/\/c\/([a-zA-Z0-9\-_]+)/);
      if (m) { convId = m[1]; site = "chatgpt"; }
    } else if (host.endsWith("gemini.google.com")) {
      const m = path.match(/\/app\/([a-zA-Z0-9\-_]+)/);
      if (m) { convId = m[1]; site = "gemini"; }
    }
  } catch {}
  if (!convId) return null;
  // 페이지 타이틀에서 대화명 추출 (사이트 이름 접미 제거)
  let cleanTitle = (title || "").trim();
  cleanTitle = cleanTitle.replace(/\s*[-—|·]\s*(Claude|ChatGPT|Gemini).*$/i, "");
  if (!cleanTitle) cleanTitle = "(이름 없음)";
  return { convId, site, url, title: cleanTitle.slice(0, 80) };
}

async function _saveToHistory(sender, apiResult) {
  if (!sender?.tab?.url) return;
  const info = _extractConvInfo(sender.tab.url, sender.tab.title);
  if (!info) return;
  const items = Array.isArray(apiResult)
    ? apiResult
    : (Array.isArray(apiResult?.results) ? apiResult.results : []);
  if (!items.length) return;
  const newPkgs = items.map(r => ({
    name: r.package || r.name || "(unknown)",
    level: r.level || "UNKNOWN",
    verdict: r.verdict || "",
    at: Date.now(),
  })).filter(p => p.name && p.name !== "(unknown)");
  if (!newPkgs.length) return;

  const stored = await chrome.storage.local.get(["detectionHistory"]);
  const history = Array.isArray(stored.detectionHistory) ? stored.detectionHistory : [];
  const existingIdx = history.findIndex(h => h.convId === info.convId);
  let entry;
  if (existingIdx >= 0) {
    // 기존 — LRU bump + 패키지 병합 (이름 기준 dedup, 최신 verdict 우선)
    entry = history.splice(existingIdx, 1)[0];
    const byName = new Map(entry.packages.map(p => [p.name, p]));
    for (const p of newPkgs) byName.set(p.name, p);
    entry.packages = [...byName.values()].slice(-PACKAGES_PER_CONV_MAX);
    entry.lastSeenAt = Date.now();
    entry.title = info.title;
    entry.url = info.url;
  } else {
    entry = {
      convId: info.convId,
      site: info.site,
      url: info.url,
      title: info.title,
      lastSeenAt: Date.now(),
      packages: newPkgs.slice(0, PACKAGES_PER_CONV_MAX),
    };
  }
  history.push(entry);
  // FIFO evict — max 5건 유지
  while (history.length > HISTORY_MAX) history.shift();
  await chrome.storage.local.set({ detectionHistory: history });
}

// ── 헬스체크 ────────────────────────────────────────────────────────────────
async function checkHealth() {
  try {
    const res = await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(3000) });
    return res.ok;
  } catch {
    return false;
  }
}

// ── 패키지 분석 ─────────────────────────────────────────────────────────────
async function analyzePackages(packages) {
  const cacheKey = `pkg_${await sha256(packages.sort().join(","))}`;
  const cached = getFromCache(cacheKey);
  if (cached) return cached;

  const body = JSON.stringify({ packages });
  const sigHeaders = await _hmacHeaders(body);
  const res = await fetch(`${API_BASE}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...sigHeaders },
    body,
    signal: AbortSignal.timeout(120000),
  });
  if (!res.ok) throw new Error(`API 오류: ${res.status}`);

  const data = await res.json();
  setCache(cacheKey, data);
  await updateRiskState(data);
  return data;
}

// ── 코드 파싱 + 분석 ─────────────────────────────────────────────────────────
async function parseAndAnalyze(filename, code) {
  const cacheKey = `code_${await sha256(filename + code)}`;
  const cached = getFromCache(cacheKey);
  if (cached) return cached;

  const body = JSON.stringify({ filename, code });
  const sigHeaders = await _hmacHeaders(body);
  const res = await fetch(`${API_BASE}/parse-and-analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...sigHeaders },
    body,
    signal: AbortSignal.timeout(120000),
  });
  if (!res.ok) throw new Error(`API 오류: ${res.status}`);

  const data = await res.json();
  setCache(cacheKey, data);
  await updateRiskState(data);
  return data;
}

// ── 메시지 핸들러 ────────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  const handle = async () => {
    switch (message.type) {
      case "HEALTH_CHECK":
        return { ok: await checkHealth() };
      case "ANALYZE_PACKAGES": {
        const result = await analyzePackages(message.packages);
        await _saveToHistory(_sender, result);
        return result;
      }
      case "PARSE_AND_ANALYZE": {
        const codeIn = (message.code || "").replace(/\u00a0/g, " ");
        const result = await parseAndAnalyze(message.filename, codeIn);
        await _saveToHistory(_sender, result);
        return result;
      }
      case "GET_STATS":
        return new Promise((resolve) => {
          chrome.storage.local.get(['scanStats'], (res) => resolve(res.scanStats || null));
        });
      case "GET_HISTORY":
        return new Promise((resolve) => {
          chrome.storage.local.get(['detectionHistory'], (res) =>
            resolve(Array.isArray(res.detectionHistory) ? res.detectionHistory : [])
          );
        });
      case "CLEAR_HISTORY":
        return new Promise((resolve) => {
          chrome.storage.local.remove("detectionHistory", () => resolve({ ok: true }));
        });
      default:
        return { error: `알 수 없는 메시지 타입: ${message.type}` };
    }
  };

  handle()
    .then(sendResponse)
    .catch((err) => sendResponse({ error: err.message }));

  return true;
});