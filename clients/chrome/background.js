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
    "X-PkgSentinel-Tool": "pkgsentinel-chrome/0.3.0",
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
// 집계는 엔진 raw verdict(본 로직)를 직접 따른다.
// PackageResult.verdict ∈ { MALICIOUS, HIGH_RISK, SUSPICIOUS, AGENTIC, CLEAN,
//                           CANNOT_ANALYZE, ERROR }
// 매핑(팝업 4박스):
//   MALICIOUS / CANNOT_ANALYZE → malicious (미등록=슬롭스쿼팅 강력 의심)
//   AGENTIC                    → agentic (별도 — langchain 등 AI 라이브러리, opt-in 필요)
//   HIGH_RISK / SUSPICIOUS     → suspicious
//   CLEAN                      → safe
//   ERROR / 기타               → 집계 제외 (분석 실패/불가는 안전이 아님)
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
      const v = (item && item.verdict) || "";
      if (v === "MALICIOUS" || v === "CANNOT_ANALYZE") stats.malicious++;
      else if (v === "AGENTIC" || item?.is_agentic) stats.agentic++;
      else if (v === "HIGH_RISK" || v === "SUSPICIOUS") stats.suspicious++;
      else if (v === "CLEAN") stats.safe++;
      // ERROR / 기타: 집계 제외
    }

    chrome.storage.local.set({ scanStats: stats });
  });
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
      case "ANALYZE_PACKAGES":
        return await analyzePackages(message.packages);
      case "PARSE_AND_ANALYZE": {
        const codeIn = (message.code || "").replace(/\u00a0/g, " ");
        return await parseAndAnalyze(message.filename, codeIn);
      }
      case "GET_STATS":
        return new Promise((resolve) => {
          chrome.storage.local.get(['scanStats'], (res) => resolve(res.scanStats || null));
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