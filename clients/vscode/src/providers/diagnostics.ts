/**
 * Diagnostics — 의존성 한 줄마다 squiggle.
 *
 * 색상 (엔진 본 로직 verdict 기준):
 *   MALICIOUS / HIGH_RISK / CANNOT_ANALYZE → Error (red squiggle)
 *   SUSPICIOUS / AGENTIC                   → Warning (yellow)
 *   CLEAN                                  → 표시 안 함
 *   NETWORK_ERROR / ERROR                  → Information (회색)
 */
import * as vscode from 'vscode';

import { AnalyzeResponse, Verdict } from '../client/api';
import { DependencyMention } from '../manifest/types';

const SOURCE = 'pkgsentinel';

export class DiagnosticsManager {
  readonly collection: vscode.DiagnosticCollection;
  /** (uri.toString() → name → response) — hover provider 가 사용 */
  private store = new Map<string, Map<string, AnalyzeResponse>>();

  constructor() {
    this.collection = vscode.languages.createDiagnosticCollection('pkgsentinel');
  }

  dispose(): void {
    this.collection.dispose();
  }

  /** 한 문서의 진단을 *교체* (덮어쓰기). */
  setForUri(
    uri: vscode.Uri,
    mentions: DependencyMention[],
    responses: Map<string, AnalyzeResponse>,
  ): void {
    const diags: vscode.Diagnostic[] = [];
    const docStore = new Map<string, AnalyzeResponse>();

    for (const m of mentions) {
      const r = responses.get(m.name);
      if (!r) continue;
      docStore.set(m.name, r);
      const sev = severityFor(r.verdict);
      // 주의: DiagnosticSeverity.Error === 0 이므로 falsy 검사(!sev)를 쓰면
      // Error(MALICIOUS/HIGH_RISK/CANNOT_ANALYZE)가 0 으로 걸러져 물결선이
      // 안 뜬다. null(=표시 안 함, CLEAN) 만 건너뛴다.
      if (sev === null) continue;
      const range = new vscode.Range(
        new vscode.Position(m.line, m.startChar),
        new vscode.Position(m.line, m.endChar),
      );
      const msg = formatMessage(m, r);
      const d = new vscode.Diagnostic(range, msg, sev);
      d.source = SOURCE;
      d.code = r.verdict;
      diags.push(d);
    }
    this.collection.set(uri, diags);
    this.store.set(uri.toString(), docStore);
  }

  /** hover provider 가 호출. 라인 위치로 응답을 조회. */
  responseAt(
    uri: vscode.Uri,
    mentions: DependencyMention[],
    position: vscode.Position,
  ): { mention: DependencyMention; response: AnalyzeResponse } | null {
    const map = this.store.get(uri.toString());
    if (!map) return null;
    for (const m of mentions) {
      if (
        m.line === position.line &&
        position.character >= m.startChar &&
        position.character <= m.endChar
      ) {
        const r = map.get(m.name);
        if (r) return { mention: m, response: r };
      }
    }
    return null;
  }

  clear(uri: vscode.Uri): void {
    this.collection.delete(uri);
    this.store.delete(uri.toString());
  }

  clearAll(): void {
    this.collection.clear();
    this.store.clear();
  }
}

function severityFor(v: Verdict | undefined): vscode.DiagnosticSeverity | null {
  switch (v) {
    case 'MALICIOUS':
    case 'HIGH_RISK':
    case 'CANNOT_ANALYZE':   // 미등록 = 슬롭스쿼팅 강력 의심
      return vscode.DiagnosticSeverity.Error;
    case 'SUSPICIOUS':
    case 'AGENTIC':          // AI 에이전트 권한 — opt-in 검토 필요
      return vscode.DiagnosticSeverity.Warning;
    case 'NETWORK_ERROR':
    case 'ERROR':            // 분석 실패
      return vscode.DiagnosticSeverity.Information;
    default:
      return null;
  }
}

function formatMessage(m: DependencyMention, r: AnalyzeResponse): string {
  const v = r.verdict ?? 'UNKNOWN';
  if (v === 'NETWORK_ERROR') {
    return `pkgsentinel: 서버 연결 실패 (${r.error || 'unknown'}). 설정의 serverUrl 확인.`;
  }
  const conf = r.confidence !== undefined ? ` (conf ${(r.confidence * 100).toFixed(0)}%)` : '';
  const cache = r.cache?.hit ? ' [cached]' : '';
  const ttp = r.evidence_summary?.[0]?.ttp_name;
  const reason = r.reasoning?.split('\n')[0]?.slice(0, 140);
  return `${m.ecosystem}/${m.name}${m.resolvedVersion ? '@' + m.resolvedVersion : ''}: ${v}${conf}${cache}` +
    (ttp ? `  — ${ttp}` : '') +
    (reason ? `\n${reason}` : '');
}
