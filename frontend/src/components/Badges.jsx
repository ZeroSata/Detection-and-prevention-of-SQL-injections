export const RISK_LABELS = { low: 'LOW', medium: 'MEDIUM', high: 'HIGH', critical: 'CRITICAL' }
export const STATUS_LABELS = { new: 'новый', investigating: 'в работе', closed: 'закрыт' }
export const LOG_STATUS_LABELS = { ok: 'ok', error: 'ошибка', blocked: 'заблокирован' }
export const MODE_LABELS = { insecure: 'insecure', secure: 'secure', dashboard: 'dashboard', other: 'other' }
export const ATTACK_TYPE_LABELS = {
  tautology: 'тавтология',
  union: 'UNION',
  comment: 'комментарий',
  stacked: 'stacked',
  time_based: 'time-based',
  error_based: 'error-based',
  recon: 'разведка',
  keyword: 'ключевое слово',
  quote: 'кавычка',
  semicolon: 'точка с запятой',
  obfuscation: 'обфускация',
}

export function RiskBadge({ risk }) {
  return <span className={`badge risk-${risk}`}>{RISK_LABELS[risk] || risk}</span>
}

export function StatusBadge({ status }) {
  return <span className={`badge st-${status}`}>{STATUS_LABELS[status] || status}</span>
}

export function LogStatusBadge({ status }) {
  return <span className={`badge ls-${status}`}>{LOG_STATUS_LABELS[status] || status}</span>
}

export function ModeChip({ mode }) {
  return <span className={`chip mode-${mode}`}>{MODE_LABELS[mode] || mode}</span>
}

export function WafChip({ enabled }) {
  return <span className={`chip waf-${enabled ? 'on' : 'off'}`}>WAF {enabled ? 'ON' : 'OFF'}</span>
}
