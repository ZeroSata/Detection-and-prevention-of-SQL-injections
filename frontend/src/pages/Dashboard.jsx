import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Legend, Pie, PieChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import { get, patch } from '../api.js'
import { ATTACK_TYPE_LABELS, RiskBadge, StatusBadge } from '../components/Badges.jsx'

const RISK_COLORS = { low: '#94a3b8', medium: '#fbbf24', high: '#fb923c', critical: '#ef4444' }
const ATTACK_TYPES = ['', ...Object.keys(ATTACK_TYPE_LABELS)]

function Card({ label, value, tone }) {
  return (
    <div className={`card ${tone ? `card--${tone}` : ''}`}>
      <div className="card__value">{value}</div>
      <div className="card__label">{label}</div>
    </div>
  )
}

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [data, setData] = useState(null)
  const [detail, setDetail] = useState(null)
  const [filters, setFilters] = useState({ risk: '', status: '', attack_type: '', ip: '' })
  const [page, setPage] = useState(1)
  const [error, setError] = useState('')
  const [updated, setUpdated] = useState('')

  const queryString = useMemo(() => {
    const p = new URLSearchParams()
    Object.entries(filters).forEach(([k, v]) => v && p.set(k, v))
    p.set('page', String(page))
    p.set('page_size', '12')
    return p.toString()
  }, [filters, page])

  const load = useCallback(async () => {
    try {
      const [s, i] = await Promise.all([get('/api/dashboard/stats'), get(`/api/dashboard/incidents?${queryString}`)])
      setStats(s)
      setData(i)
      setUpdated(new Date().toLocaleTimeString('ru-RU'))
      setError('')
    } catch (e) {
      setError('Не удалось получить данные дашборда. Бэкенд запущен?')
    }
  }, [queryString])

  useEffect(() => {
    load()
    const t = setInterval(load, 4000) // обновление в реальном времени: polling 4 c
    return () => clearInterval(t)
  }, [load])

  async function openDetail(id) {
    const d = await get(`/api/dashboard/incidents/${id}`)
    setDetail(d)
  }

  async function changeStatus(id, status) {
    await patch(`/api/dashboard/incidents/${id}/status`, { status })
    await load()
    if (detail?.incident?.id === id) setDetail({ ...detail, incident: { ...detail.incident, status } })
  }

  function setFilter(key, value) {
    setFilters((f) => ({ ...f, [key]: value }))
    setPage(1)
  }

  const timeline = stats?.timeline?.map((r) => ({ ...r, time: r.minute })) || []
  const byRisk = Object.entries(stats?.by_risk || {}).map(([k, v]) => ({ name: k, value: v }))

  return (
    <div className="dashboard">
      <div className="dashboard__head">
        <h1>Security Dashboard</h1>
        <div className="muted small">
          Обновление в реальном времени (polling 4 c){updated && <> · последние данные: {updated}</>}
        </div>
      </div>

      {error && <div className="error-box">{error}</div>}

      <div className="cards">
        <Card label="Инцидентов всего" value={stats?.incidents_total ?? '…'} tone="info" />
        <Card label="Открытых инцидентов" value={stats?.incidents_open ?? '…'} tone="warn" />
        <Card label="Критических" value={stats?.by_risk?.critical ?? '…'} tone="danger" />
        <Card label="Уникальных IP-атакеров" value={stats?.unique_attackers ?? '…'} tone="info" />
        <Card label="Запросов всего" value={stats?.requests_total ?? '…'} />
        <Card label="Заблокировано WAF" value={stats?.blocked_total ?? '…'} tone="ok" />
        <Card label="Ошибок СУБД" value={stats?.error_total ?? '…'} tone="warn" />
        <Card label="Среднее время ответа" value={stats?.avg_response_ms != null ? `${stats.avg_response_ms} мс` : '…'} />
      </div>

      <div className="charts">
        <section className="panel">
          <h2>Активность атак (60 минут)</h2>
          <div className="chart-box">
            <ResponsiveContainer width="100%" height={230}>
              <AreaChart data={timeline} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2a44" />
                <XAxis dataKey="time" stroke="#8ea0bf" fontSize={10} interval={9} />
                <YAxis allowDecimals={false} stroke="#8ea0bf" fontSize={11} />
                <Tooltip contentStyle={{ background: '#121a2b', border: '1px solid #1f2a44' }} />
                <Legend />
                <Area type="monotone" dataKey="attacks" name="атаки (блокировки)" stroke="#f87171" fill="#f87171" fillOpacity={0.25} />
                <Area type="monotone" dataKey="incidents" name="новые инциденты" stroke="#38bdf8" fill="#38bdf8" fillOpacity={0.2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </section>

        <section className="panel">
          <h2>По типам атак</h2>
          <div className="chart-box">
            <ResponsiveContainer width="100%" height={230}>
              <BarChart data={stats?.by_type || []} layout="vertical" margin={{ top: 5, right: 20, left: 60, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2a44" />
                <XAxis type="number" allowDecimals={false} stroke="#8ea0bf" fontSize={11} />
                <YAxis type="category" dataKey="attack_type" width={90} stroke="#8ea0bf" fontSize={11}
                      tickFormatter={(t) => ATTACK_TYPE_LABELS[t] || t} />
                <Tooltip contentStyle={{ background: '#121a2b', border: '1px solid #1f2a44' }}
                         formatter={(v) => [v, 'инцидентов']}
                         labelFormatter={(t) => ATTACK_TYPE_LABELS[t] || t} />
                <Bar dataKey="count" name="инцидентов" fill="#fb923c" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </section>

        <section className="panel">
          <h2>Распределение по риску</h2>
          <div className="chart-box">
            <ResponsiveContainer width="100%" height={230}>
              <PieChart>
                <Pie data={byRisk} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label>
                  {byRisk.map((e) => <Cell key={e.name} fill={RISK_COLORS[e.name]} />)}
                </Pie>
                <Tooltip contentStyle={{ background: '#121a2b', border: '1px solid #1f2a44' }} />
                <Legend formatter={(v) => <span className="legend-item">{v}</span>} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </section>

        <section className="panel">
          <h2>Топ IP-источников</h2>
          <div className="table-wrap">
            <table className="table table--compact">
              <thead><tr><th>IP</th><th>инцидентов</th><th>макс. риск</th></tr></thead>
              <tbody>
                {(stats?.top_ips || []).map((r) => (
                  <tr key={r.ip}>
                    <td className="td-mono">{r.ip}</td>
                    <td>{r.count}</td>
                    <td><RiskBadge risk={r.max_risk} /></td>
                  </tr>
                ))}
                {(!stats?.top_ips?.length) && <tr><td colSpan="3" className="muted">нет данных</td></tr>}
              </tbody>
            </table>
          </div>
        </section>
      </div>

      <section className="panel">
        <div className="panel__head">
          <h2>Инциденты</h2>
          <div className="filters">
            <select className="input" value={filters.risk} onChange={(e) => setFilter('risk', e.target.value)}>
              <option value="">риск: все</option>
              <option value="low">low</option><option value="medium">medium</option>
              <option value="high">high</option><option value="critical">critical</option>
            </select>
            <select className="input" value={filters.status} onChange={(e) => setFilter('status', e.target.value)}>
              <option value="">статус: все</option>
              <option value="new">новые</option><option value="investigating">в работе</option><option value="closed">закрытые</option>
            </select>
            <select className="input" value={filters.attack_type} onChange={(e) => setFilter('attack_type', e.target.value)}>
              <option value="">тип: все</option>
              {ATTACK_TYPES.filter(Boolean).map((t) => <option key={t} value={t}>{ATTACK_TYPE_LABELS[t]}</option>)}
            </select>
            <input className="input" placeholder="IP…" value={filters.ip} onChange={(e) => setFilter('ip', e.target.value)} />
          </div>
        </div>

        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr><th>время</th><th>IP</th><th>тип</th><th>payload</th><th>правило</th><th>риск</th><th>повторы</th><th>статус</th></tr>
            </thead>
            <tbody>
              {(data?.items || []).map((i) => (
                <tr key={i.id} onClick={() => openDetail(i.id)} className="row-click">
                  <td className="nowrap">{String(i.ts).replace('T', ' ').slice(5, 19)}</td>
                  <td className="td-mono">{i.source_ip}</td>
                  <td>{ATTACK_TYPE_LABELS[i.attack_type] || i.attack_type}</td>
                  <td className="td-mono td-trunc">{i.payload}</td>
                  <td className="td-mono small">{i.matched_rule}</td>
                  <td><RiskBadge risk={i.risk_level} />{i.escalated && <span className="esc-flag" title="риск повышен корреляцией">↗</span>}</td>
                  <td>{i.repeat_count > 1 ? `×${i.repeat_count}` : 1}</td>
                  <td onClick={(e) => e.stopPropagation()}>
                    <select className={`input input--inline st-select-${i.status}`} value={i.status}
                            onChange={(e) => changeStatus(i.id, e.target.value)}>
                      <option value="new">новый</option><option value="investigating">в работе</option><option value="closed">закрыт</option>
                    </select>
                  </td>
                </tr>
              ))}
              {(!data?.items?.length) && <tr><td colSpan="8" className="muted">Инцидентов нет — отправьте атаки в Playground</td></tr>}
            </tbody>
          </table>
        </div>

        <div className="pagination">
          <button className="btn" disabled={page <= 1} onClick={() => setPage(page - 1)}>← назад</button>
          <span className="muted">стр. {data?.page ?? 1} из {data?.pages ?? 1} · всего {data?.total ?? 0}</span>
          <button className="btn" disabled={(data?.pages ?? 1) <= page} onClick={() => setPage(page + 1)}>вперёд →</button>
        </div>
      </section>

      {detail && (
        <div className="modal-backdrop" onClick={() => setDetail(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal__head">
              <h2>Инцидент #{detail.incident.id}</h2>
              <button className="btn btn--ghost" onClick={() => setDetail(null)}>✕</button>
            </div>
            <div className="modal__grid">
              <div><span className="muted">Время:</span> {String(detail.incident.ts).replace('T', ' ').slice(0, 19)}</div>
              <div><span className="muted">IP:</span> <code>{detail.incident.source_ip}</code></div>
              <div><span className="muted">Тип:</span> {ATTACK_TYPE_LABELS[detail.incident.attack_type] || detail.incident.attack_type}</div>
              <div><span className="muted">Правило:</span> <code>{detail.incident.matched_rule}</code></div>
              <div><span className="muted">Риск:</span> <RiskBadge risk={detail.incident.risk_level} /> {detail.incident.escalated && <span className="muted small">(повышен корреляцией)</span>}</div>
              <div><span className="muted">Повторы:</span> {detail.incident.repeat_count}</div>
              <div><span className="muted">Статус:</span>
                <select className="input input--inline" value={detail.incident.status}
                        onChange={(e) => changeStatus(detail.incident.id, e.target.value)}>
                  <option value="new">новый</option><option value="investigating">в работе</option><option value="closed">закрыт</option>
                </select>
              </div>
            </div>
            <div className="sql-box">
              <div className="sql-box__label">Payload</div>
              <pre>{detail.incident.payload}</pre>
            </div>
            {detail.audit_log && (
              <>
                <div className="sql-box">
                  <div className="sql-box__label">Связанная запись аудита #{detail.audit_log.id} ({detail.audit_log.result_status})</div>
                  <pre>{`endpoint: ${detail.audit_log.endpoint}\ninput: ${detail.audit_log.raw_input}\nsql: ${detail.audit_log.generated_sql || '— (заблокировано до выполнения)'}`}</pre>
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
