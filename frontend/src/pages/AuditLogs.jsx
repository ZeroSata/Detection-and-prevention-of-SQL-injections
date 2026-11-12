import { useCallback, useEffect, useMemo, useState } from 'react'
import { get } from '../api.js'
import { LogStatusBadge, ModeChip } from '../components/Badges.jsx'

export default function AuditLogs() {
  const [data, setData] = useState(null)
  const [filters, setFilters] = useState({ mode: '', status: '', endpoint: '', ip: '' })
  const [page, setPage] = useState(1)
  const [expanded, setExpanded] = useState(null)
  const [error, setError] = useState('')

  const qs = useMemo(() => {
    const p = new URLSearchParams()
    Object.entries(filters).forEach(([k, v]) => v && p.set(k, v))
    p.set('page', String(page))
    p.set('page_size', '15')
    return p.toString()
  }, [filters, page])

  const load = useCallback(async () => {
    try {
      setData(await get(`/api/dashboard/audit-logs?${qs}`))
      setError('')
    } catch {
      setError('Не удалось загрузить журнал. Бэкенд запущен?')
    }
  }, [qs])

  useEffect(() => {
    load()
    const t = setInterval(load, 5000)
    return () => clearInterval(t)
  }, [load])

  function setFilter(key, value) {
    setFilters((f) => ({ ...f, [key]: value }))
    setPage(1)
  }

  return (
    <div className="audit-logs">
      <div className="dashboard__head">
        <h1>Журнал аудита</h1>
        <div className="muted small">Каждый /api-запрос: ввод, сгенерированный SQL, статус и время ответа. Обновление 5 c.</div>
      </div>

      {error && <div className="error-box">{error}</div>}

      <section className="panel">
        <div className="panel__head">
          <h2>audit_logs <span className="muted small">({data?.total ?? '…'} записей)</span></h2>
          <div className="filters">
            <select className="input" value={filters.mode} onChange={(e) => setFilter('mode', e.target.value)}>
              <option value="">режим: все</option>
              <option value="insecure">insecure</option><option value="secure">secure</option>
              <option value="dashboard">dashboard</option><option value="other">other</option>
            </select>
            <select className="input" value={filters.status} onChange={(e) => setFilter('status', e.target.value)}>
              <option value="">статус: все</option>
              <option value="ok">ok</option><option value="error">ошибка</option><option value="blocked">заблокирован</option>
            </select>
            <input className="input" placeholder="эндпоинт…" value={filters.endpoint} onChange={(e) => setFilter('endpoint', e.target.value)} />
            <input className="input" placeholder="IP…" value={filters.ip} onChange={(e) => setFilter('ip', e.target.value)} />
          </div>
        </div>

        <div className="table-wrap">
          <table className="table table--compact">
            <thead>
              <tr><th></th><th>время</th><th>IP</th><th>эндпоинт</th><th>режим</th><th>WAF</th><th>результат</th><th>код</th><th>мс</th></tr>
            </thead>
            <tbody>
              {(data?.items || []).map((a) => (
                <>
                  <tr key={a.id} className="row-click" onClick={() => setExpanded(expanded === a.id ? null : a.id)}>
                    <td className="nowrap">{expanded === a.id ? '▾' : '▸'}</td>
                    <td className="nowrap">{String(a.ts).replace('T', ' ').slice(5, 19)}</td>
                    <td className="td-mono">{a.source_ip}</td>
                    <td className="td-mono">{a.endpoint}</td>
                    <td><ModeChip mode={a.mode} /></td>
                    <td>{a.waf_enabled ? 'ON' : 'OFF'}</td>
                    <td><LogStatusBadge status={a.result_status} /></td>
                    <td>{a.status_code}</td>
                    <td>{a.response_time_ms}</td>
                  </tr>
                  {expanded === a.id && (
                    <tr key={`${a.id}-x`} className="row-expanded">
                      <td colSpan="9">
                        <div className="expanded-grid">
                          <div><b>Ввод:</b><pre>{a.raw_input || '—'}</pre></div>
                          <div><b>Сгенерированный SQL:</b><pre>{a.generated_sql || '— (заблокировано до выполнения)'}</pre></div>
                          {a.error_detail && <div><b>Ошибка:</b><pre>{a.error_detail}</pre></div>}
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              ))}
              {(!data?.items?.length) && <tr><td colSpan="9" className="muted">Записей нет</td></tr>}
            </tbody>
          </table>
        </div>

        <div className="pagination">
          <button className="btn" disabled={page <= 1} onClick={() => setPage(page - 1)}>← назад</button>
          <span className="muted">стр. {data?.page ?? 1} из {data?.pages ?? 1} · всего {data?.total ?? 0}</span>
          <button className="btn" disabled={(data?.pages ?? 1) <= page} onClick={() => setPage(page + 1)}>вперёд →</button>
        </div>
      </section>
    </div>
  )
}
