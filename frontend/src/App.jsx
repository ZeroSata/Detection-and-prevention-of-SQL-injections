import { NavLink, Route, Routes } from 'react-router-dom'
import Playground from './pages/Playground.jsx'
import Dashboard from './pages/Dashboard.jsx'
import AuditLogs from './pages/AuditLogs.jsx'

export default function App() {
  return (
    <div className="app">
      <header className="topbar">
        <div className="topbar__brand">
          <span className="topbar__logo">🛡</span>
          <div>
            <div className="topbar__title">DB Security Lab</div>
            <div className="topbar__subtitle">аудит · WAF · SQLi — учебный стенд</div>
          </div>
        </div>
        <nav className="topbar__nav">
          <NavLink to="/" end>SQLi Playground</NavLink>
          <NavLink to="/dashboard">Security Dashboard</NavLink>
          <NavLink to="/audit-logs">Журнал аудита</NavLink>
        </nav>
        <div className="topbar__warn">⚠️ Демо-стенд: намеренно уязвимый код. Не размещать в публичной сети.</div>
      </header>

      <main className="content">
        <Routes>
          <Route path="/" element={<Playground />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/audit-logs" element={<AuditLogs />} />
        </Routes>
      </main>

      <footer className="footer">
        DB Security Lab — демонстрация уязвимой конкатенации строк vs параметризованных запросов,
        WAF-сигнатур, корреляции инцидентов и журналирования PostgreSQL.
      </footer>
    </div>
  )
}
