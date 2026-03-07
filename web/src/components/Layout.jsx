import { NavLink } from 'react-router-dom'
import { Activity, Bot, Clock3, Cpu, RefreshCw, Settings, Shield } from 'lucide-react'
import { api } from '../lib/api.js'
import { useState } from 'react'

const links = [
  { to: '/status', label: 'STATUS', icon: Activity },
  { to: '/chat', label: 'CHAT', icon: Bot },
  { to: '/skills', label: 'SKILLS', icon: Cpu },
  { to: '/config', label: 'CONFIG', icon: Settings },
  { to: '/crons', label: 'CRONS', icon: Clock3 },
]

export default function Layout({ children }) {
  const [busy, setBusy] = useState(false)

  const restart = async () => {
    setBusy(true)
    try {
      await api.post('/api/restart', { reason: 'web-ui' })
    } finally {
      setTimeout(() => setBusy(false), 1500)
    }
  }

  return (
    <div className="flex h-full bg-shell text-text">
      <aside className="flex w-64 flex-col border-r border-border bg-panel">
        <div className="border-b border-border p-5">
          <div className="flex items-center gap-3">
            <div className="rounded-xl border border-neon/40 bg-neon/10 p-2 text-neon">
              <Shield className="h-5 w-5" />
            </div>
            <div>
              <div className="font-mono text-sm font-bold tracking-[0.22em] text-neon">SECURITYCLAW</div>
              <div className="font-mono text-[11px] uppercase tracking-[0.22em] text-dim">service console</div>
            </div>
          </div>
        </div>

        <nav className="flex-1 space-y-1 p-3">
          {links.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-lg border px-3 py-3 font-mono text-xs tracking-[0.16em] transition ` +
                (isActive
                  ? 'border-cyan bg-cyan/10 text-cyan'
                  : 'border-transparent text-dim hover:border-border hover:bg-panel2 hover:text-text')
              }
            >
              <Icon className="h-4 w-4" />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="border-t border-border p-4">
          <button className="btn btn-danger w-full" onClick={restart} disabled={busy}>
            <RefreshCw className={`h-4 w-4 ${busy ? 'animate-spin' : ''}`} />
            {busy ? 'RESTARTING' : 'RESTART'}
          </button>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 items-center justify-between border-b border-border bg-panel px-6">
          <div className="font-mono text-xs uppercase tracking-[0.22em] text-dim">Autonomous SOC Operations Interface</div>
          <div className="badge badge-green">online</div>
        </header>
        <div className="min-h-0 flex-1 overflow-auto p-6">{children}</div>
      </div>
    </div>
  )
}
