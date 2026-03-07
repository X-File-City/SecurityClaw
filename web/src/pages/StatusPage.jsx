import { useEffect, useState } from 'react'
import { Activity, Brain, Clock3, ShieldCheck } from 'lucide-react'
import { api } from '../lib/api.js'
import PageHeader from '../components/PageHeader.jsx'

function Stat({ icon: Icon, label, value, tone = 'cyan' }) {
  const colorMap = {
    cyan: 'text-cyan border-cyan/20 bg-cyan/10',
    green: 'text-neon border-neon/20 bg-neon/10',
    amber: 'text-amber border-amber/20 bg-amber/10',
  }
  return (
    <div className="panel p-4">
      <div className="flex items-center gap-3">
        <div className={`rounded-lg border p-2 ${colorMap[tone]}`}>
          <Icon className="h-5 w-5" />
        </div>
        <div>
          <div className="font-mono text-[11px] uppercase tracking-[0.18em] text-dim">{label}</div>
          <div className="font-mono text-lg font-semibold text-text">{value}</div>
        </div>
      </div>
    </div>
  )
}

export default function StatusPage() {
  const [data, setData] = useState(null)

  useEffect(() => {
    api.get('/api/status').then((res) => setData(res.data))
  }, [])

  return (
    <div>
      <PageHeader title="Status" subtitle="Live service health and runtime inventory." />
      {!data ? <div className="font-mono text-dim">Loading status…</div> : (
        <div className="space-y-6">
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            <Stat icon={ShieldCheck} label="agent" value={data.agent_name} tone="green" />
            <Stat icon={Activity} label="scheduler" value={data.scheduler_running ? 'running' : 'stopped'} />
            <Stat icon={Brain} label="skills loaded" value={data.skill_count} />
            <Stat icon={Clock3} label="generated" value={new Date(data.generated_at).toLocaleTimeString()} tone="amber" />
          </div>

          <div className="panel p-5">
            <div className="mb-4 font-mono text-xs uppercase tracking-[0.18em] text-cyan">Runtime Inventory</div>
            <div className="space-y-3">
              <div>
                <div className="mb-2 font-mono text-[11px] uppercase tracking-[0.16em] text-dim">Skills</div>
                <div className="flex flex-wrap gap-2">
                  {data.skills_loaded.map((skill) => <span key={skill} className="badge badge-dim">{skill}</span>)}
                </div>
              </div>
              <div>
                <div className="mb-2 font-mono text-[11px] uppercase tracking-[0.16em] text-dim">Missing Skill Variables</div>
                {Object.keys(data.missing_skill_vars || {}).length === 0 ? (
                  <div className="badge badge-green">none</div>
                ) : (
                  <div className="space-y-2">
                    {Object.entries(data.missing_skill_vars).map(([skill, vars]) => (
                      <div key={skill} className="rounded-lg border border-amber/20 bg-amber/10 p-3">
                        <div className="font-mono text-xs text-amber">{skill}</div>
                        <div className="mt-1 text-sm text-text">{vars.join(', ')}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
