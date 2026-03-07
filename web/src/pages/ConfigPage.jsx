import { useEffect, useMemo, useState } from 'react'
import { api } from '../lib/api.js'
import PageHeader from '../components/PageHeader.jsx'
import EditorPanel from '../components/EditorPanel.jsx'

export default function ConfigPage() {
  const [configRaw, setConfigRaw] = useState('')
  const [env, setEnv] = useState({})
  const [savingConfig, setSavingConfig] = useState(false)
  const [savingEnv, setSavingEnv] = useState(false)

  const load = async () => {
    const res = await api.get('/api/config')
    setConfigRaw(res.data.config_raw || '')
    setEnv(res.data.env || {})
  }

  useEffect(() => { load() }, [])

  const envEntries = useMemo(() => Object.entries(env), [env])

  const saveConfig = async () => {
    setSavingConfig(true)
    try {
      await api.put('/api/config', { content: configRaw })
      await load()
    } finally {
      setSavingConfig(false)
    }
  }

  const saveEnv = async () => {
    setSavingEnv(true)
    try {
      const values = {}
      for (const [key, meta] of Object.entries(env)) {
        values[key] = meta.value
      }
      await api.put('/api/env', { values })
      await load()
    } finally {
      setSavingEnv(false)
    }
  }

  const updateEnvValue = (key, value) => {
    setEnv((prev) => ({ ...prev, [key]: { ...prev[key], value } }))
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Config" subtitle="Edit core agent configuration and secret environment variables." actions={<button className="btn btn-primary" onClick={saveEnv} disabled={savingEnv}>{savingEnv ? 'SAVING ENV' : 'SAVE ENV'}</button>} />

      <div className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
        <EditorPanel title="config.yaml" subtitle="Core agent, database, LLM, RAG, anomaly, and GeoIP settings." value={configRaw} onChange={setConfigRaw} onSave={saveConfig} saving={savingConfig} rows={28} />

        <div className="panel p-4">
          <div className="mb-4 font-mono text-xs uppercase tracking-[0.18em] text-cyan">.env Secrets</div>
          <div className="space-y-4">
            {envEntries.length === 0 ? <div className="font-mono text-dim">No environment variables found.</div> : null}
            {envEntries.map(([key, meta]) => (
              <div key={key}>
                <div className="mb-1 font-mono text-[11px] uppercase tracking-[0.16em] text-dim">{key}</div>
                <input
                  className="input"
                  type={meta.is_secret ? 'password' : 'text'}
                  value={meta.value || ''}
                  onChange={(e) => updateEnvValue(key, e.target.value)}
                  placeholder={meta.is_secret ? '••••••••' : ''}
                />
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
