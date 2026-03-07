export default function PageHeader({ title, subtitle, actions }) {
  return (
    <div className="mb-6 flex items-start justify-between gap-4">
      <div>
        <h1 className="font-mono text-2xl font-bold uppercase tracking-[0.22em] text-neon">{title}</h1>
        {subtitle ? <p className="mt-1 font-mono text-sm text-dim">{subtitle}</p> : null}
      </div>
      {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
    </div>
  )
}
