export default function NotFound() {
  return (
    <main className="flex min-h-screen items-center justify-center bg-[#0b0e10] px-6 text-slate-100">
      <div className="text-center">
        <p className="font-mono text-xs tracking-[0.2em] text-cyan-300">INCIDENTFORGE / 404</p>
        <h1 className="mt-3 text-2xl font-semibold text-white">Route not found</h1>
        <p className="mt-2 text-sm text-slate-500">The requested security workspace does not exist.</p>
      </div>
    </main>
  )
}
