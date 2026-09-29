export function MeterLoadingState() {
  return (
    <div className="space-y-6">
      {/* KPI Cards Loading */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3">
        {Array.from({ length: 8 }).map((_, i) => (
          <div key={i} className="h-24 bg-[#1B1B1B] border-[#2A2A2A] rounded-lg animate-pulse border" />
        ))}
      </div>

      {/* Charts Loading */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="h-80 bg-[#1B1B1B] border-[#2A2A2A] rounded-lg animate-pulse border" />
        ))}
      </div>

      {/* Comparison and Alerts Loading */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {Array.from({ length: 2 }).map((_, i) => (
          <div key={i} className="h-96 bg-[#1B1B1B] border-[#2A2A2A] rounded-lg animate-pulse border" />
        ))}
      </div>
    </div>
  )
}
