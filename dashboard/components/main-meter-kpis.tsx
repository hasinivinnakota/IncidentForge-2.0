"use client"

import { Card, CardContent } from "@/components/ui/card"
import { useSelectedMeter } from "@/lib/store/hooks"

const Kpi = ({
  title,
  value,
  unit,
  colorClass,
}: { title: string; value: string; unit: string; colorClass: string }) => (
  <Card className="bg-[#1F1F1F] border-[#2A2A2A] text-center p-4">
    <CardContent className="p-0">
      <div className="text-xs text-[#9A9A9A] uppercase font-semibold">{title}</div>
      <div className="flex items-baseline justify-center gap-2 mt-1">
        <span className={`text-3xl font-bold ${colorClass}`}>{value}</span>
        <span className="text-lg text-[#9A9A9A]">{unit}</span>
      </div>
    </CardContent>
  </Card>
)

export function MainMeterKpis() {
  const selectedMeter = useSelectedMeter()

  if (!selectedMeter) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {Array.from({ length: 3 }).map((_, i) => (
          <div key={i} className="h-24 bg-[#1F1F1F] border-[#2A2A2A] rounded-lg animate-pulse" />
        ))}
      </div>
    )
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      <Kpi title="Current Power" value={selectedMeter.kpiData.activePower} unit="kW" colorClass="text-red-400" />
      <Kpi title="Energy Today" value={selectedMeter.kpiData.energyToday} unit="kWh" colorClass="text-orange-400" />
      <Kpi title="Cost Today" value={selectedMeter.kpiData.costToday} unit="" colorClass="text-green-400" />
    </div>
  )
}
