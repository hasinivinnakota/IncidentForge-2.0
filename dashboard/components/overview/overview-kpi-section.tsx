"use client"

import { UnifiedKpiCard } from "@/components/unified-kpi-card"
import { Zap, TrendingUp, DollarSign, Leaf } from "lucide-react"
import { useOverviewData } from "@/lib/store/hooks"

export function OverviewKpiSection() {
  const data = useOverviewData()

  if (!data) {
    return (
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="h-36 bg-[#1B1B1B] border border-[#2A2A2A] rounded-lg animate-pulse" />
        ))}
      </div>
    )
  }

  const { kpis } = data

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      <UnifiedKpiCard
        title="Total Consumption (Today)"
        value={kpis.totalConsumption.value.toLocaleString()}
        unit="kWh"
        icon={<Zap />}
        emphasis="primary"
        trend={{
          direction: kpis.totalConsumption.trend >= 0 ? "up" : "down",
          percentage: `${Math.abs(kpis.totalConsumption.trend).toFixed(1)}%`,
          period: "vs yesterday",
        }}
      />
      <UnifiedKpiCard
        title="Peak Demand (Today)"
        value={kpis.peakDemand.value.toLocaleString()}
        unit="kW"
        icon={<TrendingUp />}
        emphasis="secondary"
        trend={{
          direction: kpis.peakDemand.trend >= 0 ? "up" : "down",
          percentage: `${Math.abs(kpis.peakDemand.trend).toFixed(1)}%`,
          period: "vs yesterday",
        }}
      />
      <UnifiedKpiCard
        title="Energy Cost (Today)"
        value={`$${kpis.energyCost.value.toLocaleString(undefined, {
          minimumFractionDigits: 2,
          maximumFractionDigits: 2,
        })}`}
        icon={<DollarSign />}
        emphasis="secondary"
        trend={{
          direction: kpis.energyCost.trend >= 0 ? "up" : "down",
          percentage: `${Math.abs(kpis.energyCost.trend).toFixed(1)}%`,
          period: "vs yesterday",
        }}
      />
      <UnifiedKpiCard
        title="CO₂ Emissions (Today)"
        value={kpis.co2Emissions.value.toLocaleString()}
        unit="kg"
        icon={<Leaf />}
        emphasis="tertiary"
        trend={{
          direction: kpis.co2Emissions.trend >= 0 ? "up" : "down",
          percentage: `${Math.abs(kpis.co2Emissions.trend).toFixed(1)}%`,
          period: "vs yesterday",
        }}
      />
    </div>
  )
}
