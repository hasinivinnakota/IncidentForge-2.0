"use client"

import { MainMeterKpis } from "@/components/main-meter-kpis"
import { HourlyPowerBreakdown } from "@/components/hourly-power-breakdown"
import { PowerDistributionPie } from "@/components/power-distribution-pie"
import { PowerSpikesChart } from "@/components/power-spikes-chart"
import { MeterAlerts } from "@/components/meter-alerts"
import { MeterReadingsHistoryTable } from "@/components/meter-readings-history-table"
import { MeterLoadingState } from "@/components/meter-loading-state"
import { useSelectedMeter, useMetersLoading } from "@/lib/store/hooks"

export function MeterInsights() {
  const selectedMeter = useSelectedMeter()
  const loading = useMetersLoading()

  if (loading && !selectedMeter) {
    return <MeterLoadingState />
  }

  if (!selectedMeter) {
    return (
      <div className="flex items-center justify-center h-96 text-[#9A9A9A] bg-[#1B1B1B] border border-[#2A2A2A] rounded-lg">
        Select a meter to view its detailed insights.
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <MainMeterKpis />
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2">
          <HourlyPowerBreakdown />
        </div>
        <div className="lg:col-span-1">
          <PowerDistributionPie />
        </div>
        <div className="lg:col-span-2">
          <PowerSpikesChart />
        </div>
        <div className="lg:col-span-1">
          <MeterAlerts />
        </div>
        <div className="lg:col-span-3">
          <MeterReadingsHistoryTable />
        </div>
      </div>
    </div>
  )
}
