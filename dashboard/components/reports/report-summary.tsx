"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Calendar, Activity, TrendingUp, DollarSign } from "lucide-react"
import { useMeters, useOverviewData } from "@/lib/store/hooks"
import type { ReportFilters } from "@/app/reports/page"

interface ReportSummaryProps {
  filters: ReportFilters
}

export function ReportSummary({ filters }: ReportSummaryProps) {
  const meters = useMeters()
  const overviewData = useOverviewData()

  const selectedMeters = meters.filter((meter) => filters.meterIds.includes(meter.id))

  const getTimeRangeLabel = (timeRange: string) => {
    switch (timeRange) {
      case "24h":
        return "Last 24 Hours"
      case "7d":
        return "Last 7 Days"
      case "30d":
        return "Last 30 Days"
      case "90d":
        return "Last 90 Days"
      case "1y":
        return "Last Year"
      default:
        return timeRange
    }
  }

  const getReportTypeLabel = (reportType: string) => {
    switch (reportType) {
      case "consumption":
        return "Energy Consumption"
      case "peak-analysis":
        return "Peak Analysis"
      case "efficiency":
        return "Efficiency Report"
      case "cost-analysis":
        return "Cost Analysis"
      default:
        return reportType
    }
  }

  // Calculate summary metrics based on selected meters
  const totalConsumption = selectedMeters.reduce((sum, meter) => {
    return sum + Number.parseFloat(meter.kpiData.energyToday)
  }, 0)

  const totalCost = selectedMeters.reduce((sum, meter) => {
    const cost = Number.parseFloat(meter.kpiData.costToday.replace("$", ""))
    return sum + cost
  }, 0)

  const avgEfficiency = selectedMeters.reduce((sum, meter) => sum + meter.efficiency, 0) / selectedMeters.length

  return (
    <Card className="bg-[#1B1B1B] border-[#2A2A2A] text-[#EDEDED]">
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <span>Report Summary</span>
          <Badge variant="outline" className="bg-[#FF6B00]/10 text-[#FF6B00] border-[#FF6B00]/30">
            Generated {new Date().toLocaleString()}
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {/* Report Details */}
          <div className="space-y-3">
            <div className="flex items-center gap-2 text-sm">
              <Calendar className="h-4 w-4 text-[#FF6B00]" />
              <span className="text-[#9A9A9A]">Time Range:</span>
            </div>
            <div className="font-semibold">{getTimeRangeLabel(filters.timeRange)}</div>

            <div className="flex items-center gap-2 text-sm">
              <Activity className="h-4 w-4 text-[#FF6B00]" />
              <span className="text-[#9A9A9A]">Report Type:</span>
            </div>
            <div className="font-semibold">{getReportTypeLabel(filters.reportType)}</div>
          </div>

          {/* Meters Included */}
          <div className="space-y-3">
            <div className="text-sm text-[#9A9A9A]">Meters Included:</div>
            <div className="font-semibold text-lg">{selectedMeters.length}</div>
            <div className="text-xs text-[#9A9A9A]">
              {selectedMeters
                .slice(0, 2)
                .map((meter) => meter.name)
                .join(", ")}
              {selectedMeters.length > 2 && ` +${selectedMeters.length - 2} more`}
            </div>
          </div>

          {/* Total Consumption */}
          <div className="space-y-3">
            <div className="flex items-center gap-2 text-sm">
              <TrendingUp className="h-4 w-4 text-[#FF6B00]" />
              <span className="text-[#9A9A9A]">Total Consumption:</span>
            </div>
            <div className="font-semibold text-lg">{totalConsumption.toLocaleString()} kWh</div>
            <div className="text-xs text-[#9A9A9A]">Avg Efficiency: {avgEfficiency.toFixed(1)}%</div>
          </div>

          {/* Total Cost */}
          <div className="space-y-3">
            <div className="flex items-center gap-2 text-sm">
              <DollarSign className="h-4 w-4 text-[#FF6B00]" />
              <span className="text-[#9A9A9A]">Total Cost:</span>
            </div>
            <div className="font-semibold text-lg">${totalCost.toFixed(2)}</div>
            <div className="text-xs text-[#9A9A9A]">
              Avg: ${(totalCost / selectedMeters.length).toFixed(2)} per meter
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
