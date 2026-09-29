"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Badge } from "@/components/ui/badge"
import { TrendingUp, Clock, Zap } from "lucide-react"
import { useMeters } from "@/lib/store/hooks"
import type { ReportTimeRange } from "@/app/reports/page"

interface PeakUsageTableProps {
  timeRange: ReportTimeRange
}

interface PeakReading {
  id: string
  meterName: string
  meterId: string
  timestamp: string
  peakValue: number
  unit: string
  duration: string
  severity: "high" | "medium" | "low"
}

export function PeakUsageTable({ timeRange }: PeakUsageTableProps) {
  const meters = useMeters()

  // Generate mock peak usage data based on time range
  const generatePeakReadings = (): PeakReading[] => {
    const readings: PeakReading[] = []
    const now = new Date()

    const getTimeRangeHours = (range: ReportTimeRange) => {
      switch (range) {
        case "24h":
          return 24
        case "7d":
          return 168
        case "30d":
          return 720
        case "90d":
          return 2160
        case "1y":
          return 8760
        default:
          return 168
      }
    }

    const hours = getTimeRangeHours(timeRange)
    const readingsPerMeter = Math.min(10, Math.max(3, Math.floor(hours / 24)))

    meters.forEach((meter) => {
      for (let i = 0; i < readingsPerMeter; i++) {
        const hoursAgo = Math.floor(Math.random() * hours)
        const timestamp = new Date(now.getTime() - hoursAgo * 60 * 60 * 1000)

        // Generate realistic peak values based on meter type
        const basePeak = Number.parseFloat(meter.kpiData.activePower)
        const peakMultiplier = 1.2 + Math.random() * 0.8 // 1.2x to 2.0x of normal
        const peakValue = basePeak * peakMultiplier

        const severity: "high" | "medium" | "low" =
          peakValue > basePeak * 1.8 ? "high" : peakValue > basePeak * 1.5 ? "medium" : "low"

        readings.push({
          id: `${meter.id}-${i}`,
          meterName: meter.name,
          meterId: meter.id,
          timestamp: timestamp.toISOString(),
          peakValue: peakValue,
          unit: "kW",
          duration: `${Math.floor(Math.random() * 120 + 15)}min`,
          severity,
        })
      }
    })

    // Sort by timestamp (most recent first)
    return readings.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
  }

  const peakReadings = generatePeakReadings()

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "high":
        return "bg-red-600/20 text-red-400 border-red-600/30"
      case "medium":
        return "bg-orange-600/20 text-orange-400 border-orange-600/30"
      case "low":
        return "bg-green-600/20 text-green-400 border-green-600/30"
      default:
        return "bg-gray-600/20 text-gray-400 border-gray-600/30"
    }
  }

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp)
    return {
      date: date.toLocaleDateString(),
      time: date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    }
  }

  // Calculate summary stats
  const avgPeak = peakReadings.reduce((sum, reading) => sum + reading.peakValue, 0) / peakReadings.length
  const maxPeak = Math.max(...peakReadings.map((r) => r.peakValue))
  const highSeverityCount = peakReadings.filter((r) => r.severity === "high").length

  return (
    <Card className="bg-[#1B1B1B] border-[#2A2A2A] text-[#EDEDED]">
      <CardHeader>
        <div className="flex flex-col gap-4">
          <CardTitle className="flex items-center gap-2">
            <TrendingUp className="h-5 w-5 text-[#FF6B00]" />
            Peak Usage Readings
          </CardTitle>

          {/* Summary Stats */}
          <div className="grid grid-cols-3 gap-4">
            <div className="bg-[#0E0E0E]/50 p-3 rounded-lg text-center">
              <div className="text-lg font-bold text-[#FF6B00]">{maxPeak.toFixed(1)}</div>
              <div className="text-xs text-[#9A9A9A]">Max Peak (kW)</div>
            </div>
            <div className="bg-[#0E0E0E]/50 p-3 rounded-lg text-center">
              <div className="text-lg font-bold text-[#EDEDED]">{avgPeak.toFixed(1)}</div>
              <div className="text-xs text-[#9A9A9A]">Avg Peak (kW)</div>
            </div>
            <div className="bg-[#0E0E0E]/50 p-3 rounded-lg text-center">
              <div className="text-lg font-bold text-red-400">{highSeverityCount}</div>
              <div className="text-xs text-[#9A9A9A]">High Severity</div>
            </div>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="border-b-[#2A2A2A] hover:bg-transparent">
                <TableHead className="text-[#9A9A9A]">Meter</TableHead>
                <TableHead className="text-[#9A9A9A]">Peak Value</TableHead>
                <TableHead className="text-[#9A9A9A]">Duration</TableHead>
                <TableHead className="text-[#9A9A9A]">Timestamp</TableHead>
                <TableHead className="text-[#9A9A9A]">Severity</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {peakReadings.slice(0, 15).map((reading) => {
                const { date, time } = formatTimestamp(reading.timestamp)
                return (
                  <TableRow key={reading.id} className="border-b-[#2A2A2A] hover:bg-[#1F1F1F]">
                    <TableCell>
                      <div>
                        <div className="font-medium text-[#EDEDED]">{reading.meterName}</div>
                        <div className="text-xs text-[#9A9A9A]">{reading.meterId}</div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <Zap className="h-3 w-3 text-[#FF6B00]" />
                        <span className="font-mono font-semibold">
                          {reading.peakValue.toFixed(1)} {reading.unit}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <Clock className="h-3 w-3 text-[#9A9A9A]" />
                        <span className="text-sm">{reading.duration}</span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="text-sm">
                        <div className="font-medium">{date}</div>
                        <div className="text-[#9A9A9A]">{time}</div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge className={getSeverityColor(reading.severity)}>{reading.severity.toUpperCase()}</Badge>
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        </div>

        {peakReadings.length > 15 && (
          <div className="mt-4 text-center text-sm text-[#9A9A9A]">
            Showing 15 of {peakReadings.length} peak readings
          </div>
        )}
      </CardContent>
    </Card>
  )
}
