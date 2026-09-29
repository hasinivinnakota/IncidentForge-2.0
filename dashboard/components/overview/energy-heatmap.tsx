"use client"

import type React from "react"

import { useState, useMemo } from "react"
import { createPortal } from "react-dom"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { useOverviewData } from "@/lib/store/hooks"
import { Calendar, TrendingUp } from "lucide-react"

interface HeatmapCell {
  day: string
  hour: number
  value: number
  intensity: number
}

interface TooltipData {
  day: string
  hour: number
  value: number
  x: number
  y: number
  show: boolean
}

export function EnergyHeatmap() {
  const data = useOverviewData()
  const [tooltip, setTooltip] = useState<TooltipData>({
    day: "",
    hour: 0,
    value: 0,
    x: 0,
    y: 0,
    show: false,
  })

  // Seeded random function for consistent values
  const seededRandom = (seed: number) => {
    const x = Math.sin(seed) * 10000
    return x - Math.floor(x)
  }

  // Memoize heatmap data to prevent regeneration on every render
  const heatmapData = useMemo((): HeatmapCell[] => {
    const days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    const heatmapData: HeatmapCell[] = []

    // Generate realistic energy consumption patterns with consistent values
    days.forEach((day, dayIndex) => {
      for (let hour = 0; hour < 24; hour++) {
        let baseConsumption = 200 // Base load

        // Weekend pattern (lower consumption)
        const isWeekend = dayIndex >= 5
        if (isWeekend) {
          baseConsumption *= 0.7
        }

        // Hour-based patterns
        if (hour >= 6 && hour <= 8) {
          // Morning peak
          baseConsumption *= isWeekend ? 1.2 : 1.8
        } else if (hour >= 9 && hour <= 17) {
          // Business hours
          baseConsumption *= isWeekend ? 0.8 : 1.5
        } else if (hour >= 18 && hour <= 21) {
          // Evening peak
          baseConsumption *= isWeekend ? 1.4 : 1.6
        } else if (hour >= 22 || hour <= 5) {
          // Night hours
          baseConsumption *= 0.6
        }

        // Add consistent randomness using seeded random
        const seed = dayIndex * 24 + hour + 12345 // Consistent seed
        const randomVariation = (seededRandom(seed) - 0.5) * 100
        const consumption = baseConsumption + randomVariation

        heatmapData.push({
          day,
          hour,
          value: Math.max(50, consumption),
          intensity: 0, // Will be calculated after all values are generated
        })
      }
    })

    // Calculate intensity (0-1) based on min/max values
    const values = heatmapData.map((cell) => cell.value)
    const minValue = Math.min(...values)
    const maxValue = Math.max(...values)
    const range = maxValue - minValue

    return heatmapData.map((cell) => ({
      ...cell,
      intensity: (cell.value - minValue) / range,
    }))
  }, []) // Empty dependency array - only generate once

  const days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
  const hours = Array.from({ length: 24 }, (_, i) => i)

  // Calculate insights (also memoized to prevent recalculation)
  const insights = useMemo(() => {
    const weekdayAvg =
      heatmapData.filter((cell) => !["Sat", "Sun"].includes(cell.day)).reduce((sum, cell) => sum + cell.value, 0) /
      (5 * 24)

    const weekendAvg =
      heatmapData.filter((cell) => ["Sat", "Sun"].includes(cell.day)).reduce((sum, cell) => sum + cell.value, 0) /
      (2 * 24)

    const peakHours = heatmapData.filter((cell) => cell.hour >= 9 && cell.hour <= 17)
    const peakAvg = peakHours.reduce((sum, cell) => sum + cell.value, 0) / peakHours.length

    return { weekdayAvg, weekendAvg, peakAvg }
  }, [heatmapData])

  if (!data) {
    return <div className="h-[400px] bg-[#1B1B1B] border border-[#2A2A2A] rounded-lg animate-pulse" />
  }

  const getIntensityColor = (intensity: number) => {
    const opacity = Math.max(0.1, intensity)
    return `rgba(255, 107, 0, ${opacity})`
  }

  const getCellValue = (day: string, hour: number) => {
    return heatmapData.find((cell) => cell.day === day && cell.hour === hour)
  }

  const handleCellHover = (event: React.MouseEvent, day: string, hour: number, value: number) => {
    const rect = event.currentTarget.getBoundingClientRect()
    const x = rect.left + rect.width / 2
    const y = rect.top - 10

    setTooltip({
      day,
      hour,
      value,
      x,
      y,
      show: true,
    })
  }

  const handleCellLeave = () => {
    setTooltip((prev) => ({ ...prev, show: false }))
  }

  // Portal tooltip component
  const TooltipPortal = () => {
    if (!tooltip.show || typeof window === "undefined") return null

    return createPortal(
      <div
        className="fixed bg-[#0E0E0E] border border-[#2A2A2A] rounded px-2 py-1 text-xs whitespace-nowrap text-[#EDEDED] pointer-events-none transition-opacity duration-200 shadow-lg"
        style={{
          left: tooltip.x,
          top: tooltip.y,
          transform: "translateX(-50%)",
          zIndex: 99999,
        }}
      >
        {tooltip.day} {tooltip.hour.toString().padStart(2, "0")}:00
        <br />
        {tooltip.value.toFixed(0)} kWh
        {/* Arrow pointing down */}
        <div
          className="absolute top-full left-1/2 transform -translate-x-1/2 w-0 h-0"
          style={{
            borderLeft: "4px solid transparent",
            borderRight: "4px solid transparent",
            borderTop: "4px solid #2A2A2A",
          }}
        />
      </div>,
      document.body,
    )
  }

  return (
    <>
      <Card className="bg-[#1B1B1B] border-[#2A2A2A] text-[#EDEDED]">
        <CardHeader>
          <div className="flex flex-col gap-4">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Calendar className="h-5 w-5 text-[#FF6B00]" />
                Energy Consumption Heatmap
              </CardTitle>
              <CardDescription className="text-[#9A9A9A] mt-1">
                Weekly consumption patterns by hour and day
              </CardDescription>
            </div>
            <div className="flex items-center gap-4 text-sm">
              <div className="bg-[#0E0E0E]/50 px-3 py-2 rounded-lg text-center">
                <div className="text-lg font-bold text-[#EDEDED]">{insights.weekdayAvg.toFixed(0)}</div>
                <div className="text-xs text-[#9A9A9A]">Weekday Avg</div>
              </div>
              <div className="bg-[#0E0E0E]/50 px-3 py-2 rounded-lg text-center">
                <div className="text-lg font-bold text-[#EDEDED]">{insights.peakAvg.toFixed(0)}</div>
                <div className="text-xs text-[#9A9A9A]">Peak Hours</div>
              </div>
            </div>
          </div>
        </CardHeader>
        <CardContent className="h-[280px] p-2">
          {/* Heatmap Grid */}
          <div className="h-full flex flex-col">
            <div className="flex-1 overflow-hidden">
              <div className="h-full flex flex-col">
                {/* Hour labels */}
                <div className="flex mb-1">
                  <div className="w-10"></div>
                  {hours.map((hour) => (
                    <div key={hour} className="flex-1 text-center text-[9px] text-[#9A9A9A] min-w-[12px]">
                      {hour % 4 === 0 ? `${hour.toString().padStart(2, "0")}` : ""}
                    </div>
                  ))}
                </div>

                {/* Heatmap rows */}
                <div className="flex-1 flex flex-col justify-between">
                  {days.map((day, dayIndex) => (
                    <div key={day} className="flex items-center">
                      <div className="w-10 text-[10px] text-[#9A9A9A] font-medium pr-2">{day}</div>
                      <div className="flex-1 flex">
                        {hours.map((hour) => {
                          const cell = getCellValue(day, hour)
                          return (
                            <div
                              key={`${day}-${hour}`}
                              className="flex-1 aspect-square min-w-[12px] mx-[1px] rounded-sm cursor-pointer transition-all hover:scale-110 hover:brightness-125"
                              style={{
                                backgroundColor: cell ? getIntensityColor(cell.intensity) : "#2A2A2A",
                              }}
                              onMouseEnter={(e) => cell && handleCellHover(e, day, hour, cell.value)}
                              onMouseLeave={handleCellLeave}
                            />
                          )
                        })}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Legend */}
            <div className="flex items-center justify-between mt-3 pt-3 border-t border-[#2A2A2A]">
              <div className="flex items-center gap-2 text-xs text-[#9A9A9A]">
                <span>Low</span>
                <div className="flex">
                  {[0.1, 0.3, 0.5, 0.7, 0.9].map((intensity) => (
                    <div
                      key={intensity}
                      className="w-3 h-3 mx-0.5 rounded-sm"
                      style={{ backgroundColor: getIntensityColor(intensity) }}
                    />
                  ))}
                </div>
                <span>High</span>
              </div>
            </div>
          </div>
        </CardContent>

        {/* Compact Insights */}
        <div className="px-6 pb-4">
          <div className="flex items-start gap-2 p-2 bg-[#0E0E0E]/30 rounded-lg">
            <TrendingUp className="h-3 w-3 text-[#FF6B00] mt-0.5 flex-shrink-0" />
            <div className="text-xs">
              <div className="font-medium text-[#EDEDED]">Usage Pattern</div>
              <div className="text-[#9A9A9A] mt-1">
                Weekend: {((insights.weekendAvg / insights.weekdayAvg - 1) * 100).toFixed(0)}%
                {insights.weekendAvg > insights.weekdayAvg ? " higher" : " lower"} • Peak hours: 9-17h
              </div>
            </div>
          </div>
        </div>
      </Card>

      {/* Portal-based tooltip */}
      <TooltipPortal />
    </>
  )
}
