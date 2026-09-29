"use client"

import { useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Bar, BarChart, CartesianGrid, XAxis, YAxis, ResponsiveContainer, Tooltip } from "recharts"
import { BarChart3, Download, TrendingUp } from "lucide-react"
import { useOverviewData } from "@/lib/store/hooks"
import type { ReportTimeRange, ReportType } from "@/app/reports/page"

interface EnergyConsumptionChartProps {
  timeRange: ReportTimeRange
  reportType: ReportType
}

type ChartView = "consumption" | "cost" | "efficiency"

export function EnergyConsumptionChart({ timeRange, reportType }: EnergyConsumptionChartProps) {
  const overviewData = useOverviewData()
  const [chartView, setChartView] = useState<ChartView>("consumption")

  // Generate chart data based on time range
  const generateChartData = () => {
    if (!overviewData) return []

    const baseData = (() => {
      switch (timeRange) {
        case "24h":
          return overviewData.peakUsage.map((item) => ({
            period: `${item.hour}:00`,
            consumption: item.consumption,
            cost: item.consumption * 0.12, // $0.12 per kWh
            efficiency: 85 + Math.random() * 15, // 85-100%
          }))
        case "7d":
          return overviewData.energyTrend["7d"].map((item) => ({
            period: item.date,
            consumption: item.consumption,
            cost: item.consumption * 0.12,
            efficiency: 85 + Math.random() * 15,
          }))
        case "30d":
          return overviewData.energyTrend["30d"].map((item) => ({
            period: item.date,
            consumption: item.consumption,
            cost: item.consumption * 0.12,
            efficiency: 85 + Math.random() * 15,
          }))
        case "90d":
          // Generate 90 days of data
          return Array.from({ length: 90 }, (_, i) => {
            const date = new Date()
            date.setDate(date.getDate() - (89 - i))
            const consumption = 10000 + Math.random() * 5000
            return {
              period: date.toLocaleDateString("en-US", { month: "short", day: "numeric" }),
              consumption,
              cost: consumption * 0.12,
              efficiency: 85 + Math.random() * 15,
            }
          })
        case "1y":
          // Generate 12 months of data
          return Array.from({ length: 12 }, (_, i) => {
            const date = new Date()
            date.setMonth(date.getMonth() - (11 - i))
            const consumption = 300000 + Math.random() * 100000
            return {
              period: date.toLocaleDateString("en-US", { month: "short", year: "2-digit" }),
              consumption,
              cost: consumption * 0.12,
              efficiency: 85 + Math.random() * 15,
            }
          })
        default:
          return overviewData.energyTrend["7d"].map((item) => ({
            period: item.date,
            consumption: item.consumption,
            cost: item.consumption * 0.12,
            efficiency: 85 + Math.random() * 15,
          }))
      }
    })()

    return baseData
  }

  const chartData = generateChartData()

  const getChartConfig = () => {
    switch (chartView) {
      case "consumption":
        return {
          dataKey: "consumption",
          label: "Energy Consumption",
          unit: "kWh",
          color: "hsl(var(--chart-1))",
        }
      case "cost":
        return {
          dataKey: "cost",
          label: "Energy Cost",
          unit: "$",
          color: "hsl(var(--chart-2))",
        }
      case "efficiency":
        return {
          dataKey: "efficiency",
          label: "Efficiency",
          unit: "%",
          color: "hsl(var(--chart-3))",
        }
      default:
        return {
          dataKey: "consumption",
          label: "Energy Consumption",
          unit: "kWh",
          color: "hsl(var(--chart-1))",
        }
    }
  }

  const config = getChartConfig()

  // Calculate summary metrics
  const totalValue = chartData.reduce((sum, item) => sum + item[config.dataKey], 0)
  const avgValue = totalValue / chartData.length
  const maxValue = Math.max(...chartData.map((item) => item[config.dataKey]))

  const getTimeRangeLabel = () => {
    switch (timeRange) {
      case "24h":
        return "24 Hours"
      case "7d":
        return "7 Days"
      case "30d":
        return "30 Days"
      case "90d":
        return "90 Days"
      case "1y":
        return "12 Months"
      default:
        return timeRange
    }
  }

  return (
    <Card className="bg-[#1B1B1B] border-[#2A2A2A] text-[#EDEDED]">
      <CardHeader>
        <div className="flex flex-col gap-4">
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <BarChart3 className="h-5 w-5 text-[#FF6B00]" />
              Energy Consumption Chart
            </CardTitle>
            <Button variant="outline" size="sm" className="bg-transparent border-[#2A2A2A] hover:bg-[#2A2A2A]">
              <Download className="mr-2 h-4 w-4" />
              Export
            </Button>
          </div>

          {/* Chart View Toggle */}
          <div className="flex items-center gap-2 bg-[#0E0E0E] p-1 rounded-lg w-fit">
            {(["consumption", "cost", "efficiency"] as ChartView[]).map((view) => (
              <Button
                key={view}
                size="sm"
                variant={chartView === view ? "default" : "ghost"}
                onClick={() => setChartView(view)}
                className={`
                  ${chartView === view ? "bg-[#FF6B00] hover:bg-[#E55A00] text-black" : "hover:bg-[#2A2A2A]"}
                  px-3 py-1 h-7 text-xs capitalize
                `}
              >
                {view}
              </Button>
            ))}
          </div>

          {/* Summary Stats */}
          <div className="grid grid-cols-3 gap-4">
            <div className="bg-[#0E0E0E]/50 p-3 rounded-lg text-center">
              <div className="text-lg font-bold text-[#FF6B00]">
                {config.unit === "$" ? `$${totalValue.toFixed(2)}` : `${totalValue.toLocaleString()} ${config.unit}`}
              </div>
              <div className="text-xs text-[#9A9A9A]">Total ({getTimeRangeLabel()})</div>
            </div>
            <div className="bg-[#0E0E0E]/50 p-3 rounded-lg text-center">
              <div className="text-lg font-bold text-[#EDEDED]">
                {config.unit === "$" ? `$${avgValue.toFixed(2)}` : `${avgValue.toFixed(0)} ${config.unit}`}
              </div>
              <div className="text-xs text-[#9A9A9A]">Average</div>
            </div>
            <div className="bg-[#0E0E0E]/50 p-3 rounded-lg text-center">
              <div className="text-lg font-bold text-green-400">
                {config.unit === "$" ? `$${maxValue.toFixed(2)}` : `${maxValue.toFixed(0)} ${config.unit}`}
              </div>
              <div className="text-xs text-[#9A9A9A]">Peak</div>
            </div>
          </div>
        </div>
      </CardHeader>
      <CardContent className="h-[300px] p-2">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={chartData} margin={{ top: 10, right: 20, left: -10, bottom: 0 }}>
            <CartesianGrid vertical={false} strokeDasharray="3 3" stroke="#2A2A2A" />
            <XAxis
              dataKey="period"
              tick={{ fill: "#9A9A9A", fontSize: 10 }}
              tickLine={false}
              axisLine={false}
              interval={chartData.length > 20 ? Math.floor(chartData.length / 10) : 0}
            />
            <YAxis tick={{ fill: "#9A9A9A", fontSize: 10 }} tickLine={false} axisLine={false} unit={config.unit} />
            <Tooltip
              cursor={{ fill: "hsl(var(--accent))", opacity: 0.1 }}
              contentStyle={{
                backgroundColor: "#0E0E0E",
                border: "1px solid #2A2A2A",
                borderRadius: "0.5rem",
              }}
              itemStyle={{ color: config.color }}
              labelStyle={{ color: "#9A9A9A" }}
              formatter={(value) => [
                config.unit === "$"
                  ? `$${(value as number).toFixed(2)}`
                  : `${(value as number).toLocaleString()} ${config.unit}`,
                config.label,
              ]}
            />
            <Bar dataKey={config.dataKey} fill={config.color} radius={[4, 4, 0, 0]} strokeWidth={0} />
          </BarChart>
        </ResponsiveContainer>
      </CardContent>

      {/* Trend Insight */}
      <div className="px-6 pb-4">
        <div className="flex items-start gap-2 p-2 bg-[#0E0E0E]/30 rounded-lg">
          <TrendingUp className="h-3 w-3 text-[#FF6B00] mt-0.5 flex-shrink-0" />
          <div className="text-xs">
            <div className="font-medium text-[#EDEDED]">Trend Analysis</div>
            <div className="text-[#9A9A9A] mt-1">
              {chartView === "consumption" && `Peak consumption period shows ${maxValue.toFixed(0)} kWh usage`}
              {chartView === "cost" &&
                `Highest cost period: $${maxValue.toFixed(2)} • Total cost: $${totalValue.toFixed(2)}`}
              {chartView === "efficiency" &&
                `Average efficiency: ${avgValue.toFixed(1)}% • Peak efficiency: ${maxValue.toFixed(1)}%`}
            </div>
          </div>
        </div>
      </div>
    </Card>
  )
}
