"use client"

import { useState } from "react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Bar, BarChart, CartesianGrid, XAxis, YAxis, ResponsiveContainer, Tooltip } from "recharts"
import { useOverviewData } from "@/lib/store/hooks"
import { BarChart3 } from "lucide-react"

type TimeRange = "24h" | "7d" | "30d"

export function EnergyTrendChart() {
  const data = useOverviewData()
  const [timeRange, setTimeRange] = useState<TimeRange>("24h")

  if (!data) {
    return <div className="h-[400px] bg-[#1B1B1B] border border-[#2A2A2A] rounded-lg animate-pulse" />
  }

  const chartData = data.energyTrend[timeRange]

  return (
    <Card className="bg-[#1B1B1B] border-[#2A2A2A] text-[#EDEDED]">
      <CardHeader>
        <div className="flex flex-col gap-4">
          <div>
            <CardTitle className="flex items-center gap-2">
              <BarChart3 className="h-5 w-5 text-[#FF6B00]" />
              Energy Consumption
            </CardTitle>
            <CardDescription className="text-[#9A9A9A] mt-1">
              Total consumption across selected time periods.
            </CardDescription>
          </div>
          <div className="flex items-center gap-2 bg-[#0E0E0E] p-1 rounded-lg w-fit">
            {(["24h", "7d", "30d"] as TimeRange[]).map((range) => (
              <Button
                key={range}
                size="sm"
                variant={timeRange === range ? "default" : "ghost"}
                onClick={() => setTimeRange(range)}
                className={`
                  ${timeRange === range ? "bg-[#FF6B00] hover:bg-[#E55A00] text-black" : "hover:bg-[#2A2A2A]"}
                  px-3 py-1 h-7 text-xs
                `}
              >
                {range.toUpperCase()}
              </Button>
            ))}
          </div>
        </div>
      </CardHeader>
      <CardContent className="h-[280px] p-2">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={chartData} margin={{ top: 10, right: 20, left: -10, bottom: 0 }}>
            <CartesianGrid vertical={false} strokeDasharray="3 3" stroke="#2A2A2A" />
            <XAxis
              dataKey={timeRange === "24h" ? "time" : "date"}
              tick={{ fill: "#9A9A9A", fontSize: 10 }}
              tickLine={false}
              axisLine={false}
            />
            <YAxis
              tick={{ fill: "#9A9A9A", fontSize: 10 }}
              tickLine={false}
              axisLine={false}
              unit="kWh"
              domain={["dataMin - 100", "dataMax + 100"]}
            />
            <Tooltip
              cursor={{ fill: "hsl(var(--accent))", opacity: 0.1 }}
              contentStyle={{
                backgroundColor: "#0E0E0E",
                border: "1px solid #2A2A2A",
                borderRadius: "0.5rem",
              }}
              itemStyle={{ color: "hsl(var(--chart-1))" }}
              labelStyle={{ color: "#9A9A9A" }}
              formatter={(value) => [`${(value as number).toLocaleString()} kWh`, "Consumption"]}
            />
            <Bar dataKey="consumption" fill="hsl(var(--chart-1))" radius={[4, 4, 0, 0]} strokeWidth={0} />
          </BarChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  )
}
