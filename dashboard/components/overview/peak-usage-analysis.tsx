"use client"

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Area, AreaChart, CartesianGrid, XAxis, YAxis, ResponsiveContainer, Tooltip } from "recharts"
import { useOverviewData } from "@/lib/store/hooks"
import { TrendingUp } from "lucide-react"

export function PeakUsageAnalysis() {
  const data = useOverviewData()

  if (!data) {
    return <div className="h-[400px] bg-[#1B1B1B] border border-[#2A2A2A] rounded-lg animate-pulse" />
  }

  const peakHour = data.peakUsage.reduce((max, hour) => (hour.consumption > max.consumption ? hour : max))
  const avgConsumption = data.peakUsage.reduce((sum, hour) => sum + hour.consumption, 0) / data.peakUsage.length
  const minConsumption = Math.min(...data.peakUsage.map((hour) => hour.consumption))

  return (
    <Card className="bg-[#1B1B1B] border-[#2A2A2A] text-[#EDEDED]">
      <CardHeader>
        <div>
          <CardTitle className="flex items-center gap-2">
            <TrendingUp className="h-5 w-5 text-[#FF6B00]" />
            Peak Usage Trend
          </CardTitle>
          <CardDescription className="text-[#9A9A9A] mt-1">
            24-hour consumption trend showing peak patterns and variations.
          </CardDescription>
        </div>
        <div className="flex items-center gap-4 text-sm mt-3">
          <div className="bg-[#0E0E0E]/50 px-3 py-2 rounded-lg text-center">
            <div className="text-lg font-bold text-[#FF6B00]">{peakHour.consumption.toFixed(0)}</div>
            <div className="text-xs text-[#9A9A9A]">Peak (kWh)</div>
          </div>
          <div className="bg-[#0E0E0E]/50 px-3 py-2 rounded-lg text-center">
            <div className="text-lg font-bold text-[#EDEDED]">{avgConsumption.toFixed(0)}</div>
            <div className="text-xs text-[#9A9A9A]">Avg (kWh)</div>
          </div>
          <div className="bg-[#0E0E0E]/50 px-3 py-2 rounded-lg text-center">
            <div className="text-lg font-bold text-green-400">{minConsumption.toFixed(0)}</div>
            <div className="text-xs text-[#9A9A9A]">Min (kWh)</div>
          </div>
        </div>
      </CardHeader>
      <CardContent className="h-[280px] p-2">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data.peakUsage} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="peakGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="hsl(var(--chart-2))" stopOpacity={0.8} />
                <stop offset="95%" stopColor="hsl(var(--chart-2))" stopOpacity={0.1} />
              </linearGradient>
            </defs>
            <CartesianGrid vertical={false} strokeDasharray="3 3" stroke="#2A2A2A" />
            <XAxis
              dataKey="hour"
              tick={{ fill: "#9A9A9A", fontSize: 10 }}
              tickLine={false}
              axisLine={false}
              tickFormatter={(value) => `${value}:00`}
            />
            <YAxis
              tick={{ fill: "#9A9A9A", fontSize: 10 }}
              tickLine={false}
              axisLine={false}
              unit="kWh"
              domain={["dataMin - 20", "dataMax + 20"]}
            />
            <Tooltip
              cursor={{ fill: "hsl(var(--accent))", opacity: 0.1 }}
              contentStyle={{
                backgroundColor: "#0E0E0E",
                border: "1px solid #2A2A2A",
                borderRadius: "0.5rem",
              }}
              itemStyle={{ color: "hsl(var(--chart-2))" }}
              labelStyle={{ color: "#9A9A9A" }}
              formatter={(value) => [`${(value as number).toFixed(0)} kWh`, "Consumption"]}
              labelFormatter={(label) => `Hour: ${label}:00`}
            />
            <Area
              type="monotone"
              dataKey="consumption"
              stroke="hsl(var(--chart-2))"
              fill="url(#peakGradient)"
              strokeWidth={2}
            />
          </AreaChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  )
}
