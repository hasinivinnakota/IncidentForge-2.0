"use client"

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Area, AreaChart, CartesianGrid, XAxis, YAxis, ResponsiveContainer, Tooltip, ReferenceLine } from "recharts"
import { useOverviewData } from "@/lib/store/hooks"
import { TrendingDown, AlertTriangle } from "lucide-react"

export function LoadDurationCurve() {
  const data = useOverviewData()

  if (!data) {
    return <div className="h-[400px] bg-[#1B1B1B] border border-[#2A2A2A] rounded-lg animate-pulse" />
  }

  // Generate load duration curve data from 24h consumption data
  const generateLoadDurationData = () => {
    // Get hourly consumption and sort in descending order
    const hourlyLoads = data.peakUsage.map((item) => item.consumption).sort((a, b) => b - a)
    const peakLoad = Math.max(...hourlyLoads)
    const threshold80 = peakLoad * 0.8

    // Create duration curve data points with hours instead of percentage
    const durationData = hourlyLoads.map((load, index) => ({
      hours: index + 1,
      load: load,
      isPeak: load >= threshold80,
    }))

    return { durationData, peakLoad, threshold80 }
  }

  const { durationData, peakLoad, threshold80 } = generateLoadDurationData()

  // Calculate hours above 80% threshold
  const hoursAbove80Percent = durationData.filter((point) => point.isPeak).length

  return (
    <Card className="bg-[#1B1B1B] border-[#2A2A2A] text-[#EDEDED]">
      <CardHeader>
        <div className="flex flex-col gap-4">
          <div>
            <CardTitle className="flex items-center gap-2">
              <TrendingDown className="h-5 w-5 text-[#FF6B00]" />
              Load Duration Curve (24h)
            </CardTitle>
            <CardDescription className="text-[#9A9A9A] mt-1">
              Load distribution over time for demand response planning
            </CardDescription>
          </div>
          <div className="flex items-center gap-4 text-sm">
            <div className="bg-[#0E0E0E]/50 px-3 py-2 rounded-lg text-center">
              <div className="text-lg font-bold text-[#FF6B00]">{hoursAbove80Percent}h</div>
              <div className="text-xs text-[#9A9A9A]">Time &gt; 80% Peak</div>
            </div>
            <div className="bg-[#0E0E0E]/50 px-3 py-2 rounded-lg text-center">
              <div className="text-lg font-bold text-[#EDEDED]">{peakLoad.toFixed(0)}</div>
              <div className="text-xs text-[#9A9A9A]">Peak Load (kW)</div>
            </div>
          </div>
        </div>
      </CardHeader>
      <CardContent className="h-[280px] p-2">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={durationData} margin={{ top: 10, right: 20, left: -10, bottom: 0 }}>
            <defs>
              <linearGradient id="loadGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="hsl(var(--chart-1))" stopOpacity={0.8} />
                <stop offset="95%" stopColor="hsl(var(--chart-1))" stopOpacity={0.1} />
              </linearGradient>
            </defs>
            <CartesianGrid vertical={false} strokeDasharray="3 3" stroke="#2A2A2A" />
            <XAxis
              dataKey="hours"
              type="number"
              tick={{ fill: "#9A9A9A", fontSize: 10 }}
              tickLine={false}
              axisLine={false}
              unit="h"
              domain={[0, 24]}
              ticks={[0, 4, 8, 12, 16, 20, 24]}
            />
            <YAxis
              tick={{ fill: "#9A9A9A", fontSize: 10 }}
              tickLine={false}
              axisLine={false}
              unit="kW"
              domain={[0, "dataMax + 50"]}
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
              formatter={(value, name, props) => [
                `${(value as number).toFixed(1)} kW`,
                props.payload.isPeak ? "Peak Load" : "Base Load",
              ]}
              labelFormatter={(label) => `Duration: ${label} hours`}
            />
            <ReferenceLine
              y={threshold80}
              stroke="#FF6B00"
              strokeDasharray="5 5"
              strokeWidth={2}
              label={{
                value: "80% Peak",
                position: "topRight",
                fill: "#FF6B00",
                fontSize: 10,
              }}
            />
            <Area
              type="monotone"
              dataKey="load"
              stroke="hsl(var(--chart-1))"
              fill="url(#loadGradient)"
              strokeWidth={2}
            />
          </AreaChart>
        </ResponsiveContainer>
      </CardContent>

      {/* Compact Insights */}
      <div className="px-6 pb-4">
        <div className="flex items-start gap-2 p-2 bg-[#0E0E0E]/30 rounded-lg">
          <AlertTriangle className="h-3 w-3 text-[#FF6B00] mt-0.5 flex-shrink-0" />
          <div className="text-xs">
            <div className="font-medium text-[#EDEDED]">Demand Response Insight</div>
            <div className="text-[#9A9A9A] mt-1">
              Load exceeds 80% of peak for {hoursAbove80Percent} hours.
              {hoursAbove80Percent > 6 ? " Consider load shifting strategies." : " Good load distribution."}
            </div>
          </div>
        </div>
      </div>
    </Card>
  )
}
