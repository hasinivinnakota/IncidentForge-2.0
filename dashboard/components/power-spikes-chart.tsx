"use client"

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Area, AreaChart, CartesianGrid, XAxis, ResponsiveContainer, Tooltip } from "recharts"
import { useSelectedMeter } from "@/lib/store/hooks"
import { TrendingUp } from "lucide-react"

export function PowerSpikesChart() {
  const selectedMeter = useSelectedMeter()

  if (!selectedMeter) return null

  return (
    <Card className="bg-[#1B1B1B] border-[#2A2A2A] text-[#EDEDED]">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <TrendingUp className="h-5 w-5 text-[#FF6B00]" />
          Power Spikes This Week
        </CardTitle>
        <CardDescription className="text-[#9A9A9A]">Rate of power change over the last 7 days</CardDescription>
      </CardHeader>
      <CardContent className="h-[300px] p-2">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={selectedMeter.powerSpikes} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="fillRate" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="hsl(var(--chart-2))" stopOpacity={0.8} />
                <stop offset="95%" stopColor="hsl(var(--chart-2))" stopOpacity={0.1} />
              </linearGradient>
            </defs>
            <CartesianGrid vertical={false} strokeDasharray="3 3" stroke="#2A2A2A" />
            <XAxis
              dataKey="time"
              tickFormatter={(value) => new Date(value).toLocaleDateString([], { month: "short", day: "numeric" })}
              tick={{ fill: "#9A9A9A", fontSize: 10 }}
              tickLine={false}
              axisLine={false}
            />
            <Tooltip
              cursor={{ fill: "hsl(var(--accent))", opacity: 0.1 }}
              contentStyle={{
                backgroundColor: "#0E0E0E",
                border: "1px solid #2A2A2A",
                borderRadius: "0.5rem",
              }}
              itemStyle={{ color: "#EDEDED" }}
              labelStyle={{ color: "#9A9A9A" }}
              formatter={(value) => [(value as number).toFixed(4), "Rate"]}
              labelFormatter={(label) => new Date(label).toLocaleString()}
            />
            <Area type="monotone" dataKey="rate" stroke="hsl(var(--chart-2))" fill="url(#fillRate)" strokeWidth={2} />
          </AreaChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  )
}
