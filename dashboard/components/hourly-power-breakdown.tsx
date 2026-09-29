"use client"

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Bar, BarChart, CartesianGrid, XAxis, YAxis, ResponsiveContainer, Legend, Tooltip } from "recharts"
import { Activity } from "lucide-react"
import { useSelectedMeter } from "@/lib/store/hooks"

export function HourlyPowerBreakdown() {
  const selectedMeter = useSelectedMeter()

  if (!selectedMeter) return null

  return (
    <Card className="bg-[#1B1B1B] border-[#2A2A2A] text-[#EDEDED]">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Activity className="h-5 w-5 text-[#FF6B00]" />
          Hourly Power by Device
        </CardTitle>
        <CardDescription className="text-[#9A9A9A]">24-hour power consumption breakdown</CardDescription>
      </CardHeader>
      <CardContent className="h-[300px] p-2">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={selectedMeter.hourlyBreakdown} margin={{ top: 10, right: 10, left: -10, bottom: 0 }}>
            <CartesianGrid vertical={false} strokeDasharray="3 3" stroke="#2A2A2A" />
            <XAxis dataKey="hour" tick={{ fill: "#9A9A9A", fontSize: 10 }} tickLine={false} axisLine={false} />
            <YAxis tick={{ fill: "#9A9A9A", fontSize: 10 }} tickLine={false} axisLine={false} unit="kW" />
            <Tooltip
              cursor={{ fill: "hsl(var(--accent))", opacity: 0.1 }}
              contentStyle={{
                backgroundColor: "#0E0E0E",
                border: "1px solid #2A2A2A",
                borderRadius: "0.5rem",
              }}
              itemStyle={{ color: "#EDEDED" }}
              labelStyle={{ color: "#9A9A9A" }}
              formatter={(value, name) => [
                `${(value as number).toFixed(2)} kW`,
                name.charAt(0).toUpperCase() + name.slice(1),
              ]}
            />
            <Legend wrapperStyle={{ fontSize: "11px" }} />
            <Bar dataKey="base" name="Base Load" stackId="a" fill="hsl(var(--chart-1))" radius={[4, 4, 0, 0]} />
            <Bar dataKey="peak" name="Peak Load" stackId="a" fill="hsl(var(--chart-2))" />
            <Bar dataKey="auxiliary" name="Auxiliary" stackId="a" fill="hsl(var(--chart-3))" />
          </BarChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  )
}
