"use client"

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Pie, PieChart, ResponsiveContainer, Legend, Cell, Tooltip } from "recharts"
import { useSelectedMeter } from "@/lib/store/hooks"
import { PieChartIcon as PieIcon } from "lucide-react"

export function PowerDistributionPie() {
  const selectedMeter = useSelectedMeter()

  if (!selectedMeter || !selectedMeter.type.includes("3-Phase")) {
    return (
      <Card className="bg-[#1B1B1B] border-[#2A2A2A] text-[#EDEDED] flex items-center justify-center h-full">
        <div className="text-center text-[#9A9A9A]">
          <p>Load Distribution</p>
          <p className="text-sm">Not applicable for this meter type.</p>
        </div>
      </Card>
    )
  }

  const data = [
    { name: "Phase 1", value: selectedMeter.loadDistribution.l1, fill: "hsl(var(--chart-1))" },
    { name: "Phase 2", value: selectedMeter.loadDistribution.l2, fill: "hsl(var(--chart-2))" },
    { name: "Phase 3", value: selectedMeter.loadDistribution.l3, fill: "hsl(var(--chart-3))" },
  ]

  return (
    <Card className="bg-[#1B1B1B] border-[#2A2A2A] text-[#EDEDED]">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <PieIcon className="h-5 w-5 text-[#FF6B00]" />
          Load Distribution
        </CardTitle>
        <CardDescription className="text-[#9A9A9A]">Power distribution across phases</CardDescription>
      </CardHeader>
      <CardContent className="h-[300px] p-2">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Tooltip
              cursor={{ fill: "hsl(var(--accent))", opacity: 0.1 }}
              contentStyle={{
                backgroundColor: "#0E0E0E",
                border: "1px solid #2A2A2A",
                borderRadius: "0.5rem",
              }}
              itemStyle={{ color: "#EDEDED" }}
              formatter={(value, name) => [`${value}%`, name]}
            />
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              cx="50%"
              cy="50%"
              outerRadius={80}
              innerRadius={50}
              strokeWidth={2}
            >
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.fill} />
              ))}
            </Pie>
            <Legend wrapperStyle={{ fontSize: "11px" }} />
          </PieChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  )
}
