"use client"

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Pie, PieChart, ResponsiveContainer, Legend, Cell, Tooltip } from "recharts"
import { useOverviewData } from "@/lib/store/hooks"
import { PieChartIcon as PieIcon } from "lucide-react"

export function ConsumptionBreakdown() {
  const data = useOverviewData()

  if (!data) {
    return <div className="h-[400px] bg-[#1B1B1B] border border-[#2A2A2A] rounded-lg animate-pulse" />
  }

  const totalConsumption = data.consumptionBreakdown.reduce((sum, item) => sum + item.value, 0)

  return (
    <Card className="bg-[#1B1B1B] border-[#2A2A2A] text-[#EDEDED]">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <PieIcon className="h-5 w-5 text-[#FF6B00]" />
          Consumption Breakdown
        </CardTitle>
        <CardDescription className="text-[#9A9A9A]">Distribution of energy usage by area.</CardDescription>
      </CardHeader>
      <CardContent className="h-[280px] p-2">
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
              data={data.consumptionBreakdown}
              dataKey="value"
              nameKey="name"
              cx="50%"
              cy="50%"
              innerRadius={50}
              outerRadius={80}
              strokeWidth={2}
              paddingAngle={5}
            >
              {data.consumptionBreakdown.map((entry) => (
                <Cell key={entry.name} fill={entry.color} />
              ))}
            </Pie>
            <Legend
              iconSize={8}
              layout="vertical"
              verticalAlign="middle"
              align="right"
              wrapperStyle={{ fontSize: "11px", color: "#9A9A9A" }}
            />
          </PieChart>
        </ResponsiveContainer>
      </CardContent>

      {/* Summary */}
      <div className="px-6 pb-4">
        <div className="grid grid-cols-2 gap-4">
          <div className="bg-[#0E0E0E]/50 p-2 rounded-lg text-center">
            <div className="text-lg font-bold text-[#FF6B00]">{data.consumptionBreakdown[0].value}%</div>
            <div className="text-xs text-[#9A9A9A]">Top Consumer</div>
          </div>
          <div className="bg-[#0E0E0E]/50 p-2 rounded-lg text-center">
            <div className="text-lg font-bold text-[#EDEDED]">{totalConsumption}%</div>
            <div className="text-xs text-[#9A9A9A]">Total Coverage</div>
          </div>
        </div>
      </div>
    </Card>
  )
}
