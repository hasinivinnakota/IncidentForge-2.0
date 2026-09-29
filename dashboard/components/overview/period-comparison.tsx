"use client"

import type React from "react"

import { useState } from "react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { TrendingUp, TrendingDown, ArrowRight, DollarSign, Zap } from "lucide-react"
import { useOverviewData } from "@/lib/store/hooks"

type ComparisonPeriod = "WTD" | "MTD" | "YTD"

const ComparisonMetric = ({
  title,
  change,
  period,
  icon: Icon,
  value,
}: {
  title: string
  change: number
  period: string
  icon: React.ElementType
  value: string
}) => {
  const isUp = change >= 0
  const TrendIcon = isUp ? TrendingUp : TrendingDown

  return (
    <div className="bg-[#0E0E0E]/50 p-2 rounded-lg border border-[#2A2A2A]/50 hover:border-[#FF6B00]/30 transition-all">
      <div className="flex items-center justify-between mb-1">
        <div className="flex items-center gap-1.5">
          <div className="p-1 bg-[#FF6B00]/10 rounded">
            <Icon className="h-2.5 w-2.5 text-[#FF6B00]" />
          </div>
          <span className="text-xs font-medium text-[#EDEDED]">{title}</span>
        </div>
        <div
          className={`flex items-center gap-0.5 px-1.5 py-0.5 rounded-full text-xs font-medium ${
            isUp ? "bg-green-600/20 text-green-400" : "bg-red-600/20 text-red-400"
          }`}
        >
          <TrendIcon className="h-2 w-2" />
          {isUp ? "+" : ""}
          {change.toFixed(1)}%
        </div>
      </div>

      <div>
        <div className="text-base font-bold text-[#EDEDED]">{value}</div>
        <div className="text-xs text-[#9A9A9A]">{period}</div>
      </div>
    </div>
  )
}

export function PeriodComparison() {
  const data = useOverviewData()
  const [selectedPeriod, setSelectedPeriod] = useState<ComparisonPeriod>("WTD")

  if (!data) {
    return <div className="h-[400px] bg-[#1B1B1B] border border-[#2A2A2A] rounded-lg animate-pulse" />
  }

  // Mock data for different periods with actual values
  const periodData = {
    WTD: {
      consumption: { change: 5.2, period: "vs last week", value: "12,456 kWh" },
      cost: { change: 4.8, period: "vs last week", value: "$1,495" },
      demand: { change: -2.1, period: "vs last week", value: "876 kW" },
    },
    MTD: {
      consumption: { change: 8.7, period: "vs last month", value: "48,230 kWh" },
      cost: { change: 7.3, period: "vs last month", value: "$5,788" },
      demand: { change: 3.2, period: "vs last month", value: "924 kW" },
    },
    YTD: {
      consumption: { change: -2.4, period: "vs last year", value: "2.1M kWh" },
      cost: { change: -1.8, period: "vs last year", value: "$252K" },
      demand: { change: -5.6, period: "vs last year", value: "1,150 kW" },
    },
  }

  const currentData = periodData[selectedPeriod]
  const totalChange = (currentData.consumption.change + currentData.cost.change + currentData.demand.change) / 3
  const positiveChanges = [currentData.consumption.change, currentData.cost.change, currentData.demand.change].filter(
    (c) => c > 0,
  ).length

  return (
    <Card className="bg-[#1B1B1B] border-[#2A2A2A] text-[#EDEDED]">
      <CardHeader className="pb-2">
        <div className="flex flex-col gap-3">
          <div>
            <CardTitle className="flex items-center gap-2">
              <ArrowRight className="h-5 w-5 text-[#FF6B00]" />
              Period Comparison
            </CardTitle>
            <CardDescription className="text-[#9A9A9A] mt-1">
              Performance metrics compared to previous periods.
            </CardDescription>
          </div>
          <div className="flex items-center gap-2 bg-[#0E0E0E] p-1 rounded-lg w-fit">
            {(["WTD", "MTD", "YTD"] as ComparisonPeriod[]).map((period) => (
              <Button
                key={period}
                size="sm"
                variant={selectedPeriod === period ? "default" : "ghost"}
                onClick={() => setSelectedPeriod(period)}
                className={`
                  ${selectedPeriod === period ? "bg-[#FF6B00] hover:bg-[#E55A00] text-black" : "hover:bg-[#2A2A2A]"}
                  px-3 py-1 h-7 text-xs
                `}
              >
                {period}
              </Button>
            ))}
          </div>
        </div>
      </CardHeader>
      <CardContent className="h-[280px] p-2">
        <div className="h-full flex flex-col justify-between">
          <div className="space-y-1.5">
            <ComparisonMetric
              title="Energy Consumption"
              change={currentData.consumption.change}
              period={currentData.consumption.period}
              value={currentData.consumption.value}
              icon={Zap}
            />
            <ComparisonMetric
              title="Energy Cost"
              change={currentData.cost.change}
              period={currentData.cost.period}
              value={currentData.cost.value}
              icon={DollarSign}
            />
            <ComparisonMetric
              title="Peak Demand"
              change={currentData.demand.change}
              period={currentData.demand.period}
              value={currentData.demand.value}
              icon={TrendingUp}
            />
          </div>

          {/* Compact Summary */}
          <div className="pt-2 border-t border-[#2A2A2A]">
            <div className="grid grid-cols-2 gap-2">
              <div className="bg-[#0E0E0E]/50 p-1.5 rounded text-center">
                <div className={`text-sm font-bold ${totalChange >= 0 ? "text-green-400" : "text-red-400"}`}>
                  {totalChange >= 0 ? "+" : ""}
                  {totalChange.toFixed(1)}%
                </div>
                <div className="text-xs text-[#9A9A9A]">Overall</div>
              </div>
              <div className="bg-[#0E0E0E]/50 p-1.5 rounded text-center">
                <div className="text-sm font-bold text-[#EDEDED]">{positiveChanges}/3</div>
                <div className="text-xs text-[#9A9A9A]">Improving</div>
              </div>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
