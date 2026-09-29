"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator,
  DropdownMenuLabel,
} from "@/components/ui/dropdown-menu"
import { ChevronDown, Zap, Activity, AlertCircle, CheckCircle, Wrench } from "lucide-react"
import { useAppDispatch, useMeters, useSelectedMeterId, useMetersLoading } from "@/lib/store/hooks"
import { selectMeter } from "@/lib/store/slices/metersSlice"

export function MeterDropdownSelector() {
  const dispatch = useAppDispatch()
  const meters = useMeters()
  const selectedMeterId = useSelectedMeterId()
  const loading = useMetersLoading()

  const handleMeterSelect = (meterId: string) => {
    dispatch(selectMeter(meterId))
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "online":
        return <CheckCircle className="h-3 w-3 text-green-400" />
      case "offline":
        return <AlertCircle className="h-3 w-3 text-red-400" />
      case "maintenance":
        return <Wrench className="h-3 w-3 text-orange-400" />
      default:
        return <Activity className="h-3 w-3 text-gray-400" />
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case "online":
        return "text-green-400"
      case "offline":
        return "text-red-400"
      case "maintenance":
        return "text-orange-400"
      default:
        return "text-gray-400"
    }
  }

  const selectedMeter = meters.find((m) => m.id === selectedMeterId)
  const onlineCount = meters.filter((m) => m.status === "online").length
  const offlineCount = meters.filter((m) => m.status === "offline").length
  const maintenanceCount = meters.filter((m) => m.status === "maintenance").length

  if (loading && meters.length === 0) {
    return (
      <Card className="bg-[#1B1B1B] border-[#2A2A2A] text-[#EDEDED]">
        <CardContent className="p-6">
          <div className="flex items-center justify-center h-16">
            <div className="text-[#9A9A9A]">Loading meters...</div>
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className="bg-[#1B1B1B] border-[#2A2A2A] text-[#EDEDED]">
      <CardHeader className="pb-3 pt-4 px-4 sm:px-6">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <CardTitle className="flex items-center gap-3 text-lg font-semibold text-[#EDEDED]">
            <Zap className="h-5 w-5 text-[#FF6B00]" />
            Meter Selection
          </CardTitle>

          <div className="flex items-center flex-wrap gap-4 justify-start sm:justify-end w-full sm:w-auto">
            {/* Status Summary */}
            <div className="flex items-center gap-4 text-sm">
              <div className="flex items-center gap-1">
                <CheckCircle className="h-4 w-4 text-green-400" />
                <span className="text-[#9A9A9A]">{onlineCount}</span>
              </div>
              <div className="flex items-center gap-1">
                <AlertCircle className="h-4 w-4 text-red-400" />
                <span className="text-[#9A9A9A]">{offlineCount}</span>
              </div>
              <div className="flex items-center gap-1">
                <Wrench className="h-4 w-4 text-orange-400" />
                <span className="text-[#9A9A9A]">{maintenanceCount}</span>
              </div>
            </div>

            {/* Meter Dropdown */}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="outline"
                  className="bg-[#FF6B00] hover:bg-[#E55A00] text-black border-[#FF6B00] hover:border-[#E55A00] w-full sm:w-[250px] justify-between"
                >
                  {selectedMeter ? (
                    <div className="flex items-center gap-2">
                      {getStatusIcon(selectedMeter.status)}
                      <span className="truncate">{selectedMeter.name}</span>
                    </div>
                  ) : (
                    "Select Meter"
                  )}
                  <ChevronDown className="h-4 w-4 ml-2" />
                </Button>
              </DropdownMenuTrigger>

              <DropdownMenuContent className="w-80 bg-[#1B1B1B] border-[#2A2A2A] text-[#EDEDED]">
                <DropdownMenuLabel className="text-[#FF6B00] font-semibold">Available Meters</DropdownMenuLabel>
                <DropdownMenuSeparator className="bg-[#2A2A2A]" />
                {meters.map((meter) => (
                  <DropdownMenuItem
                    key={meter.id}
                    onClick={() => handleMeterSelect(meter.id)}
                    className={`cursor-pointer hover:bg-[#2A2A2A] focus:bg-[#2A2A2A] ${
                      selectedMeterId === meter.id ? "bg-[#FF6B00]/10" : ""
                    }`}
                  >
                    <div className="flex items-center justify-between w-full">
                      <div className="flex items-center gap-2">
                        {getStatusIcon(meter.status)}
                        <div>
                          <div className="font-medium text-[#EDEDED]">{meter.name}</div>
                          <div className="text-xs text-[#9A9A9A]">{meter.id}</div>
                        </div>
                      </div>
                      <div className={`text-sm font-semibold ${getStatusColor(meter.status)}`}>
                        {meter.status === "online" ? `${meter.currentLoad.toFixed(1)}%` : meter.status}
                      </div>
                    </div>
                  </DropdownMenuItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>

        {/* Selected Meter Summary */}
        {selectedMeter && (
          <div className="mt-4 p-4 bg-[#FF6B00]/10 border border-[#FF6B00]/30 rounded-lg">
            <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                {getStatusIcon(selectedMeter.status)}
                <div>
                  <h3 className="font-semibold text-[#EDEDED]">{selectedMeter.name}</h3>
                  <p className="text-sm text-[#9A9A9A]">
                    {selectedMeter.id} • {selectedMeter.location} • {selectedMeter.type}
                  </p>
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
                <div className="text-center">
                  <div className={`text-lg font-bold ${getStatusColor(selectedMeter.status)}`}>
                    {selectedMeter.status.toUpperCase()}
                  </div>
                  <div className="text-xs text-[#9A9A9A]">Status</div>
                </div>
                <div className="text-center">
                  <div className="text-lg font-bold text-[#EDEDED]">{selectedMeter.currentLoad.toFixed(1)}%</div>
                  <div className="text-xs text-[#9A9A9A]">Current Load</div>
                </div>
                <div className="text-center">
                  <div className="text-lg font-bold text-[#EDEDED]">{selectedMeter.efficiency}%</div>
                  <div className="text-xs text-[#9A9A9A]">Efficiency</div>
                </div>
                <div className="text-center">
                  <div className="text-sm font-medium text-[#9A9A9A]">{selectedMeter.lastReading}</div>
                  <div className="text-xs text-[#9A9A9A]">Last Reading</div>
                </div>
              </div>
            </div>
          </div>
        )}
      </CardHeader>
    </Card>
  )
}
