"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Checkbox } from "@/components/ui/checkbox"
import { Input } from "@/components/ui/input"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from "@/components/ui/command"
import { Badge } from "@/components/ui/badge"
import { FileText, Download, Calendar, Filter, Loader2, ChevronDown, Check, X, Zap, Search } from "lucide-react"
import { useMeters, useAppDispatch } from "@/lib/store/hooks"
import { fetchMetersRequest } from "@/lib/store/slices/metersSlice"
import type { ReportFilters, ReportTimeRange, ReportType } from "@/app/reports/page"

interface ReportGeneratorProps {
  onGenerateReport: (filters: ReportFilters) => void
  isGenerating: boolean
}

export function ReportGenerator({ onGenerateReport, isGenerating }: ReportGeneratorProps) {
  const dispatch = useAppDispatch()
  const meters = useMeters()
  const [filters, setFilters] = useState<ReportFilters>({
    timeRange: "7d",
    reportType: "consumption",
    meterIds: [],
  })
  const [meterDropdownOpen, setMeterDropdownOpen] = useState(false)

  // Fetch meters when component mounts
  useEffect(() => {
    if (meters.length === 0) {
      dispatch(fetchMetersRequest())
    }
  }, [dispatch, meters.length])

  const timeRangeOptions: { value: ReportTimeRange; label: string }[] = [
    { value: "24h", label: "Last 24 Hours" },
    { value: "7d", label: "Last 7 Days" },
    { value: "30d", label: "Last 30 Days" },
    { value: "90d", label: "Last 90 Days" },
    { value: "1y", label: "Last Year" },
  ]

  const reportTypeOptions: { value: ReportType; label: string; description: string }[] = [
    { value: "consumption", label: "Energy Consumption", description: "Total energy usage analysis" },
    { value: "peak-analysis", label: "Peak Analysis", description: "Peak demand and load patterns" },
    { value: "efficiency", label: "Efficiency Report", description: "System efficiency metrics" },
    { value: "cost-analysis", label: "Cost Analysis", description: "Energy cost breakdown" },
  ]

  const handleMeterToggle = (meterId: string, checked: boolean) => {
    setFilters((prev) => ({
      ...prev,
      meterIds: checked ? [...prev.meterIds, meterId] : prev.meterIds.filter((id) => id !== meterId),
    }))
  }

  const handleSelectAllMeters = () => {
    const allMeterIds = meters.map((meter) => meter.id)
    setFilters((prev) => ({
      ...prev,
      meterIds: prev.meterIds.length === allMeterIds.length ? [] : allMeterIds,
    }))
  }

  const handleClearAllMeters = () => {
    setFilters((prev) => ({
      ...prev,
      meterIds: [],
    }))
  }

  const removeMeter = (meterId: string) => {
    setFilters((prev) => ({
      ...prev,
      meterIds: prev.meterIds.filter((id) => id !== meterId),
    }))
  }

  const handleGenerateReport = () => {
    onGenerateReport(filters)
  }

  const selectedMeters = meters.filter((meter) => filters.meterIds.includes(meter.id))

  const getStatusColor = (status: string) => {
    switch (status) {
      case "online":
        return "bg-green-500"
      case "maintenance":
        return "bg-yellow-500"
      case "offline":
        return "bg-red-500"
      default:
        return "bg-gray-500"
    }
  }

  const getStatusText = (status: string) => {
    switch (status) {
      case "online":
        return "Online"
      case "maintenance":
        return "Maintenance"
      case "offline":
        return "Offline"
      default:
        return "Unknown"
    }
  }

  return (
    <Card className="bg-[#1B1B1B] border-[#2A2A2A] text-[#EDEDED]">
      <CardHeader className="pb-4 sm:pb-6">
        <CardTitle className="flex items-center gap-2 text-lg sm:text-xl">
          <FileText className="h-4 w-4 sm:h-5 sm:w-5 text-[#FF6B00]" />
          Report Generator
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4 sm:space-y-6">
        {/* Filter Controls */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-6">
          {/* Time Range */}
          <div className="space-y-2">
            <Label className="flex items-center gap-2 text-sm font-medium">
              <Calendar className="h-3 w-3 sm:h-4 sm:w-4" />
              Time Range
            </Label>
            <Select
              value={filters.timeRange}
              onValueChange={(value: ReportTimeRange) => setFilters((prev) => ({ ...prev, timeRange: value }))}
            >
              <SelectTrigger className="bg-[#0E0E0E] border-[#2A2A2A] h-10 sm:h-11">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-[#1B1B1B] border-[#2A2A2A] text-[#EDEDED]">
                {timeRangeOptions.map((option) => (
                  <SelectItem key={option.value} value={option.value} className="cursor-pointer hover:!bg-[#2A2A2A]">
                    {option.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Report Type */}
          <div className="space-y-2">
            <Label className="flex items-center gap-2 text-sm font-medium">
              <Filter className="h-3 w-3 sm:h-4 sm:w-4" />
              Report Type
            </Label>
            <Select
              value={filters.reportType}
              onValueChange={(value: ReportType) => setFilters((prev) => ({ ...prev, reportType: value }))}
            >
              <SelectTrigger className="bg-[#0E0E0E] border-[#2A2A2A] h-10 sm:h-11">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-[#1B1B1B] border-[#2A2A2A] text-[#EDEDED]">
                {reportTypeOptions.map((option) => (
                  <SelectItem key={option.value} value={option.value} className="cursor-pointer hover:!bg-[#2A2A2A]">
                    <div>
                      <div className="font-medium text-sm">{option.label}</div>
                      <div className="text-xs text-[#9A9A9A] hidden sm:block">{option.description}</div>
                    </div>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Custom Date Range */}
          <div className="space-y-2">
            <Label className="text-sm font-medium">From Date (Optional)</Label>
            <Input
              type="date"
              value={filters.dateFrom || ""}
              onChange={(e) => setFilters((prev) => ({ ...prev, dateFrom: e.target.value }))}
              className="bg-[#0E0E0E] border-[#2A2A2A] h-10 sm:h-11"
            />
          </div>

          <div className="space-y-2">
            <Label className="text-sm font-medium">To Date (Optional)</Label>
            <Input
              type="date"
              value={filters.dateTo || ""}
              onChange={(e) => setFilters((prev) => ({ ...prev, dateTo: e.target.value }))}
              className="bg-[#0E0E0E] border-[#2A2A2A] h-10 sm:h-11"
            />
          </div>
        </div>

        {/* Enhanced Meter Selection */}
        <div className="space-y-3 sm:space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <Label className="flex items-center gap-2 text-sm font-medium">
              <Zap className="h-3 w-3 sm:h-4 sm:w-4" />
              Select Meters ({meters.length} available)
            </Label>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={handleSelectAllMeters}
                className="bg-transparent border-[#2A2A2A] hover:bg-[#2A2A2A] text-xs h-8 px-3 min-w-[80px]"
              >
                {filters.meterIds.length === meters.length ? "Deselect All" : "Select All"}
              </Button>
              {filters.meterIds.length > 0 && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleClearAllMeters}
                  className="bg-transparent border-[#2A2A2A] hover:bg-[#2A2A2A] text-xs h-8 px-3"
                >
                  Clear
                </Button>
              )}
            </div>
          </div>

          {/* Meter Dropdown */}
          <Popover open={meterDropdownOpen} onOpenChange={setMeterDropdownOpen}>
            <PopoverTrigger asChild>
              <Button
                variant="outline"
                role="combobox"
                aria-expanded={meterDropdownOpen}
                className="w-full justify-between bg-[#0E0E0E] border-[#2A2A2A] hover:bg-[#1B1B1B] hover:border-[#FF6B00]/50 h-11 sm:h-12 text-[#EDEDED] transition-all duration-200"
              >
                <div className="flex items-center gap-2 min-w-0">
                  <Zap className="h-4 w-4 text-[#FF6B00] flex-shrink-0" />
                  <span className="text-sm font-medium truncate">
                    {filters.meterIds.length === 0
                      ? "Select meters..."
                      : `${filters.meterIds.length} meter${filters.meterIds.length !== 1 ? "s" : ""} selected`}
                  </span>
                </div>
                <ChevronDown
                  className={`ml-2 h-4 w-4 shrink-0 text-[#9A9A9A] transition-transform duration-200 ${meterDropdownOpen ? "rotate-180" : ""}`}
                />
              </Button>
            </PopoverTrigger>
            <PopoverContent className="w-full p-0 bg-[#1B1B1B] border-[#2A2A2A] shadow-xl" align="start" sideOffset={4}>
              <Command className="bg-[#1B1B1B]">
                <div className="flex items-center border-b border-[#2A2A2A] px-3">
                  <Search className="mr-2 h-4 w-4 shrink-0 text-[#9A9A9A]" />
                  <CommandInput
                    placeholder="Search meters..."
                    className="flex h-10 sm:h-11 w-full rounded-md bg-transparent py-3 text-sm text-[#EDEDED] placeholder:text-[#9A9A9A] outline-none disabled:cursor-not-allowed disabled:opacity-50 border-0"
                  />
                </div>
                <CommandList className="max-h-60 sm:max-h-72 overflow-y-auto">
                  <CommandEmpty className="text-[#9A9A9A] text-center py-6 sm:py-8">
                    <div className="flex flex-col items-center gap-2">
                      <Search className="h-6 w-6 sm:h-8 sm:w-8 text-[#4A4A4A]" />
                      <p className="text-sm">No meters found.</p>
                      <p className="text-xs">Try adjusting your search terms.</p>
                    </div>
                  </CommandEmpty>
                  <CommandGroup>
                    {meters.map((meter) => {
                      const isSelected = filters.meterIds.includes(meter.id)
                      return (
                        <CommandItem
                          key={meter.id}
                          value={`${meter.name} ${meter.id} ${meter.location} ${meter.type}`}
                          onSelect={() => {
                            handleMeterToggle(meter.id, !isSelected)
                          }}
                          className={`flex items-center space-x-3 px-3 sm:px-4 py-3 sm:py-4 cursor-pointer transition-all duration-200 border-l-2 ${
                            isSelected
                              ? "bg-[#FF6B00]/15 hover:bg-[#FF6B00]/25 text-[#EDEDED] border-l-[#FF6B00]"
                              : "hover:bg-[#2A2A2A] text-[#EDEDED] border-l-transparent"
                          }`}
                        >
                          <Checkbox
                            checked={isSelected}
                            onChange={() => {}}
                            className="data-[state=checked]:bg-[#FF6B00] data-[state=checked]:border-[#FF6B00] border-[#4A4A4A] h-4 w-4 flex-shrink-0"
                          />
                          <div className="flex items-center gap-2 sm:gap-3 flex-1 min-w-0">
                            <div
                              className={`w-2 h-2 sm:w-2.5 sm:h-2.5 rounded-full flex-shrink-0 ${getStatusColor(meter.status)}`}
                            />
                            <div className="flex-1 min-w-0">
                              <div
                                className={`font-semibold text-sm truncate ${isSelected ? "text-[#FFFFFF]" : "text-[#EDEDED]"}`}
                              >
                                {meter.name}
                              </div>
                              <div className={`text-xs truncate ${isSelected ? "text-[#E0E0E0]" : "text-[#9A9A9A]"}`}>
                                {meter.id} • {meter.location}
                              </div>
                              <div
                                className={`text-xs flex items-center gap-1 sm:gap-2 mt-1 ${isSelected ? "text-[#CCCCCC]" : "text-[#7A7A7A]"}`}
                              >
                                <span className="truncate">
                                  Last: {meter.lastReading.value} {meter.lastReading.unit}
                                </span>
                                <span className="hidden sm:inline">•</span>
                                <span
                                  className={`px-1.5 py-0.5 rounded text-xs flex-shrink-0 ${
                                    meter.status === "online"
                                      ? "bg-green-500/20 text-green-400"
                                      : meter.status === "maintenance"
                                        ? "bg-yellow-500/20 text-yellow-400"
                                        : "bg-red-500/20 text-red-400"
                                  }`}
                                >
                                  {getStatusText(meter.status)}
                                </span>
                              </div>
                            </div>
                            <div
                              className={`text-xs px-2 sm:px-2.5 py-1 sm:py-1.5 rounded-md font-medium flex-shrink-0 ${
                                isSelected
                                  ? "bg-[#FF6B00]/30 text-[#FF6B00] border border-[#FF6B00]/50"
                                  : "bg-[#2A2A2A] text-[#9A9A9A] border border-[#3A3A3A]"
                              }`}
                            >
                              {meter.type}
                            </div>
                          </div>
                          {isSelected && (
                            <Check className="h-4 w-4 text-[#FF6B00] flex-shrink-0 animate-in fade-in-0 zoom-in-95 duration-200" />
                          )}
                        </CommandItem>
                      )
                    })}
                  </CommandGroup>
                </CommandList>
              </Command>
            </PopoverContent>
          </Popover>

          {/* Selected Meters Display */}
          {selectedMeters.length > 0 && (
            <div className="space-y-3">
              <div className="text-sm text-[#9A9A9A] font-medium">Selected Meters:</div>
              <div className="flex flex-wrap gap-2">
                {selectedMeters.map((meter) => (
                  <Badge
                    key={meter.id}
                    variant="secondary"
                    className="bg-[#2A2A2A] text-[#EDEDED] hover:bg-[#3A3A3A] px-2 sm:px-3 py-1.5 sm:py-2 text-xs sm:text-sm flex items-center gap-1.5 sm:gap-2 border border-[#4A4A4A] transition-all duration-200 hover:border-[#FF6B00]/50 max-w-full"
                  >
                    <div className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${getStatusColor(meter.status)}`} />
                    <span className="font-medium text-[#EDEDED] truncate">{meter.name}</span>
                    <span className="text-xs text-[#9A9A9A] bg-[#1B1B1B] px-1.5 py-0.5 rounded flex-shrink-0">
                      {meter.id}
                    </span>
                    <button
                      onClick={() => removeMeter(meter.id)}
                      className="ml-1 hover:bg-[#4A4A4A] rounded-full p-1 transition-colors text-[#9A9A9A] hover:text-[#FF6B00] flex-shrink-0 touch-manipulation"
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </Badge>
                ))}
              </div>
              <div className="text-xs text-[#9A9A9A] bg-[#0E0E0E] px-3 py-2 rounded border border-[#2A2A2A]">
                <span className="font-medium text-[#FF6B00]">{filters.meterIds.length}</span> of{" "}
                <span className="font-medium">{meters.length}</span> meters selected
              </div>
            </div>
          )}
        </div>

        {/* Generate Button */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pt-4 border-t border-[#2A2A2A]">
          <div className="text-sm text-[#9A9A9A] order-2 sm:order-1">
            {filters.meterIds.length === 0
              ? "Select at least one meter to generate report"
              : `Ready to generate ${reportTypeOptions.find((r) => r.value === filters.reportType)?.label.toLowerCase()} report`}
          </div>
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 order-1 sm:order-2">
            <Button
              onClick={handleGenerateReport}
              disabled={filters.meterIds.length === 0 || isGenerating}
              className="bg-[#FF6B00] hover:bg-[#E55A00] text-black disabled:opacity-50 font-medium h-10 sm:h-11 touch-manipulation"
            >
              {isGenerating ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Generating...
                </>
              ) : (
                <>
                  <FileText className="mr-2 h-4 w-4" />
                  Generate Report
                </>
              )}
            </Button>
            <Button
              variant="outline"
              disabled={isGenerating}
              className="bg-transparent border-[#2A2A2A] hover:bg-[#2A2A2A] font-medium h-10 sm:h-11 touch-manipulation"
            >
              <Download className="mr-2 h-4 w-4" />
              Export
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
