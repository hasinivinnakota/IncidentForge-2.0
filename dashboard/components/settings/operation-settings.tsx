"use client"

import { useEffect, useState } from "react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Checkbox } from "@/components/ui/checkbox"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { Trash2, Plus, DollarSign, Clock, Calculator } from "lucide-react"
import { settingsApi } from "@/lib/api"

interface OperationSettingsProps {
  isAdmin: boolean
}

interface TariffRate {
  id: string
  name: string
  rate: number
  currency: string
  timeStart?: string
  timeEnd?: string
  isDefault: boolean
}

interface Shift {
  id: string
  name: string
  startTime: string
  endTime: string
  operatingDays: string[]
}

export function OperationSettings({ isAdmin }: OperationSettingsProps) {
  const days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

  const [tariffRates, setTariffRates] = useState<TariffRate[]>([
    {
      id: "1",
      name: "Standard Rate",
      rate: 0.12,
      currency: "USD",
      isDefault: true,
    },
    {
      id: "2",
      name: "Peak Hours",
      rate: 0.18,
      currency: "USD",
      timeStart: "09:00",
      timeEnd: "17:00",
      isDefault: false,
    },
    {
      id: "3",
      name: "Off-Peak Hours",
      rate: 0.08,
      currency: "USD",
      timeStart: "22:00",
      timeEnd: "06:00",
      isDefault: false,
    },
  ])

  const [newTariff, setNewTariff] = useState({
    name: "",
    rate: "",
    currency: "USD",
    timeStart: "",
    timeEnd: "",
  })

  const [shifts, setShifts] = useState<Shift[]>([
    {
      id: "1",
      name: "Main Shift",
      startTime: "09:00",
      endTime: "17:00",
      operatingDays: ["Mon", "Tue", "Wed", "Thu", "Fri"],
    },
    {
      id: "2",
      name: "Night Shift",
      startTime: "22:00",
      endTime: "06:00",
      operatingDays: ["Mon", "Tue", "Wed", "Thu", "Fri"],
    },
  ])
  const [status, setStatus] = useState<string | null>(null)

  useEffect(() => {
    settingsApi.get().then((settings) => {
      setTariffRates(settings.tariff_rates as unknown as TariffRate[])
      setShifts(settings.shifts as unknown as Shift[])
    }).catch(() => setStatus("Unable to load saved operation settings."))
  }, [])

  const addTariffRate = () => {
    if (newTariff.name && newTariff.rate) {
      const tariff: TariffRate = {
        id: Date.now().toString(),
        name: newTariff.name,
        rate: Number.parseFloat(newTariff.rate),
        currency: newTariff.currency,
        timeStart: newTariff.timeStart || undefined,
        timeEnd: newTariff.timeEnd || undefined,
        isDefault: false,
      }
      setTariffRates([...tariffRates, tariff])
      setNewTariff({ name: "", rate: "", currency: "USD", timeStart: "", timeEnd: "" })
    }
  }

  const removeTariffRate = (id: string) => {
    setTariffRates(tariffRates.filter((t) => t.id !== id))
  }

  const setDefaultTariff = (id: string) => {
    setTariffRates(
      tariffRates.map((t) => ({
        ...t,
        isDefault: t.id === id,
      })),
    )
  }

  const calculateExampleCost = (consumption: number, rate: number) => {
    return (consumption * rate).toFixed(2)
  }

  const addNewShift = () => {
    const newShift: Shift = {
      id: Date.now().toString(),
      name: `Shift ${shifts.length + 1}`,
      startTime: "09:00",
      endTime: "17:00",
      operatingDays: ["Mon", "Tue", "Wed", "Thu", "Fri"],
    }
    setShifts([...shifts, newShift])
  }

  const removeShift = (id: string) => {
    if (shifts.length > 1) {
      setShifts(shifts.filter((shift) => shift.id !== id))
    }
  }

  const updateShift = (id: string, field: keyof Shift, value: string | string[]) => {
    setShifts(shifts.map((shift) => (shift.id === id ? { ...shift, [field]: value } : shift)))
  }

  const toggleOperatingDay = (shiftId: string, day: string) => {
    setShifts(
      shifts.map((shift) => {
        if (shift.id === shiftId) {
          const operatingDays = shift.operatingDays.includes(day)
            ? shift.operatingDays.filter((d) => d !== day)
            : [...shift.operatingDays, day]
          return { ...shift, operatingDays }
        }
        return shift
      }),
    )
  }

  const saveChanges = async () => {
    try {
      await settingsApi.update({ tariff_rates: tariffRates, shifts })
      setStatus("Operation settings saved.")
    } catch {
      setStatus("Unable to save operation settings.")
    }
  }

  return (
    <div className="space-y-4 sm:space-y-6">
      {/* Energy Tariff Section */}
      <Card className="bg-[#1B1B1B] border-[#2A2A2A] text-[#EDEDED]">
        <CardHeader className="pb-4 sm:pb-6">
          <CardTitle className="flex items-center gap-2 text-base sm:text-lg">
            <DollarSign className="h-4 w-4 sm:h-5 sm:w-5 text-[#FF6B00]" />
            Energy Tariff Configuration
          </CardTitle>
          <CardDescription className="text-[#9A9A9A] text-sm">
            Set up energy tariff rates for cost calculations. Formula: Energy Consumption × Tariff Rate = Cost
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4 sm:space-y-6">
          {/* Current Tariff Rates */}
          <div className="space-y-3 sm:space-y-4">
            <h4 className="font-semibold text-[#EDEDED] text-sm sm:text-base">Current Tariff Rates</h4>
            <div className="grid gap-3 sm:gap-4">
              {tariffRates.map((tariff) => (
                <div
                  key={tariff.id}
                  className={`border rounded-lg p-3 sm:p-4 ${
                    tariff.isDefault ? "border-[#FF6B00]/50 bg-[#FF6B00]/5" : "border-[#2A2A2A]"
                  }`}
                >
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between sm:gap-4">
                    <div className="flex-1 space-y-2">
                      <div className="flex items-center gap-2">
                        <h5 className="font-medium text-[#EDEDED] text-sm sm:text-base">{tariff.name}</h5>
                        {tariff.isDefault && (
                          <span className="px-2 py-1 text-xs bg-[#FF6B00]/20 text-[#FF6B00] rounded-full">Default</span>
                        )}
                      </div>
                      <div className="flex flex-col sm:flex-row sm:flex-wrap sm:items-center gap-2 sm:gap-4 text-xs sm:text-sm text-[#9A9A9A]">
                        <span className="flex items-center gap-1">
                          <DollarSign className="h-3 w-3" />
                          {tariff.rate.toFixed(3)} {tariff.currency}/kWh
                        </span>
                        {tariff.timeStart && tariff.timeEnd && (
                          <span className="flex items-center gap-1">
                            <Clock className="h-3 w-3" />
                            {tariff.timeStart} - {tariff.timeEnd}
                          </span>
                        )}
                        <span className="flex items-center gap-1">
                          <Calculator className="h-3 w-3" />
                          Example: 1000 kWh = ${calculateExampleCost(1000, tariff.rate)}
                        </span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {!tariff.isDefault && (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setDefaultTariff(tariff.id)}
                          disabled={!isAdmin}
                          className="border-[#2A2A2A] hover:bg-[#2A2A2A] bg-transparent text-xs h-8 px-3 touch-manipulation"
                        >
                          Set Default
                        </Button>
                      )}
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => removeTariffRate(tariff.id)}
                        disabled={!isAdmin || tariff.isDefault}
                        className="text-red-400 hover:bg-red-600/20 hover:text-red-300 h-8 w-8 touch-manipulation"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <Separator className="bg-[#2A2A2A]" />

          {/* Add New Tariff Rate */}
          <fieldset disabled={!isAdmin} className="disabled:opacity-50">
            <div className="space-y-3 sm:space-y-4">
              <h4 className="font-semibold text-[#EDEDED] text-sm sm:text-base">Add New Tariff Rate</h4>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 sm:gap-4">
                <div className="space-y-2">
                  <Label htmlFor="tariff-name" className="text-sm font-medium">
                    Rate Name
                  </Label>
                  <Input
                    id="tariff-name"
                    placeholder="e.g., Peak Hours"
                    value={newTariff.name}
                    onChange={(e) => setNewTariff({ ...newTariff, name: e.target.value })}
                    className="bg-[#0E0E0E] border-[#2A2A2A] h-10 sm:h-11"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="tariff-rate" className="text-sm font-medium">
                    Rate (per kWh)
                  </Label>
                  <Input
                    id="tariff-rate"
                    type="number"
                    step="0.001"
                    placeholder="0.120"
                    value={newTariff.rate}
                    onChange={(e) => setNewTariff({ ...newTariff, rate: e.target.value })}
                    className="bg-[#0E0E0E] border-[#2A2A2A] h-10 sm:h-11"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="tariff-currency" className="text-sm font-medium">
                    Currency
                  </Label>
                  <Select
                    value={newTariff.currency}
                    onValueChange={(value) => setNewTariff({ ...newTariff, currency: value })}
                  >
                    <SelectTrigger className="bg-[#0E0E0E] border-[#2A2A2A] h-10 sm:h-11">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="bg-[#1B1B1B] border-[#2A2A2A] text-[#EDEDED]">
                      <SelectItem value="USD">USD</SelectItem>
                      <SelectItem value="EUR">EUR</SelectItem>
                      <SelectItem value="GBP">GBP</SelectItem>
                      <SelectItem value="JPY">JPY</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="tariff-start" className="text-sm font-medium">
                    Start Time (Optional)
                  </Label>
                  <Input
                    id="tariff-start"
                    type="time"
                    value={newTariff.timeStart}
                    onChange={(e) => setNewTariff({ ...newTariff, timeStart: e.target.value })}
                    className="bg-[#0E0E0E] border-[#2A2A2A] h-10 sm:h-11"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="tariff-end" className="text-sm font-medium">
                    End Time (Optional)
                  </Label>
                  <Input
                    id="tariff-end"
                    type="time"
                    value={newTariff.timeEnd}
                    onChange={(e) => setNewTariff({ ...newTariff, timeEnd: e.target.value })}
                    className="bg-[#0E0E0E] border-[#2A2A2A] h-10 sm:h-11"
                  />
                </div>
                <div className="flex items-end">
                  <Button
                    onClick={addTariffRate}
                    className="bg-[#FF6B00] hover:bg-[#E55A00] text-black w-full h-10 sm:h-11 touch-manipulation"
                  >
                    <Plus className="mr-2 h-4 w-4" />
                    Add Rate
                  </Button>
                </div>
              </div>
            </div>
          </fieldset>
        </CardContent>
      </Card>

      {/* Operation Hours Section */}
      <Card className="bg-[#1B1B1B] border-[#2A2A2A] text-[#EDEDED]">
        <CardHeader className="pb-4 sm:pb-6">
          <CardTitle className="flex items-center gap-2 text-base sm:text-lg">
            <Clock className="h-4 w-4 sm:h-5 sm:w-5 text-[#FF6B00]" />
            Operation Hours
          </CardTitle>
          <CardDescription className="text-[#9A9A9A] text-sm">
            Define company-wide operation hours for accurate reporting and shift management.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4 sm:space-y-6">
          <fieldset disabled={!isAdmin} className="disabled:opacity-50">
            <div className="space-y-3 sm:space-y-4">
              {shifts.map((shift, index) => (
                <div key={shift.id} className="border border-[#2A2A2A] p-3 sm:p-4 rounded-lg space-y-3 sm:space-y-4">
                  <div className="flex items-center justify-between gap-3">
                    <Input
                      value={shift.name}
                      onChange={(e) => updateShift(shift.id, "name", e.target.value)}
                      className="font-semibold bg-transparent border-none p-0 h-auto text-[#EDEDED] focus-visible:ring-0 text-sm sm:text-base"
                      disabled={!isAdmin}
                    />
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => removeShift(shift.id)}
                      disabled={!isAdmin || shifts.length <= 1}
                      className="text-red-400 hover:bg-red-600/20 hover:text-red-300 h-8 w-8 flex-shrink-0 touch-manipulation"
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 sm:gap-4">
                    <div>
                      <Label htmlFor={`start-time-${shift.id}`} className="text-sm font-medium">
                        Start Time
                      </Label>
                      <Input
                        id={`start-time-${shift.id}`}
                        type="time"
                        value={shift.startTime}
                        onChange={(e) => updateShift(shift.id, "startTime", e.target.value)}
                        className="bg-[#0E0E0E] border-[#2A2A2A] h-10 sm:h-11 mt-2"
                        disabled={!isAdmin}
                      />
                    </div>
                    <div>
                      <Label htmlFor={`end-time-${shift.id}`} className="text-sm font-medium">
                        End Time
                      </Label>
                      <Input
                        id={`end-time-${shift.id}`}
                        type="time"
                        value={shift.endTime}
                        onChange={(e) => updateShift(shift.id, "endTime", e.target.value)}
                        className="bg-[#0E0E0E] border-[#2A2A2A] h-10 sm:h-11 mt-2"
                        disabled={!isAdmin}
                      />
                    </div>
                  </div>
                  <div>
                    <Label className="text-sm font-medium">Operating Days</Label>
                    <div className="flex flex-wrap gap-3 sm:gap-4 mt-2">
                      {days.map((day) => (
                        <div key={day} className="flex items-center gap-2">
                          <Checkbox
                            id={`${shift.id}-day-${day}`}
                            checked={shift.operatingDays.includes(day)}
                            onCheckedChange={() => toggleOperatingDay(shift.id, day)}
                            disabled={!isAdmin}
                            className="h-4 w-4"
                          />
                          <Label
                            htmlFor={`${shift.id}-day-${day}`}
                            className="text-sm font-normal cursor-pointer touch-manipulation"
                          >
                            {day}
                          </Label>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>
            <Button
              onClick={addNewShift}
              variant="outline"
              className="mt-4 border-[#2A2A2A] hover:bg-[#2A2A2A] bg-transparent h-10 sm:h-11 touch-manipulation w-full sm:w-auto"
              disabled={!isAdmin}
            >
              <Plus className="mr-2 h-4 w-4" />
              Add Another Shift
            </Button>
          </fieldset>
        </CardContent>
      </Card>

      {/* Save Changes */}
      <div className="flex justify-end pt-4 border-t border-[#2A2A2A]">
        <Button
          disabled={!isAdmin}
          onClick={saveChanges}
          className="bg-[#FF6B00] hover:bg-[#E55A00] text-black disabled:opacity-50 disabled:cursor-not-allowed h-10 sm:h-11 px-6 touch-manipulation w-full sm:w-auto"
        >
          Save All Changes
        </Button>
      </div>
      {status && <p className="text-right text-xs text-[#9A9A9A]">{status}</p>}
    </div>
  )
}
