"use client"

import type React from "react"
import { useState, useEffect } from "react"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"
import { useMetersLoading } from "@/lib/store/hooks"
import type { MeterData } from "@/lib/store/types"

interface MeterEditDialogProps {
  isOpen: boolean
  setIsOpen: (open: boolean) => void
  meter: MeterData | null
}

export function MeterEditDialog({ isOpen, setIsOpen, meter }: MeterEditDialogProps) {
  const loading = useMetersLoading()
  const [formData, setFormData] = useState({
    name: "",
    location: "",
    type: "3-Phase Digital",
    status: "online" as "online" | "offline" | "maintenance",
  })

  useEffect(() => {
    if (meter) {
      setFormData({
        name: meter.name,
        location: meter.location,
        type: meter.type,
        status: meter.status,
      })
    } else {
      setFormData({
        name: "",
        location: "",
        type: "3-Phase Digital",
        status: "online",
      })
    }
  }, [meter, isOpen])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    if (meter) {
      // TODO: Implement update meter action
      console.log("Updating meter:", meter.id, formData)
    } else {
      // TODO: Implement create meter action
      console.log("Creating new meter:", formData)
    }

    setIsOpen(false)
  }

  const meterTypes = [
    "3-Phase Digital",
    "3-Phase Analog",
    "Single Phase Digital",
    "Single Phase Analog",
    "3-Phase Industrial",
    "3-Phase Commercial",
    "Smart Meter",
    "IoT Meter",
  ]

  return (
    <Dialog open={isOpen} onOpenChange={setIsOpen}>
      <DialogContent className="bg-[#1B1B1B] border-[#2A2A2A] text-[#EDEDED] sm:max-w-[500px]">
        <DialogHeader>
          <DialogTitle>{meter ? "Edit Meter" : "Add New Meter"}</DialogTitle>
          <DialogDescription className="text-[#9A9A9A]">
            {meter ? "Update the meter's configuration." : "Add a new meter to the system."}
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit}>
          <div className="grid gap-4 py-4">
            <div className="grid grid-cols-4 items-center gap-4">
              <Label htmlFor="meter-name" className="text-right text-[#9A9A9A]">
                Name
              </Label>
              <Input
                id="meter-name"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                className="col-span-3 bg-[#0E0E0E] border-[#2A2A2A]"
                placeholder="e.g., Main Distribution Panel"
                required
              />
            </div>

            <div className="grid grid-cols-4 items-start gap-4">
              <Label htmlFor="meter-location" className="text-right text-[#9A9A9A] pt-2">
                Location
              </Label>
              <Textarea
                id="meter-location"
                value={formData.location}
                onChange={(e) => setFormData({ ...formData, location: e.target.value })}
                className="col-span-3 bg-[#0E0E0E] border-[#2A2A2A] min-h-[60px]"
                placeholder="e.g., Building A - Ground Floor"
                required
              />
            </div>

            <div className="grid grid-cols-4 items-center gap-4">
              <Label htmlFor="meter-type" className="text-right text-[#9A9A9A]">
                Type
              </Label>
              <Select value={formData.type} onValueChange={(value) => setFormData({ ...formData, type: value })}>
                <SelectTrigger className="col-span-3 bg-[#0E0E0E] border-[#2A2A2A]">
                  <SelectValue placeholder="Select meter type" />
                </SelectTrigger>
                <SelectContent className="bg-[#1B1B1B] border-[#2A2A2A] text-[#EDEDED]">
                  {meterTypes.map((type) => (
                    <SelectItem key={type} value={type} className="cursor-pointer hover:!bg-[#2A2A2A]">
                      {type}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="grid grid-cols-4 items-center gap-4">
              <Label htmlFor="meter-status" className="text-right text-[#9A9A9A]">
                Status
              </Label>
              <Select
                value={formData.status}
                onValueChange={(value: "online" | "offline" | "maintenance") =>
                  setFormData({ ...formData, status: value })
                }
              >
                <SelectTrigger className="col-span-3 bg-[#0E0E0E] border-[#2A2A2A]">
                  <SelectValue placeholder="Select status" />
                </SelectTrigger>
                <SelectContent className="bg-[#1B1B1B] border-[#2A2A2A] text-[#EDEDED]">
                  <SelectItem value="online" className="cursor-pointer hover:!bg-[#2A2A2A]">
                    <div className="flex items-center gap-2">
                      <div className="w-2 h-2 bg-green-400 rounded-full" />
                      Online
                    </div>
                  </SelectItem>
                  <SelectItem value="offline" className="cursor-pointer hover:!bg-[#2A2A2A]">
                    <div className="flex items-center gap-2">
                      <div className="w-2 h-2 bg-red-400 rounded-full" />
                      Offline
                    </div>
                  </SelectItem>
                  <SelectItem value="maintenance" className="cursor-pointer hover:!bg-[#2A2A2A]">
                    <div className="flex items-center gap-2">
                      <div className="w-2 h-2 bg-orange-400 rounded-full" />
                      Maintenance
                    </div>
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => setIsOpen(false)}
              className="bg-transparent border-[#2A2A2A] hover:bg-[#2A2A2A]"
            >
              Cancel
            </Button>
            <Button
              type="submit"
              disabled={loading || !formData.name || !formData.location}
              className="bg-[#FF6B00] hover:bg-[#E55A00] text-black"
            >
              {loading ? "Saving..." : meter ? "Update Meter" : "Add Meter"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
