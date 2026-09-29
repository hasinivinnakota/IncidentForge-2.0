"use client"

import { useState, useEffect } from "react"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Button } from "@/components/ui/button"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { MoreHorizontal, PlusCircle, Edit, Trash2 } from "lucide-react"
import { useAppDispatch, useMeters, useMetersLoading } from "@/lib/store/hooks"
import { fetchMetersRequest } from "@/lib/store/slices/metersSlice"
import type { MeterData } from "@/lib/store/types"
import { MeterEditDialog } from "./meter-edit-dialog"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"

interface MeterManagementProps {
  isAdmin: boolean
}

export function MeterManagement({ isAdmin }: MeterManagementProps) {
  const dispatch = useAppDispatch()
  const meters = useMeters()
  const loading = useMetersLoading()
  const [isEditDialogOpen, setIsEditDialogOpen] = useState(false)
  const [isDeleteDialogOpen, setIsDeleteDialogOpen] = useState(false)
  const [selectedMeter, setSelectedMeter] = useState<MeterData | null>(null)

  useEffect(() => {
    dispatch(fetchMetersRequest())
  }, [dispatch])

  const handleAddMeter = () => {
    setSelectedMeter(null)
    setIsEditDialogOpen(true)
  }

  const handleEditMeter = (meter: MeterData) => {
    setSelectedMeter(meter)
    setIsEditDialogOpen(true)
  }

  const handleDeleteMeter = (meter: MeterData) => {
    setSelectedMeter(meter)
    setIsDeleteDialogOpen(true)
  }

  const confirmDelete = () => {
    if (selectedMeter) {
      // TODO: Implement delete meter action
      console.log("Deleting meter:", selectedMeter.id)
      setIsDeleteDialogOpen(false)
      setSelectedMeter(null)
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case "online":
        return "bg-green-600/20 text-green-400"
      case "offline":
        return "bg-red-600/20 text-red-400"
      case "maintenance":
        return "bg-orange-600/20 text-orange-400"
      default:
        return "bg-gray-600/20 text-gray-300"
    }
  }

  if (loading && meters.length === 0) {
    return (
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-base sm:text-lg font-medium text-[#EDEDED]">Meter Configuration</h3>
            <p className="text-sm text-[#9A9A9A] mt-1">Add, edit, or remove meters from the system.</p>
          </div>
          <div className="h-10 w-full sm:w-24 bg-[#1B1B1B] border border-[#2A2A2A] rounded animate-pulse" />
        </div>
        <div className="h-48 sm:h-64 bg-[#1B1B1B] border border-[#2A2A2A] rounded-lg animate-pulse" />
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h3 className="text-base sm:text-lg font-medium text-[#EDEDED]">Meter Configuration</h3>
          <p className="text-sm text-[#9A9A9A] mt-1">Add, edit, or remove meters from the system.</p>
        </div>
        <Button
          onClick={handleAddMeter}
          disabled={!isAdmin || loading}
          className="bg-[#FF6B00] hover:bg-[#E55A00] text-black disabled:opacity-50 disabled:cursor-not-allowed h-10 px-4 touch-manipulation w-full sm:w-auto"
        >
          <PlusCircle className="mr-2 h-4 w-4" />
          Add Meter
        </Button>
      </div>

      {/* Table Container */}
      <div className="border border-[#2A2A2A] rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent border-b-[#2A2A2A]">
                <TableHead className="text-[#9A9A9A] text-xs sm:text-sm">ID</TableHead>
                <TableHead className="text-[#9A9A9A] text-xs sm:text-sm">Name</TableHead>
                <TableHead className="text-[#9A9A9A] hidden sm:table-cell text-xs sm:text-sm">Location</TableHead>
                <TableHead className="text-[#9A9A9A] hidden md:table-cell text-xs sm:text-sm">Type</TableHead>
                <TableHead className="text-[#9A9A9A] text-xs sm:text-sm">Status</TableHead>
                <TableHead className="text-[#9A9A9A] hidden lg:table-cell text-xs sm:text-sm">Load</TableHead>
                <TableHead className="w-[50px]">
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {meters.map((meter) => (
                <TableRow key={meter.id} className="border-b-[#2A2A2A] hover:bg-[#1F1F1F]">
                  <TableCell className="font-mono text-xs text-[#9A9A9A] py-3 sm:py-4">{meter.id}</TableCell>
                  <TableCell className="font-medium text-[#EDEDED] py-3 sm:py-4">
                    <div>
                      <div className="font-medium text-sm sm:text-base">{meter.name}</div>
                      <div className="text-xs text-[#9A9A9A] sm:hidden mt-1">{meter.location}</div>
                    </div>
                  </TableCell>
                  <TableCell className="text-[#9A9A9A] hidden sm:table-cell text-sm">{meter.location}</TableCell>
                  <TableCell className="text-[#9A9A9A] hidden md:table-cell text-sm">{meter.type}</TableCell>
                  <TableCell className="py-3 sm:py-4">
                    <span className={`px-2 py-1 text-xs rounded-full ${getStatusColor(meter.status)}`}>
                      {meter.status}
                    </span>
                  </TableCell>
                  <TableCell className="text-[#9A9A9A] hidden lg:table-cell text-sm">
                    {meter.status === "online" ? `${meter.currentLoad.toFixed(1)}%` : "—"}
                  </TableCell>
                  <TableCell className="py-3 sm:py-4">
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button
                          variant="ghost"
                          className="h-8 w-8 p-0 touch-manipulation"
                          disabled={!isAdmin || loading}
                        >
                          <span className="sr-only">Open menu</span>
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end" className="bg-[#1B1B1B] border-[#2A2A2A] text-[#EDEDED]">
                        <DropdownMenuItem
                          onClick={() => handleEditMeter(meter)}
                          className="cursor-pointer hover:!bg-[#2A2A2A] py-2.5 px-3 touch-manipulation"
                        >
                          <Edit className="mr-2 h-4 w-4" /> Edit
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          onClick={() => handleDeleteMeter(meter)}
                          className="cursor-pointer text-red-400 hover:!bg-red-600/20 hover:!text-red-300 py-2.5 px-3 touch-manipulation"
                        >
                          <Trash2 className="mr-2 h-4 w-4" /> Delete
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 sm:gap-4 pt-4">
        <div className="bg-[#0E0E0E]/50 p-3 rounded-lg text-center">
          <div className="text-base sm:text-lg font-bold text-[#EDEDED]">{meters.length}</div>
          <div className="text-xs text-[#9A9A9A]">Total Meters</div>
        </div>
        <div className="bg-[#0E0E0E]/50 p-3 rounded-lg text-center">
          <div className="text-base sm:text-lg font-bold text-green-400">
            {meters.filter((m) => m.status === "online").length}
          </div>
          <div className="text-xs text-[#9A9A9A]">Online</div>
        </div>
        <div className="bg-[#0E0E0E]/50 p-3 rounded-lg text-center">
          <div className="text-base sm:text-lg font-bold text-red-400">
            {meters.filter((m) => m.status === "offline").length}
          </div>
          <div className="text-xs text-[#9A9A9A]">Offline</div>
        </div>
        <div className="bg-[#0E0E0E]/50 p-3 rounded-lg text-center">
          <div className="text-base sm:text-lg font-bold text-orange-400">
            {meters.filter((m) => m.status === "maintenance").length}
          </div>
          <div className="text-xs text-[#9A9A9A]">Maintenance</div>
        </div>
      </div>

      <MeterEditDialog isOpen={isEditDialogOpen} setIsOpen={setIsEditDialogOpen} meter={selectedMeter} />

      <AlertDialog open={isDeleteDialogOpen} onOpenChange={setIsDeleteDialogOpen}>
        <AlertDialogContent className="bg-[#1B1B1B] border-[#2A2A2A] text-[#EDEDED] mx-4 sm:mx-0 max-w-md sm:max-w-lg">
          <AlertDialogHeader>
            <AlertDialogTitle className="text-base sm:text-lg">Are you sure?</AlertDialogTitle>
            <AlertDialogDescription className="text-[#9A9A9A] text-sm">
              This action cannot be undone. This will permanently delete the meter "{selectedMeter?.name}" and all its
              associated data.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter className="flex-col sm:flex-row gap-2 sm:gap-0">
            <AlertDialogCancel className="bg-transparent border-[#2A2A2A] hover:bg-[#2A2A2A] h-10 touch-manipulation w-full sm:w-auto">
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={confirmDelete}
              className="bg-red-600 hover:bg-red-700 text-white h-10 touch-manipulation w-full sm:w-auto"
            >
              Delete Meter
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
