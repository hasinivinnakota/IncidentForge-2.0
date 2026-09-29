"use client"

import { useState, useEffect, useRef } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useSelectedMeter } from "@/lib/store/hooks"
import { Clock, Activity } from "lucide-react"
import type { MeterData } from "@/lib/store/types"

type Reading = Pick<MeterData, "kpiData" | "timestamp">

const MAX_HISTORY_LENGTH = 10

export function MeterReadingsHistoryTable() {
  const selectedMeter = useSelectedMeter()
  const [history, setHistory] = useState<Reading[]>([])
  const lastTimestampRef = useRef<string | undefined>()

  useEffect(() => {
    if (selectedMeter && selectedMeter.timestamp && selectedMeter.timestamp !== lastTimestampRef.current) {
      const newReading: Reading = {
        kpiData: selectedMeter.kpiData,
        timestamp: selectedMeter.timestamp,
      }

      setHistory((prevHistory) => {
        const updatedHistory = [newReading, ...prevHistory]
        if (updatedHistory.length > MAX_HISTORY_LENGTH) {
          return updatedHistory.slice(0, MAX_HISTORY_LENGTH)
        }
        return updatedHistory
      })

      lastTimestampRef.current = selectedMeter.timestamp
    }
  }, [selectedMeter])

  if (!selectedMeter) {
    return null
  }

  const isThreePhase = selectedMeter.type.includes("3-Phase")

  return (
    <Card className="bg-[#1B1B1B] border-[#2A2A2A] text-[#EDEDED]">
      <CardHeader className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
        <CardTitle className="flex items-center gap-2">
          <Activity className="h-5 w-5 text-[#FF6B00]" />
          Live Meter Readings
        </CardTitle>
        <div className="flex items-center gap-2 text-sm text-[#9A9A9A]">
          <Clock className="h-4 w-4" />
          <span>Updates every 5 seconds</span>
        </div>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto">
          <Table className="text-xs min-w-[640px]">
            <TableHeader>
              <TableRow className="border-b-[#2A2A2A] hover:bg-transparent">
                <TableHead className="w-28 text-[#9A9A9A]">Timestamp</TableHead>
                {isThreePhase ? (
                  <>
                    <TableHead className="text-right text-[#9A9A9A]">V L1</TableHead>
                    <TableHead className="text-right text-[#9A9A9A]">V L2</TableHead>
                    <TableHead className="text-right text-[#9A9A9A]">V L3</TableHead>
                    <TableHead className="text-right text-[#9A9A9A]">A L1</TableHead>
                    <TableHead className="text-right text-[#9A9A9A]">A L2</TableHead>
                    <TableHead className="text-right text-[#9A9A9A]">A L3</TableHead>
                  </>
                ) : (
                  <>
                    <TableHead className="text-right text-[#9A9A9A]">Voltage</TableHead>
                    <TableHead className="text-right text-[#9A9A9A]">Current</TableHead>
                  </>
                )}
                <TableHead className="text-right text-[#9A9A9A]">kW</TableHead>
                <TableHead className="text-right text-[#9A9A9A]">PF</TableHead>
                <TableHead className="text-right text-[#9A9A9A]">Hz</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {history.length > 0 ? (
                history.map((reading, index) => (
                  <TableRow
                    key={reading.timestamp}
                    className={`border-b-[#2A2A2A] hover:bg-[#1F1F1F] transition-opacity duration-500 ${
                      index === 0 ? "opacity-100 bg-[#FF6B00]/5" : "opacity-80"
                    }`}
                  >
                    <TableCell className="font-mono text-[#9A9A9A]">
                      {new Date(reading.timestamp!).toLocaleTimeString()}
                    </TableCell>
                    {isThreePhase ? (
                      <>
                        <TableCell className="text-right font-mono text-[#EDEDED]">
                          {reading.kpiData.voltage.l1}
                        </TableCell>
                        <TableCell className="text-right font-mono text-[#EDEDED]">
                          {reading.kpiData.voltage.l2}
                        </TableCell>
                        <TableCell className="text-right font-mono text-[#EDEDED]">
                          {reading.kpiData.voltage.l3}
                        </TableCell>
                        <TableCell className="text-right font-mono text-[#EDEDED]">
                          {reading.kpiData.current.l1}
                        </TableCell>
                        <TableCell className="text-right font-mono text-[#EDEDED]">
                          {reading.kpiData.current.l2}
                        </TableCell>
                        <TableCell className="text-right font-mono text-[#EDEDED]">
                          {reading.kpiData.current.l3}
                        </TableCell>
                      </>
                    ) : (
                      <>
                        <TableCell className="text-right font-mono text-[#EDEDED]">
                          {reading.kpiData.voltage.l1}
                        </TableCell>
                        <TableCell className="text-right font-mono text-[#EDEDED]">
                          {reading.kpiData.current.l1}
                        </TableCell>
                      </>
                    )}
                    <TableCell className="text-right font-mono text-[#EDEDED]">{reading.kpiData.activePower}</TableCell>
                    <TableCell className="text-right font-mono text-[#EDEDED]">{reading.kpiData.powerFactor}</TableCell>
                    <TableCell className="text-right font-mono text-[#EDEDED]">{reading.kpiData.frequency}</TableCell>
                  </TableRow>
                ))
              ) : (
                <TableRow className="border-b-[#2A2A2A]">
                  <TableCell colSpan={isThreePhase ? 10 : 6} className="text-center text-[#9A9A9A] h-24">
                    Waiting for first reading...
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  )
}
