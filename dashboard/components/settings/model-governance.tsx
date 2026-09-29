"use client"

import { useState } from "react"
import { AlertTriangle, BrainCircuit, CheckCircle2, Download, LockKeyhole, RotateCcw, ShieldCheck } from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Input } from "@/components/ui/input"
import { settingsApi } from "@/lib/api"
import { useEffect } from "react"

const metrics = [
  ["Precision", "100%", "No benign incidents were classified as attacks in the held-out test set."],
  ["Recall", "100%", "All synthetic attack samples were detected in the held-out test set."],
  ["F1 score", "100%", "Balanced precision and recall for the development benchmark."],
  ["ROC-AUC", "100%", "Perfect ranking on this synthetic evaluation split."],
  ["PR-AUC", "100%", "Perfect precision-recall ranking on this synthetic evaluation split."],
  ["Test samples", "100", "75% training split and 25% held-out evaluation split."],
] as const

const confusionMatrix = [[47, 0], [0, 53]]
const featureWeights = [
  ["has_privilege_escalation", 1.0103],
  ["has_suspicious_process", 0.9374],
  ["has_auth_attack", 0.6734],
  ["has_network_activity", 0.669],
  ["correlation_count", 0.5197],
  ["mitre_count", 0.3145],
]

export function ModelGovernance({ isAdmin }: { isAdmin: boolean }) {
  const [highThreshold, setHighThreshold] = useState("50")
  const [criticalThreshold, setCriticalThreshold] = useState("75")
  const [approved, setApproved] = useState(false)
  const [applied, setApplied] = useState(false)
  const [status, setStatus] = useState<string | null>(null)

  useEffect(() => {
    settingsApi.get().then((settings) => {
      setHighThreshold(String(settings.high_threshold))
      setCriticalThreshold(String(settings.critical_threshold))
    }).catch(() => setStatus("Unable to load saved model policy settings."))
  }, [])

  const hasValidThresholds = Number(highThreshold) >= 1 && Number(highThreshold) < Number(criticalThreshold) && Number(criticalThreshold) <= 100

  const downloadReport = () => {
    const report = [
      "IncidentForge Model Governance Report",
      "Model: baseline_logistic_regression v1.0",
      "Dataset: 400 synthetic development samples, seed 42",
      "Precision: 1.0 | Recall: 1.0 | F1: 1.0 | ROC-AUC: 1.0 | PR-AUC: 1.0",
      "Confusion matrix: [[47, 0], [0, 53]]",
      "Warning: These metrics are not production benchmark results.",
    ].join("\n")
    const blob = new Blob([report], { type: "text/plain" })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement("a")
    anchor.href = url
    anchor.download = "incidentforge-model-governance.txt"
    anchor.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-4 sm:space-y-6">
      <Card className="border-amber-400/30 bg-amber-400/[0.06] text-[#EDEDED]">
        <CardContent className="flex items-start gap-3 p-4 sm:p-5">
          <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-300" />
          <div>
            <div className="font-semibold text-amber-200">Development baseline, not production validation</div>
            <p className="mt-1 text-xs leading-relaxed text-amber-100/70">The perfect scores below come from a deliberately separable synthetic SOC dataset. This model is useful for demonstrating transparent risk ranking, but it needs representative telemetry before production claims.</p>
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-4 xl:grid-cols-[1.2fr_0.8fr]">
        <Card className="border-[#2A2A2A] bg-[#1B1B1B] text-[#EDEDED]">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base sm:text-lg"><BrainCircuit className="h-5 w-5 text-[#FF6B00]" />Model status</CardTitle>
            <CardDescription className="text-[#9A9A9A]">The model used to prioritize incidents and dataset-security attack chains.</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-3 sm:grid-cols-2">
            {[["Model", "baseline_logistic_regression"], ["Version", "v1.0"], ["Training data", "400 synthetic incidents"], ["Training seed", "42"], ["Runtime", "Deterministic inference"], ["Artifact", "Metadata fallback active"]].map(([label, value]) => <div key={label} className="rounded-lg border border-[#2A2A2A] bg-[#0E0E0E] p-3"><div className="text-[10px] uppercase tracking-wider text-[#777]">{label}</div><div className="mt-1 break-words font-mono text-xs text-[#EDEDED]">{value}</div></div>)}
          </CardContent>
        </Card>

        <Card className="border-[#2A2A2A] bg-[#1B1B1B] text-[#EDEDED]">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base sm:text-lg"><ShieldCheck className="h-5 w-5 text-emerald-400" />Risk policy</CardTitle>
            <CardDescription className="text-[#9A9A9A]">Preview thresholds before they affect incident priority labels.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-2 gap-3"><label className="text-xs text-[#9A9A9A]">High starts at<Input value={highThreshold} onChange={(event) => { setHighThreshold(event.target.value); setApplied(false) }} type="number" min="1" max="99" className="mt-1 bg-[#0E0E0E] border-[#2A2A2A]" /></label><label className="text-xs text-[#9A9A9A]">Critical starts at<Input value={criticalThreshold} onChange={(event) => { setCriticalThreshold(event.target.value); setApplied(false) }} type="number" min="2" max="100" className="mt-1 bg-[#0E0E0E] border-[#2A2A2A]" /></label></div>
            <div className="rounded border border-[#2A2A2A] bg-[#0E0E0E] p-3 font-mono text-[10px] text-[#9A9A9A]">LOW 0-{Number(highThreshold) - 1} · HIGH {highThreshold}-{Number(criticalThreshold) - 1} · CRITICAL {criticalThreshold}-100</div>
            <label className="flex items-start gap-2 text-xs text-[#9A9A9A]"><Checkbox checked={approved} onCheckedChange={(value) => setApproved(value === true)} disabled={!isAdmin} /><span>I approve this staged policy preview for analyst review.</span></label>
            <Button disabled={!isAdmin || !approved || !hasValidThresholds} onClick={async () => {
              try {
                await settingsApi.update({ high_threshold: Number(highThreshold), critical_threshold: Number(criticalThreshold) })
                setApplied(true)
                setStatus("Model policy thresholds saved.")
              } catch {
                setStatus("Unable to save model policy thresholds.")
              }
            }} className="w-full bg-[#FF6B00] text-black hover:bg-[#E55A00]">{applied ? "Policy staged for audit" : "Approve and stage change"}</Button>
            {!isAdmin && <div className="flex items-center gap-2 text-[10px] text-amber-300"><LockKeyhole size={12} />Admin role required for model-policy changes.</div>}
            {applied && <div className="flex items-center gap-2 text-[10px] text-emerald-300"><CheckCircle2 size={12} />No backend model changed. This prototype records the approval state for demonstration.</div>}
          </CardContent>
        </Card>
      </div>

      {status && <p className="text-right text-xs text-[#9A9A9A]">{status}</p>}

      <Card className="border-[#2A2A2A] bg-[#1B1B1B] text-[#EDEDED]">
        <CardHeader className="flex-row items-center justify-between gap-3"><div><CardTitle className="text-base sm:text-lg">Held-out evaluation metrics</CardTitle><CardDescription className="text-[#9A9A9A]">Synthetic test split: 100 samples, evaluated after offline training.</CardDescription></div><Button onClick={downloadReport} variant="outline" className="border-[#FF6B00]/40 bg-transparent text-[#FFB15C] hover:bg-[#FF6B00]/10"><Download className="mr-2 h-4 w-4" />Export</Button></CardHeader>
        <CardContent className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">{metrics.map(([label, value, detail]) => <div key={label} className="rounded-lg border border-[#2A2A2A] bg-[#0E0E0E] p-4"><div className="text-[10px] uppercase tracking-wider text-[#777]">{label}</div><div className="mt-1 font-mono text-2xl font-semibold text-[#FFB15C]">{value}</div><div className="mt-1 text-[10px] leading-relaxed text-[#777]">{detail}</div></div>)}</CardContent>
      </Card>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card className="border-[#2A2A2A] bg-[#1B1B1B] text-[#EDEDED]"><CardHeader><CardTitle className="text-base sm:text-lg">Confusion matrix</CardTitle><CardDescription className="text-[#9A9A9A]">Rows are actual labels; columns are predicted labels.</CardDescription></CardHeader><CardContent><div className="grid grid-cols-3 gap-1 text-center text-xs"><div /><div className="bg-[#0E0E0E] p-3 text-[#777]">Predicted benign</div><div className="bg-[#0E0E0E] p-3 text-[#777]">Predicted attack</div><div className="bg-[#0E0E0E] p-3 text-left text-[#777]">Actual benign</div><div className="bg-emerald-400/10 p-4 font-mono text-emerald-300">{confusionMatrix[0][0]} TN</div><div className="bg-red-400/10 p-4 font-mono text-red-300">{confusionMatrix[0][1]} FP</div><div className="bg-[#0E0E0E] p-3 text-left text-[#777]">Actual attack</div><div className="bg-red-400/10 p-4 font-mono text-red-300">{confusionMatrix[1][0]} FN</div><div className="bg-emerald-400/10 p-4 font-mono text-emerald-300">{confusionMatrix[1][1]} TP</div></div></CardContent></Card>
        <Card className="border-[#2A2A2A] bg-[#1B1B1B] text-[#EDEDED]"><CardHeader><CardTitle className="text-base sm:text-lg">Top risk drivers</CardTitle><CardDescription className="text-[#9A9A9A]">Learned feature weights from the stored synthetic baseline.</CardDescription></CardHeader><CardContent className="space-y-3">{featureWeights.map(([name, weight]) => <div key={name}><div className="flex justify-between gap-3 text-xs"><span className="truncate font-mono text-[#BDBDBD]">{name}</span><span className="font-mono text-[#FFB15C]">+{weight}</span></div><div className="mt-1 h-1.5 overflow-hidden rounded-full bg-[#2A2A2A]"><div className="h-full rounded-full bg-[#FF6B00]" style={{ width: `${Math.min(100, Number(weight) * 75)}%` }} /></div></div>)}</CardContent></Card>
      </div>

      <Card className="border-red-400/20 bg-red-400/[0.04] text-[#EDEDED]"><CardContent className="flex items-start gap-3 p-4"><RotateCcw className="mt-0.5 h-4 w-4 shrink-0 text-red-300" /><div className="text-xs leading-relaxed text-[#AFAFAF]"><span className="font-semibold text-red-200">Compatibility review required:</span> stored metadata reports feature version v1.0, while the current runtime extractor is v2.0 with dataset-security features. Retraining and artifact alignment should happen before treating dataset-security scoring as production-ready.</div></CardContent></Card>
    </div>
  )
}
