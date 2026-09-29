"use client"

import { useEffect, useState } from "react"
import { BarChart3, Cpu, Database, CheckCircle2, AlertTriangle, Clock } from "lucide-react"

interface ModelMetadata {
  model_name: string
  model_version: string
  feature_version: string
  training_timestamp: string
  features: string[]
  weights: Record<string, number>
  intercept: number
  evaluation_metrics: {
    precision: number
    recall: number
    f1: number
    roc_auc: number
  }
  dataset_info: {
    type: string
    n_samples: number
    seed: number
    note: string
  }
}

const METRICS = [
  {
    key: "binary_f1",
    label: "Binary F1",
    value: 0.9943,
    target: 0.95,
    color: "text-emerald-400",
    bar: "bg-emerald-400",
  },
  {
    key: "binary_accuracy",
    label: "Binary Accuracy",
    value: 0.996,
    target: 0.95,
    color: "text-emerald-400",
    bar: "bg-emerald-400",
  },
  {
    key: "four_class_f1",
    label: "4-Class Macro F1",
    value: 0.4583,
    target: 0.82,
    color: "text-orange-400",
    bar: "bg-orange-400",
  },
  {
    key: "four_class_accuracy",
    label: "4-Class Accuracy",
    value: 0.5618,
    target: 0.82,
    color: "text-orange-400",
    bar: "bg-orange-400",
  },
]

const CLASS_METRICS = [
  { label: "low", precision: 0.557, recall: 1.0, f1: 0.715, support: 88 },
  { label: "medium", precision: 0.833, recall: 0.067, f1: 0.124, support: 75 },
  { label: "high", precision: 1.0, recall: 0.2, f1: 0.333, support: 50 },
  { label: "critical", precision: 0.494, recall: 1.0, f1: 0.661, support: 38 },
]

const LEVEL_COLORS: Record<string, string> = {
  low: "text-blue-400 bg-blue-400/10 border-blue-400/20",
  medium: "text-yellow-400 bg-yellow-400/10 border-yellow-400/20",
  high: "text-orange-400 bg-orange-400/10 border-orange-400/20",
  critical: "text-red-400 bg-red-400/10 border-red-400/20",
}

function fmt(v: number) {
  return (v * 100).toFixed(1) + "%"
}

export default function ModelMetadataWidget() {
  const [meta, setMeta] = useState<ModelMetadata | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch("/api/v1/ml/artifacts")
      .then((r) => r.json())
      .then((d) => {
        setMeta(d)
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }, [])

  const trainedAt = meta?.training_timestamp
    ? new Date(meta.training_timestamp).toLocaleString()
    : "N/A"

  return (
    <div className="space-y-6 p-5">
      {/* Header bar */}
      <div className="flex items-center gap-3 rounded-lg border border-white/5 bg-black/20 px-4 py-3">
        <Cpu size={16} className="text-orange-400" />
        <div className="flex-1">
          <div className="font-mono text-xs font-semibold text-slate-200">
            {loading ? "Loading…" : meta?.model_name ?? "baseline_logistic_regression"}
          </div>
          <div className="mt-0.5 font-mono text-[10px] text-slate-500">
            {meta?.model_version ?? "v1.0"} · Feature set {meta?.feature_version ?? "v2.0"} · {meta?.features?.length ?? 23} features
          </div>
        </div>
        <div className="flex items-center gap-1.5 rounded bg-emerald-400/10 px-2 py-1 text-[10px] font-bold uppercase text-emerald-400">
          <CheckCircle2 size={10} />
          Active
        </div>
      </div>

      {/* Training info row */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div className="rounded border border-white/5 bg-[#14181b] p-3">
          <div className="text-[10px] uppercase tracking-wider text-slate-500">Trained At</div>
          <div className="mt-1 font-mono text-xs text-slate-200 leading-tight">{trainedAt}</div>
        </div>
        <div className="rounded border border-white/5 bg-[#14181b] p-3">
          <div className="text-[10px] uppercase tracking-wider text-slate-500">Train Samples</div>
          <div className="mt-1 font-mono text-sm font-bold text-orange-300">{meta?.dataset_info?.n_samples ?? 1000}</div>
        </div>
        <div className="rounded border border-white/5 bg-[#14181b] p-3">
          <div className="text-[10px] uppercase tracking-wider text-slate-500">Feature Count</div>
          <div className="mt-1 font-mono text-sm font-bold text-orange-300">{meta?.features?.length ?? 23}</div>
        </div>
        <div className="rounded border border-white/5 bg-[#14181b] p-3">
          <div className="text-[10px] uppercase tracking-wider text-slate-500">Data Type</div>
          <div className="mt-1 font-mono text-[10px] text-slate-300 leading-tight">
            {meta?.dataset_info?.type ?? "synthetic_development_data"}
          </div>
        </div>
      </div>

      {/* Evaluation Metrics */}
      <div>
        <div className="mb-3 text-[10px] font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
          <BarChart3 size={12} />
          Evaluation Metrics — Held-Out Test Set (251 samples)
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          {METRICS.map((m) => (
            <div key={m.key} className="rounded border border-white/5 bg-[#14181b] p-3">
              <div className="flex items-center justify-between">
                <span className="text-[11px] text-slate-400">{m.label}</span>
                <div className="flex items-center gap-2">
                  <span className={`font-mono text-sm font-bold ${m.color}`}>{fmt(m.value)}</span>
                  {m.value >= m.target ? (
                    <CheckCircle2 size={12} className="text-emerald-400" />
                  ) : (
                    <AlertTriangle size={12} className="text-orange-400" />
                  )}
                </div>
              </div>
              {/* Progress bar */}
              <div className="mt-2 h-1 w-full rounded-full bg-white/5">
                <div
                  className={`h-1 rounded-full ${m.bar} transition-all`}
                  style={{ width: `${Math.min(m.value * 100, 100)}%` }}
                />
              </div>
              <div className="mt-1 text-[9px] text-slate-600">Target: {fmt(m.target)}</div>
            </div>
          ))}
        </div>
      </div>

      {/* 4-Class per-class breakdown */}
      <div>
        <div className="mb-3 text-[10px] font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
          <Database size={12} />
          4-Class Risk Level Breakdown
        </div>
        <div className="overflow-x-auto rounded border border-white/5">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-white/5 bg-black/30">
                <th className="px-3 py-2 text-left font-mono text-[10px] uppercase tracking-wider text-slate-500">Class</th>
                <th className="px-3 py-2 text-right font-mono text-[10px] uppercase tracking-wider text-slate-500">Precision</th>
                <th className="px-3 py-2 text-right font-mono text-[10px] uppercase tracking-wider text-slate-500">Recall</th>
                <th className="px-3 py-2 text-right font-mono text-[10px] uppercase tracking-wider text-slate-500">F1</th>
                <th className="px-3 py-2 text-right font-mono text-[10px] uppercase tracking-wider text-slate-500">Support</th>
              </tr>
            </thead>
            <tbody>
              {CLASS_METRICS.map((row) => (
                <tr key={row.label} className="border-b border-white/5 hover:bg-white/[0.02]">
                  <td className="px-3 py-2">
                    <span className={`rounded border px-2 py-0.5 font-mono text-[10px] font-bold uppercase ${LEVEL_COLORS[row.label]}`}>
                      {row.label}
                    </span>
                  </td>
                  <td className={`px-3 py-2 text-right font-mono ${row.precision >= 0.7 ? "text-emerald-400" : "text-orange-400"}`}>
                    {fmt(row.precision)}
                  </td>
                  <td className={`px-3 py-2 text-right font-mono ${row.recall >= 0.5 ? "text-emerald-400" : "text-red-400"}`}>
                    {fmt(row.recall)}
                  </td>
                  <td className={`px-3 py-2 text-right font-mono font-bold ${row.f1 >= 0.6 ? "text-emerald-400" : "text-orange-400"}`}>
                    {fmt(row.f1)}
                  </td>
                  <td className="px-3 py-2 text-right font-mono text-slate-400">{row.support}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Hindsight Memory Status */}
      <div className="rounded border border-violet-400/20 bg-violet-400/[0.04] p-3">
        <div className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-wider text-violet-300">
          <Clock size={11} />
          Hindsight Memory Integration
        </div>
        <p className="mt-2 text-[11px] text-slate-400 leading-relaxed">
          Hindsight agent memory is <span className="font-semibold text-violet-300">integrated</span> into the AI Investigator.
          Set <code className="rounded bg-white/5 px-1 font-mono text-violet-200">HINDSIGHT_API_KEY</code> in your environment
          to enable live recall of past incident precedents, false positive suppression, and entity memory profiles.
        </p>
      </div>

      {/* Data disclaimer */}
      <div className="rounded border border-amber-400/20 bg-amber-400/[0.04] p-3 text-[10px] text-amber-200/80 leading-relaxed">
        <strong className="font-semibold">NOTE:</strong> Metrics are evaluated on 100% synthetic data.
        Results do not represent real-world SOC detection performance. Binary classification achieves strong
        separation; 4-class accuracy suffers from sigmoid saturation at extreme risk bins (middle-tier squashing).
        Planned fix: multi-class calibrated model (Platt scaling / LightGBM).
      </div>
    </div>
  )
}
