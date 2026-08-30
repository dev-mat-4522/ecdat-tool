"use client"

/** Compliance posture against published PQC mandates with real deadlines. */

import { useMemo, useState } from "react"
import { AlertTriangle, CheckCircle2, CircleSlash, MinusCircle } from "lucide-react"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { cn } from "@/lib/utils"
import type { ComplianceControl, CompliancePosture, ControlStatus } from "@/lib/ecdat/compliance"

const STATUS_META: Record<ControlStatus, { label: string; icon: typeof CheckCircle2; tone: string; ring: string }> = {
  pass: { label: "Pass", icon: CheckCircle2, tone: "text-low", ring: "border-low/35" },
  warn: { label: "Warn", icon: AlertTriangle, tone: "text-medium", ring: "border-medium/35" },
  fail: { label: "Fail", icon: CircleSlash, tone: "text-critical", ring: "border-critical/35" },
  "not-applicable": { label: "N/A", icon: MinusCircle, tone: "text-muted-foreground", ring: "border-border" },
}

const GRADE_TONE: Record<string, string> = {
  A: "text-low",
  B: "text-low",
  C: "text-medium",
  D: "text-high",
  F: "text-critical",
}

const DEADLINES = [
  { year: 2030, label: "RSA/ECC deprecated", source: "NIST IR 8547" },
  { year: 2030, label: "Classical signing exclusive-out", source: "CNSA 2.0" },
  { year: 2033, label: "PQC exclusive for NSS", source: "CNSA 2.0" },
  { year: 2035, label: "RSA/ECC disallowed", source: "NIST IR 8547" },
]

function ControlRow({ control }: { control: ComplianceControl }) {
  const [open, setOpen] = useState(false)
  const meta = STATUS_META[control.status]
  const Icon = meta.icon

  return (
    <Collapsible open={open} onOpenChange={setOpen}>
      <div className={cn("rounded-md border bg-secondary/25", open ? "border-primary/40" : meta.ring)}>
        <CollapsibleTrigger
          render={<button type="button" className="flex w-full items-start gap-3 p-3 text-left" />}
        >
          <Icon className={cn("mt-0.5 size-4 shrink-0", meta.tone)} aria-hidden="true" />
          <div className="flex min-w-0 flex-1 flex-col gap-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm font-medium text-foreground">{control.title}</span>
              <span className="rounded-sm border border-border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                {control.framework}
              </span>
            </div>
            <span className="font-mono text-[11px] text-muted-foreground">{control.deadline}</span>
          </div>
          <span className={cn("shrink-0 font-mono text-[11px] uppercase tracking-wider", meta.tone)}>{meta.label}</span>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <div className="flex flex-col gap-3 border-t border-border p-3">
            <p className="text-xs leading-relaxed text-muted-foreground">{control.requirement}</p>
            <p className="text-xs leading-relaxed text-foreground">{control.detail}</p>
            {control.offenders.length ? (
              <div className="flex flex-col gap-1">
                <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                  {control.status === "pass" ? "Evidence" : "Offending assets"}
                </span>
                <ul className="flex flex-col gap-0.5">
                  {control.offenders.slice(0, 10).map((offender) => (
                    <li key={`${offender.name}-${offender.location}`} className="font-mono text-[11px] text-muted-foreground">
                      <span className="text-foreground">{offender.name}</span> — {offender.location}
                    </li>
                  ))}
                  {control.offenders.length > 10 ? (
                    <li className="font-mono text-[11px] text-muted-foreground">
                      +{control.offenders.length - 10} more
                    </li>
                  ) : null}
                </ul>
              </div>
            ) : null}
          </div>
        </CollapsibleContent>
      </div>
    </Collapsible>
  )
}

export function CompliancePanel({ posture }: { posture: CompliancePosture }) {
  const currentYear = new Date().getFullYear()

  const grouped = useMemo(() => {
    const order: ControlStatus[] = ["fail", "warn", "pass", "not-applicable"]
    return [...posture.controls].sort((a, b) => order.indexOf(a.status) - order.indexOf(b.status))
  }, [posture.controls])

  return (
    <div className="flex flex-col gap-4">
      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardContent className="flex items-center gap-5">
            <div className="flex flex-col items-center">
              <span className={cn("tabular text-5xl font-semibold leading-none", GRADE_TONE[posture.grade])}>
                {posture.grade}
              </span>
              <span className="mt-1.5 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Grade</span>
            </div>
            <div className="flex flex-1 flex-col gap-2">
              <div className="flex items-baseline justify-between">
                <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Posture score</span>
                <span className="tabular font-mono text-sm text-foreground">{posture.score}/100</span>
              </div>
              <div className="h-2 overflow-hidden rounded-full bg-muted">
                <div
                  className={cn(
                    "h-full transition-all duration-500",
                    posture.score >= 75 ? "bg-low" : posture.score >= 55 ? "bg-medium" : posture.score >= 35 ? "bg-high" : "bg-critical",
                  )}
                  style={{ width: `${posture.score}%` }}
                />
              </div>
              <div className="flex flex-wrap gap-x-4 gap-y-1 font-mono text-[11px]">
                <span className="text-low">{posture.passed} pass</span>
                <span className="text-medium">{posture.warned} warn</span>
                <span className="text-critical">{posture.failed} fail</span>
                <span className="text-muted-foreground">{posture.notApplicable} n/a</span>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Regulatory clock</CardTitle>
            <CardDescription>{posture.headline}</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-2.5">
            {DEADLINES.map((deadline) => {
              const years = deadline.year - currentYear
              const urgency = years <= 4 ? "bg-critical" : years <= 7 ? "bg-high" : "bg-medium"
              return (
                <div key={`${deadline.year}-${deadline.label}`} className="flex items-center gap-3">
                  <span className="tabular w-11 font-mono text-xs text-foreground">{deadline.year}</span>
                  <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted">
                    <div className={cn("h-full", urgency)} style={{ width: `${Math.max(6, 100 - years * 7)}%` }} />
                  </div>
                  <span className="w-[190px] shrink-0 truncate text-xs text-muted-foreground">{deadline.label}</span>
                  <span className="hidden w-24 shrink-0 font-mono text-[10px] uppercase tracking-wider text-muted-foreground sm:block">
                    {deadline.source}
                  </span>
                  <span className="tabular w-12 shrink-0 text-right font-mono text-xs text-foreground">{years}y</span>
                </div>
              )
            })}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Controls</CardTitle>
          <CardDescription>
            Failing controls first. Each control cites a published requirement — expand for the offending assets.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          {grouped.map((control) => (
            <ControlRow key={control.id} control={control} />
          ))}
        </CardContent>
      </Card>
    </div>
  )
}
