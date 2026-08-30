"use client"

/**
 * Evidence drill-down for a single crypto asset. Every number shown here is
 * traceable: the matched token, the source line, the Mosca arithmetic, and the
 * NIST standard behind the recommendation.
 */

import { Badge } from "@/components/ui/badge"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Separator } from "@/components/ui/separator"
import { TIER_STYLES, TierChip, TypeBadge, ScopeCaption } from "@/components/ecdat/tier"
import { cn } from "@/lib/utils"
import type { CryptoAsset } from "@/lib/ecdat/types"

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1 border-b border-border py-2 last:border-0 sm:flex-row sm:items-baseline sm:gap-4">
      <span className="w-40 shrink-0 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">{label}</span>
      <div className="min-w-0 flex-1 text-sm leading-relaxed text-foreground">{children}</div>
    </div>
  )
}

export function AssetDetail({ asset, onClose }: { asset: CryptoAsset | null; onClose: () => void }) {
  return (
    <Dialog open={asset !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-h-[86vh] max-w-3xl overflow-hidden p-0 sm:max-w-3xl">
        {asset ? (
          <>
            <DialogHeader className="border-b border-border p-4 pr-12">
              <div className="flex flex-wrap items-center gap-2">
                <TierChip tier={asset.riskTier} />
                <DialogTitle className="font-mono text-base">{asset.name}</DialogTitle>
                {asset.keySize ? (
                  <Badge variant="secondary" className="font-mono text-[11px]">
                    {asset.keySize}-bit
                  </Badge>
                ) : null}
                <Badge variant="outline" className="font-mono text-[11px]">
                  {asset.primitive}
                </Badge>
                <TypeBadge type={asset.type} />
              </div>
              <DialogDescription className="font-mono text-xs">{asset.location}</DialogDescription>
              {/* U5 — scope disclaimer travels with the finding, verbatim. */}
              <ScopeCaption note={asset.scopeNote} className="mt-1" />
            </DialogHeader>

            <ScrollArea className="max-h-[calc(86vh-6rem)]">
              <div className="flex flex-col gap-5 p-4">
                <section className="flex flex-col gap-2">
                  <h3 className="font-mono text-[10px] uppercase tracking-widest text-primary">Evidence</h3>
                  <pre className="overflow-x-auto rounded-md border border-border bg-secondary/40 p-3 font-mono text-xs leading-relaxed text-foreground">
                    <code>{asset.snippet || "(no source line captured)"}</code>
                  </pre>
                  <div className="flex flex-col">
                    <Row label="Detector">
                      <span className="font-mono">{asset.detector}</span>
                    </Row>
                    <Row label="Evidence type">
                      <span className="font-mono">{asset.evidence}</span>
                    </Row>
                    <Row label="Mode">
                      <span className="font-mono">{asset.mode}</span>
                    </Row>
                    <Row label="Confidence">
                      <span
                        className={cn(
                          "font-mono",
                          asset.confidence === "high" ? "text-low" : asset.confidence === "medium" ? "text-medium" : "text-high",
                        )}
                      >
                        {asset.confidence}
                      </span>
                    </Row>
                    <Row label="Occurrences">
                      <div className="flex flex-col gap-1">
                        <span className="tabular font-mono">{asset.occurrences}</span>
                        {asset.locations.length > 1 ? (
                          <ul className="flex flex-col gap-0.5">
                            {asset.locations.slice(0, 8).map((loc) => (
                              <li key={loc} className="font-mono text-[11px] text-muted-foreground">
                                {loc}
                              </li>
                            ))}
                            {asset.locations.length > 8 ? (
                              <li className="font-mono text-[11px] text-muted-foreground">
                                +{asset.locations.length - 8} more
                              </li>
                            ) : null}
                          </ul>
                        ) : null}
                      </div>
                    </Row>
                    {asset.detail ? (
                      <Row label="Detail">
                        <span className="font-mono text-xs">{asset.detail}</span>
                      </Row>
                    ) : null}
                  </div>
                </section>

                <Separator />

                <section className="flex flex-col gap-2">
                  <h3 className="font-mono text-[10px] uppercase tracking-widest text-primary">Mosca inequality</h3>
                  <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-secondary/40 p-3 font-mono text-sm">
                    <span className="text-muted-foreground">(X</span>
                    <span className="tabular text-foreground">{asset.mosca.x}</span>
                    <span className="text-muted-foreground">+ Y</span>
                    <span className="tabular text-foreground">{asset.mosca.y}</span>
                    <span className="text-muted-foreground">) − Z</span>
                    <span className="tabular text-foreground">{asset.mosca.z}</span>
                    <span className="text-muted-foreground">=</span>
                    <span className={cn("tabular font-semibold", TIER_STYLES[asset.riskTier].text)}>
                      {asset.mosca.margin > 0 ? "+" : ""}
                      {asset.mosca.margin} years
                    </span>
                  </div>
                  <p className="text-sm leading-relaxed text-muted-foreground">{asset.mosca.explanation}</p>
                  <div className="flex flex-col">
                    <Row label="Business criticality">{asset.classification.businessCriticality}</Row>
                    <Row label="Sensitive data">
                      <div className="flex flex-col gap-0.5">
                        <span className={asset.classification.sensitiveData ? "text-amber-400/90" : "text-muted-foreground"}>
                          {asset.classification.sensitiveData ? "Yes" : "No"}
                        </span>
                        <span className="font-mono text-[11px] text-muted-foreground">
                          {asset.classification.sensitiveDataRationale}
                        </span>
                      </div>
                    </Row>
                    <Row label="Facing">
                      <span className="font-mono text-xs">
                        {asset.classification.facing}
                        <span className="ml-2 text-muted-foreground">via {asset.classification.facingSource}</span>
                      </span>
                    </Row>
                    <Row label="Classification basis">
                      <span className="text-muted-foreground">{asset.classification.rationale}</span>
                    </Row>
                    <Row label="NIST status">
                      <span className="font-mono text-xs">{asset.nistStatus}</span>
                    </Row>
                  </div>
                </section>

                <Separator />

                <section className="flex flex-col gap-2">
                  <h3 className="font-mono text-[10px] uppercase tracking-widest text-primary">Recommended migration</h3>
                  {asset.recommendation ? (
                    <div className="flex flex-col">
                      <Row label="Primary target">
                        <span className="font-mono font-medium text-primary">{asset.recommendation.primary}</span>
                      </Row>
                      <Row label="Standard">
                        <span className="font-mono text-xs">{asset.recommendation.standard}</span>
                      </Row>
                      {asset.recommendation.hybrid ? (
                        <Row label="Hybrid option">
                          <span className="font-mono text-xs">{asset.recommendation.hybrid}</span>
                        </Row>
                      ) : null}
                      {asset.recommendation.conservative ? (
                        <Row label="Conservative">
                          <span className="font-mono text-xs">{asset.recommendation.conservative}</span>
                        </Row>
                      ) : null}
                      <Row label="Complexity">{asset.recommendation.complexity}</Row>
                      {asset.recommendation.performanceNote ? (
                        <Row label="Performance">
                          <span className="text-muted-foreground">
                            {asset.recommendation.performanceNote}
                            {asset.recommendation.latencyWeighted ? (
                              <span className="ml-2 font-mono text-[10px] uppercase tracking-wider text-primary">
                                hybrid preferred
                              </span>
                            ) : null}
                          </span>
                        </Row>
                      ) : null}
                      <Row label="Notes">
                        <span className="text-muted-foreground">{asset.recommendation.notes}</span>
                      </Row>
                    </div>
                  ) : (
                    <p className="text-sm leading-relaxed text-muted-foreground">
                      No migration required — this primitive is already quantum-resistant or is not a security-relevant use.
                    </p>
                  )}
                </section>
              </div>
            </ScrollArea>
          </>
        ) : null}
      </DialogContent>
    </Dialog>
  )
}
