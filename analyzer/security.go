package analyzer

import (
	"context"
	"fmt"
	"time"

	"antox/patterns"
)

// AnalyzeSecurity maps the app's security hardening layers: root detection,
// Frida detection, emulator detection, anti-debug, SSL pinning, FLAG_SECURE,
// crypto-at-rest and integrity checks. Every subcategory becomes a finding
// group so you can see which protections are (or are not) present.
func (e *Engine) AnalyzeSecurity(ctx context.Context, o Options) (*Report, error) {
	start := time.Now()
	r := &Report{Mode: o.Mode, AppName: "unknown", APKPackage: e.appPackage(ctx)}

	evaluated := []string{}
	for _, cat := range patterns.SecurityCategories {
		if err := ctx.Err(); err != nil {
			break
		}
		findings := e.runCategory(ctx, cat, o.Package)
		if len(findings) > 0 {
			r.Findings = append(r.Findings, findings...)
		}
		evaluated = append(evaluated, cat.ID)
	}

	// Posture summary note — only for categories that were actually evaluated.
	// On an interrupted run the trailing categories never ran, so claiming
	// "no evidence found" for them would be misleading.
	present := map[string]bool{}
	for _, f := range r.Findings {
		present[f.Category] = true
	}
	evalSet := map[string]bool{}
	for _, id := range evaluated {
		evalSet[id] = true
	}
	var absent []string
	for _, cat := range patterns.SecurityCategories {
		if evalSet[cat.ID] && !present[cat.ID] {
			absent = append(absent, cat.Label)
		}
	}
	if len(absent) > 0 {
		r.Notes = append(r.Notes, "No evidence found for: "+joinLabels(absent))
	}
	if len(evaluated) < len(patterns.SecurityCategories) {
		r.Notes = append(r.Notes,
			fmt.Sprintf("analysis stopped early (%d/%d categories evaluated) — remaining categories skipped",
				len(evaluated), len(patterns.SecurityCategories)))
	}

	r.DurationMS = time.Since(start).Milliseconds()
	e.finishReport(ctx, r)
	return r, nil
}

func joinLabels(labels []string) string {
	out := ""
	for i, l := range labels {
		if i > 0 {
			out += "; "
		}
		out += l
	}
	return out
}
