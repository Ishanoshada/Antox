package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"antox/patterns"
)

// AnalyzeDetection discovers the app's detection logic: known detection /
// hardening SDKs (RootBeer, Talsec, LSPosed, Integrity, ...) and the
// entry-point methods that implement root/frida/emulator/debugger checks.
func (e *Engine) AnalyzeDetection(ctx context.Context, o Options) (*Report, error) {
	start := time.Now()
	r := &Report{Mode: o.Mode, AppName: "unknown", APKPackage: e.appPackage(ctx)}

	// 0) Vendor security / hardening SDK inventory (RASP, attestation,
	// device-intel, hook frameworks, ...) by class-name search.
	e.sdkFindings(ctx, r, o.Package)

	// 1) Known detection / hardening libraries, matched by class name.
	for _, term := range patterns.DetectionClassTerms {
		if err := ctx.Err(); err != nil {
			break
		}
		classes, err := e.search(ctx, patterns.C(term), o.Package, 30)
		if err != nil {
			e.Errs = append(e.Errs, fmt.Sprintf("search class %q: %v", term, err))
			continue
		}
		for _, cls := range classes {
			r.Findings = append(r.Findings, Finding{
				Category: "detection-library",
				Severity: "info",
				Title:    "Detection / hardening library referenced",
				Class:    cls,
				Detail:   fmt.Sprintf("class-name search hit for %q", term),
			})
		}
	}

	// 2) Detection entry-point methods across the app (concurrent fetches).
	seen := map[string]bool{}
	var methodClasses []string
	for _, method := range patterns.DetectionMethodTerms {
		if err := ctx.Err(); err != nil {
			break
		}
		classes, err := e.searchMethod(ctx, method)
		if err != nil {
			e.Errs = append(e.Errs, fmt.Sprintf("search method %q: %v", method, err))
			continue
		}
		for _, cls := range classes {
			if !seen[cls] {
				seen[cls] = true
				methodClasses = append(methodClasses, cls)
			}
		}
	}
	sources := e.fetchSources(ctx, methodClasses, e.Limit*2)
	for cls, src := range sources {
		if f := findingsFromSource(cls, patterns.Category{
			ID: "detection", Severity: "info", Label: "Detection entry point",
			Regexes: patterns.DetectionEvidenceRegexes,
		}, src); len(f) > 0 {
			r.Findings = append(r.Findings, f...)
		}
	}

	// 3) Detection surfaces summary note.
	surfaces := map[string]bool{}
	for _, f := range r.Findings {
		if f.Method != "" {
			surfaces[f.Method] = true
		}
	}
	if len(surfaces) > 0 {
		var names []string
		for m := range surfaces {
			names = append(names, m)
		}
		r.Notes = append(r.Notes, fmt.Sprintf("detection surfaces: %s", strings.Join(names, ", ")))
	}

	r.DurationMS = time.Since(start).Milliseconds()
	e.finishReport(ctx, r)
	return r, nil
}
