package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"antox/patterns"
)

// AnalyzeSDKs inventories the vendor security / hardening / device-intelligence
// SDKs the app embeds, by class-name search on the package prefixes in
// patterns.SecuritySDKs. This is cheap (class-name searches only, no source
// fetch) and answers "what third-party protection/analytics is in this build?"
func (e *Engine) AnalyzeSDKs(ctx context.Context, o Options) (*Report, error) {
	start := time.Now()
	r := &Report{Mode: o.Mode, AppName: "unknown", APKPackage: e.appPackage(ctx)}
	e.sdkFindings(ctx, r, o.Package)
	r.DurationMS = time.Since(start).Milliseconds()
	e.finishReport(ctx, r)
	return r, nil
}

// sdkFindings searches the SDK catalog by class-name token and appends one
// finding per matched SDK (category "sdk"). An SDK is reported once even if
// several of its tokens or classes hit; the first few matching classes are
// listed as evidence.
func (e *Engine) sdkFindings(ctx context.Context, r *Report, pkg string) {
	for _, sdk := range patterns.SecuritySDKs {
		if err := ctx.Err(); err != nil {
			break
		}
		var classes []string
		for _, term := range sdk.Terms {
			hit, err := e.search(ctx, patterns.C(term), pkg, 20)
			if err != nil {
				e.Errs = append(e.Errs, fmt.Sprintf("search sdk %q (%q): %v", sdk.SDK, term, err))
				continue
			}
			classes = append(classes, hit...)
			if len(hit) > 0 {
				break // first token that matches is enough
			}
		}
		if len(classes) == 0 {
			continue
		}
		classes = uniqueStrings(classes)
		detail := fmt.Sprintf("vendor %s — %s", sdk.Vendor, sdk.Desc)
		if n := len(classes); n > 0 {
			detail += "  (matched classes: " + strings.Join(classes[:min(3, n)], ", ") + ")"
		}
		r.Findings = append(r.Findings, Finding{
			Category: "sdk",
			Severity: sdk.Severity,
			Title:    fmt.Sprintf("%s [%s]", sdk.SDK, sdk.Kind),
			Class:    sdk.Package,
			Detail:   detail,
		})
	}
}
