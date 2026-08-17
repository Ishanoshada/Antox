package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// AnalyzeAll runs every mode in sequence and merges the results into one
// report. The .so string sweep (sostr) is included when -apk dirs are
// provided, since that mode needs the raw files on disk.
func (e *Engine) AnalyzeAll(ctx context.Context, o Options) (*Report, error) {
	return e.runModeList(ctx, "all", allModes(o.ApkDir), o), nil
}

// allModes is the full-scan mode list. The .so string sweep (sostr) is
// included only when -apk dirs are provided, since that mode reads raw files.
// fridahook writes an app-tailored bypass script into the output directory
// (reports/frida-hook.js) as part of the normal analysis.
func allModes(apkDir string) []string {
	modes := []string{"manifest", "secrets", "firebase", "security", "detection", "native", "hexenc", "hexstr", "backend", "fridahook"}
	if apkDir != "" {
		modes = append(modes, "sostr")
	}
	return modes
}

// RunModes runs an explicit list of modes in sequence and merges the results
// into one report. Used by the CLI's "sostr detection,secrets" form, where the
// primary mode and extra modes share one report.
func (e *Engine) RunModes(ctx context.Context, modes []string, o Options) (*Report, error) {
	if len(modes) == 0 {
		return nil, fmt.Errorf("no modes to run")
	}
	return e.runModeList(ctx, strings.Join(modes, "+"), modes, o), nil
}

// runModeList runs each mode in sequence, merging findings / errors / notes
// into one report labeled with modeLabel. The manifest is analyzed first when
// it is in the list so the merged report carries the package name and the raw
// manifest.
func (e *Engine) runModeList(ctx context.Context, modeLabel string, modes []string, o Options) *Report {
	start := time.Now()
	merged := &Report{Mode: modeLabel, AppName: "unknown"}
	for _, m := range modes {
		if err := ctx.Err(); err != nil {
			break
		}
		o.Mode = m
		e.logf("[%s] running mode %q ...", modeLabel, m)
		sub, serr := e.Run(ctx, o)
		if serr != nil {
			merged.Errors = append(merged.Errors, fmt.Sprintf("%s: %v", m, serr))
			continue
		}
		if sub == nil {
			continue
		}
		if merged.AppName == "unknown" && sub.AppName != "unknown" {
			merged.AppName = sub.AppName
		}
		if merged.APKPackage == "" {
			merged.APKPackage = sub.APKPackage
		}
		if merged.Manifest == "" {
			merged.Manifest = sub.Manifest
		}
		merged.Findings = append(merged.Findings, sub.Findings...)
		merged.Errors = append(merged.Errors, sub.Errors...)
		merged.Notes = append(merged.Notes, sub.Notes...)
	}
	merged.DurationMS = time.Since(start).Milliseconds()
	e.finishReport(ctx, merged)
	return merged
}
