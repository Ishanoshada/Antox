package analyzer

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"antox/patterns"
)

// AnalyzeNative inventories the app's native surface: System.loadLibrary /
// System.load calls, JNI_OnLoad / RegisterNatives usage, the .so files that
// are referenced in code, and — automatically — the native function names
// (Java_* JNI exports and "native ... name(" declarations). Suspicious
// security payload .so names (libsnitchtt, libsna, libsnb, libzygisk,
// libfrida) are flagged.
func (e *Engine) AnalyzeNative(ctx context.Context, o Options) (*Report, error) {
	start := time.Now()
	r := &Report{Mode: o.Mode, AppName: "unknown", APKPackage: e.appPackage(ctx)}

	classes := e.collectClasses(ctx, patterns.NativeTerms, o.Package, e.Limit*6)
	sources := e.fetchSources(ctx, classes, e.Limit*2)

	// Packaged .so / .dex files (resource scope): the actual native libraries
	// and dex payloads shipped in the APK. These never appear in Java class
	// source, so enumerate the resource file names directly.
	e.scanResources(ctx, r, "")

	// Dedicated "hook" sweep: hooking-framework classes (Dobby, ShadowHook,
	// Xposed, LSPosed, ...) and hook API call sites. Runs separately so a hook
	// library class is found even if it never calls System.loadLibrary.
	hookClasses := e.collectClasses(ctx, patterns.NativeHookTerms, o.Package, e.Limit*6)
	hookSources := e.fetchSources(ctx, hookClasses, e.Limit*2)

	libSet := map[string]bool{}
	nativeClasses := map[string]bool{}
	funcNames := map[string]bool{}
	jniExports := map[string]bool{}
	hookClassesSeen := map[string]bool{}

	for cls, src := range sources {
		libs := collectRegexMatches(src, patterns.NativeRegexes[:1])
		decls := collectRegexMatches(src, patterns.NativeRegexes[1:])
		if len(libs) == 0 && len(decls) == 0 {
			continue
		}
		for _, l := range libs {
			libSet[filepath.Base(l)] = true
		}
		if len(decls) > 0 {
			nativeClasses[cls] = true
		}

		// Auto-detect native function names in this class.
		for _, fn := range collectRegexMatches(src, []*regexp.Regexp{
			patterns.JNIExportRe, patterns.RegisterNativesRe, patterns.NativeMethodRe,
		}) {
			fn = strings.Trim(fn, " \t\"{},")
			if fn != "" {
				funcNames[fn] = true
			}
		}
		for _, exp := range collectRegexMatches(src, []*regexp.Regexp{patterns.JNIExportRe}) {
			jniExports[exp] = true
		}

		r.Findings = append(r.Findings, Finding{
			Category: "native",
			Severity: "info",
			Title:    "Native code usage",
			Class:    cls,
			Detail:   summarize(libs, decls),
			Evidence: strings.Join(decls, "\n"),
		})

		// Per native class: try to find hex-encoded strings and extract them.
		// Decoded detection text (hooking/frida/...) and decoded credentials are
		// surfaced as findings under the native-hex category.
		if results := interestingHexResults(src); len(results) > 0 {
			r.Findings = append(r.Findings, hexFindings(cls, "native-hex", results)...)
		}

		// Per native class: hook API usage inside the class body.
		if evs := collectRegexMatches(src, patterns.NativeHookRegexes); len(evs) > 0 {
			hookClassesSeen[cls] = true
			r.Findings = append(r.Findings, Finding{
				Category: "native-hook",
				Severity: "high",
				Title:    "Hooking framework / hook API usage",
				Class:    cls,
				Detail:   "hook API calls or hook framework references in native class",
				Evidence: strings.Join(uniqueStrings(evs), "\n"),
			})
		}
	}

	// Dedicated hook sweep results: classes found via the "hook" keyword
	// search get their own findings (deduped against the native-loop hits).
	for cls, src := range hookSources {
		if hookClassesSeen[cls] {
			continue
		}
		evs := collectRegexMatches(src, patterns.NativeHookRegexes)
		if len(evs) == 0 {
			continue
		}
		r.Findings = append(r.Findings, Finding{
			Category: "native-hook",
			Severity: "high",
			Title:    "Hooking framework / hook API usage",
			Class:    cls,
			Detail:   "class matched hook framework / hook API keywords",
			Evidence: strings.Join(uniqueStrings(evs), "\n"),
		})
	}

	// .so inventory + suspicious payloads.
	var allLibs []string
	for l := range libSet {
		allLibs = append(allLibs, l)
	}
	allLibs = uniqueStrings(allLibs)
	if len(allLibs) > 0 {
		r.Notes = append(r.Notes, fmt.Sprintf("native libraries referenced: %s", strings.Join(allLibs, ", ")))
	}
	for _, lib := range allLibs {
		for _, suspect := range patterns.NativeSoNames {
			if strings.Contains(lib, suspect) {
				r.Findings = append(r.Findings, Finding{
					Category: "native",
					Severity: "high",
					Title:    "Suspicious native security/detection library",
					Class:    lib,
					Detail:   "library basename matches a known detection payload (.so) family",
				})
			}
		}
		for _, eng := range patterns.FrameworkSoNames {
			if strings.Contains(lib, eng) {
				r.Findings = append(r.Findings, Finding{
					Category: "native",
					Severity: "info",
					Title:    "App framework engine (.so)",
					Class:    lib,
					Detail:   "library identifies the runtime engine (Flutter / React Native / Hermes)",
				})
			}
		}
	}

	// Auto-detected function names.
	if len(funcNames) > 0 {
		var names []string
		for n := range funcNames {
			names = append(names, n)
		}
		names = uniqueStrings(names)
		if len(names) > 6 {
			names = append(names[:6], "...")
		}
		r.Findings = append(r.Findings, Finding{
			Category: "native",
			Severity: "info",
			Title:    fmt.Sprintf("Native function names detected (%d)", len(funcNames)),
			Class:    "auto-detect",
			Detail:   strings.Join(names, ", "),
		})
	}

	if len(nativeClasses) > 0 {
		var names []string
		for c := range nativeClasses {
			names = append(names, c)
		}
		r.Notes = append(r.Notes,
			fmt.Sprintf("classes declaring native methods: %s", strings.Join(names, ", ")))
	}

	// Cross-check detected function names against the known native detection
	// dictionary from cpp/ (nativeScanMaps, sna_e, ...).
	if len(funcNames) > 0 {
		var knownHits []string
		for n := range funcNames {
			for _, known := range patterns.NativeFunctionNames {
				if strings.Contains(n, known) {
					knownHits = append(knownHits, n)
					break
				}
			}
		}
		if len(knownHits) > 0 {
			r.Findings = append(r.Findings, Finding{
				Category: "native",
				Severity: "high",
				Title:    "Known native detection function names",
				Class:    "auto-detect",
				Detail:   "matched snitchtt/DeviceTrust native detection dictionary",
				Evidence: strings.Join(knownHits, "\n"),
			})
		}
	}

	r.DurationMS = time.Since(start).Milliseconds()
	e.finishReport(ctx, r)
	return r, nil
}

// collectRegexMatches returns every unique full match of the regexes over a
// source string.
func collectRegexMatches(src string, regexes []*regexp.Regexp) []string {
	var out []string
	seen := map[string]bool{}
	for _, re := range regexes {
		for _, m := range re.FindAllString(src, -1) {
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	return out
}

func summarize(primary, secondary []string) string {
	parts := []string{}
	for _, p := range primary {
		parts = append(parts, "loads "+p)
	}
	for _, s := range secondary {
		if len(s) > 100 {
			s = s[:100] + "..."
		}
		parts = append(parts, "declares "+strings.TrimSpace(s))
	}
	if len(parts) > 6 {
		parts = parts[:6]
		parts = append(parts, "...")
	}
	return strings.Join(parts, "; ")
}
