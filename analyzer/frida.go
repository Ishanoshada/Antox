package analyzer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"antox/patterns"
)

// AnalyzeFridaHook generates an app-tailored Frida hook script ("bypass.js")
// from the security / detection findings of the loaded APK.
//
// Unlike a generic bypass script (e.g. s8.js), it discovers the LIVE class
// names in this specific build — the Talsec threat-callback implementation is
// usually renamed to something like K0.h — by searching the loaded APK, then
// composes:
//   - generic framework-level blocks (Debug, Settings, File, Runtime.exec,
//     SystemProperties, PackageManager, SSL pinning, Frida-port blocking, ...)
//     that are valid on any app, and
//   - app-specific blocks that target the exact discovered classes/methods.
//
// The script is written to o.OutDir (file if it ends in .js, else a directory)
// as frida-hook.js. Usage: frida -U -f <package> -l <script>.
func (e *Engine) AnalyzeFridaHook(ctx context.Context, o Options) (*Report, error) {
	start := time.Now()
	r := &Report{Mode: o.Mode, AppName: "unknown", APKPackage: e.appPackage(ctx)}

	profile := e.fridaProfile(ctx, o)
	script := buildFridaScript(e.appPackage(ctx), profile)

	out := fridaOutPath(o)
	if err := writeScript(out, script); err != nil {
		e.Errs = append(e.Errs, fmt.Sprintf("write frida script: %v", err))
	} else {
		r.Findings = append(r.Findings, Finding{
			Category: "frida",
			Severity: "high",
			Title:    "Frida hook script generated",
			Class:    out,
			Detail:   "app-tailored bypass script — run: frida -U -f " + r.APKPackage + " -l " + out,
		})
	}
	for _, t := range profile.targets {
		r.Findings = append(r.Findings, Finding{
			Category: "frida",
			Severity: "info",
			Title:    "Hook target discovered",
			Class:    t.cls,
			Method:   strings.Join(t.methods, ", "),
			Detail:   t.reason,
		})
	}
	if len(profile.notes) > 0 {
		r.Notes = append(r.Notes, profile.notes...)
	}

	r.DurationMS = time.Since(start).Milliseconds()
	e.finishReport(ctx, r)
	return r, nil
}

// hookTarget is one class the generated script hooks, with the reason it was
// discovered (which finding it corresponds to). returns is true when the target
// methods are boolean detection gates (hooked to return false) rather than void
// callbacks (hooked to no-op).
type hookTarget struct {
	cls      string
	methods  []string
	reason   string
	returns  bool
}

// fridaProfile is the app-specific hooking surface discovered in the APK.
type fridaProfile struct {
	packageName string
	targets     []hookTarget
	notes       []string
}

// detectionGate is one common detection entry-point method searched across ANY
// app. These make the generated hook app-specific even for apps without a RASP
// SDK (root / emulator / debugger / frida / hook / vpn checks all get made to
// return false out of the box).
type detectionGate struct {
	method string
	reason string
}

// "isDebuggable" is deliberately absent: it is a substring-common framework
// method (io.flutter.embedding.android.FlutterActivity.isDebuggable) and would
// add noise, and the generated script already covers debuggable via the
// Debug.isDebuggerConnected and ro.debuggable system-property blocks.
var detectionGates = []detectionGate{
	{"isRooted", "root detection"},
	{"detectRoot", "root detection"},
	{"isDeviceRooted", "root detection"},
	{"checkForRoot", "root detection"},
	{"isEmulator", "emulator detection"},
	{"isEmulatorBuild", "emulator detection"},
	{"isDebuggerConnected", "debugger detection"},
	{"detectFrida", "Frida detection"},
	{"isFridaRunning", "Frida detection"},
	{"isFridaDetected", "Frida detection"},
	{"isHookDetected", "hooking detection"},
	{"isVpnConnected", "VPN detection"},
}

// fridaProfile discovers the live class/method names this build uses for
// detection, so the generated script hooks the real (often obfuscated) classes.
// It works on any app: RASP-protected builds get the full threat-callback
// treatment, and plain builds get their root / emulator / debugger / frida /
// hook / vpn detection entry points neutralized.
func (e *Engine) fridaProfile(ctx context.Context, o Options) fridaProfile {
	p := fridaProfile{packageName: e.appPackage(ctx)}

	// targetsByClass keeps insertion order while grouping gate methods per class.
	var order []string
	targetsByClass := map[string]*hookTarget{}
	add := func(t hookTarget) {
		if t.cls == "" || len(t.methods) == 0 {
			return
		}
		if _, ok := targetsByClass[t.cls]; !ok {
			order = append(order, t.cls)
		}
		got := targetsByClass[t.cls]
		if got == nil {
			targetsByClass[t.cls] = &t
			return
		}
		got.methods = append(got.methods, t.methods...)
		got.methods = uniqueStrings(got.methods)
		if got.reason != "" && t.reason != "" && got.reason != t.reason {
			got.reason += ", " + t.reason
		}
		got.returns = got.returns || t.returns
	}

	// 1) Talsec RASP threat-callback implementation. The ThreatDetected base is
	// usually implemented by an obfuscated class (K0.h) — the method search for
	// onDebuggerDetected returns it by name even when the class is renamed.
	if classes, err := e.searchMethod(ctx, "onDebuggerDetected"); err == nil {
		for _, c := range classes {
			if strings.Contains(c, "ThreatDetected") {
				continue // abstract base — the impl class overrides everything
			}
			if isModelClass(c) {
				continue
			}
			add(hookTarget{
				cls:     c,
				methods: talsecCallbacks,
				reason:  "concrete Talsec threat-callback implementation (ThreatDetected)",
			})
			p.notes = append(p.notes, fmt.Sprintf("Talsec RASP: hooking %s to block threat callbacks", c))
			break
		}
	}

	// 2) ThreatListener wiring — no-op registerListener/onReceive so callbacks
	// never reach the app even if the impl class changes in a rebuild.
	if classes, err := e.search(ctx, patterns.C("ThreatListener"), o.Package, 8); err == nil {
		for _, c := range classes {
			if strings.Contains(c, "$") {
				continue
			}
			add(hookTarget{
				cls:     c,
				methods: []string{"registerListener", "unregisterListener", "onReceive"},
				reason:  "Talsec ThreatListener wiring (registerListener no-ops the RASP wiring)",
			})
			break
		}
	}

	// 3) Generic detection entry points — the out-of-the-box coverage for any
	// app. Each method is searched across all classes; hits are grouped per
	// class so one target neutralizes every detection gate it owns.
	for _, gate := range detectionGates {
		if err := ctx.Err(); err != nil {
			break
		}
		classes, err := e.searchMethod(ctx, gate.method)
		if err != nil {
			e.Errs = append(e.Errs, fmt.Sprintf("search detection gate %q: %v", gate.method, err))
			continue
		}
		for _, c := range classes {
			if isModelClass(c) {
				continue
			}
			if existing := targetsByClass[c]; existing != nil && isRASPTarget(existing) {
				continue // RASP impl target already covers every callback
			}
			add(hookTarget{cls: c, methods: []string{gate.method}, reason: gate.reason, returns: true})
		}
	}

	// 4) SSL pinning — the concrete pinner class, so check() is neutralized
	// even when it is not okhttp3.CertificatePinner.
	if classes, err := e.search(ctx, patterns.C("CertificatePinner"), o.Package, 8); err == nil {
		for _, c := range classes {
			if isModelClass(c) {
				continue
			}
			if existing := targetsByClass[c]; existing != nil && isRASPTarget(existing) {
				continue
			}
			add(hookTarget{
				cls:     c,
				methods: []string{"check"},
				reason:  "SSL certificate pinner (check)",
				returns: true,
			})
		}
	}

	for _, c := range order {
		p.targets = append(p.targets, *targetsByClass[c])
	}
	return p
}

// isModelClass filters out crashlytics/gson-style data-model classes whose
// isRooted/isEmulator are plain getters, not detection logic.
func isModelClass(cls string) bool {
	low := strings.ToLower(cls)
	return strings.Contains(low, ".model.") || strings.Contains(low, "autovalue") ||
		strings.Contains(low, ".dataclass") || strings.Contains(low, "$dataclass")
}

// talsecCallbacks are the ThreatDetected callback names a RASP SDK may override
// (Talsec v18 ships most of these). The generated hook guards each with an
// existence check, so unknown names are safely skipped at runtime.
var talsecCallbacks = []string{
	"onRootDetected", "onEmulatorDetected", "onDebuggerDetected",
	"onHookDetected", "onTamperDetected", "onAutomationDetected",
	"onMultiInstanceDetected", "onObfuscationIssuesDetected",
	"onDeviceBindingDetected", "onLocationSpoofingDetected",
	"onTimeSpoofingDetected", "onScreenRecordingDetected",
	"onScreenshotDetected", "onUnsecureWifiDetected",
	"onUntrustedInstallationSourceDetected", "onSystemVPNDetected",
	"onADBEnabledDetected", "onMalwareDetected",
}

// fridaOutPath resolves where the script is written: -out frida-hook.js uses the
// file directly; -out <dir> writes <dir>/frida-hook.js; nothing uses ./frida-hook.js.
func fridaOutPath(o Options) string {
	target := strings.TrimSpace(o.OutDir)
	if target == "" {
		return "frida-hook.js"
	}
	if strings.HasSuffix(strings.ToLower(target), ".js") {
		return target
	}
	return filepath.Join(target, "frida-hook.js")
}

func writeScript(path, content string) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

// buildFridaScript composes the final script: a header, the app-specific blocks
// (only for detected features), then the generic framework-level blocks.
func buildFridaScript(pkg string, p fridaProfile) string {
	var b strings.Builder
	fmt.Fprintf(&b, "// frida-hook.js — generated by antox fridahook\n")
	fmt.Fprintf(&b, "// package: %s\n", orDash(pkg))
	fmt.Fprintf(&b, "// run:     frida -U -f %s -l %s\n", orDash(pkg), "frida-hook.js")
	b.WriteString("//\n")
	b.WriteString("// App-specific targets discovered in this build:\n")
	if len(p.targets) == 0 {
		b.WriteString("//   (none — generic framework-level bypasses only)\n")
	} else {
		for _, t := range p.targets {
			fmt.Fprintf(&b, "//   %s  %s\n", t.cls, strings.Join(t.methods, ", "))
		}
	}
	b.WriteString("//\n")
	b.WriteString(fridaHeader)

	for _, t := range p.targets {
		if t.cls == "" || len(t.methods) == 0 {
			continue
		}
		b.WriteString("\n// ===== app-specific: " + t.cls + " =====\n")
		if isTalsecImpl(t) {
			// RASP threat-callback implementation: no-op every callback the
			// concrete class may override.
			b.WriteString(strings.ReplaceAll(fridaBlockTalsecCallbacks, "@@CLASS@@", t.cls))
		} else {
			// Generic detection entry points: boolean gates -> false, callbacks
			// (e.g. registerListener) -> no-op.
			helper := "hookVoid"
			if t.returns {
				helper = "hookReturnsFalse"
			}
			block := strings.ReplaceAll(fridaBlockNoop, "@@CLASS@@", t.cls)
			block = strings.ReplaceAll(block, "@@METHODS@@", fridaMethodList(t.methods))
			block = strings.ReplaceAll(block, "@@HELPER@@", helper)
			b.WriteString(block)
		}
		b.WriteString("\n")
	}

	// Generic framework-level bypasses (valid on any app).
	b.WriteString(fridaBlockPorts)
	b.WriteString(fridaBlockNetstat)
	b.WriteString(fridaBlockDevMode)
	b.WriteString(fridaBlockEmulator)
	b.WriteString(fridaBlockHookingDetect)
	b.WriteString(fridaBlockFiles)
	b.WriteString(fridaBlockProcess)
	b.WriteString(fridaBlockRootLibs)
	b.WriteString(fridaBlockSSL)
	b.WriteString(fridaBlockDebugger)
	b.WriteString(fridaBlockProps)
	b.WriteString(fridaBlockPackages)
	b.WriteString(fridaBlockSelfProtection)
	b.WriteString(fridaBlockThreads)
	b.WriteString(fridaBlockVPN)
	b.WriteString(fridaBlockScreen)
	b.WriteString(fridaBlockADB)
	b.WriteString(fridaFooter)
	return b.String()
}

// fridaMethodList renders a JS array of method names: ["a", "b"].
func fridaMethodList(methods []string) string {
	quoted := make([]string, 0, len(methods))
	for _, m := range methods {
		quoted = append(quoted, `"`+m+`"`)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

func isTalsecImpl(t hookTarget) bool {
	return isRASPTarget(&t)
}

// isRASPTarget reports whether a target is a RASP threat-callback impl (its
// callbacks are all neutralized via the RASP block, so gate methods must not be
// appended to it).
func isRASPTarget(t *hookTarget) bool {
	for _, m := range t.methods {
		if m == "onDebuggerDetected" {
			return true
		}
	}
	return false
}
