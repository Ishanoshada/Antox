package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"antox/patterns"
)

// AnalyzeHexEnc identifies string/encoding obfuscation and native hex
// handling: long hex literals, hex byte arrays, XOR routines, custom
// decrypt/deobfuscate methods, Base64 usage and char-array string builds.
func (e *Engine) AnalyzeHexEnc(ctx context.Context, o Options) (*Report, error) {
	start := time.Now()
	r := &Report{Mode: o.Mode, AppName: "unknown", APKPackage: e.appPackage(ctx)}

	cat := patterns.Category{
		ID: "hexenc", Severity: "info", Label: "Hex / string obfuscation",
		Terms:   patterns.HexTerms,
		Regexes: patterns.HexRegexes,
	}
	findings := e.runCategory(ctx, cat, o.Package)
	r.Findings = append(r.Findings, findings...)

	// Summarize which obfuscation flavors were seen.
	flavors := map[string]bool{}
	for _, re := range patterns.HexRegexes {
		flavors[fmt.Sprintf("%s", re)] = false
	}
	for _, f := range findings {
		for _, re := range patterns.HexRegexes {
			for _, ln := range strings.Split(f.Evidence, "\n") {
				if re.MatchString(ln) {
					flavors[fmt.Sprintf("%s", re)] = true
				}
			}
		}
	}
	seen := map[string]bool{}
	var names []string
	for re, hit := range flavors {
		if !hit {
			continue
		}
		name := classifyHexRegex(fmt.Sprintf("%s", re))
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	if len(names) > 0 {
		r.Notes = append(r.Notes, "obfuscation flavors detected: "+strings.Join(names, ", "))
	}

	r.DurationMS = time.Since(start).Milliseconds()
	e.finishReport(ctx, r)
	return r, nil
}

func classifyHexRegex(pattern string) string {
	switch {
	case contains(pattern, `"[0-9a-fA-F]{16,}"`):
		return "hex-encoded strings"
	case contains(pattern, `0x[0-9a-fA-F]{2}(,\s*0x`):
		return "hex byte arrays"
	case contains(pattern, `0x[0-9a-fA-F]+\s*\^`):
		return "XOR encoding"
	case contains(pattern, `decrypt|deobfuscate`):
		return "custom decrypt/deobfuscate routines"
	case contains(pattern, `Base64`):
		return "Base64 (en|de)coding"
	case contains(pattern, `\(char\)`):
		return "char-code string building"
	default:
		return "string manipulation"
	}
}

func contains(s, sub string) bool {
	return strings.Contains(s, sub)
}
