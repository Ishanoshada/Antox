package analyzer

import (
	"context"
	"strings"
	"time"

	"antox/patterns"
)

// AnalyzeHexStr is the hex-level string extraction mode. It scans decompiled
// classes for hex-encoded payloads — byte-array literals, hex string literals
// and hex blobs — decodes them (plain ASCII and XOR 0x42, the key used by
// cpp/str_enc.h) and surfaces the ones that decode to "interesting" text
// (hooking messages, detection strings, credentials, Flutter/Dart symbols).
func (e *Engine) AnalyzeHexStr(ctx context.Context, o Options) (*Report, error) {
	start := time.Now()
	r := &Report{Mode: o.Mode, AppName: "unknown", APKPackage: e.appPackage(ctx)}

	classes := e.collectClasses(ctx, patterns.HexTerms, o.Package, e.Limit*6)
	sources := e.fetchSources(ctx, classes, e.Limit*2)

	for cls, src := range sources {
		r.Findings = append(r.Findings, scanSourceForHex(cls, src)...)
	}

	// Summary of what flavors were found.
	flavors := map[string]int{}
	for _, f := range r.Findings {
		flavors[f.Category]++
	}
	if len(r.Findings) == 0 {
		r.Notes = append(r.Notes, "no interesting hex-encoded strings found")
	}

	r.DurationMS = time.Since(start).Milliseconds()
	e.finishReport(ctx, r)
	return r, nil
}

// interestingHexResults scans one source for hex-encoded blobs (byte-array
// literals, hex string literals), decodes each with the common XOR keys, and
// returns the interpretations whose text is either detection-relevant
// (HexInterestingKeywords: hooking/frida/root/...) or credential-shaped
// (SecretPatterns: API keys, tokens, passwords). Shared by the hexstr mode
// and the per-native-class hex extraction in native mode.
func interestingHexResults(src string) []patterns.HexResult {
	var blobs [][]byte
	for _, m := range patterns.ByteArrayRe.FindAllString(src, -1) {
		if raw := patterns.ParseHexBytes(m); len(raw) >= 4 {
			blobs = append(blobs, raw)
		}
	}
	for _, m := range patterns.HexStringRe.FindAllString(src, -1) {
		if raw := patterns.ParseHexBytes(m); len(raw) >= 4 {
			blobs = append(blobs, raw)
		}
	}
	var out []patterns.HexResult
	for _, raw := range blobs {
		for _, hr := range patterns.DecodeHexBlob(raw) {
			if hr.Interesting() || len(patterns.MatchSecrets(hr.Decoded)) > 0 {
				out = append(out, hr)
			}
		}
	}
	return out
}

// hexFindings groups decoded hex results by decode key (ascii, xor-0x42, ...)
// into one finding per key. If a decoded string matches a credential pattern
// the finding is raised to high severity and names the pattern.
func hexFindings(cls, category string, results []patterns.HexResult) []Finding {
	type grp struct {
		readable []string
		secrets  []string
	}
	groups := map[string]*grp{}
	var order []string
	for _, hr := range results {
		g, ok := groups[hr.KeyName]
		if !ok {
			g = &grp{}
			groups[hr.KeyName] = g
			order = append(order, hr.KeyName)
		}
		g.readable = append(g.readable, hr.Readable...)
		g.secrets = append(g.secrets, patterns.MatchSecrets(hr.Decoded)...)
	}

	var out []Finding
	for _, key := range order {
		g := groups[key]
		strs := uniqueStrings(g.readable)
		if len(strs) > 10 {
			strs = strs[:10]
		}
		sevs := uniqueStrings(g.secrets)
		sev := "medium"
		title := "Hex-encoded string decoded (" + key + ")"
		if len(sevs) > 0 {
			sev = "high"
			title += " — possible " + strings.Join(sevs, ", ")
		}
		out = append(out, Finding{
			Category: category,
			Severity: sev,
			Title:    title,
			Class:    cls,
			Detail:   "decoded from hex blob in code",
			Evidence: strings.Join(strs, "\n"),
		})
	}
	return out
}

// scanSourceForHex finds every hex blob in one class source, decodes it, and
// emits one finding per class listing the interesting decoded strings.
func scanSourceForHex(cls, src string) []Finding {
	return hexFindings(cls, "hexstr", interestingHexResults(src))
}
