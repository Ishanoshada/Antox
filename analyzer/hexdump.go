package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"antox/patterns"
)

// AnalyzeHexDump decodes a user-supplied hex blob (byte dump, byte-array
// literal or hex string) into every interpretation: plain ASCII, XOR 0x42,
// XOR 0x41, XOR 0x5A — with readable strings extracted. This is the "hex
// level extract" utility: paste a dump like "77 6E C4 5F 54 65 78 74 ..." and
// get back the strings hidden in it.
func (e *Engine) AnalyzeHexDump(ctx context.Context, o Options) (*Report, error) {
	start := time.Now()
	r := &Report{Mode: o.Mode, AppName: "-", APKPackage: "-"}

	if o.Term == "" {
		return r, fmt.Errorf("hexdump mode requires hex input via -term")
	}

	raw := patterns.ParseHexBytes(o.Term)
	if len(raw) == 0 {
		r.Errors = append(r.Errors, "could not parse input as hex bytes")
		r.DurationMS = time.Since(start).Milliseconds()
		e.finishReport(ctx, r)
		return r, nil
	}

	r.Notes = append(r.Notes, fmt.Sprintf("parsed %d bytes", len(raw)))

	for _, hr := range patterns.DecodeHexBlob(raw) {
		strs := uniqueStrings(hr.Readable)
		if len(strs) > 20 {
			strs = strs[:20]
		}
		sev := "low"
		if hr.Interesting() {
			sev = "high"
		}
		detail := strings.Join(hr.Keywords, ", ")
		// Credential-shaped decoded text is the "secure data" case — raise it
		// and name the pattern in the title.
		if sevs := uniqueStrings(patterns.MatchSecrets(hr.Decoded)); len(sevs) > 0 {
			sev = "critical"
			title := fmt.Sprintf("Decoded (%s) — possible %s", hr.KeyName, strings.Join(sevs, ", "))
			r.Findings = append(r.Findings, Finding{
				Category: "hexdump",
				Severity: sev,
				Title:    title,
				Class:    "hex",
				Evidence: strings.Join(strs, "\n"),
				Detail:   detail,
			})
			continue
		}
		r.Findings = append(r.Findings, Finding{
			Category: "hexdump",
			Severity: sev,
			Title:    fmt.Sprintf("Decoded (%s) — %d readable strings", hr.KeyName, len(hr.Readable)),
			Class:    "hex",
			Evidence: strings.Join(strs, "\n"),
			Detail:   detail,
		})
	}

	if len(r.Findings) == 0 {
		r.Notes = append(r.Notes, "no readable strings decoded from the input")
	}

	// Also dump a JSON view of the raw bytes for the saved report.
	if rb, err := json.Marshal(raw); err == nil {
		r.Notes = append(r.Notes, "raw_bytes="+string(rb))
	}

	r.DurationMS = time.Since(start).Milliseconds()
	e.finishReport(ctx, r)
	return r, nil
}
