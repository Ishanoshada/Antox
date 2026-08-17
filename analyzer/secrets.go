package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"antox/mcp"
	"antox/patterns"
)

// AnalyzeSecrets hunts for hardcoded credentials in decompiled code and string
// resources: API keys, tokens, private keys and secret assignments.
func (e *Engine) AnalyzeSecrets(ctx context.Context, o Options) (*Report, error) {
	start := time.Now()
	r := &Report{Mode: o.Mode, AppName: "unknown", APKPackage: e.appPackage(ctx)}

	// 1) Keyword search over code -> fetch sources concurrently -> run secret regexes.
	classes := e.collectClasses(ctx, patterns.SecretsTerms, o.Package, e.Limit*6)
	sources := e.fetchSources(ctx, classes, e.Limit*2)
	for cls, src := range sources {
		r.Findings = append(r.Findings, scanSourceForSecrets(cls, src)...)
	}

	// 2) String resources (strings.xml) — often where keys end up.
	if stringsFound := e.scanStringsForSecrets(ctx); len(stringsFound) > 0 {
		r.Findings = append(r.Findings, stringsFound...)
	}

	// 3) Resource files that look credential-related.
	if res := e.resourceNamesMatching(ctx, patterns.SecretResourceHints); len(res) > 0 {
		r.Notes = append(r.Notes,
			fmt.Sprintf("credential-related resources: %s", strings.Join(res, ", ")))
	}

	r.DurationMS = time.Since(start).Milliseconds()
	e.finishReport(ctx, r)
	return r, nil
}

// scanSourceForSecrets applies every SecretPattern to one class source.
func scanSourceForSecrets(cls, src string) []Finding {
	var out []Finding
	seenKey := map[string]bool{}
	for _, pat := range patterns.SecretPatterns {
		for _, ln := range strings.Split(src, "\n") {
			m := pat.Regexp.FindString(ln)
			if m == "" {
				continue
			}
			key := pat.Name + "|" + m
			if seenKey[key] {
				continue
			}
			seenKey[key] = true
			out = append(out, Finding{
				Category: "secrets",
				Severity: pat.Severity,
				Title:    pat.Name,
				Class:    cls,
				Evidence: strings.TrimSpace(ln),
			})
		}
	}
	return out
}

// scanStringsForSecrets pulls every string resource and runs secret regexes
// over the values.
func (e *Engine) scanStringsForSecrets(ctx context.Context) []Finding {
	tr, err := e.Client.CallTool(ctx, "get_strings", map[string]any{"offset": 0, "count": 0})
	if err != nil {
		e.Errs = append(e.Errs, fmt.Sprintf("get_strings: %v", err))
		return nil
	}
	vals := extractStringValues(tr)
	if len(vals) == 0 {
		return nil
	}
	var out []Finding
	seen := map[string]bool{}
	for _, v := range vals {
		for _, pat := range patterns.SecretPatterns {
			m := pat.Regexp.FindString(v)
			if m == "" {
				continue
			}
			key := pat.Name + "|" + m
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, Finding{
				Category: "secrets",
				Severity: pat.Severity,
				Title:    pat.Name,
				Class:    "res/values/strings.xml",
				Evidence: truncate(v, 160),
			})
		}
	}
	return out
}

// extractStringValues flattens a get_strings result into plain string values.
func extractStringValues(tr *mcp.ToolResult) []string {
	raw := toolRawJSON(tr)
	var out []string
	var items []json.RawMessage
	var doc struct {
		Items []json.RawMessage `json:"items"`
	}
	if json.Unmarshal(raw, &doc) == nil && len(doc.Items) > 0 {
		items = doc.Items
	}
	if items == nil {
		_ = json.Unmarshal(raw, &items)
	}
	for _, it := range items {
		var s string
		if json.Unmarshal(it, &s) == nil {
			if s != "" {
				out = append(out, s)
			}
			continue
		}
		var m map[string]any
		if json.Unmarshal(it, &m) == nil {
			// Prefer the value of any string-valued field.
			for _, k := range []string{"value", "text", "name", "key", "string", "content"} {
				if v, ok := m[k]; ok {
					if s, ok := v.(string); ok && s != "" {
						out = append(out, s)
					}
				}
			}
		}
	}
	return uniqueStrings(out)
}

// resourceNamesMatching lists resource file names containing any hint (lowercase match).
func (e *Engine) resourceNamesMatching(ctx context.Context, hints []string) []string {
	tr, err := e.Client.CallTool(ctx, "get_all_resource_file_names", map[string]any{"offset": 0, "count": 0})
	if err != nil {
		return nil
	}
	var out []string
	for _, name := range extractStringValues(tr) {
		lower := strings.ToLower(name)
		for _, h := range hints {
			if strings.Contains(lower, h) {
				out = append(out, name)
				break
			}
		}
	}
	return uniqueStrings(out)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
