package analyzer

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Finding is a single detected item produced by an analysis mode.
type Finding struct {
	Category string `json:"category"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Class    string `json:"class,omitempty"`
	Method   string `json:"method,omitempty"`
	Evidence string `json:"evidence,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// Report is the full result of one analysis run.
type Report struct {
	AppName     string         `json:"app_name"`
	APKPackage  string         `json:"package,omitempty"`
	Mode        string         `json:"mode"`
	Server      string         `json:"server"`
	GeneratedAt string         `json:"generated_at"`
	DurationMS  int64          `json:"duration_ms"`
	Summary     map[string]int `json:"summary"`
	Findings    []Finding      `json:"findings"`
	Manifest    string         `json:"manifest,omitempty"`
	Notes       []string       `json:"notes,omitempty"`
	Errors      []string       `json:"errors,omitempty"`
}

func (r *Report) countByCategory() map[string]int {
	out := map[string]int{}
	for _, f := range r.Findings {
		out[f.Category]++
	}
	return out
}

// RenderConsole writes a human-readable report to w.
func (r *Report) RenderConsole(w io.Writer, color bool) {
	sep := "="
	line := strings.Repeat(sep, 64)
	fmt.Fprintf(w, "\n%s\n", line)
	fmt.Fprintf(w, "  JADX ANALYSIS REPORT  (%s)\n", r.Mode)
	fmt.Fprintf(w, "%s\n", line)
	fmt.Fprintf(w, "  server     : %s\n", r.Server)
	fmt.Fprintf(w, "  package    : %s\n", orDash(r.APKPackage))
	fmt.Fprintf(w, "  app        : %s\n", orDash(r.AppName))
	fmt.Fprintf(w, "  generated  : %s\n", r.GeneratedAt)
	fmt.Fprintf(w, "  duration   : %.1fs\n", float64(r.DurationMS)/1000)
	fmt.Fprintf(w, "  findings   : %d\n", len(r.Findings))
	fmt.Fprintf(w, "  errors     : %d\n", len(r.Errors))
	fmt.Fprintf(w, "%s\n", line)

	// Summary table
	if len(r.Summary) > 0 {
		fmt.Fprintf(w, "\n  %-28s %8s\n", "category", "count")
		fmt.Fprintf(w, "  %-28s %8s\n", strings.Repeat("-", 28), strings.Repeat("-", 8))
		keys := make([]string, 0, len(r.Summary))
		for k := range r.Summary {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(w, "  %-28s %8d\n", k, r.Summary[k])
		}
	}

	if len(r.Notes) > 0 {
		fmt.Fprintf(w, "\n  notes:\n")
		for _, n := range r.Notes {
			fmt.Fprintf(w, "    - %s\n", n)
		}
	}

	// Findings grouped by category
	if len(r.Findings) > 0 {
		fmt.Fprintf(w, "\n  FINDINGS\n")
		groups := map[string][]Finding{}
		var cats []string
		for _, f := range r.Findings {
			if _, ok := groups[f.Category]; !ok {
				cats = append(cats, f.Category)
			}
			groups[f.Category] = append(groups[f.Category], f)
		}
		sort.Strings(cats)
		for _, cat := range cats {
			fmt.Fprintf(w, "\n  [%s] %d item(s)\n", cat, len(groups[cat]))
			for _, f := range groups[cat] {
				sev := f.Severity
				if sev == "" {
					sev = "info"
				}
				label := sevLabel(sev)
				if color {
					fmt.Fprintf(w, "    %s %s %s\n", sevColor(sev, label), f.Class, f.Title)
				} else {
					fmt.Fprintf(w, "    %s %s %s\n", label, f.Class, f.Title)
				}
				if f.Method != "" {
					fmt.Fprintf(w, "        method : %s\n", f.Method)
				}
				if f.Evidence != "" {
					for _, ev := range strings.Split(f.Evidence, "\n") {
						fmt.Fprintf(w, "        %s\n", ev)
					}
				}
			}
		}
	}

	if len(r.Errors) > 0 {
		fmt.Fprintf(w, "\n  ERRORS\n")
		for _, e := range r.Errors {
			fmt.Fprintf(w, "    - %s\n", e)
		}
	}
	fmt.Fprintf(w, "\n")
}

// RenderMarkdown produces a markdown report.
func (r *Report) RenderMarkdown() string {
	var b strings.Builder
	b.WriteString("# JADX Analysis Report\n\n")
	fmt.Fprintf(&b, "- **mode**: `%s`\n", r.Mode)
	fmt.Fprintf(&b, "- **server**: `%s`\n", r.Server)
	fmt.Fprintf(&b, "- **package**: `%s`\n", orDash(r.APKPackage))
	fmt.Fprintf(&b, "- **app**: %s\n", orDash(r.AppName))
	fmt.Fprintf(&b, "- **generated**: %s\n", r.GeneratedAt)
	fmt.Fprintf(&b, "- **duration**: %.1fs\n", float64(r.DurationMS)/1000)
	fmt.Fprintf(&b, "- **findings**: %d\n\n", len(r.Findings))

	if len(r.Summary) > 0 {
		b.WriteString("## Summary\n\n| category | count |\n|---|---|\n")
		keys := make([]string, 0, len(r.Summary))
		for k := range r.Summary {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "| %s | %d |\n", k, r.Summary[k])
		}
		b.WriteString("\n")
	}

	if len(r.Notes) > 0 {
		b.WriteString("## Notes\n\n")
		for _, n := range r.Notes {
			fmt.Fprintf(&b, "- %s\n", n)
		}
		b.WriteString("\n")
	}

	if len(r.Findings) > 0 {
		b.WriteString("## Findings\n\n")
		groups := map[string][]Finding{}
		var cats []string
		for _, f := range r.Findings {
			if _, ok := groups[f.Category]; !ok {
				cats = append(cats, f.Category)
			}
			groups[f.Category] = append(groups[f.Category], f)
		}
		sort.Strings(cats)
		for _, cat := range cats {
			fmt.Fprintf(&b, "### %s\n\n", cat)
			for _, f := range groups[cat] {
				sev := f.Severity
				if sev == "" {
					sev = "info"
				}
				fmt.Fprintf(&b, "- **%s** — %s `%s`\n", sev, f.Title, f.Class)
				if f.Method != "" {
					fmt.Fprintf(&b, "  - method: `%s`\n", f.Method)
				}
				if f.Detail != "" {
					fmt.Fprintf(&b, "  - detail: %s\n", f.Detail)
				}
				if f.Evidence != "" {
					b.WriteString("  - evidence:\n")
					for _, ev := range strings.Split(f.Evidence, "\n") {
						fmt.Fprintf(&b, "    ```text\n    %s\n    ```\n", ev)
					}
				}
			}
			b.WriteString("\n")
		}
	}

	if len(r.Errors) > 0 {
		b.WriteString("## Errors\n\n")
		for _, e := range r.Errors {
			fmt.Fprintf(&b, "- %s\n", e)
		}
		b.WriteString("\n")
	}

	if r.Manifest != "" {
		b.WriteString("## AndroidManifest.xml\n\n```xml\n")
		b.WriteString(r.Manifest)
		b.WriteString("\n```\n")
	}
	return b.String()
}

// Save writes the report to disk. If dirOrFile ends in .md/.json it is used as
// the exact output path; otherwise it is treated as a directory and the report
// is written as <mode>-<timestamp>.<ext> inside it. Returns the written paths.
func (r *Report) Save(dirOrFile, format string) ([]string, error) {
	format = strings.ToLower(format)
	if format == "" || format == "markdown" {
		format = "md"
	}
	ext := map[string]string{"md": ".md", "json": ".json"}[format]
	if format != "both" && ext == "" {
		return nil, fmt.Errorf("unsupported format %q (use md, json or both)", format)
	}

	var written []string
	write := func(full string, data []byte) error {
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		return os.WriteFile(full, data, 0o644)
	}

	if format == "both" {
		if strings.HasSuffix(strings.ToLower(dirOrFile), ".md") || strings.HasSuffix(strings.ToLower(dirOrFile), ".json") {
			return nil, fmt.Errorf("cannot use -format both with an explicit file path; pass a directory")
		}
		base := filepath.Join(dirOrFile, r.fileBase())
		md := base + ".md"
		if err := write(md, []byte(r.RenderMarkdown())); err != nil {
			return nil, err
		}
		written = append(written, md)
		jp := base + ".json"
		if err := write(jp, r.marshalJSON()); err != nil {
			return nil, err
		}
		written = append(written, jp)
		return written, nil
	}

	if strings.HasSuffix(strings.ToLower(dirOrFile), ext) {
		if err := write(dirOrFile, r.renderFormat(format)); err != nil {
			return nil, err
		}
		return []string{dirOrFile}, nil
	}

	full := filepath.Join(dirOrFile, r.fileBase()+ext)
	if err := write(full, r.renderFormat(format)); err != nil {
		return nil, err
	}
	return []string{full}, nil
}

func (r *Report) renderFormat(format string) []byte {
	if format == "json" {
		return r.marshalJSON()
	}
	return []byte(r.RenderMarkdown())
}

func (r *Report) marshalJSON() []byte {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return []byte(`{"error":"marshal failed"}`)
	}
	return b
}

func (r *Report) fileBase() string {
	base := strings.NewReplacer(" ", "-", ":", "-", "/", "-", "\\", "-").Replace(r.APKPackage)
	if base == "" {
		base = "apk"
	}
	return fmt.Sprintf("%s-%s-%s", r.Mode, base, time.Now().Format("20060102-150405"))
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

var sevLabels = map[string]string{
	"info":     "info",
	"low":      "low",
	"medium":   "medium",
	"high":     "high",
	"critical": "critical",
}

func sevLabel(s string) string {
	if l, ok := sevLabels[strings.ToLower(s)]; ok {
		return l
	}
	return "info"
}

// ANSI color helpers (Windows 10+ terminals support these).
const (
	ansiReset  = "\x1b[0m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiRed    = "\x1b[31m"
	ansiBold   = "\x1b[1m"
	ansiCyan   = "\x1b[36m"
)

func sevColor(sev, label string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return ansiBold + ansiRed + "[" + label + "]" + ansiReset
	case "high":
		return ansiRed + "[" + label + "]" + ansiReset
	case "medium":
		return ansiYellow + "[" + label + "]" + ansiReset
	case "low":
		return ansiCyan + "[" + label + "]" + ansiReset
	default:
		return ansiGreen + "[" + label + "]" + ansiReset
	}
}
