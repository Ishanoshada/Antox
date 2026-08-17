// Package analyzer orchestrates static analysis of a decompiled Android app by
// driving the jadx MCP server (jadx-mcp-server) over HTTP. Each mode maps to a
// switchable analysis dimension and produces a Report that can be printed and
// saved to disk.
package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"antox/mcp"
	"antox/patterns"
)

// Options carries per-run configuration from the CLI.
type Options struct {
	Mode    string
	Term    string // custom search term (search mode / shell)
	Scope   string // custom search scope (search mode)
	Package string // restrict searches to a package
	Limit   int    // max class sources fetched per search term
	Debug   bool
	ApkDir  string // unzipped APK directory for raw binary resource scanning
	OutDir  string // output directory / file for artifact-writing modes (fridahook)
}

// Engine drives analysis against an MCP client.
type Engine struct {
	Client  *mcp.Client
	Debug   bool
	Limit   int
	Workers int // concurrent class-source fetches (default 8)
	Quiet   bool
	NoColor bool // disable ANSI colors in the progress bar / banner
	Errs    []string

	initOnce sync.Once
	initErr  error

	pkgOnce bool
	pkgName string

	// suppressSearchLog quiets the per-term search line while the collectClasses
	// progress bar is live, so the two never interleave on the same line.
	suppressSearchLog bool
}

// NewEngine builds an analysis engine bound to an MCP client.
func NewEngine(client *mcp.Client, limit int, debug bool) *Engine {
	if limit <= 0 {
		limit = 8
	}
	return &Engine{Client: client, Limit: limit, Debug: debug, Workers: 8}
}

// logf writes a progress line to stderr unless quiet.
func (e *Engine) logf(format string, args ...any) {
	if e.Quiet {
		return
	}
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

// banner draws a simple box banner naming the analysis mode, so every run opens
// with a clear loading header (suppressed under -quiet).
func (e *Engine) banner(mode string) {
	if e.Quiet {
		return
	}
	cyan := func(s string) string { return s }
	dim := func(s string) string { return s }
	if !e.NoColor {
		cyan = func(s string) string { return "\x1b[36m" + s + "\x1b[0m" }
		dim = func(s string) string { return "\x1b[2m" + s + "\x1b[0m" }
	}
	edge := strings.Repeat("─", 52)
	fmt.Fprintf(os.Stderr, "%s\n", cyan("┌"+edge+"┐"))
	fmt.Fprintf(os.Stderr, "%s  ⚡ antox · mode %s  %s\n",
		cyan("│"), mode, cyan("│"))
	fmt.Fprintf(os.Stderr, "%s  %s  %s\n",
		cyan("│"), dim("jadx MCP: "+e.Client.BaseURL()), cyan("│"))
	fmt.Fprintf(os.Stderr, "%s\n", cyan("└"+edge+"┘"))
}

// ensureInit performs the MCP handshake once per engine, lazily, so any mode
// works without an explicit initialize step.
func (e *Engine) ensureInit(ctx context.Context) error {
	e.initOnce.Do(func() {
		_, e.initErr = e.Client.Initialize(ctx)
	})
	return e.initErr
}

// Run dispatches to the mode handler named by o.Mode. The report's Mode field
// is set here so handlers don't need to repeat it.
func (e *Engine) Run(ctx context.Context, o Options) (*Report, error) {
	if err := e.ensureInit(ctx); err != nil {
		return nil, fmt.Errorf("connect to MCP server: %w", err)
	}
	e.Errs = nil
	e.Debug = o.Debug
	e.banner(o.Mode)
	if o.Limit > 0 {
		e.Limit = o.Limit
	}
	var (
		rep *Report
		err error
	)
	switch o.Mode {
	case "manifest":
		rep, err = e.AnalyzeManifest(ctx, o)
	case "secrets", "apikey", "apikeys", "keys":
		o.Mode = "secrets"
		rep, err = e.AnalyzeSecrets(ctx, o)
	case "firebase":
		rep, err = e.AnalyzeFirebase(ctx, o)
	case "security", "hardening":
		o.Mode = "security"
		rep, err = e.AnalyzeSecurity(ctx, o)
	case "detection":
		rep, err = e.AnalyzeDetection(ctx, o)
	case "sdks", "sdk", "libraries", "libs":
		o.Mode = "sdks"
		rep, err = e.AnalyzeSDKs(ctx, o)
	case "fridahook", "frida", "hookjs", "bypass":
		o.Mode = "fridahook"
		rep, err = e.AnalyzeFridaHook(ctx, o)
	case "native", "so", "jni":
		o.Mode = "native"
		rep, err = e.AnalyzeNative(ctx, o)
	case "sostr", "so-scan", "sostrings":
		o.Mode = "sostr"
		rep, err = e.AnalyzeSoStrings(ctx, o)
	case "hexenc", "obfuscation", "obfuscate":
		o.Mode = "hexenc"
		rep, err = e.AnalyzeHexEnc(ctx, o)
	case "hexstr", "hex", "hextract":
		o.Mode = "hexstr"
		rep, err = e.AnalyzeHexStr(ctx, o)
	case "hexdump", "hexdecode":
		o.Mode = "hexdump"
		rep, err = e.AnalyzeHexDump(ctx, o)
	case "backend", "hosts", "endpoints", "infra":
		o.Mode = "backend"
		rep, err = e.AnalyzeBackend(ctx, o)
	case "search":
		rep, err = e.AnalyzeSearch(ctx, o)
	case "all", "full":
		o.Mode = "all"
		rep, err = e.AnalyzeAll(ctx, o)
	default:
		return nil, fmt.Errorf("unknown mode %q", o.Mode)
	}
	if rep != nil {
		if ctx.Err() != nil {
			// Interrupted (Ctrl+C): the in-flight HTTP/SSE calls all fail with
			// "interrupt signal received" / "context canceled" — that's noise,
			// not analysis errors. Drop it and say the report is partial.
			for _, er := range e.Errs {
				if !isCancellationErr(er) {
					rep.Errors = append(rep.Errors, er)
				}
			}
			rep.Notes = append(rep.Notes, "interrupted by user (Ctrl+C) — report shows partial results")
		} else {
			rep.Errors = append(rep.Errors, e.Errs...)
		}
	}
	return rep, err
}

// isCancellationErr reports whether a recorded error string is just the noise
// produced when the context is cancelled (user pressed Ctrl+C).
func isCancellationErr(s string) bool {
	low := strings.ToLower(s)
	for _, marker := range []string{
		"interrupt", "context canceled", "context cancelled",
		"context deadline exceeded", "operation was canceled",
		"operation was cancelled", "request canceled", "client closed",
	} {
		if strings.Contains(low, marker) {
			return true
		}
	}
	return false
}

// appPackage lazily resolves the app package name from the manifest.
func (e *Engine) appPackage(ctx context.Context) string {
	if e.pkgOnce {
		return e.pkgName
	}
	e.pkgOnce = true
	mi, _, err := fetchManifest(ctx, e.Client)
	if err != nil {
		return ""
	}
	e.pkgName = mi.Package
	return e.pkgName
}

// search runs a jadx keyword search and returns the matching class names.
func (e *Engine) search(ctx context.Context, term patterns.Term, pkg string, count int) ([]string, error) {
	args := map[string]any{
		"search_term": term.Text,
		"package":     pkg,
		"search_in":   term.Scope,
		"offset":      0,
		"count":       count,
	}
	tr, err := e.Client.CallTool(ctx, "search_classes_by_keyword", args)
	if err != nil {
		return nil, err
	}
	names := parseSearchResult(tr)
	if !e.suppressSearchLog {
		e.logf("  search %q (%s) -> %d classes", term.Text, term.Scope, len(names))
	}
	return names, nil
}

// resourceFiles enumerates every resource / packaged file path in the APK via
// get_all_resource_file_names, walking all paginated pages (the server caps a
// page at 100 items). Paths look like
// "lib/arm64-v8a/libx.so", "classes.dex", "res/...", "AndroidManifest.xml".
func (e *Engine) resourceFiles(ctx context.Context) []string {
	seen := map[string]bool{}
	var all []string
	for offset := 0; offset < 100000; offset += 100 {
		if err := ctx.Err(); err != nil {
			break
		}
		tr, err := e.Client.CallTool(ctx, "get_all_resource_file_names",
			map[string]any{"offset": offset, "count": 100})
		if err != nil {
			e.Errs = append(e.Errs, fmt.Sprintf("get_all_resource_file_names: %v", err))
			break
		}
		added := 0
		for _, n := range parseSearchResult(tr) {
			if !seen[n] {
				seen[n] = true
				all = append(all, n)
				added++
			}
		}
		if !moreFromResult(tr) || added == 0 {
			break
		}
	}
	return all
}

// moreFromResult reports whether a paginated tool response has more pages.
func moreFromResult(tr *mcp.ToolResult) bool {
	var doc struct {
		Pagination struct {
			HasMore bool `json:"has_more"`
		} `json:"pagination"`
	}
	if raw := toolRawJSON(tr); len(raw) > 0 {
		if json.Unmarshal(raw, &doc) == nil {
			return doc.Pagination.HasMore
		}
	}
	return false
}

// scanResources searches the packaged resource file names — this is the
// "resource" search scope. A term filters the file list; .so and .dex files
// are always surfaced (they never appear in Java class source). Known
// detection payload libraries (libsna, libsnb, libsnitchtt, libfrida, ...)
// are flagged.
func (e *Engine) scanResources(ctx context.Context, r *Report, term string) {
	files := e.resourceFiles(ctx)
	if len(files) == 0 {
		return
	}
	termL := strings.ToLower(term)
	var so, dex, other []string
	for _, f := range files {
		fl := strings.ToLower(f)
		if term != "" && !strings.Contains(fl, termL) {
			continue
		}
		switch {
		case strings.HasSuffix(fl, ".so"):
			so = append(so, f)
		case strings.HasSuffix(fl, ".dex"):
			dex = append(dex, f)
		default:
			other = append(other, f)
		}
	}
	if term != "" {
		r.Notes = append(r.Notes,
			fmt.Sprintf("resource scope: %d of %d files match %q", len(so)+len(dex)+len(other), len(files), term))
	}

	// Native / dex libraries present in the package.
	for _, f := range so {
		sev, detail := "medium", "native library packaged in APK"
		switch {
		case isSuspiciousSo(f):
			sev, detail = "high", "native library matches a known detection payload (.so) family"
		case isFrameworkSo(f):
			sev, detail = "info", "app framework engine (.so) — identifies the runtime (Flutter / React Native / Hermes)"
		}
		r.Findings = append(r.Findings, Finding{
			Category: "resource",
			Severity: sev,
			Title:    "Native .so library in APK resources",
			Class:    f,
			Detail:   detail,
		})
	}
	for _, f := range dex {
		r.Findings = append(r.Findings, Finding{
			Category: "resource",
			Severity: "low",
			Title:    "Dex file in APK resources",
			Class:    f,
			Detail:   "packaged .dex (may be a loader / additional code)",
		})
	}
	// Non-library files are only surfaced when they matched an explicit term;
	// with an empty term (list everything) they would just be noise.
	if term != "" {
		for _, f := range other {
			r.Findings = append(r.Findings, Finding{
				Category: "resource",
				Severity: "info",
				Title:    "Resource file matching search term",
				Class:    f,
			})
		}
	}
}

// isSuspiciousSo reports whether a resource path names a known security /
// detection / hooking payload library (libts, libsna, libsnb, libsnitchtt,
// libzygisk, libfrida, libdobby, ...).
func isSuspiciousSo(f string) bool {
	base := strings.ToLower(filepath.Base(f))
	for _, suspect := range patterns.NativeSoNames {
		if strings.Contains(base, suspect) {
			return true
		}
	}
	return false
}

// isFrameworkSo reports whether a resource path names a legit app framework
// engine (Flutter libapp/libflutter, RN libhermes/libreactnativejni, ...).
func isFrameworkSo(f string) bool {
	base := strings.ToLower(filepath.Base(f))
	for _, eng := range patterns.FrameworkSoNames {
		if strings.Contains(base, eng) {
			return true
		}
	}
	return false
}

// searchMethod runs a method-name search and returns matching class names.
func (e *Engine) searchMethod(ctx context.Context, method string) ([]string, error) {
	tr, err := e.Client.CallTool(ctx, "search_method_by_name", map[string]any{"method_name": method})
	if err != nil {
		return nil, err
	}
	return parseSearchResult(tr), nil
}

// classSource fetches the decompiled source of one class.
func (e *Engine) classSource(ctx context.Context, cls string) (string, error) {
	tr, err := e.Client.CallTool(ctx, "get_class_source", map[string]any{"class_name": cls})
	if err != nil {
		return "", err
	}
	text := tr.Text()
	var m map[string]any
	if json.Unmarshal([]byte(text), &m) == nil {
		for _, k := range []string{"response", "source", "code", "content", "class_source", "java", "javaCode"} {
			if v, ok := m[k]; ok {
				if s, ok := v.(string); ok && s != "" {
					return s, nil
				}
			}
		}
	}
	return text, nil
}

// collectClasses runs keyword searches for each term (sequentially — searches
// are the heavy part server-side), de-duplicates the results and returns the
// union of matching class names.
func (e *Engine) collectClasses(ctx context.Context, terms []patterns.Term, pkg string, perTerm int) []string {
	seen := map[string]bool{}
	var mu sync.Mutex
	var all []string
	var wg sync.WaitGroup
	// Searches are the slowest step (server-side, whole-APK scans). Run them
	// concurrently with a small pool — 4 concurrent keeps the jadx server
	// busy without hammering it.
	pool := 4
	if e.workerCount() < pool {
		pool = e.workerCount()
	}
	sem := make(chan struct{}, pool)
	// One keyword search completes per worker — the progress bar tracks them.
	var done int32
	var pb *Progress
	if !e.Quiet {
		pb = NewProgress(os.Stderr, len(terms), fmt.Sprintf("searching %d keywords", len(terms)), !e.NoColor)
	}
	e.suppressSearchLog = pb != nil
	defer func() { e.suppressSearchLog = false }()
	for _, term := range terms {
		if err := ctx.Err(); err != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(t patterns.Term) {
			defer wg.Done()
			defer func() { <-sem }()
			classes, err := e.search(ctx, t, pkg, perTerm)
			mu.Lock()
			if err != nil {
				e.Errs = append(e.Errs, fmt.Sprintf("search %q: %v", t.Text, err))
			} else {
				for _, cls := range classes {
					if !seen[cls] {
						seen[cls] = true
						all = append(all, cls)
					}
				}
			}
			n := atomic.AddInt32(&done, 1)
			mu.Unlock()
			if pb != nil {
				pb.Update(int(n))
			}
		}(term)
	}
	wg.Wait()
	if pb != nil {
		pb.Finish()
	}
	e.logf("search complete -> %d classes", len(all))
	return all
}

// fetchSources fetches the sources of up to max classes concurrently using a
// bounded worker pool. Failed fetches are silently skipped (they don't change
// findings). Progress is driven by a tqdm-style bar counting every fetch
// attempt so the bar always reaches total even when sources error out.
func (e *Engine) fetchSources(ctx context.Context, classes []string, max int) map[string]string {
	if max > 0 && max < len(classes) {
		classes = classes[:max]
	}
	out := map[string]string{}
	var mu sync.Mutex
	var done int32
	sem := make(chan struct{}, e.workerCount())
	var wg sync.WaitGroup
	var pb *Progress
	if !e.Quiet {
		pb = NewProgress(os.Stderr, len(classes), fmt.Sprintf("fetching %d sources", len(classes)), !e.NoColor)
	}
	for _, cls := range classes {
		if err := ctx.Err(); err != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(c string) {
			defer wg.Done()
			defer func() { <-sem }()
			src, err := e.classSource(ctx, c)
			mu.Lock()
			if err == nil {
				out[c] = src
			}
			n := atomic.AddInt32(&done, 1)
			mu.Unlock()
			if pb != nil {
				pb.Update(int(n))
			}
		}(cls)
	}
	wg.Wait()
	if pb != nil {
		pb.Finish()
	}
	return out
}

func (e *Engine) workerCount() int {
	if e.Workers <= 0 {
		return 8
	}
	return e.Workers
}

// runCategory performs keyword searches for a category, fetches a bounded
// number of class sources concurrently, and extracts evidence lines.
func (e *Engine) runCategory(ctx context.Context, cat patterns.Category, pkg string) []Finding {
	classes := e.collectClasses(ctx, cat.Terms, pkg, e.Limit*6)
	sources := e.fetchSources(ctx, classes, e.Limit)
	var findings []Finding
	for cls, src := range sources {
		findings = append(findings, findingsFromSource(cls, cat, src)...)
	}
	return findings
}

// findingsFromSource builds at most one finding per class per category, with
// matched evidence lines joined.
func findingsFromSource(cls string, cat patterns.Category, src string) []Finding {
	var evs []string
	seen := map[string]bool{}
	for _, re := range cat.Regexes {
		for _, ln := range strings.Split(src, "\n") {
			if re.MatchString(ln) {
				t := strings.TrimSpace(ln)
				if len(t) > 0 && !seen[t] {
					seen[t] = true
					if len(t) > 240 {
						t = t[:240] + "..."
					}
					evs = append(evs, t)
				}
			}
		}
	}
	if len(evs) == 0 {
		return nil
	}
	if len(evs) > 8 {
		evs = evs[:8]
	}
	return []Finding{{
		Category: cat.ID,
		Severity: cat.Severity,
		Title:    cat.Label,
		Class:    cls,
		Evidence: strings.Join(evs, "\n"),
	}}
}

// scanRegexes runs a set of evidence regexes over one class source and emits a
// single finding per class (evidence lines joined), using the given category.
func scanRegexes(cls, category, severity string, regexes []*regexp.Regexp, src string) []Finding {
	cat := patterns.Category{ID: category, Severity: severity, Regexes: regexes}
	return findingsFromSource(cls, cat, src)
}

// finishReport fills in the common report metadata and summary counts.
func (e *Engine) finishReport(ctx context.Context, r *Report) {
	r.Server = e.Client.BaseURL()
	r.GeneratedAt = nowStr()
	r.Summary = r.countByCategory()
	if r.APKPackage == "" {
		r.APKPackage = e.appPackage(ctx)
	}
}

func nowStr() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

// toolRawJSON prefers the structuredContent blob, falling back to the text
// content (which is itself usually a JSON document).
func toolRawJSON(tr *mcp.ToolResult) []byte {
	if b := tr.StructuredContent; len(b) > 0 && string(b) != "null" {
		return b
	}
	return []byte(tr.Text())
}

// parseSearchResult normalizes the many shapes a search result can take
// (standard paginated-list, top-level array, dict with classes/methods key)
// into a flat list of class names.
func parseSearchResult(tr *mcp.ToolResult) []string {
	raw := toolRawJSON(tr)
	if len(raw) == 0 {
		return nil
	}

	var doc struct {
		Items []json.RawMessage `json:"items"`
	}
	if json.Unmarshal(raw, &doc) == nil && len(doc.Items) > 0 {
		return rawItemsToStrings(doc.Items)
	}

	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) == nil && len(arr) > 0 {
		return rawItemsToStrings(arr)
	}

	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) == nil {
		for _, k := range []string{"classes", "methods", "results", "items", "matches"} {
			if v, ok := m[k]; ok {
				var items []json.RawMessage
				if json.Unmarshal(v, &items) == nil && len(items) > 0 {
					return rawItemsToStrings(items)
				}
			}
		}
		// Some tools (e.g. search_method_by_name) return a newline-joined string
		// under "response": {"response":"A\nB\nC"}. Split it into class names.
		if v, ok := m["response"]; ok {
			var s string
			if json.Unmarshal(v, &s) == nil {
				var out []string
				for _, ln := range strings.Split(s, "\n") {
					if ln = strings.TrimSpace(ln); ln != "" {
						out = append(out, ln)
					}
				}
				return out
			}
		}
	}
	return nil
}

func rawItemsToStrings(items []json.RawMessage) []string {
	out := []string{}
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
			for _, k := range []string{"class_name", "className", "name", "class", "path", "full_name", "fullName"} {
				if v, ok := m[k]; ok {
					if s, ok := v.(string); ok && s != "" {
						out = append(out, s)
						break
					}
				}
			}
		}
	}
	return out
}

// uniqueStrings de-duplicates while preserving order.
func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
