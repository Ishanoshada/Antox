package analyzer

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"antox/patterns"
)

// AnalyzeBackend maps the app's backend infrastructure: hosts and IPs (code +
// resource content), API service prefixes and endpoints, Firebase
// configuration values, and cleartext/TLS posture from
// network_security_config.xml. Many of these values live in compiled binary
// resources (resources.arsc) or the Dart AOT snapshot (libapp.so), so the
// raw resource file content is fetched and scanned too.
func (e *Engine) AnalyzeBackend(ctx context.Context, o Options) (*Report, error) {
	start := time.Now()
	r := &Report{Mode: o.Mode, AppName: "unknown", APKPackage: e.appPackage(ctx)}

	// 1) Code: hosts / IPs / URLs / API paths in decompiled classes.
	classes := e.collectClasses(ctx, patterns.FirebaseTerms, o.Package, e.Limit*4)
	sources := e.fetchSources(ctx, classes, e.Limit)
	for cls, src := range sources {
		if f := scanRegexes(cls, "backend", "info", patterns.BackendCodeRegexes, src); len(f) > 0 {
			r.Findings = append(r.Findings, f...)
		}
	}

	// 2) String resources (get_strings) — this is where the Firebase values
	// surface even when they only exist in resources.arsc.
	if tr, err := e.Client.CallTool(ctx, "get_strings", map[string]any{"offset": 0, "count": 0}); err == nil {
		for _, v := range extractStringValues(tr) {
			for _, re := range patterns.FirebaseConfigRegexes {
				if m := re.FindString(v); m != "" {
					r.Findings = append(r.Findings, Finding{
						Category: "backend", Severity: "high",
						Title: "Firebase/Google configuration value", Class: "res/values/strings.xml",
						Detail: m,
					})
				}
			}
			for _, u := range patterns.CleartextURLs(v) {
				r.Findings = append(r.Findings, Finding{
					Category: "backend", Severity: "high",
					Title: "Cleartext HTTP URL in strings", Class: "res/values/strings.xml",
					Detail: u,
				})
			}
		}
	}

	// 3) Raw resource file contents: network_security_config.xml, certs.ts,
	// and (best-effort) the binary snapshots. Binary files may come back
	// undecodable — best effort only.
	files := e.resourceFiles(ctx)
	seen := map[string]bool{}
	for _, f := range files {
		lower := strings.ToLower(f)
		if !interestingBackendResource(lower) {
			continue
		}
		if seen[lower] {
			continue
		}
		seen[lower] = true
		e.scanBackendResource(ctx, r, f)
	}

	// 4) Raw APK on disk (optional -apk input): the plugin can't return binary
	// bytes for resources.arsc / libapp.so, but the raw APK can be read
	// directly — this is where the Firebase string values, hosts and endpoints
	// actually live. Mirrors the reference python scanner. Each token may be an
	// unzipped APK root or a raw .apk/.zip file; multiple tokens are
	// comma-separated: the base APK root holds resources.arsc while the split
	// config APK holds lib/arm64-v8a/libapp.so.
	if o.ApkDir != "" {
		for _, d := range strings.FieldsFunc(o.ApkDir, func(c rune) bool { return c == ',' || c == ';' }) {
			if strings.TrimSpace(d) != "" {
				e.scanApkInput(ctx, r, strings.TrimSpace(d))
			}
		}
	}

	// Summary note of the infrastructure picture.
	if len(r.Findings) > 0 {
		r.Notes = append(r.Notes, "backend scan: hosts/IPs/endpoints from code + resource contents + raw APK files")
	}

	r.DurationMS = time.Since(start).Milliseconds()
	e.finishReport(ctx, r)
	return r, nil
}

// interestingBackendResource reports whether a resource path is worth reading
// for backend / Firebase data.
func interestingBackendResource(lower string) bool {
	for _, name := range patterns.BackendResourceNames {
		if strings.Contains(lower, name) {
			return true
		}
	}
	return false
}

// scanBackendResource fetches one resource file's content and extracts
// hosts, IPs, endpoints, Firebase values and cleartext URLs.
func (e *Engine) scanBackendResource(ctx context.Context, r *Report, name string) {
	tr, err := e.Client.CallTool(ctx, "get_resource_file", map[string]any{"resource_name": name})
	if err != nil {
		e.Errs = append(e.Errs, fmt.Sprintf("get_resource_file %s: %v", name, err))
		return
	}
	content := tr.Text()
	if strings.TrimSpace(content) == "" {
		content = string(toolRawJSON(tr))
	}
	if len(content) == 0 || len(content) > 40_000_000 {
		e.Errs = append(e.Errs, fmt.Sprintf("get_resource_file %s: empty or oversized (%d bytes)", name, len(content)))
		return
	}

	isBinary := strings.ContainsRune(content, '\x00')
	if isBinary {
		// Best effort on binary: scan the printable runs.
		content = strings.Join(patterns.ExtractReadable([]byte(content)), " ")
	}
	e.emitBackendFinding(r, name, name, content)
}

func backendDetail(name string, cleartext bool) string {
	base := "hosts/IPs/endpoints/Firebase values recovered from packaged resource"
	if cleartext {
		base += " — contains cleartext http:// URLs (MITM exposure)"
	}
	return base
}

// extractBackendData runs every backend regex over a chunk of text and returns
// the evidence plus flags. cleartext is set only for real http:// URLs —
// schema/XML-namespace URIs (ns.adobe.com, www.w3.org, ...) are excluded.
// tlsPolicy is set when a network-security-config permits cleartext to a
// recovered IP. Evidence is capped so a packed binary snapshot stays readable.
func extractBackendData(text string) (evidence string, hosts, ips []string, secrets, cleartext, tlsPolicy bool) {
	ev := strings.Builder{}
	lines := 0
	seen := map[string]bool{}
	write := func(m string) {
		if seen[m] {
			return
		}
		seen[m] = true
		if lines >= 240 {
			return
		}
		lines++
		ev.WriteString(m + "\n")
	}
	truncated := 0

	secretRes := []*regexp.Regexp{
		patterns.FirebaseKeyRe, patterns.FirebaseAppIDRe, patterns.FirebaseSenderRe,
		patterns.StorageBucketRe,
	}
	for _, re := range secretRes {
		for _, m := range re.FindAllString(text, -1) {
			if len(m) > 3 {
				write(m)
				secrets = true
			}
		}
	}
	for _, u := range patterns.CleartextURLs(text) {
		write(u)
		cleartext = true
	}
	for _, re := range []*regexp.Regexp{patterns.ServicePrefixRe, patterns.EndpointRe} {
		for _, m := range re.FindAllString(text, -1) {
			if len(m) > 3 {
				if !seen[m] {
					seen[m] = true
					if lines < 240 {
						lines++
						ev.WriteString(m + "\n")
					} else {
						truncated++
					}
				}
			}
		}
	}
	hosts = uniqueStrings(patterns.DomainRe.FindAllString(text, -1))
	ips = uniqueStrings(patterns.IPv4Re.FindAllString(text, -1))

	// A cleartext posture exists only inside an actual network-security-config
	// (the hyphenated resource/XML name appears in the XML and its compiled
	// string pool, not in Java attribute references like networkSecurityConfig).
	if strings.Contains(text, "cleartextTrafficPermitted") && strings.Contains(text, "network-security-config") && len(ips) > 0 {
		tlsPolicy = true
	}
	if truncated > 0 {
		ev.WriteString(fmt.Sprintf("(+%d more matches truncated)", truncated))
	}
	evidence = strings.TrimRight(ev.String(), "\n")
	return evidence, hosts, ips, secrets, cleartext, tlsPolicy
}

// emitBackendFinding appends one backend finding for a scanned text chunk
// (a resource file served by the plugin, or a raw APK file read from disk).
// baseTitle is the bare file/resource name; the severity prefix is added here.
func (e *Engine) emitBackendFinding(r *Report, baseTitle string, class string, text string) {
	ev, hosts, ips, secrets, cleartext, tlsPolicy := extractBackendData(text)
	firebase := filterFirebaseDomains(hosts)
	if !secrets && !cleartext && !tlsPolicy && len(firebase) == 0 && len(ips) == 0 {
		return
	}

	// Hosts are surfaced only when they are Firebase domains (the DNS family
	// the app actually depends on); no other predefined domain list is curated.
	// Any domain already inside a cleartext URL is shown via the URL evidence.
	b := strings.Builder{}
	if ev != "" {
		b.WriteString(ev + "\n")
	}
	if len(firebase) > 0 {
		b.WriteString("hosts: " + strings.Join(trimList(firebase, 40), ", ") + "\n")
	}
	if len(ips) > 0 {
		b.WriteString("ips: " + strings.Join(trimList(ips, 40), ", ") + "\n")
	}

	sev := "info"
	title := "Backend infrastructure in " + baseTitle
	switch {
	case secrets:
		sev = "high"
		title = "Firebase/Google secrets in " + baseTitle
	case tlsPolicy:
		sev = "high"
		title = "Cleartext TLS policy in " + baseTitle
	case cleartext:
		sev = "high"
		title = "Cleartext HTTP URLs in " + baseTitle
	}

	r.Findings = append(r.Findings, Finding{
		Category: "backend",
		Severity: sev,
		Title:    title,
		Class:    class,
		Detail:   backendDetail(class, cleartext),
		Evidence: strings.TrimRight(b.String(), "\n"),
	})
}

// filterFirebaseDomains keeps only Firebase-hosted domains from a host list.
func filterFirebaseDomains(hosts []string) []string {
	var out []string
	for _, h := range hosts {
		if patterns.FirebaseDomainRe.MatchString(h) {
			out = append(out, h)
		}
	}
	return out
}

// trimList returns at most n items; the remainder is summarized with a count so
// a packed binary snapshot (dozens of SDK domains) stays readable.
func trimList(items []string, n int) []string {
	if len(items) <= n {
		return items
	}
	out := append([]string{}, items[:n]...)
	out = append(out, fmt.Sprintf("(+%d more)", len(items)-n))
	return out
}

// scanApkInput scans one -apk token, which may be an unzipped APK root
// directory or a raw .apk/.zip file.
func (e *Engine) scanApkInput(ctx context.Context, r *Report, input string) {
	fi, err := os.Stat(input)
	if err != nil {
		e.Errs = append(e.Errs, fmt.Sprintf("scanApkInput stat %s: %v", input, err))
		return
	}
	if fi.IsDir() {
		e.scanApkDir(ctx, r, input)
		return
	}
	e.scanApkZip(ctx, r, input)
}

// scanApkZip scans the raw files inside a .apk/.zip: resources.arsc (compiled
// string pool), libapp.so (Dart AOT snapshot), classes.dex and
// network_security_config.xml. Mirrors scanApkDir for a ZIP container. Entry
// sizes are capped so a hostile/inflated archive can't exhaust memory.
func (e *Engine) scanApkZip(ctx context.Context, r *Report, apkPath string) {
	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		e.Errs = append(e.Errs, fmt.Sprintf("scanApkZip open %s: %v", apkPath, err))
		return
	}
	defer zr.Close()

	visited := map[string]bool{}
	for _, zf := range zr.File {
		lower := strings.ToLower(zf.Name)
		if !interestingBackendResource(lower) {
			continue
		}
		base := strings.ToLower(filepath.Base(zf.Name))
		if visited[base] {
			continue
		}
		visited[base] = true
		if zf.UncompressedSize64 > 60_000_000 {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			continue
		}
		data, rerr := io.ReadAll(rc)
		rc.Close()
		if rerr != nil {
			continue
		}
		e.scanApkRawBytes(r, zf.Name, apkPath, data)
	}
	if !visited["resources.arsc"] && !visited["libapp.so"] {
		r.Notes = append(r.Notes, "backend scan: -apk file provided but no resources.arsc/libapp.so entries found")
	}
}

// scanApkDir walks an unzipped APK directory (-apk) and scans the raw files the
// MCP plugin can't return as binary: resources.arsc (compiled string pool),
// libapp.so (Dart AOT snapshot), classes.dex and network_security_config.xml.
// This is where the Firebase string values, hosts and API endpoints actually
// live — mirroring the reference python scanner's _verify_from_arsc /
// _verify_from_libapp.
func (e *Engine) scanApkDir(ctx context.Context, r *Report, dir string) {
	visited := map[string]bool{}
	err := filepath.Walk(dir, func(path string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return nil
		}
		lower := strings.ToLower(path)
		if !interestingBackendResource(lower) {
			return nil
		}
		// One snapshot per base name: the split config APK repeats the same
		// .so/.dex per ABI — scanning the first copy is enough.
		base := strings.ToLower(fi.Name())
		if visited[base] {
			return nil
		}
		visited[base] = true
		e.scanApkRawFile(r, path, fi.Size())
		return nil
	})
	if err != nil {
		e.Errs = append(e.Errs, fmt.Sprintf("scanApkDir walk %s: %v", dir, err))
		return
	}
	if !visited["resources.arsc"] && !visited["libapp.so"] {
		r.Notes = append(r.Notes, "backend scan: -apk dir provided but no resources.arsc/libapp.so found — pass the unzipped APK root")
	}
}

// scanApkRawFile reads one raw APK file from disk and scans it (shared with
// scanApkRawBytes).
func (e *Engine) scanApkRawFile(r *Report, path string, size int64) {
	if size > 60_000_000 {
		return // refuse to slurp huge blobs
	}
	data, err := os.ReadFile(path)
	if err != nil {
		e.Errs = append(e.Errs, fmt.Sprintf("scanApkRawFile %s: %v", path, err))
		return
	}
	e.scanApkRawBytes(r, filepath.Base(path), path, data)
}

// scanApkRawBytes extracts hosts, IPs, endpoints, Firebase values and cleartext
// URLs from one raw APK file's content (from a directory walk or a ZIP entry).
// Binary blobs (arsc / libapp.so / dex) get their printable runs extracted
// first, which recovers the Dart AOT string pool and the compiled resource
// string pool.
func (e *Engine) scanApkRawBytes(r *Report, name, source string, data []byte) {
	var text string
	if strings.ContainsRune(string(data), '\x00') {
		text = strings.Join(patterns.ExtractReadable(data), " ")
	} else {
		text = string(data)
	}

	e.emitBackendFinding(r, name+" (raw)", source, text)
}
