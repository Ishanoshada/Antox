package analyzer

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"antox/patterns"
)

// AnalyzeSearch is the generic mode: run one user-supplied keyword across a
// chosen scope and report every class that matches, with evidence lines.
//
// Supported scopes (comma-separated): class, method, field, code, resource,
// comments. "comments" is normalized to the server's "comment" scope.
// "resource" is handled locally: it searches the packaged resource file
// names and surfaces .so / .dex files rather than class sources.
func (e *Engine) AnalyzeSearch(ctx context.Context, o Options) (*Report, error) {
	scope := o.Scope
	if scope == "" {
		scope = "code"
	}
	start := time.Now()
	r := &Report{Mode: o.Mode, AppName: "unknown", APKPackage: e.appPackage(ctx)}

	// Normalize the scope list: "comments" -> "comment" (server name), and
	// pull "resource" out since it is resolved against file names, not
	// class source.
	var serverScopes, resourceScopes []string
	for _, sc := range strings.Split(scope, ",") {
		sc = strings.ToLower(strings.TrimSpace(sc))
		switch sc {
		case "":
			continue
		case "resource":
			resourceScopes = append(resourceScopes, sc)
		case "comments":
			serverScopes = append(serverScopes, "comment")
		default:
			serverScopes = append(serverScopes, sc)
		}
	}

	// A term is only required when searching class sources. Resource scope can
	// run with an empty term to surface every packaged .so / .dex file.
	if o.Term == "" && len(serverScopes) > 0 {
		return nil, fmt.Errorf("search mode requires a search term (-term)")
	}

	// Resource scope: enumerate packaged files, surface .so / .dex / matches.
	if len(resourceScopes) > 0 {
		e.scanResources(ctx, r, o.Term)
	}

	if len(serverScopes) == 0 {
		r.DurationMS = time.Since(start).Milliseconds()
		e.finishReport(ctx, r)
		return r, nil
	}

	term := patterns.Term{Text: o.Term, Scope: strings.Join(serverScopes, ",")}
	classes, err := e.search(ctx, term, o.Package, e.Limit*6)
	if err != nil {
		e.Errs = append(e.Errs, fmt.Sprintf("search %q: %v", o.Term, err))
		r.DurationMS = time.Since(start).Milliseconds()
		e.finishReport(ctx, r)
		return r, err
	}
	if len(classes) == 0 {
		r.Notes = append(r.Notes, fmt.Sprintf("no classes matched %q (scope=%s)", o.Term, strings.Join(serverScopes, ",")))
	}

	cat := patterns.Category{
		ID: "search", Severity: "info",
		Label:   fmt.Sprintf("Search matches for %q", o.Term),
		Regexes: []*regexp.Regexp{regexp.MustCompile(regexp.QuoteMeta(o.Term))},
	}
	fetched := 0
	for _, cls := range classes {
		if fetched >= e.Limit {
			break
		}
		fetched++
		src, err := e.classSource(ctx, cls)
		if err != nil {
			continue
		}
		if f := findingsFromSource(cls, cat, src); len(f) > 0 {
			r.Findings = append(r.Findings, f...)
		} else {
			r.Findings = append(r.Findings, Finding{
				Category: "search", Severity: "info",
				Title: "Class matched search term", Class: cls,
			})
		}
	}

	r.DurationMS = time.Since(start).Milliseconds()
	e.finishReport(ctx, r)
	return r, nil
}
