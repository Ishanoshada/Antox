package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"antox/patterns"
)

// AnalyzeFirebase extracts Firebase / Google-services configuration: project
// ids, web API keys, database URLs, storage buckets and messaging sender ids,
// from code, string resources and google-services.json.
func (e *Engine) AnalyzeFirebase(ctx context.Context, o Options) (*Report, error) {
	start := time.Now()
	r := &Report{Mode: o.Mode, AppName: "unknown", APKPackage: e.appPackage(ctx)}

	// 1) Code search (concurrent source fetches).
	classes := e.collectClasses(ctx, patterns.FirebaseTerms, o.Package, e.Limit*6)
	sources := e.fetchSources(ctx, classes, e.Limit*2)
	for cls, src := range sources {
		findings := scanRegexes(cls, "firebase", "info", patterns.FirebaseRegexes, src)
		if len(findings) > 0 {
			r.Findings = append(r.Findings, findings...)
		}
	}

	// 2) String resources.
	tr, err := e.Client.CallTool(ctx, "get_strings", map[string]any{"offset": 0, "count": 0})
	if err == nil {
		for _, v := range extractStringValues(tr) {
			if f := scanValueForFirebase("res/values/strings.xml", v); len(f) > 0 {
				r.Findings = append(r.Findings, f...)
			}
		}
	}

	// 3) google-services.json (and friends).
	res := e.resourceNamesMatching(ctx, patterns.FirebaseResourceHints)
	if len(res) > 0 {
		r.Notes = append(r.Notes, fmt.Sprintf("firebase-related resources: %s", strings.Join(res, ", ")))
	}
	for _, name := range res {
		lower := strings.ToLower(name)
		if strings.Contains(lower, "google-services") && strings.HasSuffix(lower, ".json") {
			r.Findings = append(r.Findings, e.firebaseFromResource(ctx, name)...)
		}
	}

	r.DurationMS = time.Since(start).Milliseconds()
	e.finishReport(ctx, r)
	return r, nil
}

func scanValueForFirebase(class, value string) []Finding {
	var out []Finding
	for _, re := range patterns.FirebaseRegexes {
		m := re.FindString(value)
		if m != "" {
			out = append(out, Finding{
				Category: "firebase", Severity: "high",
				Title: "Firebase configuration value", Class: class,
				Evidence: truncate(m, 200),
			})
		}
	}
	return out
}

func (e *Engine) firebaseFromResource(ctx context.Context, name string) []Finding {
	rtr, err := e.Client.CallTool(ctx, "get_resource_file", map[string]any{"resource_name": name})
	if err != nil {
		e.Errs = append(e.Errs, fmt.Sprintf("get_resource_file %s: %v", name, err))
		return nil
	}
	raw := toolRawJSON(rtr)

	// google-services.json is an array of {project_info, client[], ...}.
	var root []map[string]any
	if json.Unmarshal(raw, &root) != nil {
		var single map[string]any
		if json.Unmarshal(raw, &single) == nil {
			root = []map[string]any{single}
		}
	}
	if len(root) == 0 {
		return nil
	}

	var out []Finding
	seen := map[string]bool{}
	for _, entry := range root {
		if pi, ok := entry["project_info"].(map[string]any); ok {
			for _, f := range []struct {
				key   string
				title string
			}{
				{key: "project_id", title: "Firebase project id"},
				{key: "storage_bucket", title: "Firebase storage bucket"},
				{key: "firebase_url", title: "Firebase database URL"},
			} {
				if v, ok := pi[f.key].(string); ok && v != "" && !seen[v] {
					seen[v] = true
					out = append(out, Finding{
						Category: "firebase", Severity: "medium",
						Title: f.title, Class: name, Detail: v,
					})
				}
			}
		}
		// API keys live under each client's api_key.current_key.
		if clients, ok := entry["client"].([]any); ok {
			for _, c := range clients {
				cm, _ := c.(map[string]any)
				if ak, ok := cm["api_key"].(map[string]any); ok {
					if key, ok := ak["current_key"].(string); ok && key != "" && !seen["api:"+key] {
						seen["api:"+key] = true
						out = append(out, Finding{
							Category: "firebase", Severity: "critical",
							Title: "Firebase/Google API key", Class: name, Detail: key,
						})
					}
				}
				if ci, ok := cm["client_info"].(map[string]any); ok {
					for _, f := range []struct {
						key   string
						title string
					}{
						{key: "android_client_info", title: "Android client"},
						{key: "mobilesdk_app_id", title: "Mobile SDK app id"},
					} {
						if v, ok := ci[f.key].(string); ok && v != "" && !seen[f.title+":"+v] {
							seen[f.title+":"+v] = true
							out = append(out, Finding{
								Category: "firebase", Severity: "medium",
								Title: f.title, Class: name, Detail: v,
							})
						}
					}
				}
			}
		}
	}
	return out
}
