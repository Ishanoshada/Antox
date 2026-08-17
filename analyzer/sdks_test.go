package analyzer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"antox/mcp"
)

// fakeSDKServer is a minimal MCP server that answers class-name searches from a
// term→classes map. Anything not searched returns an empty class list.
func fakeSDKServer(t *testing.T, hits map[string][]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var req struct {
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var resp string
		switch req.Method {
		case "initialize":
			resp = `{"jsonrpc":"2.0","id":"1","result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"fake","version":"0.0.1"}}}`
		case "tools/call":
			var p struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			}
			if err := json.Unmarshal(req.Params, &p); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			switch p.Name {
			case "search_classes_by_keyword":
				term, _ := p.Arguments["search_term"].(string)
				items, _ := json.Marshal(hits[term])
				resp = `{"jsonrpc":"2.0","id":"2","result":{"content":[],"isError":false,"structuredContent":{"type":"class-list","items":` + string(items) + `}}}`
			case "get_android_manifest":
				resp = `{"jsonrpc":"2.0","id":"2","result":{"content":[],"isError":false,"structuredContent":{"content":"<?xml version=\"1.0\" encoding=\"utf-8\"?><manifest xmlns:android=\"http://schemas.android.com/apk/res/android\" package=\"com.fake.app\"><application/></manifest>"}}}`
			default:
				resp = `{"jsonrpc":"2.0","id":"3","result":{"content":[],"isError":false,"structuredContent":[]}}`
			}
		default:
			resp = `{"jsonrpc":"2.0","id":"3","error":{"code":-32601,"message":"method not found"}}`
		}
		_, _ = w.Write([]byte(resp))
	}))
}

func TestSDKFindings_ReportsMatchedSDKsOncePerPackage(t *testing.T) {
	hits := map[string][]string{
		"Talsec": {
			"com.aheaditec.talsec_security.security.api.ThreatListener",
			"com.aheaditec.talsec_security.security.api.ThreatDetected",
		},
		"XposedBridge": {"de.robv.android.xposed.XposedBridge"},
	}
	srv := fakeSDKServer(t, hits)
	defer srv.Close()

	e := NewEngine(mcp.New(srv.URL), 8, false)
	r := &Report{Mode: "sdks", AppName: "test"}
	e.sdkFindings(context.Background(), r, "")

	if len(r.Findings) != 2 {
		t.Fatalf("expected 2 SDK findings (one per package), got %d: %+v", len(r.Findings), r.Findings)
	}
	var talsec, xposed *Finding
	for i := range r.Findings {
		switch r.Findings[i].Class {
		case "com.aheaditec.talsec_security":
			talsec = &r.Findings[i]
		case "de.robv.android.xposed":
			xposed = &r.Findings[i]
		}
	}
	if talsec == nil {
		t.Fatal("Talsec finding missing")
	}
	if !strings.Contains(talsec.Detail, "AheadITec") {
		t.Errorf("Talsec detail missing vendor: %s", talsec.Detail)
	}
	if !strings.Contains(talsec.Detail, "ThreatListener") {
		t.Errorf("Talsec detail should list a matched class: %s", talsec.Detail)
	}
	if talsec.Severity != "info" {
		t.Errorf("Talsec severity = %q, want info", talsec.Severity)
	}
	if xposed == nil {
		t.Fatal("Xposed finding missing")
	}
	if xposed.Severity != "medium" {
		t.Errorf("Xposed severity = %q, want medium (hook framework)", xposed.Severity)
	}
}

func TestSDKFindings_NoHitNoFinding(t *testing.T) {
	srv := fakeSDKServer(t, nil) // nothing matches
	defer srv.Close()

	e := NewEngine(mcp.New(srv.URL), 8, false)
	r := &Report{Mode: "sdks", AppName: "test"}
	e.sdkFindings(context.Background(), r, "")
	if len(r.Findings) != 0 {
		t.Fatalf("expected no findings, got %+v", r.Findings)
	}
}

func TestParseSearchResult_NewlineStringResponse(t *testing.T) {
	// search_method_by_name returns {"response":"K0.h\nThreatListener"} —
	// a newline-joined string, not a class-list items array.
	tr := &mcp.ToolResult{Content: []mcp.ContentBlock{{
		Type: "text",
		Text: `{"response":"K0.h\ncom.aheaditec.talsec_security.security.api.ThreatListener"}`,
	}}}
	got := parseSearchResult(tr)
	want := []string{"K0.h", "com.aheaditec.talsec_security.security.api.ThreatListener"}
	if len(got) != len(want) {
		t.Fatalf("parseSearchResult = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseSearchResult_ItemsArrayStillWorks(t *testing.T) {
	tr := &mcp.ToolResult{Content: []mcp.ContentBlock{{
		Type: "text",
		Text: `{"type":"class-list","items":["A","B"]}`,
	}}}
	if got := parseSearchResult(tr); len(got) != 2 || got[0] != "A" {
		t.Fatalf("items-array parse broken: %v", got)
	}
}

func TestAnalyzeSDKs_EndToEnd(t *testing.T) {
	hits := map[string][]string{
		"RootBeer": {"com.scottyab.rootbeer.RootBeer"},
	}
	srv := fakeSDKServer(t, hits)
	defer srv.Close()

	e := NewEngine(mcp.New(srv.URL), 8, false)
	rep, err := e.AnalyzeSDKs(context.Background(), Options{Mode: "sdks"})
	if err != nil {
		t.Fatalf("AnalyzeSDKs: %v", err)
	}
	if rep.APKPackage != "com.fake.app" {
		t.Errorf("APKPackage = %q, want com.fake.app", rep.APKPackage)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("expected 1 RootBeer finding, got %d: %+v", len(rep.Findings), rep.Findings)
	}
	if rep.Findings[0].Category != "sdk" || rep.Findings[0].Class != "com.scottyab.rootbeer" {
		t.Errorf("unexpected finding: %+v", rep.Findings[0])
	}
	if rep.Summary == nil {
		t.Error("summary should be populated by finishReport")
	}
}
