package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"antox/mcp"
)

// TestSecurity_CtrlCMidRunPartialResults is the end-to-end reproduction of the
// reported crash: run the full security mode against a slow fake MCP server and
// cancel the context mid-run (what Ctrl+C does). Before the fix, an in-flight
// search error triggered "sync: unlock of unlocked mutex" — a fatal runtime
// error that aborts the whole process, so nothing (no partial report) ever got
// shown. This test asserts:
//  1. the process survives (no fatal mutex error),
//  2. the report carries an interruption note,
//  3. findings that were already discovered before the stop ARE still shown.
func TestSecurity_CtrlCMidRunPartialResults(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		switch req.Method {
		case "initialize":
			fmt.Fprint(w, `{"jsonrpc":"2.0","id":"1","result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"fake","version":"0.0.1"}}}`)
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
			case "get_android_manifest":
				fmt.Fprint(w, `{"jsonrpc":"2.0","id":"2","result":{"structuredContent":{"content":"<?xml version=\"1.0\" encoding=\"utf-8\"?><manifest package=\"com.fake.app\"><application/></manifest>"}}}`)
			case "search_classes_by_keyword":
				n := atomic.AddInt32(&calls, 1)
				// Root-detection alone has 52 terms. Respond instantly for its
				// whole search phase + source fetch so that category completes and
				// yields findings. From call 53 on (frida-detection onwards) every
				// search stalls like a real big-APK scan, so the cancel lands while
				// later searches are in flight.
				if n > 52 {
					time.Sleep(800 * time.Millisecond)
				}
				term, _ := p.Arguments["search_term"].(string)
				low := strings.ToLower(term)
				var items []string
				switch {
				case strings.Contains(low, "isrooted"), strings.Contains(low, "magisk"),
					strings.Contains(low, "superuser"), strings.Contains(low, "busybox"),
					strings.Contains(low, "selinux"):
					items = []string{"com.fake.RootCheck"}
				case strings.Contains(low, "frida"):
					items = []string{"com.fake.FridaDetector"}
				}
				raw, _ := json.Marshal(items)
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":"2","result":{"structuredContent":{"type":"class-list","items":%s}}}`, raw)
			case "get_class_source":
				cls, _ := p.Arguments["class_name"].(string)
				src := "public class K0 { public boolean isFridaRunning() { return false; } }"
				if strings.Contains(cls, "RootCheck") {
					src = "public class K0 { public boolean isRooted() { return new File(\"/system/xbin/su\").exists(); } }"
				}
				raw, _ := json.Marshal(src)
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":"2","result":{"structuredContent":{"class_name":%q,"source":%s}}}`, cls, raw)
			default:
				fmt.Fprint(w, `{"jsonrpc":"2.0","id":"2","result":{"structuredContent":{}}}`)
			}
		default:
			fmt.Fprint(w, `{"jsonrpc":"2.0","id":"2","result":{}}`)
		}
	}))
	defer srv.Close()

	e := NewEngine(mcp.New(srv.URL), 4, false)
	e.Quiet = true
	e.Workers = 4

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(400*time.Millisecond, cancel) // Ctrl+C while later searches are in flight

	rep, err := e.Run(ctx, Options{Mode: "security"})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if rep == nil {
		t.Fatal("Run returned nil report on interrupt")
	}
	// 1. Process survived — no fatal mutex abort.
	// 2. Root-detection completed before the cancel: its findings must be present.
	foundRoot := false
	for _, f := range rep.Findings {
		if f.Category == "root-detection" {
			foundRoot = true
		}
	}
	if !foundRoot {
		t.Fatalf("expected root-detection findings (found before stop) in partial report, findings=%d",
			len(rep.Findings))
	}
	// 3. Interruption is flagged.
	foundInterruption := false
	for _, n := range rep.Notes {
		if strings.Contains(n, "interrupted") || strings.Contains(n, "stopped early") {
			foundInterruption = true
		}
	}
	if !foundInterruption {
		t.Fatalf("expected an interruption note in report notes, got: %v", rep.Notes)
	}
	t.Logf("partial findings shown: %d (category %s), notes: %v",
		len(rep.Findings), rep.Findings[0].Category, rep.Notes)
}
