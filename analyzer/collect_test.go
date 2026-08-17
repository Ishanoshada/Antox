package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"antox/mcp"
	"antox/patterns"
)

// errorSearchServer answers initialize + a JSON-RPC error envelope for every
// tools/call, which the MCP client turns into a Go error.
func errorSearchServer(t *testing.T, calls *int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var req struct {
			Method string `json:"method"`
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
			atomic.AddInt32(calls, 1)
			fmt.Fprint(w, `{"jsonrpc":"2.0","id":"2","error":{"code":-32603,"message":"boom"}}`)
		default:
			fmt.Fprint(w, `{"jsonrpc":"2.0","id":"2","result":{}}`)
		}
	}))
}

// TestCollectClasses_SearchErrorNoDoubleUnlock is a regression test for a fatal
// "sync: unlock of unlocked mutex" crash: when a keyword search returns an
// error (exactly what happens on Ctrl+C — every in-flight search fails with a
// context-cancellation error), collectClasses used to unlock the mutex twice
// and kill the whole process. This test forces every search to error and
// asserts collectClasses returns cleanly.
func TestCollectClasses_SearchErrorNoDoubleUnlock(t *testing.T) {
	var calls int32
	srv := errorSearchServer(t, &calls)
	defer srv.Close()

	e := NewEngine(mcp.New(srv.URL), 8, false)
	e.Quiet = true // suppress progress-bar noise
	terms := []patterns.Term{
		patterns.T("alpha"), patterns.T("beta"), patterns.T("gamma"), patterns.T("delta"),
	}
	got := e.collectClasses(context.Background(), terms, "", 8)
	if len(got) != 0 {
		t.Fatalf("expected 0 classes when every search errors, got %v", got)
	}
	if int(atomic.LoadInt32(&calls)) != len(terms) {
		t.Fatalf("expected %d search calls, got %d", len(terms), atomic.LoadInt32(&calls))
	}
	if len(e.Errs) != len(terms) {
		t.Fatalf("expected %d recorded errors, got %d: %v", len(terms), len(e.Errs), e.Errs)
	}
}

// TestCollectClasses_CancelledContextMidway mirrors Ctrl+C: the context is
// cancelled while searches are in flight, so the launched ones fail with a
// context-cancellation error and the loop stops launching new ones. Must return
// cleanly (partial results) — not crash.
func TestCollectClasses_CancelledContextMidway(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var req struct {
			Method string `json:"method"`
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
			time.Sleep(200 * time.Millisecond) // keep searches in flight
			fmt.Fprint(w, `{"jsonrpc":"2.0","id":"2","result":{"structuredContent":{"type":"class-list","items":["com.fake.K0"]}}}`)
		default:
			fmt.Fprint(w, `{"jsonrpc":"2.0","id":"2","result":{}}`)
		}
	}))
	defer srv.Close()

	e := NewEngine(mcp.New(srv.URL), 8, false)
	e.Quiet = true
	terms := make([]patterns.Term, 8)
	for i := range terms {
		terms[i] = patterns.T(fmt.Sprintf("term%d", i))
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(80*time.Millisecond, cancel) // cancel while searches are in flight
	got := e.collectClasses(ctx, terms, "", 8)
	_ = got // must not crash; partial results are fine
}
