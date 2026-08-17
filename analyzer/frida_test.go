package analyzer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jadx-anzle/mcp"
)

// fakeFridaServer answers both class searches (term→classes) and method
// searches (method→newline-joined class string) plus a minimal manifest.
func fakeFridaServer(t *testing.T, classHits map[string][]string, methodHits map[string]string) *httptest.Server {
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
				items, _ := json.Marshal(classHits[term])
				resp = `{"jsonrpc":"2.0","id":"2","result":{"content":[],"isError":false,"structuredContent":{"type":"class-list","items":` + string(items) + `}}}`
			case "search_method_by_name":
				method, _ := p.Arguments["method_name"].(string)
				out, ok := methodHits[method]
				if !ok {
					out = ""
				}
				// JSON-encode so a newline separator becomes the escaped \n the
				// real jadx server emits, not a raw byte inside the JSON string.
				sc, _ := json.Marshal(map[string]string{"response": out})
				resp = `{"jsonrpc":"2.0","id":"2","result":{"content":[],"isError":false,"structuredContent":` + string(sc) + `}}`
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

func TestBuildFridaScript_ComposesAppSpecificAndGenericBlocks(t *testing.T) {
	p := fridaProfile{packageName: "com.fake.app", targets: []hookTarget{
		{
			cls:     "K0.h",
			methods: talsecCallbacks,
			reason:  "concrete Talsec threat-callback implementation",
		},
		{
			cls:     "com.fake.CommonUtils",
			methods: []string{"isRooted", "isEmulator"},
			returns: true,
			reason:  "root/emulator detection",
		},
		{
			cls:     "com.aheaditec.talsec_security.security.api.ThreatListener",
			methods: []string{"registerListener", "onReceive"},
			reason:  "Talsec ThreatListener wiring",
		},
	}}
	s := buildFridaScript("com.fake.app", p)

	for _, want := range []string{
		"Java.perform",
		"// package: com.fake.app",
		`RASP_CB.forEach(function (m) { hookVoid("K0.h", m, "RASP"); });`,
		`hookReturnsFalse("com.fake.CommonUtils", m, "APP")`,
		`"isRooted", "isEmulator"`,
		`hookVoid("com.aheaditec.talsec_security.security.api.ThreatListener", m, "APP")`,
		"[ANZLE-PORT]",
		"[ANZLE-CMD]",
		"netstat/exec bypass active",
		"[ANZLE-ADB]",
		"bypass script loaded",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script missing %q", want)
		}
	}
	for _, leftover := range []string{"@@CLASS@@", "@@METHODS@@", "@@HELPER@@", "fridaBlock"} {
		if strings.Contains(s, leftover) {
			t.Errorf("unresolved placeholder %q left in script", leftover)
		}
	}
	// The method array must be FLAT — [["a","b"]] would iterate over one array
	// element and cls[array] silently no-ops every hook.
	if strings.Contains(s, `[["`) {
		t.Errorf("double-wrapped method array in script:\n%s", s)
	}
	if !strings.Contains(s, "var M = [\"isRooted\", \"isEmulator\"];") {
		t.Error("multi-method target must emit a flat JS array")
	}
}

func TestFridaProfile_DiscoversRealTargets(t *testing.T) {
	srv := fakeFridaServer(t,
		map[string][]string{
			"ThreatListener":     {"com.aheaditec.talsec_security.security.api.ThreatListener"},
			"CertificatePinner":  {"com.fake.PinningManager"},
		},
		map[string]string{
			"onDebuggerDetected": "K0.h\ncom.aheaditec.talsec_security.security.api.ThreatListener$ThreatDetected",
			"isRooted":           "com.fake.CommonUtils",
			"isEmulator":         "com.fake.CommonUtils\ncom.fake.Model$dataclass",
			"isDebuggerConnected": "com.fake.CommonUtils",
		},
	)
	defer srv.Close()

	e := NewEngine(mcp.New(srv.URL), 8, false)
	p := e.fridaProfile(context.Background(), Options{Package: ""})

	// K0.h (Talsec), ThreatListener wiring, CommonUtils (all gates grouped), and
	// the PinningManager = 4 targets. The $dataclass model class must be skipped.
	if len(p.targets) != 4 {
		t.Fatalf("expected 4 targets, got %d: %+v", len(p.targets), p.targets)
	}
	var talsec, listener, gates, pinner *hookTarget
	for i := range p.targets {
		switch {
		case p.targets[i].cls == "K0.h":
			talsec = &p.targets[i]
		case strings.Contains(p.targets[i].cls, "ThreatListener"):
			listener = &p.targets[i]
		case p.targets[i].cls == "com.fake.CommonUtils":
			gates = &p.targets[i]
		case p.targets[i].cls == "com.fake.PinningManager":
			pinner = &p.targets[i]
		}
	}
	if talsec == nil {
		t.Fatal("Talsec impl (K0.h) not discovered — the abstract base must be skipped")
	}
	if talsec.returns {
		t.Error("Talsec callbacks must be hooked as void (returns=false), not as boolean gates")
	}
	if len(talsec.methods) != len(talsecCallbacks) {
		t.Errorf("K0.h target should cover all callbacks, got %d", len(talsec.methods))
	}
	if listener == nil {
		t.Fatal("ThreatListener wiring target missing")
	}
	if gates == nil {
		t.Fatal("CommonUtils detection-gates target missing")
	}
	if !gates.returns {
		t.Error("CommonUtils gates should be returns=true (boolean gates)")
	}
	for _, m := range []string{"isRooted", "isEmulator", "isDebuggerConnected"} {
		if !slicesContains(gates.methods, m) {
			t.Errorf("CommonUtils target missing gate method %q: %v", m, gates.methods)
		}
	}
	if strings.Contains(gates.reason, "debugger") == false {
		t.Errorf("CommonUtils reason should merge gate reasons: %q", gates.reason)
	}
	if pinner == nil || !pinner.returns || len(pinner.methods) != 1 || pinner.methods[0] != "check" {
		t.Errorf("SSL pinner target wrong: %+v", pinner)
	}
}

func slicesContains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// TestFridaProfile_NormalApp_OutOfTheBox verifies that an app WITHOUT any RASP
// SDK still gets app-specific hooks (its own root/emulator/debugger detection
// classes and pinner), i.e. the "out of the box" behavior for any APK.
func TestFridaProfile_NormalApp_OutOfTheBox(t *testing.T) {
	srv := fakeFridaServer(t,
		map[string][]string{
			"CertificatePinner": {"com.acme.Pinner"},
		},
		map[string]string{
			"isRooted":     "com.acme.DeviceChecks\ncom.acme.data.UserModel$dataclass",
			"isEmulator":   "com.acme.DeviceChecks",
			"isVpnConnected": "com.acme.DeviceChecks",
		},
	)
	defer srv.Close()

	e := NewEngine(mcp.New(srv.URL), 8, false)
	p := e.fridaProfile(context.Background(), Options{Package: ""})

	if len(p.targets) != 2 {
		t.Fatalf("expected 2 targets (DeviceChecks + Pinner), got %d: %+v", len(p.targets), p.targets)
	}
	var checks, pinner *hookTarget
	for i := range p.targets {
		switch p.targets[i].cls {
		case "com.acme.DeviceChecks":
			checks = &p.targets[i]
		case "com.acme.Pinner":
			pinner = &p.targets[i]
		}
	}
	if checks == nil {
		t.Fatal("DeviceChecks target missing")
	}
	if !checks.returns {
		t.Error("DeviceChecks gates must be returns=true")
	}
	if !slicesContains(checks.methods, "isRooted") || !slicesContains(checks.methods, "isEmulator") || !slicesContains(checks.methods, "isVpnConnected") {
		t.Errorf("DeviceChecks should group all three gates: %v", checks.methods)
	}
	if pinner == nil {
		t.Fatal("pinner target missing for normal app")
	}

	// The composed script must hook these classes with hookReturnsFalse and not
	// contain any Talsec callback block.
	script := buildFridaScript("com.acme.app", p)
	if !strings.Contains(script, `hookReturnsFalse("com.acme.DeviceChecks", m, "APP")`) {
		t.Error("script should hookReturnsFalse on DeviceChecks gates")
	}
	if !strings.Contains(script, `hookReturnsFalse("com.acme.Pinner", m, "APP")`) {
		t.Error("script should neutralize the pinner check")
	}
	if strings.Contains(script, "RASP_CB") {
		t.Error("no RASP callback block expected for a normal app")
	}
	if strings.Contains(script, "onRootDetected") {
		t.Error("no Talsec callback names expected for a normal app")
	}
}

func TestFridaOutPath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "frida-hook.js"},
		{"custom.js", "custom.js"},
		{"bypass.HOOK.JS", "bypass.HOOK.JS"},
		{"out", filepath.Join("out", "frida-hook.js")},
		{"reports/", filepath.Join("reports", "frida-hook.js")},
	}
	for _, c := range cases {
		if got := fridaOutPath(Options{OutDir: c.in}); got != c.want {
			t.Errorf("fridaOutPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestAnalyzeFridaHook_EndToEnd(t *testing.T) {
	srv := fakeFridaServer(t,
		map[string][]string{
			"ThreatListener": {"com.aheaditec.talsec_security.security.api.ThreatListener"},
		},
		map[string]string{
			"onDebuggerDetected": "K0.h\ncom.aheaditec.talsec_security.security.api.ThreatListener$ThreatDetected",
			"isRooted":           "com.fake.CommonUtils",
			"isEmulator":         "com.fake.CommonUtils",
		},
	)
	defer srv.Close()

	e := NewEngine(mcp.New(srv.URL), 8, false)
	out := filepath.Join(t.TempDir(), "my-hook.js")
	o := Options{Mode: "fridahook", OutDir: out}
	rep, err := e.AnalyzeFridaHook(context.Background(), o)
	if err != nil {
		t.Fatalf("AnalyzeFridaHook: %v", err)
	}

	var gen bool
	for _, f := range rep.Findings {
		if f.Title == "Frida hook script generated" {
			gen = true
			if !strings.Contains(f.Detail, out) {
				t.Errorf("generated finding detail should reference %q: %s", out, f.Detail)
			}
		}
	}
	if !gen {
		t.Fatalf("expected 'Frida hook script generated' finding, got %+v", rep.Findings)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read generated script: %v", err)
	}
	content := string(data)
	for _, want := range []string{"K0.h", "com.fake.CommonUtils", "Java.perform", "onRootDetected", "[ANZLE-ADB]"} {
		if !strings.Contains(content, want) {
			t.Errorf("generated script missing %q", want)
		}
	}
}
