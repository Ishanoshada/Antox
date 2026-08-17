package analyzer

import (
	"strings"
	"testing"
)

func TestExtractBackendData_Secrets(t *testing.T) {
	text := "key AIzaSyCCAEfPqKQwHu2JnSaSidxvjG7Gv2AHcOc app 1:1053650329967:android:07371d68fba60ea996489a bucket lmt-go.firebasestorage.app"
	ev, hosts, ips, secrets, cleartext, tlsPolicy := extractBackendData(text)
	if !secrets {
		t.Fatal("expected secrets=true for Firebase values")
	}
	if !strings.Contains(ev, "AIzaSyCCAEfPqKQwHu2JnSaSidxvjG7Gv2AHcOc") {
		t.Errorf("evidence missing API key:\n%s", ev)
	}
	if cleartext || tlsPolicy {
		t.Errorf("unexpected cleartext=%v tlsPolicy=%v", cleartext, tlsPolicy)
	}
	if len(hosts) == 0 && len(ips) == 0 {
		t.Errorf("expected hosts or ips present")
	}
}

func TestExtractBackendData_NamespaceURLNotCleartext(t *testing.T) {
	// XML-namespace URIs must NOT count as cleartext (MITM) exposure.
	text := `xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmlns="http://schemas.android.com/apk/res/android"`
	_, _, _, _, cleartext, _ := extractBackendData(text)
	if cleartext {
		t.Fatal("namespace URI wrongly flagged as cleartext")
	}
}

func TestExtractBackendData_CleartextAndTLS(t *testing.T) {
	text := "http://10.0.2.2:8080/api endpoint and network-security-config cleartextTrafficPermitted 35.247.99.215"
	_, _, _, _, cleartext, tlsPolicy := extractBackendData(text)
	if !cleartext {
		t.Fatal("expected real cleartext http:// URL flagged")
	}
	if !tlsPolicy {
		t.Fatal("expected cleartext TLS policy flagged")
	}
}

func TestExtractBackendData_NoTLSOnDexReference(t *testing.T) {
	// A dex referencing cleartextTrafficPermitted / an IP must NOT be flagged
	// as a TLS policy — only an actual network-security-config is.
	text := "cleartextTrafficPermitted field attr 192.168.1.1"
	_, _, _, _, _, tlsPolicy := extractBackendData(text)
	if tlsPolicy {
		t.Fatal("dex attribute reference wrongly flagged as TLS policy")
	}
}

func TestFilterFirebaseDomains_OnlyFirebaseSurfaced(t *testing.T) {
	hosts := []string{
		"metrobusapiprod.eimsky.com", "lmt-go.firebasestorage.app",
		"myapp.firebaseio.com", "api.example.com", "fonts.gstatic.com",
	}
	got := filterFirebaseDomains(hosts)
	want := []string{"lmt-go.firebasestorage.app", "myapp.firebaseio.com"}
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i, h := range want {
		if got[i] != h {
			t.Errorf("expected %q at %d, got %q", h, i, got[i])
		}
	}
}

func TestIsCancellationErr(t *testing.T) {
	noise := []string{
		"search \"aheaditec\": read SSE stream: interrupt signal received",
		"get_strings: POST http://127.0.0.1:8651/mcp: context canceled",
		"read SSE stream: context deadline exceeded",
	}
	for _, s := range noise {
		if !isCancellationErr(s) {
			t.Errorf("expected %q to be classified as cancellation noise", s)
		}
	}
	real := []string{
		"search \"aheaditec\": HTTP 500 Internal Server Error",
		"get_resource_file: parse JSON: unexpected end of input",
		"get_android_manifest: EOF",
	}
	for _, s := range real {
		if isCancellationErr(s) {
			t.Errorf("expected %q to be a real error", s)
		}
	}
}

func TestTrimList_SummarizesOverflow(t *testing.T) {
	in := []string{"a", "b", "c", "d"}
	out := trimList(in, 2)
	if len(out) != 3 {
		t.Fatalf("expected 3 entries (2 + summary), got %v", out)
	}
	if !strings.Contains(out[2], "+2 more") {
		t.Errorf("expected overflow summary, got %q", out[2])
	}
	if got := trimList(in, 10); len(got) != 4 {
		t.Errorf("trimList should not touch small lists, got %v", got)
	}
}
