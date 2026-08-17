package analyzer

import "testing"

func TestAllModes_IncludesSostrOnlyWithApk(t *testing.T) {
	without := allModes("")
	fridahook := false
	for _, m := range without {
		if m == "sostr" {
			t.Fatal("sostr should not run in a full scan without -apk")
		}
		if m == "fridahook" {
			fridahook = true
		}
	}
	if !fridahook {
		t.Fatal("a full scan must generate the frida hook (fridahook mode)")
	}
	with := allModes("base.apk")
	found := false
	for _, m := range with {
		if m == "sostr" {
			found = true
		}
	}
	if !found {
		t.Fatal("full scan with -apk must include sostr")
	}
	if len(with) != len(without)+1 {
		t.Fatalf("expected one extra mode with -apk, got %d vs %d", len(with), len(without))
	}
}
