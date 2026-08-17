package patterns

import (
	"strings"
	"testing"
)

func TestExtractSectionStrings(t *testing.T) {
	data := []byte("Hello\x00World\x00!")
	got := ExtractSectionStrings(data, 0x1000, 3)
	if len(got) != 2 {
		t.Fatalf("expected 2 strings, got %d: %+v", len(got), got)
	}
	if got[0].VAddr != 0x1000 || got[0].Str != "Hello" {
		t.Fatalf("string 0 = %+v", got[0])
	}
	if got[1].VAddr != 0x1006 || got[1].Str != "World" {
		t.Fatalf("string 1 = %+v", got[1])
	}
}

func TestExtractSectionStrings_MinLen(t *testing.T) {
	data := []byte("ab\x00!cd")
	got := ExtractSectionStrings(data, 0, 3)
	// "ab" is too short (dropped); "!cd" starts at a printable char and is kept.
	if len(got) != 1 || got[0].Str != "!cd" {
		t.Fatalf("expected [\"!cd\"], got %+v", got)
	}
}

func TestExtractSectionStrings_DartBackToBack(t *testing.T) {
	// Non-printable length bytes separate adjacent Dart AOT strings.
	data := []byte("Alpha\x02\x01Beta\x04")
	got := ExtractSectionStrings(data, 0x100, 4)
	if len(got) != 2 || got[0].Str != "Alpha" || got[1].Str != "Beta" {
		t.Fatalf("expected [Alpha Beta], got %+v", got)
	}
}

func TestSoScanRe_Hooking(t *testing.T) {
	if !SoScanRe.MatchString("Hooking framework detected!") {
		t.Fatal("expected hooking message to match SoScanRe")
	}
	if SoScanRe.MatchString("just a plain label") {
		t.Fatal("plain text should not match")
	}
}

func TestMatchSoKeywords(t *testing.T) {
	got := MatchSoKeywords("Hooking framework detected!")
	want := []string{"hook", "detected"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestSoScanKeywords_CppVocabulary(t *testing.T) {
	joined := strings.Join(SoScanKeywords, " ")
	for _, want := range []string{
		"frida_gadget_load", "gum_interceptor_obtain", "pool-frida",
		"gum-js-loop", "zygisknext", "hidemyapplist", "debug_ramdisk",
		"magisk_daemon", "selinux", "PTRACE_TRACEME", "getdents64",
		"readlinkat", "ro.boot.vbmeta", "init.svc.adbd", "verifiedbootstate",
		"ssl_write", "conscrypt", "registernatives", "snitchtt", "sna_e",
		"collectnativesignals", "devicetrust", "onalert",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("SoScanKeywords missing %q", want)
		}
	}
}
