package patterns

import (
	"strings"
	"testing"
)

func TestSecuritySDKs_CatalogWellFormed(t *testing.T) {
	validKinds := map[string]bool{
		"RASP": true, "hardening": true, "packer": true, "attestation": true,
		"device-intel": true, "analytics": true, "hook": true,
		"root-check": true, "pinning": true, "framework": true,
	}
	seenPkg := map[string]bool{}
	seenTerm := map[string]bool{}
	for _, sdk := range SecuritySDKs {
		if sdk.Package == "" || sdk.SDK == "" || sdk.Vendor == "" || sdk.Kind == "" || sdk.Desc == "" {
			t.Fatalf("SDK %+v has empty required field", sdk)
		}
		if !validKinds[sdk.Kind] {
			t.Errorf("SDK %q has unknown kind %q", sdk.SDK, sdk.Kind)
		}
		if len(sdk.Terms) == 0 {
			t.Errorf("SDK %q has no search terms", sdk.SDK)
		}
		if seenPkg[sdk.Package] {
			t.Errorf("duplicate package %q", sdk.Package)
		}
		seenPkg[sdk.Package] = true
		for _, term := range sdk.Terms {
			if seenTerm[term] {
				t.Errorf("duplicate class term %q", term)
			}
			seenTerm[term] = true
		}
		if strings.TrimSpace(sdk.Severity) == "" {
			t.Errorf("SDK %q missing severity", sdk.SDK)
		}
	}
	if len(SecuritySDKs) < 20 {
		t.Errorf("catalog unexpectedly small: %d entries", len(SecuritySDKs))
	}
}

func TestFridaSDKTerms_NoBareGumToken(t *testing.T) {
	// Regression: bare "Gum" is a substring of "Argu*ments*" and false-positives
	// on io.flutter.view.FlutterRunArguments. The Frida SDK must not use it.
	var frida *SDK
	for i := range SecuritySDKs {
		if SecuritySDKs[i].Package == "eu.frida" {
			frida = &SecuritySDKs[i]
			break
		}
	}
	if frida == nil {
		t.Fatal("eu.frida SDK entry missing from catalog")
	}
	for _, term := range frida.Terms {
		if term == "Gum" {
			t.Error("Frida SDK must not use bare 'Gum' token (matches FlutterRunArguments)")
		}
		if strings.Contains(term, "Gum") && strings.Contains(term, "Script") == false && strings.Contains(term, "Interceptor") == false {
			t.Errorf("Gum-like token %q too generic", term)
		}
	}
	foundFrida := false
	for _, term := range frida.Terms {
		if strings.Contains(term, "Frida") {
			foundFrida = true
		}
	}
	if !foundFrida {
		t.Error("Frida SDK terms should include the 'Frida' token itself")
	}
}

func TestSecuritySDKClassTerms_DedupedUnionOfAllSDKTerms(t *testing.T) {
	// Every SDK must have at least one token represented in the flat list.
	want := map[string]bool{}
	for _, sdk := range SecuritySDKs {
		if len(sdk.Terms) == 0 {
			t.Fatalf("SDK %q has no terms", sdk.SDK)
		}
		want[sdk.Terms[0]] = true
	}
	got := map[string]bool{}
	for _, term := range SecuritySDKClassTerms {
		if got[term] {
			t.Errorf("duplicate term %q in SecuritySDKClassTerms", term)
		}
		got[term] = true
	}
	for term := range want {
		if !got[term] {
			t.Errorf("SecuritySDKClassTerms missing %q", term)
		}
	}
}

func TestSecuritySDKByPackage_CaseSensitiveMatch(t *testing.T) {
	// Package prefixes are matched literally (jadx class names keep case), so
	// only the exact package should resolve.
	if _, ok := SecuritySDKByPackage("com.aheaditec.talsec_security"); !ok {
		t.Fatal("expected Talsec to resolve by exact package")
	}
	if sdk, ok := SecuritySDKByPackage("com.topjohnwu.magisk"); !ok || sdk.Kind != "root-check" {
		t.Fatalf("expected Magisk root-check, got %+v ok=%v", sdk, ok)
	}
	if _, ok := SecuritySDKByPackage("com.does.not.exist"); ok {
		t.Fatal("unknown package must not resolve")
	}
}

func TestSecuritySDKs_NativeDetectionLayersPresent(t *testing.T) {
	// The cpp/ native detection layers (snitchtt JNI bridge + DeviceTrust C++)
	// must be cataloged as RASP SDKs with searchable terms.
	joined := ""
	for _, sdk := range SecuritySDKs {
		joined += sdk.SDK + " " + sdk.Package + " " + strings.Join(sdk.Terms, " ") + " "
	}
	for _, want := range []string{"snitchtt", "ai.snitchtt", "SnitchNative", "DeviceTrust", "DeviceTrustNative", "com.mikoloy.device_trust"} {
		if !strings.Contains(joined, want) {
			t.Errorf("SecuritySDKs missing %q", want)
		}
	}
}

func TestDetectionClassTerms_IncludesVendorSDKs(t *testing.T) {
	joined := strings.Join(DetectionClassTerms, " ")
	for _, want := range []string{"Talsec", "TrustKit", "ThreatMetrix", "Sift", "AppSealing", "Guardsquare", "Zimperium"} {
		if !strings.Contains(joined, want) {
			t.Errorf("DetectionClassTerms missing %q", want)
		}
	}
}

func TestSoScanKeywords_IncludesRASPTokens(t *testing.T) {
	joined := strings.Join(SoScanKeywords, " ")
	for _, want := range []string{"talsec", "threatmetrix", "ontamperdetected", "isdebuggerconnected", "attestation"} {
		if !strings.Contains(joined, want) {
			t.Errorf("SoScanKeywords missing %q", want)
		}
	}
}

func TestNativeSoNames_IncludesRASPLibs(t *testing.T) {
	joined := strings.Join(NativeSoNames, " ")
	for _, want := range []string{"libpromon", "libtalsec", "libsecneo", "libappdome", "libthreatmetrix", "libplaycore"} {
		if !strings.Contains(joined, want) {
			t.Errorf("NativeSoNames missing %q", want)
		}
	}
}
