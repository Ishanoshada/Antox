package analyzer

import (
	"strings"
	"testing"
)

// sourceWithBlob builds a synthetic native-class source containing a hex
// byte-array literal that decodes (ascii) to the given plaintext.
func sourceWithBlob(plaintext string) string {
	hexes := make([]string, len(plaintext))
	for i := 0; i < len(plaintext); i++ {
		hexes[i] = "0x" + hexByte(plaintext[i])
	}
	return "public class NativeDetector {\n" +
		"    private static final byte[] k = new byte[]{" + strings.Join(hexes, ",") + "};\n" +
		"    public static native boolean nativeScanMaps();\n" +
		"}\n"
}

func hexByte(b byte) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[b>>4], digits[b&0xf]})
}

func TestInterestingHexResults_HookingMessage(t *testing.T) {
	src := sourceWithBlob("Hooking framework detected!")
	results := interestingHexResults(src)
	if len(results) == 0 {
		t.Fatal("expected decoded hex results, got none")
	}
	// At least one interpretation should be the plaintext with keywords.
	found := false
	for _, hr := range results {
		for _, rs := range hr.Readable {
			if strings.Contains(rs, "Hooking framework detected!") {
				found = true
				break
			}
		}
	}
	if !found {
		t.Fatalf("decoded text did not contain the hooking message: %+v", results)
	}
}

func TestHexFindings_SecretClassification(t *testing.T) {
	// A decoded Google API key must be raised to high severity and name the pattern.
	src := sourceWithBlob("AIza" + strings.Repeat("A", 35))
	f := hexFindings("NativeDetector", "native-hex", interestingHexResults(src))
	if len(f) == 0 {
		t.Fatal("expected a finding for a credential-shaped blob")
	}
	sev := f[0].Severity
	if sev != "high" {
		t.Fatalf("expected high severity for credential blob, got %q", sev)
	}
	if !strings.Contains(f[0].Title, "Google API Key") {
		t.Fatalf("expected Google API Key in title, got %q", f[0].Title)
	}
}

func TestHexFindings_Category(t *testing.T) {
	f := hexFindings("X", "native-hex", interestingHexResults(sourceWithBlob("root detection")))
	if len(f) == 0 {
		t.Fatal("expected finding")
	}
	if f[0].Category != "native-hex" {
		t.Fatalf("expected category native-hex, got %q", f[0].Category)
	}
}
