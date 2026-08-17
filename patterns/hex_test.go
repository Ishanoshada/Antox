package patterns

import (
	"strings"
	"testing"
)

func TestCommonXORKeys_BruteforceCoversEveryByte(t *testing.T) {
	seen := map[byte]bool{}
	for _, k := range CommonXORKeys {
		seen[k.Key] = true
	}
	for i := 0; i <= 0xff; i++ {
		if !seen[byte(i)] {
			t.Fatalf("CommonXORKeys missing key 0x%02x", i)
		}
	}
	// ascii (key 0) must come first.
	if CommonXORKeys[0].Key != 0 {
		t.Fatalf("expected ascii first, got %+v", CommonXORKeys[0])
	}
	// The full sweep entries must be flagged so DecodeHexBlob can gate them:
	// the vast majority of the 255 non-zero keys should be Bruteforce.
	brute := 0
	for _, k := range CommonXORKeys {
		if k.Bruteforce {
			brute++
		}
	}
	if brute < 200 {
		t.Fatalf("expected the full sweep to dominate, got %d/255 bruteforce keys", brute)
	}
}

// xorEncode returns plaintext XORed with a single byte, the str_enc.h layout.
func xorEncode(s string, key byte) []byte {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		out[i] = s[i] ^ key
	}
	return out
}

func TestDecodeHexBlob_Xor0x42StrEncH(t *testing.T) {
	// The exact str_enc.h table for "/data/adb/magisk", key 0x42.
	raw := xorEncode("/data/adb/magisk", 0x42)
	results := DecodeHexBlob(raw)
	var found bool
	for _, hr := range results {
		if hr.KeyName == "xor-0x42" && strings.Contains(hr.Decoded, "/data/adb/magisk") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected xor-0x42 decode of /data/adb/magisk, got %+v", results)
	}
}

func TestDecodeHexBlob_UncommonKeyFoundByBruteforce(t *testing.T) {
	// 0x13 is not in the curated list; the full sweep must recover it.
	raw := xorEncode("tampered build", 0x13)
	results := DecodeHexBlob(raw)
	var found bool
	for _, hr := range results {
		if strings.Contains(hr.Decoded, "tampered build") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("bruteforce sweep did not recover key 0x13: %+v", results)
	}
}

func TestDecodeHexBlob_BruteforceSkipsLongBlobs(t *testing.T) {
	// A 200-byte blob XOR'd with a non-curated key 0x13 decodes to a long
	// readable run, but the bruteforce sweep is gated off for long blobs — it
	// must NOT be returned (avoids readable noise false-positives).
	raw := xorEncode(strings.Repeat("A", 200), 0x13)
	results := DecodeHexBlob(raw)
	for _, hr := range results {
		if hr.KeyName == "xor-0x13" {
			t.Fatal("bruteforce key 0x13 must not run on a 200-byte blob")
		}
	}
}

func TestDecodeHexBlob_BruteforceNeedsLongRun(t *testing.T) {
	// A 5-byte printable blob: no decode can contain a >=6 char run, so no
	// Bruteforce-flagged key may be returned; curated keys still are.
	bruteNames := map[string]bool{}
	for _, k := range CommonXORKeys {
		if k.Bruteforce {
			bruteNames[k.Name] = true
		}
	}
	raw := []byte("abcde")
	results := DecodeHexBlob(raw)
	if len(results) == 0 {
		t.Fatal("expected at least the ascii result for a 5-byte printable blob")
	}
	for _, hr := range results {
		if bruteNames[hr.KeyName] {
			t.Fatalf("bruteforce key %q must not surface a <6 char run", hr.KeyName)
		}
	}
}
