package analyzer

import "testing"

func TestIsSuspiciousSo(t *testing.T) {
	cases := map[string]bool{
		"com.app.apk/lib/arm64-v8a/libts.so":              true,  // Talsec RASP
		"lib/armeabi-v7a/libsna.so":                       true,  // snitchtt single-export
		"com.app.apk/lib/arm64-v8a/libapp.so":             false, // normal app native
		"com.app.apk/lib/arm64-v8a/libflutter.so":         false, // framework lib
		"config.x86_64.apk/lib/x86_64/libfrida-gadget.so": true,
		"lib/arm64-v8a/libdobby.so":                       true,
	}
	for f, want := range cases {
		if got := isSuspiciousSo(f); got != want {
			t.Errorf("isSuspiciousSo(%q) = %v, want %v", f, got, want)
		}
	}
}
