package patterns

import (
	"regexp"
	"testing"
)

// TestSecurityCategories_FlutterFramework confirms the Flutter / Dart AOT
// category matches real Flutter app signatures.
func TestSecurityCategories_FlutterFramework(t *testing.T) {
	cat := findCategory("flutter-framework")
	if cat == nil {
		t.Fatal("flutter-framework category missing")
	}
	src := `public class MainActivity extends FlutterActivity {
	    static { System.loadLibrary("app"); }
	    MethodChannel channel = new MethodChannel(engine.getDartExecutor(), "com.app/channel");
	    // io.flutter.embedding.engine.FlutterEngine
	}`
	if len(evidenceMatches(src, cat.Regexes)) == 0 {
		t.Fatal("Flutter source did not match flutter-framework regexes")
	}
	// DetectionClassTerms should include the framework classes.
	if !containsStr(DetectionClassTerms, "FlutterActivity") {
		t.Error("DetectionClassTerms missing FlutterActivity")
	}
}

// TestSecurityCategories_ReactNativeFramework confirms the RN / Hermes category
// matches real React Native signatures.
func TestSecurityCategories_ReactNativeFramework(t *testing.T) {
	cat := findCategory("react-native-framework")
	if cat == nil {
		t.Fatal("react-native-framework category missing")
	}
	src := `public class MainApplication extends ReactApplication {
	    HermesExecutor hermes;
	    static { SoLoader.loadLibrary("hermes"); }
	    // index.android.bundle in assets
	}`
	if len(evidenceMatches(src, cat.Regexes)) == 0 {
		t.Fatal("RN source did not match react-native-framework regexes")
	}
}

// TestSecurityCategories_ReactNative_JSIWordBoundary guards against the JSI
// token matching lowercase words like "jSimpleQueryForLong" (a real false
// positive seen against com.lankametrotransit.lmtgo).
func TestSecurityCategories_ReactNative_JSIWordBoundary(t *testing.T) {
	cat := findCategory("react-native-framework")
	if cat == nil {
		t.Fatal("react-native-framework category missing")
	}
	src := `long jSimpleQueryForLong = stmt.simpleQueryForLong() * stmt.simpleQueryForLong();`
	if len(evidenceMatches(src, cat.Regexes)) != 0 {
		t.Fatal("jSimpleQueryForLong must NOT match react-native regexes")
	}
	real := `import com.facebook.jsi.HybridData; JSI.prepare(ctx);`
	if len(evidenceMatches(real, cat.Regexes)) == 0 {
		t.Fatal("real JSI usage must match react-native regexes")
	}
}

// TestSecurityCategories_PackerProtection confirms the packer category matches
// the master-dictionary packer artifacts (jiagu, legu, bangcle, dexprotector).
func TestSecurityCategories_PackerProtection(t *testing.T) {
	cat := findCategory("packer-protection")
	if cat == nil {
		t.Fatal("packer-protection category missing")
	}
	src := `public class App extends com.stub.StubApp {
	    static { System.loadLibrary("jiagu"); }
	    // libSecShell.so, bangcleclasses.jar
	}`
	if len(evidenceMatches(src, cat.Regexes)) == 0 {
		t.Fatal("packer source did not match packer-protection regexes")
	}
	for _, want := range []string{"libjiagu", "libSecShell", "libDexProtector", "libtencent_stub"} {
		if !containsStr(NativeSuspectLibs, want) {
			t.Errorf("NativeSuspectLibs missing %q", want)
		}
	}
}

// TestFrameworkSoNames_Engines checks FrameworkSoNames lists the legit app
// runtime engines (Flutter / RN / Hermes) — and that those engines are NOT in
// NativeSoNames (the detection-payload list) so isSuspiciousSo stays clean.
func TestFrameworkSoNames_Engines(t *testing.T) {
	for _, want := range []string{
		"libapp", "libflutter", "libhermes", "libreactnativejni", "libfbjni",
		"libjsc", "libflipper",
	} {
		if !containsStr(FrameworkSoNames, want) {
			t.Errorf("FrameworkSoNames missing %q", want)
		}
		if containsStr(NativeSoNames, want) {
			t.Errorf("NativeSoNames must NOT contain engine %q (legit, not a payload)", want)
		}
		if containsStr(NativeSuspectLibs, want) {
			t.Errorf("NativeSuspectLibs must NOT contain engine %q (legit, not a payload)", want)
		}
	}
}

// TestNativeSoNames_Packers checks the .so sweep still covers packer payloads.
func TestNativeSoNames_Packers(t *testing.T) {
	for _, want := range []string{
		"libjiagu", "libSecShell", "libbaiduprotect", "libtencent_stub",
		"libDexProtector", "libexecmain",
	} {
		if !containsStr(NativeSoNames, want) {
			t.Errorf("NativeSoNames missing packer %q", want)
		}
		if !containsStr(NativeSuspectLibs, want) {
			t.Errorf("NativeSuspectLibs missing packer %q", want)
		}
	}
}

// TestSoScanKeywords_FrameworksAndPackers checks the .so string sweep keywords.
func TestSoScanKeywords_FrameworksAndPackers(t *testing.T) {
	for _, want := range []string{
		"libapp.so", "libflutter.so", "libhermes.so", "index.android.bundle",
		"jiagu", "bangcle", "dexprotector", "frida-server", "PTRACE_ATTACH",
	} {
		if !containsStr(SoScanKeywords, want) {
			t.Errorf("SoScanKeywords missing %q", want)
		}
	}
}

// TestSecuritySDKs_FrameworkAndPackerEntries checks the catalog additions.
func TestSecuritySDKs_FrameworkAndPackerEntries(t *testing.T) {
	for _, want := range []struct {
		kind string
		term string
	}{
		{"framework", "FlutterActivity"},
		{"framework", "ReactApplication"},
		{"framework", "HermesExecutor"},
		{"packer", "StubApp"},
		{"packer", "DexProtector"},
		{"packer", "Aijiami"},
		{"root-check", "JailMonkey"},
	} {
		found := false
		for _, sdk := range SecuritySDKs {
			if sdk.Kind != want.kind {
				continue
			}
			for _, term := range sdk.Terms {
				if term == want.term {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("SecuritySDKs: no %s entry with term %q", want.kind, want.term)
		}
	}
}

func findCategory(id string) *Category {
	for i := range SecurityCategories {
		if SecurityCategories[i].ID == id {
			return &SecurityCategories[i]
		}
	}
	return nil
}

func evidenceMatches(src string, res []*regexp.Regexp) []string {
	var out []string
	for _, re := range res {
		for _, ln := range splitLines(src) {
			if re.MatchString(ln) {
				out = append(out, ln)
			}
		}
	}
	return out
}

func splitLines(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == '\n' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(c)
	}
	out = append(out, cur)
	return out
}

func containsStr(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
