package patterns

// SecuritySDKs is the catalog of vendor SDKs / frameworks that are
// security-relevant when present in an APK. Unlike the keyword categories in
// patterns.go (which hunt for detection *logic*), this catalog identifies
// whole *products*.
//
// The jadx class-name search matches on class *simple* names (substring), not
// full package paths — "com.aheaditec.talsec_security" returns nothing but
// "Talsec" finds the SDK's entry classes. Each entry therefore carries Terms:
// distinctive class-name fragments the vendor actually ships (Talsec,
// ThreatListener, XposedBridge, IntegrityManager, ...). One hit is enough to
// report the SDK; the Package field is kept for analyst verification.
//
// Kinds:
//   - RASP         runtime application self-protection (active threat callbacks)
//   - hardening    code hardening / obfuscation / anti-tamper wrapper
//   - packer       shell / stub-wrapper packer (encrypted dex, stub Application)
//   - attestation  device / app attestation (Play Integrity, SafetyNet)
//   - device-intel device fingerprinting & fraud-risk scoring
//   - analytics    attribution / analytics SDK (data-leak surface)
//   - hook         Xposed / LSPosed / Frida-style hook framework
//   - root-check   dedicated root detection helper
//   - pinning      SSL/TLS certificate pinning library
//   - framework    app framework / runtime engine (Flutter, React Native, Hermes)
type SDK struct {
	Package  string   // known package prefix, for verification / reporting
	SDK      string   // short product name, e.g. "Talsec RASP"
	Vendor   string   // vendor, e.g. "AheadITec"
	Kind     string   // one of the kinds above
	Severity string
	Desc     string
	Terms    []string // class-name search fragments (first hit wins)
}

// SecuritySDKs is ordered: RASP/hardening first (most significant), then
// attestation / device-intelligence, then analytics / hook tooling.
var SecuritySDKs = []SDK{
	// RASP (runtime application self-protection) — ships active threat
	// detection callbacks (onHookDetected, onTamperDetected, ...).
	{Package: "com.aheaditec.talsec_security", SDK: "Talsec RASP", Vendor: "AheadITec", Kind: "RASP", Severity: "info",
		Desc: "active RASP — detects hooking, tampering, emulators, debuggers, screen capture",
		Terms: []string{"Talsec", "ThreatListener", "ThreatDetected"}},
	{Package: "com.promon", SDK: "Promon Shielding", Vendor: "Promon", Kind: "RASP", Severity: "info",
		Desc: "RASP / app shielding with tamper & debugger defense",
		Terms: []string{"Promon"}},
	{Package: "com.appdome", SDK: "Appdome", Vendor: "Appdome", Kind: "RASP", Severity: "info",
		Desc: "mobile defense (jailbreak/root, anti-tamper, anti-debug) wrapper",
		Terms: []string{"Appdome"}},
	{Package: "com.zimperium", SDK: "Zimperium (zShield)", Vendor: "Zimperium", Kind: "RASP", Severity: "info",
		Desc: "mobile threat defense / RASP + EMM",
		Terms: []string{"Zimperium", "zDetector"}},
	{Package: "com.crowdstrike", SDK: "CrowdStrike Falcon", Vendor: "CrowdStrike", Kind: "RASP", Severity: "info",
		Desc: "EDR / mobile threat defense",
		Terms: []string{"CrowdStrike", "Falcon"}},
	{Package: "com.norton", SDK: "Norton App Protect", Vendor: "NortonLifeLock", Kind: "RASP", Severity: "info",
		Desc: "RASP / application protection",
		Terms: []string{"Norton", "AppProtect"}},
	{Package: "com.onespan", SDK: "OneSpan App Shielding", Vendor: "OneSpan", Kind: "RASP", Severity: "info",
		Desc: "app shielding (anti-tamper, anti-debug, anti-hook)",
		Terms: []string{"OneSpan", "Shielding"}},
	// Native detection layer from cpp/ in this repo: snitchtt JNI bridge
	// (ai/snitchtt/SnitchNative) driving the single-export libsna/libsna modules,
	// plus the DeviceTrust C++ signal collector.
	{Package: "ai.snitchtt", SDK: "snitchtt native security", Vendor: "snitchtt", Kind: "RASP", Severity: "info",
		Desc: "native RASP layer — /proc scans, direct syscalls, PLT/SSL hook checks, monitor thread (libsna.so/libsnb.so)",
		Terms: []string{"SnitchNative", "Snitchtt", "SnitchNativeDetector"}},
	{Package: "com.mikoloy.device_trust", SDK: "DeviceTrust", Vendor: "mikoloy", Kind: "RASP", Severity: "info",
		Desc: "native device-trust signal collector (rwx segments, frida libs, libc hook via dladdr)",
		Terms: []string{"DeviceTrustNative", "DeviceTrust"}},

	// Hardening / obfuscation / anti-tamper wrappers.
	{Package: "com.guardsquare", SDK: "DexGuard / Guardsquare", Vendor: "Guardsquare", Kind: "hardening", Severity: "info",
		Desc: "commercial hardening & string/API obfuscation",
		Terms: []string{"DexGuard", "Guardsquare"}},
	{Package: "io.appsealing", SDK: "AppSealing", Vendor: "AppSealing", Kind: "hardening", Severity: "info",
		Desc: "APK hardening / repackaging protection",
		Terms: []string{"AppSealing"}},
	{Package: "com.secneo", SDK: "SecNeo", Vendor: "SecNeo", Kind: "hardening", Severity: "info",
		Desc: "hardening / virtualization-protected code",
		Terms: []string{"SecNeo"}},
	{Package: "com.arxan", SDK: "Arxan (Digital.ai)", Vendor: "Digital.ai", Kind: "hardening", Severity: "info",
		Desc: "application hardening / RASP",
		Terms: []string{"Arxan"}},
	{Package: "com.verimatrix", SDK: "Verimatrix XTD", Vendor: "Verimatrix", Kind: "hardening", Severity: "info",
		Desc: "anti-tamper / hardening",
		Terms: []string{"Verimatrix"}},
	{Package: "com.nowsecure", SDK: "NowSecure", Vendor: "NowSecure", Kind: "hardening", Severity: "info",
		Desc: "mobile security / runtime protection",
		Terms: []string{"NowSecure"}},

	// Attestation & device intelligence (fraud / fingerprinting).
	{Package: "com.google.android.play.core.integrity", SDK: "Play Integrity API", Vendor: "Google", Kind: "attestation", Severity: "info",
		Desc: "device/app integrity attestation (replaces SafetyNet)",
		Terms: []string{"IntegrityManager", "IntegrityTokenProvider", "PlayIntegrity"}},
	{Package: "com.google.android.gms.safetynet", SDK: "SafetyNet Attestation", Vendor: "Google", Kind: "attestation", Severity: "info",
		Desc: "device attestation / CTS profile check",
		Terms: []string{"SafetyNet"}},
	{Package: "com.threatmetrix", SDK: "ThreatMetrix", Vendor: "LexisNexis Risk", Kind: "device-intel", Severity: "info",
		Desc: "device fingerprinting & fraud-risk scoring (collects device identifiers)",
		Terms: []string{"ThreatMetrix"}},
	{Package: "com.siftscience", SDK: "Sift", Vendor: "Sift", Kind: "device-intel", Severity: "info",
		Desc: "fraud / device-intelligence SDK",
		Terms: []string{"Sift"}},
	{Package: "com.datadome", SDK: "DataDome", Vendor: "DataDome", Kind: "device-intel", Severity: "info",
		Desc: "bot & fraud protection",
		Terms: []string{"DataDome"}},

	// Analytics / attribution — data surface worth flagging.
	{Package: "com.adjust.sdk", SDK: "Adjust", Vendor: "Adjust", Kind: "analytics", Severity: "info",
		Desc: "attribution analytics (sends install/event + device data)",
		Terms: []string{"Adjust"}},
	{Package: "com.appsflyer", SDK: "AppsFlyer", Vendor: "AppsFlyer", Kind: "analytics", Severity: "info",
		Desc: "attribution analytics SDK",
		Terms: []string{"AppsFlyer"}},
	{Package: "io.branch", SDK: "Branch", Vendor: "Branch", Kind: "analytics", Severity: "info",
		Desc: "deep-linking / attribution SDK",
		Terms: []string{"Branch"}},

	// Hook / mod frameworks — presence indicates a repackaged/tampered build or
	// a detection target the app explicitly screens for.
	{Package: "de.robv.android.xposed", SDK: "Xposed Framework", Vendor: "Xposed", Kind: "hook", Severity: "medium",
		Desc: "hook framework — present in tampered builds or screened as a detection target",
		Terms: []string{"XposedBridge", "XposedHelpers", "Xposed"}},
	{Package: "org.lsposed", SDK: "LSPosed", Vendor: "LSPosed", Kind: "hook", Severity: "medium",
		Desc: "modern Xposed variant — hook framework / detection target",
		Terms: []string{"LSPosed"}},
	{Package: "com.elderdrivers", SDK: "EdXposed", Vendor: "EdXposed", Kind: "hook", Severity: "medium",
		Desc: "hook framework / detection target",
		Terms: []string{"EdXposed", "elderdrivers"}},
	// Terms deliberately avoid the bare "Gum" token: it is a substring of
	// "Argu*ments*" and would false-positive on io.flutter.view.FlutterRunArguments
	// (verified against com.lankametrotransit.lmtgo). Real frida-gum Java classes
	// are named GumScript / GumInterceptor, and the eu.frida package itself always
	// contains "Frida". Native payloads are covered by the .so sweep.
	{Package: "eu.frida", SDK: "Frida", Vendor: "Frida", Kind: "hook", Severity: "medium",
		Desc: "dynamic instrumentation toolkit / detection target (native payloads caught by the .so sweep)",
		Terms: []string{"Frida", "GumScript", "GumInterceptor"}},

	// Dedicated root-check helpers.
	{Package: "com.scottyab.rootbeer", SDK: "RootBeer", Vendor: "Scott Alexander-Bown", Kind: "root-check", Severity: "info",
		Desc: "dedicated root-detection helper",
		Terms: []string{"RootBeer"}},
	{Package: "com.topjohnwu.magisk", SDK: "Magisk (detection)", Vendor: "Magisk", Kind: "root-check", Severity: "info",
		Desc: "Magisk code referenced (detection or bundled tooling)",
		Terms: []string{"Magisk", "Sui"}},

	// Certificate pinning libraries.
	{Package: "com.datatheorem.android.trustkit", SDK: "TrustKit", Vendor: "Data Theorem", Kind: "pinning", Severity: "info",
		Desc: "SSL/TLS certificate pinning library",
		Terms: []string{"TrustKit"}},

	// App frameworks / runtime engines — identify the app's code layer so the
	// right bypass / analysis path can be chosen (Flutter AOT, RN+Hermes, ...).
	{Package: "io.flutter", SDK: "Flutter (Dart AOT)", Vendor: "Flutter", Kind: "framework", Severity: "info",
		Desc: "Dart AOT app runtime — libapp.so snapshot; bypass requires Dart hooks (reunicorn / darter)",
		Terms: []string{"FlutterActivity", "FlutterApplication", "FlutterEngine", "FlutterView", "FlutterLoader", "DartExecutor", "MethodChannel"}},
	{Package: "com.facebook.react", SDK: "React Native", Vendor: "Meta", Kind: "framework", Severity: "info",
		Desc: "React Native runtime — JS bundle in assets, native bridge via libreactnativejni",
		Terms: []string{"ReactApplication", "ReactInstanceManager", "ReactNativeHost", "ReactContext", "ReactActivity", "CatalystInstance"}},
	{Package: "com.facebook.hermes", SDK: "Hermes JS engine", Vendor: "Meta", Kind: "framework", Severity: "info",
		Desc: "Hermes bytecode (hbc) JS engine — bundle is compiled, not plain text; needs hbctool to disassemble",
		Terms: []string{"HermesExecutor", "HermesRuntime", "HermesHelper"}},

	// Packers / shell wrappers — encrypted dex behind a stub Application.
	{Package: "com.stub.StubApp", SDK: "Qihoo 360 Jiagu", Vendor: "Qihoo 360", Kind: "packer", Severity: "info",
		Desc: "360 jiagu packer — StubApp entry, libjiagu.so loads the real dex at runtime",
		Terms: []string{"StubApp", "Jiagu"}},
	{Package: "com.tencent.StubShell", SDK: "Tencent Legu", Vendor: "Tencent", Kind: "packer", Severity: "info",
		Desc: "Tencent legu packer — libtencent_stub.so / libshell.so dex loader",
		Terms: []string{"StubShell", "Legu", "TencentStub"}},
	{Package: "com.secneo.apkwrapper", SDK: "Bangcle (SecNeo)", Vendor: "Bangcle", Kind: "packer", Severity: "info",
		Desc: "bangcle packer — libSecShell.so / libsecexe.so wrapper (hardening SDK = same vendor)",
		Terms: []string{"SecShell", "DexShell"}},
	{Package: "com.licel", SDK: "DexProtector", Vendor: "Licel", Kind: "packer", Severity: "info",
		Desc: "commercial APK packer — libDexProtector.so runtime decrypts classes",
		Terms: []string{"DexProtector"}},
	{Package: "com.aijiami", SDK: "ijiami (爱加密)", Vendor: "ijiami", Kind: "packer", Severity: "info",
		Desc: "ijiami packer — libexec.so / libexecmain.so stub loader",
		Terms: []string{"Aijiami", "ijiami"}},
	{Package: "com.baidu.protect", SDK: "Baidu App Protect", Vendor: "Baidu", Kind: "packer", Severity: "info",
		Desc: "baidu protect packer — libbaiduprotect.so wrapper",
		Terms: []string{"BaiduProtect", "AppShell"}},

	// React Native root/emulator detection helper.
	{Package: "com.gantix", SDK: "JailMonkey", Vendor: "Gantix", Kind: "root-check", Severity: "info",
		Desc: "React Native jailbreak/root & mock-location detection helper",
		Terms: []string{"JailMonkey", "JailMonkeyPackage"}},
}

// SecuritySDKClassTerms is the deduplicated class-name search term list derived
// from SecuritySDKs, used by the detection / sdks modes to sweep the whole
// catalog with one pass over the term list.
var SecuritySDKClassTerms = func() []string {
	seen := map[string]bool{}
	var out []string
	for _, sdk := range SecuritySDKs {
		for _, term := range sdk.Terms {
			if !seen[term] {
				seen[term] = true
				out = append(out, term)
			}
		}
	}
	return out
}()

// SecuritySDKByPackage looks up a catalog entry by its package prefix (case
// insensitive), returning the entry and whether it was found.
func SecuritySDKByPackage(pkg string) (SDK, bool) {
	for _, sdk := range SecuritySDKs {
		if sdk.Package == pkg {
			return sdk, true
		}
	}
	return SDK{}, false
}
