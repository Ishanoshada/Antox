// Package patterns holds the analysis dimensions and search/evidence patterns
// used by the analyzer. The keywords and regexes are distilled from real-world
// reverse-engineering material in this repo:
//
//   - Frida-Mobile-Scripts/Android/*      (root, frida, emulator, ssl pinning)
//   - cpp/                                (native detection: ptrace, /proc scans, magisk)
//   - snitchtt/                           (runtime security library detection)
//
// A Category drives one dimension of a mode:
//   - Terms:   keyword list fed to the jadx search_classes_by_keyword tool.
//   - Regexes: evidence patterns run over each fetched class source.
package patterns

import "regexp"

// Term is a single search term with the scope it should be matched against.
// Scope values understood by jadx-mcp-server: code, class, method, field,
// comment, or comma-combinations of those.
type Term struct {
	Text  string
	Scope string
}

// T is a code-scope term (method bodies, statements).
func T(s string) Term { return Term{Text: s, Scope: "code"} }

// M is a method-name-scope term.
func M(s string) Term { return Term{Text: s, Scope: "method"} }

// C is a class-name-scope term.
func C(s string) Term { return Term{Text: s, Scope: "class"} }

// CM is a combined class+method scope term.
func CM(s string) Term { return Term{Text: s, Scope: "class,method"} }

// Category describes one analysis dimension.
type Category struct {
	ID       string // short id used in reports
	Label    string // human readable title
	Severity string // default severity for findings in this category
	Terms    []Term
	Regexes  []*regexp.Regexp
}

func mustRe(p string) *regexp.Regexp { return regexp.MustCompile(p) }

// SecurityCategories are the "security layer" dimensions probed by the
// security mode. Presence of a match means the app implements that layer.
var SecurityCategories = []Category{
	{
		ID: "root-detection", Label: "Root / privileged access detection", Severity: "info",
		Terms: []Term{
			T("isRooted"), T("rootbeer"), T("magisk"), T("supersu"), T("superuser"),
			T("busybox"), T("xbin/su"), T("hasRootAccess"), T("isDeviceRooted"), T("checkRoot"),
			T("apatch"), T("shamiko"), T("magisk_daemon"), T("ro.boot.vbmeta"),
			T("ro.build.tags"), T("init.svc.adbd"), T("ro.secure"), T("ro.debuggable"),
			T("checkSu"), T("checkRootAccess"), T("checkForRoot"), T("check_magisk_data"),
			T("check_su_binary"), T("check_mountinfo_magisk"), T("check_init_mountinfo"),
			T("check_magisk_unix_socket"), T("check_apatch"), T("check_zygisk"),
			T("selinux"), T("permissive"), T("/data/adb"), T("/debug_ramdisk"),
			T("ro.boot.verifiedbootstate"), T("ro.build.type"), T("eng"), T("userdebug"),
			T("@magisk_daemon"), T("su_binary"), T("magisk_in_init_mountinfo"),
			T("/su/bin/su"), T("/data/local/su"), T("/data/local/bin/su"), T("/data/local/xbin/su"),
			T("com.thirdparty.superuser"), T("eu.chainfire.supersu"), T("com.noshufou.android.su"),
			T("com.koushikdutta.superuser"), T("com.amphoras.hidemyroot"), T("com.topjohnwu.magisk"),
			T("findBinary"), T("isAccessGiven"), T("canReadSystemBin"),
		},
		Regexes: []*regexp.Regexp{
			mustRe(`(?i)magisk`),
			mustRe(`(?i)(superuser|supersu|rootcloak|hidemyroot|hidemyapplist|chainfire)`),
			mustRe(`(?i)rootbeer`),
			mustRe(`(?i)(/system/bin/su|/system/xbin/su|/system/bin/failsafe/su|/sbin/su|/system/sd/xbin/su)`),
			mustRe(`(?i)isRooted|hasRootAccess|isDeviceRooted|checkRoot|isRootedNative|checkRootAccess|checkForRoot`),
			mustRe(`(?i)busybox`),
			mustRe(`(?i)(apatch|shamiko|magisk_daemon|@magisk_daemon|hidemyapplist)`),
			mustRe(`(?i)(ro\.boot\.vbmeta|ro\.boot\.verifiedbootstate|ro\.build\.tags|ro\.build\.type|init\.svc\.adbd|ro\.debuggable|ro\.secure)`),
			mustRe(`(?i)(/data/adb/magisk|/data/adb/modules|/data/adb/lspd|/data/adb/apatch|/data/adb|/debug_ramdisk|@magisk_daemon)`),
			mustRe(`(?i)(check_magisk_data|check_su_binary|check_mountinfo_magisk|check_init_mountinfo|check_magisk_unix_socket|check_apatch|check_zygisk|check_selinux_permissive|path_exists_syscall)`),
			mustRe(`(?i)(/sys/fs/selinux/enforce|selinux.*permissive|test-keys|userdebug|\beng\b)`),
			mustRe(`(?i)(/system/bin/su|/system/xbin/su|/sbin/su|/su/bin/su|/data/local/(x?bin|xbin|su)/su|/data/local/su|/system/sd/xbin/su|/system/bin/failsafe/su)`),
			mustRe(`(?i)(com\.topjohnwu\.magisk|com\.thirdparty\.superuser|eu\.chainfire\.supersu|com\.noshufou\.android\.su|com\.koushikdutta\.superuser|com\.amphoras\.hidemyroot)`),
			mustRe(`(?i)(findBinary\s*\(|isAccessGiven\s*\(|canReadSystemBin\s*\(|execShellCommand\s*\()\s*["'][^"']*su\b`),
		},
	},
	{
		ID: "frida-detection", Label: "Frida / hook framework detection", Severity: "info",
		Terms: []Term{
			T("frida"), T("linjector"), T("libfrida"), T("TracerPid"), T("ptrace"),
			T("memfd"), T("gum-js"), T("frida-gadget"), T("gadget"),
			T("frida-agent"), T("gum-js-loop"), T("pool-frida"), T("frida-zymbiote"),
			T("gum_interceptor_obtain"), T("libfrida-agent"),
			T("frida_gadget_load"), T("frida_gadget_wait_for_debugger"),
			T("gum_init_embedded"), T("jit-cache"), T("rwxp"), T("zymbiote"),
			T("gmain"), T("gdbus"), T("gum-js"), T("detectFrida"), T("isFridaRunning"),
			T("isFridaDetected"), T("checkFrida"), T("has_frida_threads"),
			T("stack_has_frida_frame"), T("fd_has_frida_memfd"), T("probe_frida_port"),
			T("scan_frida_ports"), T("check_gadget_symbol"), T("check_gadget_listener"),
			T("frida_detect"), T("maps_scan"),
			T("frida-server"), T("frida-helper"), T("re.frida.server"), T("/tmp/frida-"),
			T("frida_agent_main"), T("gum_interceptor_replace"), T("gum_init"),
			T("27042"), T("27043"), T("4444"), T("27047"),
		},
		Regexes: []*regexp.Regexp{
			mustRe(`(?i)frida`),
			mustRe(`(?i)linjector`),
			mustRe(`(?i)TracerPid`),
			mustRe(`(?i)ptrace`),
			mustRe(`(?i)(frida-gadget|libgadget\.so|gum-js|gum\.js)`),
			mustRe(`(?i)/proc/self/maps`),
			mustRe(`(?i)(frida-agent|frida-helper|frida-zymbiote|frida_gadget_|gum_interceptor_obtain|gum_init_embedded|pool-frida|gum-js-loop|gmain|gdbus)`),
			mustRe(`(?i)(/memfd:jit-cache|rwxp|jit-cache)`),
			mustRe(`(?i)(detectFrida|isFridaRunning|isFridaDetected|checkFrida|isFrida)`),
			mustRe(`(?i)(scan_frida_ports|probe_frida_port|has_frida_threads|stack_has_frida_frame|fd_has_frida_memfd|check_gadget_symbol|check_gadget_listener|frida_detect|maps_scan)`),
			mustRe(`(?i)(/proc/self/task|/proc/self/fd|/proc/self/net/unix|/proc/self/net/tcp|/proc/net/tcp6)`),
			mustRe(`(?i)(frida-server|frida-helper|re\.frida\.server|/tmp/frida-|/data/local/tmp/frida-server|/data/local/tmp/re\.frida\.server)`),
			mustRe(`(?i)(frida_agent_main|gum_interceptor_replace|gum_init\b|gum_init_embedded)`),
		},
	},
	{
		ID: "hook-framework", Label: "Native hook framework detection", Severity: "info",
		Terms: []Term{
			T("Dobby"), T("shadowhook"), T("whale"), T("substrate"), T("XposedBridge"),
			T("edxposed"), T("zygisk"), T("libzygisk"),
			T("LSPlant"), T("SandHook"), T("YAHFA"), T("Epic"), T("Pine"), T("lspd"),
			T("is_ssl_write_hooked"), T("is_ssl_read_hooked"), T("is_libc_open_hooked"),
			T("sym_hooked"), T("caller_is_system"), T("jni_ptrs_hijacked"),
			T("reregister_natives"), T("check_late_inject"),
		},
		Regexes: []*regexp.Regexp{
			mustRe(`(?i)(Dobby|shadowhook|libwhale|whale\.so|SandHook|YAHFA|LSPlant|Epic)`),
			mustRe(`(?i)(XposedBridge|de\.robv\.android\.xposed)`),
			mustRe(`(?i)(substrate|edxposed|zygisk|libzygisk|zygisknext|lspd)`),
			mustRe(`(?i)(RegisterNatives|dlopen|dlsym|dladdr)`),
			mustRe(`(?i)(is_ssl_write_hooked|is_ssl_read_hooked|is_libc_open_hooked|sym_hooked|caller_is_system|jni_ptrs_hijacked|reregister_natives|check_late_inject)`),
		},
	},
	{
		ID: "native-detection", Label: "Native detection / anti-tamper layer", Severity: "info",
		Terms: []Term{
			T("nativeScanMaps"), T("nativeDetectFrida"), T("nativeCheckRoot"),
			T("nativeCheckLsposed"), T("snitchtt"), T("SnitchNative"), T("sna_e"),
			T("collectNativeSignals"), T("onAlert"),
			T("nativeCheckMounts"), T("nativeCheckPlt"), T("nativeCheckStack"),
			T("nativeCheckFd"), T("nativeCheckEnv"), T("nativeCheckThreads"),
			T("nativeCheckAdbNative"), T("nativeCheckBuildNative"),
			T("nativeCheckLateInject"), T("nativeScanPort"), T("nativeGetBaseline"),
			T("nativeCheckTiming"), T("nativeStartMonitor"),
			T("snb_e"), T("DeviceTrustNative"), T("Snitchtt"), T("monitor_thread"),
			T("snitchtt_early_scan"), T("reregister_natives"), T("call_sna"),
			T("call_snb"), T("load_modules"), T("full_scan"),
		},
		Regexes: []*regexp.Regexp{
			mustRe(`(?i)(nativeScanMaps|nativeDetectFrida|nativeCheckRoot|nativeCheckMounts|nativeCheckLsposed|nativeCheckThreads|nativeCheckFd|nativeCheckEnv|nativeCheckAdbNative|nativeCheckBuildNative|nativeCheckPlt|nativeCheckStack|nativeCheckLateInject|nativeScanPort|nativeCheckTiming|nativeStartMonitor)`),
			mustRe(`(?i)(snitchtt|SnitchNative|sna_e|snb_e|libsna|libsnb|libsnitchtt)`),
			mustRe(`(?i)(collectNativeSignals|DeviceTrustNative)`),
			mustRe(`(?i)(onAlert|ThreatListener|Talsec)`),
			mustRe(`(?i)(ro\.boot\.verifiedbootstate|vbmeta)`),
			mustRe(`(?i)(snitchtt_early_scan|monitor_thread|reregister_natives|call_sna|call_snb|caller_is_system|load_modules|full_scan)`),
			mustRe(`(?i)(/proc/self/maps|/proc/self/status|/proc/self/mounts|/proc/self/mountinfo|/proc/1/mountinfo)`),
		},
	},
	{
		ID: "emulator-detection", Label: "Emulator detection", Severity: "info",
		Terms: []Term{
			T("goldfish"), T("ranchu"), T("qemu"), T("Genymotion"), T("isEmulator"), T("emulator"),
			T("isRunningOnEmulator"), T("isEmulatorDetected"), T("checkEmulator"),
			T("isEmulatorBuild"), T("detectEmulator"), T("vbox"), T("nox"),
			T("bluestacks"), T("ldplayer"), T("mumu"), T("memu"),
		},
		Regexes: []*regexp.Regexp{
			mustRe(`goldfish|ranchu`),
			mustRe(`(?i)qemu`),
			mustRe(`(?i)(genymotion|bluestacks|noxplayer|ldplayer|mumu|memu)`),
			mustRe(`(?i)isEmulator|isRunningOnEmulator|isEmulatorDetected`),
			mustRe(`(?i)(/dev/qemu_pipe|/dev/socket/qemud|ro\.kernel\.qemu)`),
		},
	},
	{
		ID: "debugger-detection", Label: "Debugger / anti-debug detection", Severity: "info",
		Terms: []Term{
			T("isDebuggerConnected"), T("Debug.isDebuggerConnected"), T("TracerPid"),
			T("waitForDebugger"), T("anti-debug"), T("android.os.Debug"), T("debugger"),
			T("PTRACE_TRACEME"), T("syscall"),
			T("check_tracer_via_ptrace"), T("read_tracer_pid"), T("isBeingDebugged"),
			T("isDebuggerPresent"), T("checkForDebugger"), T("detectDebugger"),
			T("antiDebug"), T("tracepid"), T("tracer"),
			T("PTRACE_ATTACH"), T("PTRACE_DETACH"), T("fork"), T("/proc/self/wchan"),
			T("Debug.waitingForDebugger"), T("sys_ptrace"), T("TracerPid:"),
		},
		Regexes: []*regexp.Regexp{
			mustRe(`isDebuggerConnected`),
			mustRe(`(?i)TracerPid`),
			mustRe(`(?i)ptrace`),
			mustRe(`waitForDebugger`),
			mustRe(`(?i)anti[- ]?debug`),
			mustRe(`(?i)(PTRACE_TRACEME|PTRACE_ATTACH|PTRACE_DETACH|syscall\s*\(\s*__NR)`),
			mustRe(`(?i)(/proc/self/wchan|sys_ptrace|TracerPid:)`),
		},
	},
	{
		ID: "rasp-sdk", Label: "RASP / app-hardening SDK", Severity: "info",
		Terms: []Term{
			C("Talsec"), C("ThreatListener"), C("ThreatDetected"),
			C("AppSealing"), C("Appdome"), C("Promon"),
			C("DexGuard"), C("Guardsquare"), C("SecNeo"), C("Zimperium"), C("Arxan"),
			C("Verimatrix"), C("CrowdStrike"), C("Norton"), C("OneSpan"), C("NowSecure"),
			C("ThreatMetrix"), C("Sift"), C("TrustKit"), C("PlayIntegrity"), C("SafetyNet"),
			C("SnitchNative"), C("Snitchtt"), C("DeviceTrust"), C("DeviceTrustNative"),
		},
		Regexes: []*regexp.Regexp{
			mustRe(`(?i)(talsec|aheaditec|rasp)`),
			mustRe(`(?i)(appsealing|appdome|dexguard|guardsquare|secneo|promon)`),
			mustRe(`(?i)(zimperium|arxan|verimatrix|crowdstrike|norton|onespan|nowsecure)`),
			mustRe(`(?i)(threatmetrix|sift|trustkit|playintegrity|safetynet)`),
			mustRe(`(?i)on(Debugger|Hook|Tamper|Emulator|Frida|Root|Malware|ScreenRecording|Screenshot|Automation|LocationSpoofing|TimeSpoofing|UnsecureWifi|UntrustedInstallation)Detected\s*\(`),
			mustRe(`(?i)(ThreatListener|DeviceState|RaspExecutionState)`),
			mustRe(`(?i)(SnitchNative|Snitchtt|DeviceTrustNative|collectNativeSignals)`),
			mustRe(`(?i)(libsna\.so|libsnb\.so|libsnitchtt\.so|sna_e|snb_e)`),
		},
	},
	{
		ID: "ssl-pinning", Label: "SSL pinning / certificate validation", Severity: "info",
		Terms: []Term{
			T("CertificatePinner"), T("TrustManager"), T("X509TrustManager"),
			T("checkServerTrusted"), T("setHostnameVerifier"), T("SSLContext"), T("SSLPinning"),
			T("conscrypt"), T("TrustManagerImpl"), T("CertificatePinning"),
			T("PinningManager"), T("ssl_pinning"), T("is_ssl_write_hooked"),
			T("is_ssl_read_hooked"),
		},
		Regexes: []*regexp.Regexp{
			mustRe(`(?i)CertificatePinner`),
			mustRe(`(?i)(X509TrustManager|TrustManagerImpl|checkServerTrusted)`),
			mustRe(`(?i)setHostnameVerifier|HostnameVerifier`),
			mustRe(`(?i)getPeerCertificates|getCertificateChain`),
			mustRe(`(?i)okhttp3\.CertificatePinner|CertificatePinnerBuilder`),
		},
	},
	{
		ID: "flag-secure", Label: "FLAG_SECURE / screen security", Severity: "info",
		Terms: []Term{
			T("FLAG_SECURE"), T("setSecure"), T("setFlags"), T("FLAG_SECURE window"),
		},
		Regexes: []*regexp.Regexp{
			mustRe(`FLAG_SECURE`),
			mustRe(`(?i)setSecure`),
			mustRe(`setFlags\([^;]{0,100}FLAG_SECURE`),
		},
	},
	{
		ID: "crypto-hardening", Label: "Crypto / encryption at rest", Severity: "info",
		Terms: []Term{
			T("EncryptedSharedPreferences"), T("SecretKeySpec"), T("Cipher"), T("AES"),
			T("Keystore"), T("RSA"), T("GCM"), T("SecureRandom"), T("KeyGenerator"),
			T("CBC"), T("PBKDF2"), T("PBEKeySpec"), T("HMAC"), T("SHA256"), T("SHA1"),
		},
		Regexes: []*regexp.Regexp{
			mustRe(`Cipher\.getInstance`),
			mustRe(`(?i)SecretKeySpec`),
			mustRe(`(?i)EncryptedSharedPreferences|MasterKey`),
			mustRe(`(?i)javax\.crypto|KeyGenerator|KeyStore`),
			mustRe(`(?i)AES/GCM|AES/CBC`),
			mustRe(`(?i)(PBKDF2|SecureRandom|PBEKeySpec)`),
		},
	},
	{
		ID: "integrity-checks", Label: "Tamper / signature / integrity checks", Severity: "info",
		Terms: []Term{
			T("PlayIntegrity"), T("SafetyNet"), T("attestation"), T("integrity"), T("checksum"),
			T("signature"), T("tamper"), T("MessageDigest"), T("verify"),
			T("verifySignatures"), T("checkSignature"), T("verifySignature"),
			T("isTampered"), T("detectTamper"), T("checkTamper"), T("checkIntegrity"),
			T("codeIntegrity"), T("signingInfo"), T("signingCertificate"),
		},
		Regexes: []*regexp.Regexp{
			mustRe(`(?i)PlayIntegrity|IntegrityManager|IntegrityTokenResponse`),
			mustRe(`(?i)SafetyNet|attestation`),
			mustRe(`(?i)getPackageInfo|signingCertificate|getSigningInfo`),
			mustRe(`(?i)signature|MessageDigest|sha256|sha1`),
			mustRe(`(?i)tamper|codeIntegrity`),
		},
	},
	{
		ID: "flutter-framework", Label: "Flutter / Dart AOT framework", Severity: "info",
		Terms: []Term{
			T("libapp.so"), T("libflutter.so"), T("libflutter_x86.so"), T("libflutter_x86_64.so"),
			C("FlutterActivity"), C("FlutterApplication"), C("FlutterEngine"), C("FlutterView"),
			C("FlutterRunArguments"), C("FlutterMain"), C("FlutterLoader"),
			T("MethodChannel"), T("EventChannel"), T("BasicMessageChannel"), T("PlatformChannel"),
			T("io.flutter"), T("kernel_blob.bin"), T("isolate_snapshot_data"),
			T("vm_snapshot_data"), T("FontManifest.json"), T("flutter_assets"),
			T("Dart_Initialize"), T("Dart_PropagateError"), T("_kDartVmSnapshotData"),
			T("_kDartIsolateSnapshotData"), T("ssl_crypto_x509_verify_cert"),
			T("dart:ui"), T("dart:io"), T("DartVM"), T("DartExecutor"),
		},
		Regexes: []*regexp.Regexp{
			mustRe(`(?i)libapp\.so|libflutter\.so`),
			mustRe(`(?i)(io\.flutter|FlutterActivity|FlutterApplication|FlutterEngine|FlutterView|FlutterLoader)`),
			mustRe(`(?i)(MethodChannel|EventChannel|BasicMessageChannel|PlatformChannel|DartExecutor)`),
			mustRe(`(?i)(kernel_blob\.bin|isolate_snapshot_data|vm_snapshot_data|FontManifest\.json|flutter_assets)`),
			mustRe(`(?i)(Dart_Initialize|Dart_PropagateError|_kDartVmSnapshotData|_kDartIsolateSnapshotData|dart:ui|dart:io|DartVM)`),
		},
	},
	{
		ID: "react-native-framework", Label: "React Native / Hermes framework", Severity: "info",
		Terms: []Term{
			T("libhermes.so"), T("libreactnativejni.so"), T("libfbjni.so"),
			T("libjsc.so"), T("libflipper.so"),
			C("ReactApplication"), C("ReactNativeHost"), C("ReactInstanceManager"),
			C("ReactContext"), C("ReactActivity"), C("HermesExecutor"), C("ReactNativeBaseActivity"),
			T("com.facebook.react"), T("index.android.bundle"), T("index.android.bundle.hbc"),
			T("src_app_index.bundle"), T("HermesBytecode"), T("HermesRuntime"), T("hbc"),
			T("TurboModule"), T("JSI"), T("CatalystInstance"), T("ReactBridge"), T("SoLoader"),
			T("JailMonkey"), T("com.gantix"),
		},
		Regexes: []*regexp.Regexp{
			mustRe(`(?i)libhermes\.so|libreactnativejni\.so|libjsc\.so|libfbjni\.so|libflipper\.so`),
			mustRe(`(?i)(com\.facebook\.react|ReactApplication|ReactInstanceManager|ReactNativeHost|ReactActivity)`),
			mustRe(`(?i)(HermesExecutor|HermesRuntime|HermesBytecode|\.hbc\b)`),
			mustRe(`(?i)(index\.android\.bundle|src_app_index\.bundle)`),
			mustRe(`(?i)(TurboModule|NativeModule|\bJSI\b|CatalystInstance|ReactBridge|SoLoader)`),
			mustRe(`(?i)(JailMonkey|com\.gantix)`),
		},
	},
	{
		ID: "packer-protection", Label: "Packer / commercial hardening wrapper", Severity: "info",
		Terms: []Term{
			C("Jiagu"), C("Legu"), C("Bangcle"), C("DexProtector"), C("Aijiami"),
			C("StubApp"), C("StubShell"), C("SecShell"), C("DexShell"), C("ProxyApplication"),
			T("libjiagu.so"), T("libjiagu_a64.so"), T("libjiagu_x86.so"),
			T("libSecShell.so"), T("libsecexe.so"), T("bangcleclasses.jar"),
			T("libbaiduprotect.so"), T("libtencent_stub.so"), T("libshell.so"),
			T("libDexProtector.so"), T("libexec.so"), T("libexecmain.so"),
			T("com.stub.StubApp"), T("com.secneo.apkwrapper"), T("com.qihoo.util"),
		},
		Regexes: []*regexp.Regexp{
			mustRe(`(?i)(jiagu|legu|bangcle|secshell|dexshell|dexprotector|ijiami)`),
			mustRe(`(?i)(libjiagu|libSecShell|libsecexe|libbaiduprotect|libtencent_stub|libDexProtector|libexecmain|libshell)`),
			mustRe(`(?i)(StubApplication|ApplicationStub|ProxyApplication|StubApp\.override|com\.stub\.StubApp|com\.secneo\.apkwrapper)`),
			mustRe(`(?i)(bangcleclasses\.jar|libjiagu_a64|com\.qihoo\.util|com\.tencent\.StubShell)`),
		},
	},
}

// SecretPattern is a named high-signal secret/credential regex.
type SecretPattern struct {
	Name     string
	Severity string
	Regexp   *regexp.Regexp
}

// SecretPatterns is the ordered list of credential patterns the secrets mode
// scans class sources and string resources against.
var SecretPatterns = []SecretPattern{
	{Name: "AWS Access Key", Severity: "critical", Regexp: mustRe(`\bAKIA[0-9A-Z]{16}\b`)},
	{Name: "Google API Key", Severity: "critical", Regexp: mustRe(`\bAIza[0-9A-Za-z_\-]{35}\b`)},
	{Name: "Google OAuth Client", Severity: "high", Regexp: mustRe(`\b\d{10,17}-[0-9a-z]{32}\.apps\.googleusercontent\.com\b`)},
	{Name: "Slack Token", Severity: "high", Regexp: mustRe(`\bxox[baprs]-[0-9A-Za-z\-]{10,}\b`)},
	{Name: "GitHub Token", Severity: "critical", Regexp: mustRe(`\bgh[pousr]_[0-9A-Za-z]{20,}\b`)},
	{Name: "GitLab PAT", Severity: "high", Regexp: mustRe(`\bglpat-[0-9A-Za-z_\-]{20,}\b`)},
	{Name: "JWT", Severity: "high", Regexp: mustRe(`\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\b`)},
	{Name: "Stripe Key", Severity: "critical", Regexp: mustRe(`\bsk_(?:live|test)_[0-9A-Za-z]{16,}\b`)},
	{Name: "Twilio API Key", Severity: "high", Regexp: mustRe(`\bSK[0-9a-fA-F]{32}\b`)},
	{Name: "SendGrid API Key", Severity: "high", Regexp: mustRe(`\bSG\.[0-9A-Za-z_\-]{16,}\.[0-9A-Za-z_\-]{16,}\b`)},
	{Name: "Private Key Block", Severity: "critical", Regexp: mustRe(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{Name: "URL Embedded Credentials", Severity: "high", Regexp: mustRe(`\bhttps?://[^\s/@:]+:[^\s/@]+@`)},
	{Name: "Generic Secret Assignment", Severity: "high", Regexp: mustRe(`(?i)(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|private[_-]?key|secret)\s*[:=]\s*["'][^"']{6,}["']`)},
	{Name: "Hardcoded Password", Severity: "high", Regexp: mustRe(`(?i)(?:password|passwd|pwd)\s*[:=]\s*["'][^"']{4,}["']`)},
	{Name: "AWS Secret Access Key", Severity: "high", Regexp: mustRe(`(?i)(aws|amazon)[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["'][^"']{20,}["']`)},
	{Name: "Long Hex String (key/hash?)", Severity: "medium", Regexp: mustRe(`["'][0-9a-fA-F]{32,}["']`)},
	{Name: "Long Base64 String (key?)", Severity: "medium", Regexp: mustRe(`["'][A-Za-z0-9+/]{40,}={0,2}["']`)},
}

// SecretsTerms are the keywords that surface candidate classes for the
// secrets scan. Broad words (token, secret) are kept because the evidence
// regexes above filter to real assignments.
var SecretsTerms = []Term{
	T("api_key"), T("apiKey"), T("apikey"), T("API_KEY"), T("client_secret"),
	T("clientSecret"), T("access_token"), T("accessToken"), T("authToken"),
	T("auth_token"), T("bearer"), T("privateKey"), T("private_key"),
	T("secret"), T("password"), T("aws_access"),
}

// FirebaseTerms surface Firebase / Google services configuration.
var FirebaseTerms = []Term{
	T("FirebaseApp"), T("FirebaseOptions"), T("firebase"), T("google_app_id"),
	T("firebase_database_url"), T("gcm_defaultSenderId"), T("google_api_key"),
	T("firebaseio.com"), T("FirebaseMessaging"), T("FirebaseAnalytics"),
	T("com.google.firebase"), T("firebase.initialize"),
}

// FirebaseRegexes extract concrete Firebase configuration values from code.
var FirebaseRegexes = []*regexp.Regexp{
	mustRe(`https://[a-z0-9\-]+\.firebaseio\.com`),
	mustRe(`google_app_id["']?\s*[:=]\s*["']?\d+:[0-9]+:[a-z0-9]+:[0-9a-fA-F]+`),
	mustRe(`firebase_database_url["']?\s*[:=]\s*["']?https?://[^\s"']+`),
	mustRe(`storageBucket["']?\s*[:=]\s*["']?[^\s"']+`),
	mustRe(`project_id["']?\s*[:=]\s*["']?[a-z0-9\-]+`),
	mustRe(`gcm_defaultSenderId["']?\s*[:=]\s*["']?\d+`),
	mustRe(`messaging_sender_id["']?\s*[:=]\s*["']?\d+`),
	mustRe(`\bAIza[0-9A-Za-z_\-]{35}\b`),
}

// FirebaseResourceHints are resource file name fragments that point at
// Firebase / Google config (e.g. google-services.json).
var FirebaseResourceHints = []string{"google-services", "firebase", "gcm", "google_app", "fcm"}

// SecretResourceHints are resource names worth dumping for the secrets scan.
var SecretResourceHints = []string{".json", "keystore", "credentials", ".properties", "keys", "client_secret"}

// DetectionClassTerms locate known detection/hardening libraries by class name.
// Vendor RASP / hardening / device-intel products are cataloged separately in
// sdks.go (SecuritySDKs); this list keeps the concept-level sweep terms.
// Note: "Xposed" and "Integrity" are deliberately NOT here — their substrings
// appear in unrelated classes (ExposedByteArrayOutputStream, WebViewMedia
// Integrity...). The precise product terms (XposedBridge, PlayIntegrity,
// IntegrityManager) are in the catalog (sdks.go) and below instead.
var DetectionClassTerms = []string{
	"RootBeer", "Talsec", "DexGuard", "RASP", "LSPosed",
	"Magisk", "SafetyNet", "Frida", "tamper", "rootcheck",
	"shamiko", "zygisk", "substrate", "emulator",
	"SnitchNative", "Snitchtt", "DeviceTrust", "ThreatListener", "conscrypt",
	"HiddenApis", "HMA", "edxposed", "Dobby", "ShadowHook",
	"TrustKit", "CertificatePinner", "PlayIntegrity", "IntegrityManager",
	"ThreatMetrix", "Sift", "AppSealing", "Promon", "SecNeo",
	"Guardsquare", "Zimperium", "Arxan", "Verimatrix", "CrowdStrike",
	// snitchtt / DeviceTrust native layer (cpp/)
	"SnitchNative", "Snitchtt", "DeviceTrustNative", "onAlert",
	// root-check helpers (cpp/ root_check.c)
	"checkSu", "checkRootAccess", "checkForRoot", "check_magisk_data",
	"check_su_binary", "check_mountinfo_magisk", "check_init_mountinfo",
	"check_magisk_unix_socket", "check_apatch", "check_zygisk",
	"check_selinux_permissive", "selinux", "permissive",
	// frida / hook-detection (cpp/ frida_detect.c, plt_check.c)
	"detectFrida", "isFridaRunning", "isFridaDetected", "checkFrida",
	"frida_detect", "maps_scan", "scan_frida_ports", "probe_frida_port",
	"has_frida_threads", "stack_has_frida_frame", "fd_has_frida_memfd",
	"check_gadget_symbol", "check_gadget_listener", "is_ssl_write_hooked",
	"is_ssl_read_hooked", "is_libc_open_hooked", "check_lsposed_socket",
	// hiding / masking modules
	"hidemyapplist", "shamiko", "rootcloak", "hideroot",
	"LSPlant", "SandHook", "YAHFA", "Epic",
	// ADB / build state (cpp/ adb_native.c, build_native.c)
	"adb_keys", "init.svc.adbd", "ro.boot.vbmeta", "ro.boot.verifiedbootstate",
	"test-keys", "userdebug", "verifiedbootstate", "vbmeta",
	// Flutter / Dart AOT framework (app-type identification)
	"FlutterActivity", "FlutterApplication", "FlutterEngine", "FlutterView",
	"FlutterLoader", "DartExecutor", "MethodChannel", "FlutterRunArguments",
	"kernel_blob", "flutter_assets", "isolate_snapshot_data", "vm_snapshot_data",
	// React Native / Hermes framework
	"ReactApplication", "ReactInstanceManager", "ReactNativeHost", "ReactContext",
	"HermesExecutor", "HermesRuntime", "TurboModule", "CatalystInstance",
	"index.android.bundle", "JailMonkey",
	// Packers / commercial hardening wrappers
	"StubApp", "StubShell", "Jiagu", "Legu", "Bangcle", "DexProtector",
	"SecShell", "DexShell", "Aijiami", "ProxyApplication", "libjiagu",
	// anti-debug / ptrace family
	"PTRACE_ATTACH", "PTRACE_DETACH", "wchan", "sys_ptrace",
}

// DetectionMethodTerms, NativeTerms and NativeRegexes are declared in
// native.go with the full cpp-derived dictionary (dlopen/dlsym family and the
// snitchtt JNI table). This file keeps only the search-tool driven terms.

// HexTerms surface string obfuscation / native hex encoding routines.
var HexTerms = []Term{
	T("0x"), T("toCharArray"), T("XOR"), T("decrypt"), T("Cipher"), T("getBytes"),
	T("StringBuilder"), T("base64"), T("Base64"), T("obfuscat"), T("encode"), T("decode"),
	T("xorDecode"), T("deobfuscate"), T("deob"), T("stringFromBytes"),
	T("decodeString"), T("hexString"), T("toHex"), T("fromHex"), T("byteToHex"),
	T("hexToString"), T("stringToHex"), T("charCodeAt"), T("String.fromCharCode"),
	T("writeInt"), T("readInt"), T("littleEndian"), T("bigEndian"),
	T("SE_KEY"), T("0x42"), T("^ 0x"), T("^0x"), T("xorKey"), T("decryptString"),
	T("ByteBuffer"), T("UnsignedBytes"), T("bitwise"),
}

// HexRegexes flag hex-encoded strings, char arrays, XOR and custom decrypt code.
var HexRegexes = []*regexp.Regexp{
	mustRe(`"[0-9a-fA-F]{16,}"`),
	mustRe(`0x[0-9a-fA-F]{2}(,\s*0x[0-9a-fA-F]{2}){7,}`),
	mustRe(`(?i)(?:private|public|protected|static|final)?\s*\w[\w<>\[\].]*\s+(?:decrypt|deobfuscate|deob|obfuscate|xorDecode|stringFromBytes|decodeString|decryptString)\s*\(`),
	mustRe(`\b0x[0-9a-fA-F]+\s*\^|\^\s*0x[0-9a-fA-F]+`),
	mustRe(`(?i)(?:new\s+byte\[\]|newByteArray|byte\[\])\s*\{[^}]{8,}`),
	mustRe(`(?i)SE_KEY|0x42\s*\^|\^\s*0x42`),
	mustRe(`(?i)charCodeAt|fromCharCode|charAt\s*\(\s*0\)`),
	mustRe(`(?i)Base64\.(decode|encode|decodeToString|encodeToString)`),
	mustRe(`\(char\)\s*\d+`),
	mustRe(`(?i)new\s+StringBuilder.*append\([^)]*\.charAt`),
}

// NativeSuspectLibs are .so basenames known to be security/detection payloads
// (from the snitchtt project in this repo, plus common hook/root payload libs).
var NativeSuspectLibs = []string{
	"libsnitchtt", "libsnitch", "libsna", "libsnb",
	"libdevice_trust", "libdevicetrust",
	"libzygisk", "libfrida", "frida-agent", "libgadget", "libfrida-gadget",
	"libwhale", "libshadowhook", "libdobby", "libsubstrate", "libpine",
	"libriru", "liblsplant", "libsandhook",
	// Packers / commercial hardening wrappers
	"libjiagu", "libSecShell", "libsecexe", "libbaiduprotect", "libtencent_stub",
	"libshell", "libDexProtector", "libexecmain", "libexec", "bangcleclasses",
}

// DetectionEvidenceRegexes pull the actual detection calls out of a class
// source so a report shows what exactly is checked.
var DetectionEvidenceRegexes = []*regexp.Regexp{
	mustRe(`(?i)(isRooted|checkRoot|hasRootAccess|isDeviceRooted|checkRootAccess|checkForRoot)\s*\(`),
	mustRe(`(?i)(isEmulator|isRunningOnEmulator|isEmulatorDetected|isEmulatorBuild)\s*\(`),
	mustRe(`(?i)(isDebuggerConnected|Debug\.isDebuggerConnected|TracerPid|ptrace|isBeingDebugged)\s*\(`),
	mustRe(`(?i)(detectFrida|isFrida|isFridaRunning|isFridaDetected|fridaDetected|checkFrida)\s*\(`),
	mustRe(`(?i)(checkIntegrity|verifySignatures|attestation|IntegrityManager|PlayIntegrity)\s*\(`),
	mustRe(`(?i)(isHook|isHookDetected|xposed|lsposed|zygisk|magisk|rootbeer|talsec)\s*\(`),
	mustRe(`(?i)on(Debugger|Hook|Tamper|Emulator|Frida|Root|Malware|ScreenRecording|Screenshot|Automation|LocationSpoofing|TimeSpoofing|UnsecureWifi|UntrustedInstallation)Detected\s*\(`),
	// cpp/ native check functions called from Java
	mustRe(`(?i)(nativeScanMaps|nativeDetectFrida|nativeScanPort|nativeCheckRoot|nativeCheckMounts|nativeCheckPlt|nativeCheckStack|nativeCheckFd|nativeCheckEnv|nativeCheckThreads|nativeCheckLsposed|nativeCheckLateInject|nativeCheckAdbNative|nativeCheckBuildNative|nativeCheckTiming|collectNativeSignals)\s*\(`),
	mustRe(`(?i)(check_magisk_data|check_su_binary|check_mountinfo_magisk|check_init_mountinfo|check_magisk_unix_socket|check_apatch|check_zygisk|check_selinux_permissive|check_gadget_symbol|check_gadget_listener|check_lsposed_socket|is_ssl_write_hooked|is_ssl_read_hooked|is_libc_open_hooked|scan_frida_ports|has_frida_threads|stack_has_frida_frame|fd_has_frida_memfd)\s*\(`),
	mustRe(`(?i)(snitchtt_early_scan|monitor_thread|call_sna|call_snb|reregister_natives|caller_is_system)`),
	mustRe(`(?i)__system_property_get\s*\(`),
	mustRe(`(?i)(TracerPid|/proc/self/(maps|status|mounts|mountinfo|net/tcp|net/unix|fd|task))`),
}
