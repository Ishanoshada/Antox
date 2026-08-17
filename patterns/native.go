package patterns

import "regexp"

// Native detection dictionary distilled from the cpp/ folder in this repo
// (snitchtt native security library: libsna.so / libsnb.so / libsnitchtt.so).
//
// These are the identifiers, paths and strings a hardened app embeds to detect
// Frida / hook frameworks / root / LSPosed / ADB / tampered builds at the
// native layer, many of them XOR-0x42 encoded so they never appear as plain
// text in the .so.

// NativeFunctionNames are C functions and Java "native*" JNI methods from the
// detection layers (snitchtt_jni.c kMethods table, guard_entry.c, hunter_entry.c,
// the DeviceTrust C++ layer, and the per-check helpers in the module files).
var NativeFunctionNames = []string{
	// Java-side JNI methods (RegisterNatives table in snitchtt_jni.c)
	"nativeScanMaps", "nativeDetectFrida", "nativeScanPort", "nativeCheckMounts",
	"nativeCheckRoot", "nativeCheckPlt", "nativeCheckStack", "nativeCheckFd",
	"nativeCheckEnv", "nativeGetBaseline", "nativeCheckTiming", "nativeStartMonitor",
	"nativeCheckThreads", "nativeCheckLsposed", "nativeCheckLateInject",
	"nativeCheckAdbNative", "nativeCheckBuildNative",
	// JNI implementation function names behind the table above
	"n_scan_maps", "n_detect_frida", "n_scan_port", "n_check_mounts",
	"n_check_root", "n_check_plt", "n_check_stack", "n_check_fd",
	"n_check_env", "n_get_baseline", "n_check_timing", "n_start_monitor",
	"n_check_threads", "n_check_lsposed", "n_check_late_inject",
	"n_check_adb_native", "n_check_build_native",
	// JNI bridge plumbing (snitchtt_jni.c)
	"snitchtt_early_scan", "monitor_thread", "load_modules",
	"reregister_natives", "gen_key", "call_sna", "call_snb", "full_scan",
	"capture_own_base", "caller_is_system", "jni_ptrs_hijacked",
	"resolve_lib_dir", "check_late_inject",
	// C entry points (single-export detection libs)
	"sna_e", "snb_e",
	"root_check_native", "mount_check", "env_check", "lsposed_check",
	"adb_check_native", "build_check_native",
	"frida_detect", "maps_scan", "scan_frida_ports", "probe_frida_port",
	"stack_has_frida_frame", "fd_has_frida_memfd", "has_frida_threads",
	"timing_baseline", "timing_anomaly",
	// frida runtime entry points / c-symbols (public frida-gum surface)
	"frida_agent_main", "gum_interceptor_replace", "gum_init", "gum_init_embedded",
	"frida_agent_desc", "frida_get_device_manager",
	"check_su_binary", "check_magisk_data", "check_magisk_unix_socket",
	"check_mountinfo_magisk", "check_init_mountinfo", "check_busybox",
	"check_selinux_permissive", "check_apatch", "check_zygisk",
	"check_ld_preload", "check_tracer_via_ptrace", "read_tracer_pid",
	"check_zymbiote_socket", "check_gadget_listener", "check_gadget_symbol",
	"check_lsposed_socket", "scan_proc_for_lspd", "probe_dir",
	"is_ssl_write_hooked", "is_ssl_read_hooked", "is_libc_open_hooked",
	"sym_hooked", "prop_equals", "path_exists_syscall",
	"tcp6_has_listener", "frame_cb", "now_ns", "measure_one", "warmup",
	// DeviceTrust native signal collector (C++ layer)
	"collectNativeSignals", "analyzeProcMaps", "checkFdForFrida",
	"checkLibcSymbol", "parseNativeSignals",
}

// NativeDetectionStrings are the strings the native layer hunts for, decoded
// from the XOR-0x42 tables in str_enc.h. A hit means the app embeds a
// detection signal that only exists on tampered/hooked devices.
var NativeDetectionStrings = []string{
	// Frida agent / gadget / symbols
	"frida-agent-64.so", "frida-agent-32.so", "libfrida-agent-raw.so",
	"frida-helper", "frida-zymbiote", "frida_gadget_load",
	"frida_gadget_wait_for_debugger", "gum_interceptor_obtain",
	"gum_init_embedded", "gadget", "frida", "linjector", "libgadget",
	"libfrida-agent", "frida-agent", "gum-js", "gum_js",
	// Hook frameworks
	"libzygisk.so", "Dobby", "shadowhook", "whale.so", "xposed", "lsposed",
	"substrate", "edxposed", "XposedBridge", "zygisk", "zygisknext",
	"lspd", "Pine", "libwhale",
	// Root / magisk / apatch
	"magisk", "@magisk_daemon", "/data/adb/magisk", "/data/adb/modules",
	"/data/adb/lspd", "/data/adb/apatch", "/data/adb", "/debug_ramdisk", "/sbin",
	"busybox", "apatch", "shamiko", "hidemyapplist", "lspd",
	"/system/bin/su", "/system/xbin/su", "/system/sd/xbin/su",
	"/system/bin/failsafe/su", "/system/bin/", "/system/xbin/",
	// Runtime / proc paths
	"/proc/self/maps", "/proc/self/status", "/proc/self/mounts",
	"/proc/self/mountinfo", "/proc/1/mountinfo", "/proc/self/net/tcp",
	"/proc/self/net/unix", "/proc/self/fd", "/proc/self/task",
	"/proc/net/tcp6", "/proc/", "/proc", "/sys/fs/selinux/enforce",
	"/data/misc/adb/adb_keys", "/data/local/tmp", "/memfd:jit-cache",
	"rwxp", "(deleted)", "/dev/socket/lsposed", "cmdline", "comm",
	// Environment / system properties
	"LD_PRELOAD", "LD_LIBRARY_PATH", "TracerPid", "ptrace",
	"ro.debuggable", "ro.secure", "ro.build.type", "ro.build.tags",
	"ro.boot.vbmeta.digest", "ro.boot.verifiedbootstate", "init.svc.adbd",
	"test-keys", "userdebug", "eng", "conscrypt/cacerts", "tmpfs",
	"SSL_write", "SSL_read", "gdb", "adb_keys", "verifiedbootstate",
	"orange", "yellow", "CLOCK_MONOTONIC_RAW", "PROP_VALUE_MAX",
	"__system_property_get",
	// Direct-syscall / JNI plumbing
	"syscall", "__NR_openat", "__NR_getdents64", "__NR_readlinkat",
	"__NR_socket", "__NR_connect", "__NR_sendto", "__NR_recvfrom",
	"__NR_setsockopt", "AT_FDCWD", "O_CLOEXEC", "O_DIRECTORY",
	"PTRACE_TRACEME", "getdents64", "readlinkat", "openat",
	"dlopen", "dlsym", "dladdr", "Dl_info", "dli_fname", "dli_fbase",
	"RTLD_DEFAULT", "RTLD_LOCAL", "RTLD_NOW", "_Unwind_Backtrace",
	"_Unwind_GetIP", "SO_RCVTIMEO", "SO_SNDTIMEO", "JNI_OnLoad",
	"RegisterNatives", "GetStaticMethodID", "CallStaticVoidMethod",
	// snitchtt / DeviceTrust layer
	"sna_e", "snb_e", "Snitchtt", "SnitchNative", "onAlert",
	"collectNativeSignals", "DeviceTrustNative", "/apex/", "/system/lib",
	// Frida GLib worker thread names
	"gmain", "gum-js-loop", "pool-frida", "gdbus",
	// frida-server / gadget system paths and process names (master dict)
	"frida-server", "frida-helper", "re.frida.server", "/tmp/frida-",
	"/data/local/tmp/frida-server", "/data/local/tmp/re.frida.server",
	"frida_agent_main", "gum_interceptor_replace", "gum_init",
	// anti-debug: ptrace attach family + /proc wchan
	"PTRACE_ATTACH", "PTRACE_DETACH", "fork", "/proc/self/wchan", "sys_ptrace",
}

// NativeSoNames are .so basenames associated with security/detection payloads.
var NativeSoNames = []string{
	"libsnitchtt", "libsnitch", "libsna", "libsnb",
	"libdevice_trust", "libdevicetrust",
	"libzygisk", "libfrida", "frida-agent", "libgadget", "libfrida-gadget",
	"libwhale", "libshadowhook", "libdobby", "libsubstrate", "libpine",
	"liblsplant", "libsandhook", "libriru", "libriru", "libgum",
	"libts",     // Talsec / aheaditec native RASP library
	"libshella", // AppSealing
	"libkms",    // KMS / AppSealing companion
	"libappsealing", "libshield", "libnqshield", "libspark",
	// RASP / hardening / device-intel payload libraries
	"libpromon", "libsecneo", "libdexguard", "libappdome",
	"libzimperium", "libarxan", "libverimatrix", "libtrustkit",
	"libthreatmetrix", "libsift", "libcrowdstrike", "libfalcon",
	"libnorton", "libonespan", "libnowsecure", "libtalsec", "libplaycore",
	// Packers / commercial hardening wrappers (master dict)
	"libjiagu", "libjiagu_a64", "libjiagu_x86", "libSecShell", "libsecexe",
	"libbaiduprotect", "libtencent_stub", "libshell", "libDexProtector",
	"libexecmain", "libexec", "libhardening",
}

// FrameworkSoNames are .so basenames that identify the app's runtime engine
// (Flutter Dart AOT, React Native / Hermes, JavaScriptCore). These are legit
// app-type markers — unlike NativeSoNames they are NOT detection payloads, and
// are reported at info severity so a report can state "this is a Flutter app".
var FrameworkSoNames = []string{
	// Flutter / Dart AOT engine
	"libapp", "libflutter", "libflutter_x86", "libflutter_x86_64",
	// React Native / Hermes engines
	"libhermes", "libreactnativejni", "libfbjni", "libjsc", "libflipper",
}

// NativeHookTerms find hooking-framework classes and hook API call sites.
// "hook" is deliberately a broad code term so the whole APK is screened for
// inline hook frameworks (Dobby, ShadowHook), Xposed/LSPosed bridge APIs, and
// hook-detection methods; the evidence regexes below filter to real usage.
var NativeHookTerms = []Term{
	// framework / library class names
	C("Dobby"), C("ShadowHook"), C("Xposed"), C("XposedBridge"), C("XposedHelpers"),
	C("LSPosed"), C("lsposed"), C("edXposed"), C("edxposed"), C("CydiaSubstrate"),
	C("Substrate"), C("Zygisk"), C("zygisk"), C("Pine"), C("Whale"),
	C("LSPlant"), C("SandHook"), C("YAHFA"), C("Epic"),
	// hook API call sites (code scope)
	T("DobbyHook"), T("DobbyImport"), T("DobbySymbol"), T("shadowhook_hook"),
	T("shadowhookHooked"), T("hookMethod"), T("hookAllMethods"), T("hookAllConstructors"),
	T("hookInstanceMethod"), T("hookConstructor"), T("inlineHook"), T("inline_hook"),
	T("isHookDetected"), T("checkHook"), T("hookDetector"), T("onHookFridaDetected"),
	T("unhook"), T("hooked"), T("rehook"), T("hook("),
	// hook-detection helpers (cpp/ plt_check.c, env_check.c, hunter_entry.c)
	T("is_ssl_write_hooked"), T("is_ssl_read_hooked"), T("is_libc_open_hooked"),
	T("sym_hooked"), T("check_gadget_symbol"), T("check_gadget_listener"),
	T("check_lsposed_socket"), T("scan_proc_for_lspd"), T("has_frida_threads"),
	T("stack_has_frida_frame"), T("fd_has_frida_memfd"), T("probe_frida_port"),
	T("scan_frida_ports"), T("caller_is_system"), T("jni_ptrs_hijacked"),
	T("reregister_natives"), T("dlsym"), T("dladdr"),
}

// NativeHookRegexes flag hooking usage in a decompiled class: a hook API
// call, a framework import, or a hook-detection branch.
var NativeHookRegexes = []*regexp.Regexp{
	mustRe(`(?i)\bDobby(Hook|Import|Symbol|Patch)\b`),
	mustRe(`(?i)shadowhook[a-z0-9_]*\s*\(`),
	mustRe(`(?i)Xposed(Helpers|Bridge)?\s*\.\s*(hook|hookAll|hookMethod|hookAllMethods|hookAllConstructors)`),
	mustRe(`(?i)\.\s*(hookMethod|hookAllMethods|hookAllConstructors|hookInstanceMethod|hookConstructor|hookBefore|hookAfter)\s*\(`),
	mustRe(`(?i)(inlineHook|inline_hook|\.hooked\b|\.unhook\b|\.rehook\b|HookMethod)`),
	mustRe(`(?i)(isHookDetected|checkHook|onHookFridaDetected|onHookDetected|hookDetector|hookCheck)`),
	mustRe(`(?i)\b(plt|got)\s*hook|hook\s*(plt|got)`),
	mustRe(`(?i)substrate|XposedBridge|de\.robv\.android\.xposed`),
	mustRe(`(?i)\bPine\.(hook|hookMethod|hookAll)`),
	mustRe(`(?i)(is_ssl_write_hooked|is_ssl_read_hooked|is_libc_open_hooked|sym_hooked)\s*\(`),
	mustRe(`(?i)(check_gadget_symbol|check_gadget_listener|check_lsposed_socket|scan_proc_for_lspd|has_frida_threads|stack_has_frida_frame|fd_has_frida_memfd)\s*\(`),
	mustRe(`(?i)(probe_frida_port|scan_frida_ports|read_tracer_pid)\s*\(`),
	mustRe(`(?i)(caller_is_system|jni_ptrs_hijacked|reregister_natives)\s*\(`),
}

// FridaPorts are the TCP ports Frida's D-Bus/gadget typically listens on
// (scan_frida_ports fast path) plus the ADB server port.
var FridaPorts = []string{
	"27042", "27043", "4444", "1234", "8888", "9999",
	"1337", "7777", "31415", "8080", "8443", "11111",
	"5555", "6666", "2222", "54321", "12345", "5037",
}

// SyscallNames are the direct-syscall techniques used to bypass libc hooks.
// These are the Linux syscall numbers / wrapper names from syscall_utils.h.
var SyscallNames = []string{
	"syscall", "__NR_openat", "__NR_getdents64", "__NR_readlinkat",
	"__NR_read", "__NR_close", "__NR_socket", "__NR_connect", "__NR_sendto",
	"__NR_recvfrom", "__NR_setsockopt", "__NR_getpid",
	"PTRACE_TRACEME", "PTRACE_ATTACH", "PTRACE_DETACH", "ptrace", "fork",
	"getdents64", "openat", "readlinkat",
	"readlink", "sendto", "recvfrom", "setsockopt", "socket", "connect",
	"AT_FDCWD", "O_CLOEXEC", "O_DIRECTORY",
	// sc_* direct-syscall wrappers from syscall_utils.h
	"sc_open", "sc_read", "sc_close", "sc_socket", "sc_connect", "sc_send",
	"sc_recv", "sc_setsockopt", "sc_readlinkat", "sc_getdents64",
	"sc_read_file", "sc_file_exists",
}

// NativeTerms drives the native mode keyword search. Extended with the
// dlopen/dlsym/JNI family so the search finds native binder classes.
var NativeTerms = []Term{
	T("System.loadLibrary"), T("System.load"), T("loadLibrary"), T("JNI_OnLoad"),
	T("RegisterNatives"), T("jnigraphics"), T("static native"), T("native"),
	T("dlopen"), T("dlsym"), T("GetEnv"), T("NewGlobalRef"), T("GetStaticMethodID"),
}

// NativeRegexes extract .so names, native method declarations and JNI plumbing.
var NativeRegexes = []*regexp.Regexp{
	mustRe(`\blib[A-Za-z0-9_.\-]+\.so\b`),
	mustRe(`(?m)^\s*(?:public|private|protected|static|final|\s)*\bnative\s+[^;]*;`),
	mustRe(`(?i)JNI_OnLoad|RegisterNatives|GetEnv|NewGlobalRef`),
	mustRe(`\bsystem\.loadLibrary\s*\(\s*["'][^"']+["']`),
}

// JNIExportRe matches Java_<package>_<Class>_<method> JNI function names,
// which are the actual native function names baked into a .so's export table.
var JNIExportRe = mustRe(`Java_[A-Za-z0-9_]+`)

// RegisterNativesRe matches the string entries in a JNINativeMethod table.
var RegisterNativesRe = mustRe(`\{"?native[A-Za-z0-9_]+"?,`)

// NativeMethodRe matches a declared native method and captures its name.
var NativeMethodRe = mustRe(`(?m)\bnative\s+[A-Za-z0-9_<>\[\].]+\s+([A-Za-z0-9_]+)\s*\(`)

// DetectionMethodTerms extends the detection mode with the Java-side native
// method names from the snitchtt JNI table.
var DetectionMethodTerms = []string{
	// root detection
	"isRooted", "checkRoot", "isDeviceRooted", "hasRootAccess", "detectRoot",
	"checkForRoot", "isRootDetected", "checkRootAccess", "isRootedNative",
	"rootbeer", "isRootExploit", "checkMagisk", "checkSu",
	// emulator detection
	"isEmulator", "checkEmulator", "isEmulatorBuild", "isRunningOnEmulator",
	"isEmulatorDetected", "detectEmulator",
	// debugger / anti-debug
	"isDebuggerConnected", "detectDebugger", "isBeingDebugged",
	"checkForDebugger", "isDebuggerPresent", "antiDebug", "waitForDebugger",
	// frida / hook detection
	"detectFrida", "isFrida", "isFridaRunning", "isFridaDetected",
	"checkFrida", "checkIntegrity", "isHook", "isHookDetected", "checkHook",
	"detectHook", "isHookFramework", "checkForHooks",
	// integrity / signature / tamper
	"verifySignatures", "checkSignature", "verifySignature", "isAppSigned",
	"checkAppSignature", "checkTamper", "isTampered", "detectTamper",
	"isDebuggable",
	// RASP threat-callback methods (Talsec / Promon / AppSealing obfuscated impls
	// implement ThreatListener.ThreatDetected, so the method-name search finds
	// them even when the class itself is renamed to K0.h).
	"onDebuggerDetected", "onHookDetected", "onTamperDetected", "onEmulatorDetected",
	"onFridaDetected", "onRootDetected", "onMalwareDetected", "onScreenRecordingDetected",
	"onScreenshotDetected", "onAutomationDetected", "onLocationSpoofingDetected",
	"onTimeSpoofingDetected", "onUnsecureWifiDetected", "onUntrustedInstallationSourceDetected",
	"onDeviceBindingDetected", "onMultiInstanceDetected", "onPasscodeDetected",
	// native detection methods (snitchtt JNI table)
	"nativeScanMaps", "nativeDetectFrida", "nativeScanPort", "nativeCheckRoot",
	"nativeCheckMounts", "nativeCheckLsposed", "nativeCheckThreads", "nativeCheckFd",
	"nativeCheckStack", "nativeCheckEnv", "nativeCheckAdbNative",
	"nativeCheckBuildNative", "nativeCheckPlt", "nativeCheckTiming",
	"nativeCheckLateInject", "nativeGetBaseline", "nativeStartMonitor",
	"collectNativeSignals",
}

// DetectionNativeStringsRegex flags any of the native detection strings when
// they appear in decompiled code (string decryption, property lookups).
var DetectionNativeStringsRegex = buildAnyRegex(NativeDetectionStrings)

func buildAnyRegex(terms []string) *regexp.Regexp {
	// Join with |, escape regex metachars, case-insensitive.
	parts := make([]string, 0, len(terms))
	for _, t := range terms {
		parts = append(parts, regexp.QuoteMeta(t))
	}
	return mustRe("(?i)" + joinParts(parts))
}

func joinParts(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += "|"
		}
		out += p
	}
	return out
}
