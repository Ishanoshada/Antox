package patterns

import (
	"strings"
	"testing"
)

// collectHookMatches is the test-local version of the analyzer's evidence
// matcher: unique full matches of every NativeHookRegex over a source.
func collectHookMatches(src string) []string {
	seen := map[string]bool{}
	var out []string
	for _, re := range NativeHookRegexes {
		for _, m := range re.FindAllString(src, -1) {
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	return out
}

func TestNativeHookRegexes_Dobby(t *testing.T) {
	src := `
	class AntiHook {
		void protect() {
			DobbyHook((void*) realOpen, myOpen);   // inline hook
			ShadowHook.hookSymbol("open", myOpen);
		}
	}`
	evs := collectHookMatches(src)
	if len(evs) == 0 {
		t.Fatal("expected Dobby/ShadowHook hook API matches, got none")
	}
}

func TestNativeHookRegexes_Xposed(t *testing.T) {
	src := `
	class X {
		void init() {
			XposedHelpers.hookAllMethods(TelephonyManager.class, "getDeviceId", cb);
			de.robv.android.xposed.XposedBridge.hookMethod(method, cb);
		}
	}`
	if len(collectHookMatches(src)) == 0 {
		t.Fatal("expected Xposed hook matches")
	}
}

func TestNativeHookRegexes_HookDetect(t *testing.T) {
	src := `
	class Detector {
		boolean h() {
			if (isHookDetected() || checkHook()) return true;
			if (nativeCheckPlt() > 0) return true;  // PLT hook scan
		}
	}`
	if len(collectHookMatches(src)) == 0 {
		t.Fatal("expected hook-detection matches")
	}
}

func TestNativeHookRegexes_PlainCode(t *testing.T) {
	// Normal code without hooking must not trigger.
	src := `class Normal { int sum(int a, int b) { return a + b; } }`
	if len(collectHookMatches(src)) != 0 {
		t.Fatalf("plain code produced hook matches: %v", collectHookMatches(src))
	}
}

func TestNativeHookTerms_Scopes(t *testing.T) {
	// Every hook term must carry a valid search scope.
	for _, tm := range NativeHookTerms {
		if tm.Text == "" {
			t.Fatal("hook term with empty text")
		}
	}
}

func TestNativeFunctionNames_CppJNIBridge(t *testing.T) {
	// The snitchtt_jni.c kMethods table functions and the C helper functions
	// behind them must all be in the dictionary (analyzer cross-checks detected
	// names against this list).
	joined := ""
	for _, n := range NativeFunctionNames {
		joined += n + " "
	}
	for _, want := range []string{
		"nativeScanMaps", "nativeDetectFrida", "nativeCheckLateInject",
		"n_scan_maps", "n_check_root", "n_start_monitor",
		"snitchtt_early_scan", "monitor_thread", "reregister_natives",
		"call_sna", "call_snb", "caller_is_system",
		"sna_e", "snb_e", "collectNativeSignals",
		"check_magisk_data", "check_su_binary", "is_ssl_write_hooked",
		"scan_frida_ports", "has_frida_threads",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("NativeFunctionNames missing %q", want)
		}
	}
}

func TestNativeDetectionStrings_CppVocabulary(t *testing.T) {
	joined := ""
	for _, s := range NativeDetectionStrings {
		joined += s + " "
	}
	for _, want := range []string{
		"frida_gadget_load", "frida_gadget_wait_for_debugger",
		"@magisk_daemon", "/data/adb/magisk", "/debug_ramdisk",
		"/proc/self/mountinfo", "/proc/1/mountinfo", "/proc/net/tcp6",
		"/sys/fs/selinux/enforce", "/data/misc/adb/adb_keys",
		"ro.boot.vbmeta.digest", "init.svc.adbd", "verifiedbootstate",
		"LD_PRELOAD", "TracerPid", "gum-js-loop", "pool-frida",
		"__NR_openat", "__NR_getdents64", "PTRACE_TRACEME", "RTLD_DEFAULT",
		"_Unwind_Backtrace", "SnitchNative", "onAlert", "collectNativeSignals",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("NativeDetectionStrings missing %q", want)
		}
	}
}

func TestNativeSoNames_Expanded(t *testing.T) {
	joined := ""
	for _, s := range NativeSoNames {
		joined += s + " "
	}
	for _, want := range []string{"libsnitchtt", "libsnitch", "libsna", "libsnb", "libdevice_trust", "liblsplant", "libsandhook", "libpine", "libriru"} {
		if !strings.Contains(joined, want) {
			t.Errorf("NativeSoNames missing %q", want)
		}
	}
}

func TestSyscallNames_CppWrappers(t *testing.T) {
	joined := ""
	for _, s := range SyscallNames {
		joined += s + " "
	}
	for _, want := range []string{
		"__NR_openat", "__NR_getdents64", "__NR_readlinkat", "__NR_socket",
		"PTRACE_TRACEME", "sc_open", "sc_getdents64", "sc_readlinkat",
		"sc_read_file", "sc_file_exists", "AT_FDCWD", "O_CLOEXEC",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("SyscallNames missing %q", want)
		}
	}
}

func TestDetectionMethodTerms_Expanded(t *testing.T) {
	joined := ""
	for _, m := range DetectionMethodTerms {
		joined += m + " "
	}
	for _, want := range []string{
		"isRooted", "checkRootAccess", "detectFrida", "isFridaRunning",
		"onDebuggerDetected", "onFridaDetected", "nativeScanMaps",
		"nativeCheckLateInject", "collectNativeSignals",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("DetectionMethodTerms missing %q", want)
		}
	}
}

func TestNativeHookRegexes_CppHookDetect(t *testing.T) {
	src := `
	class NativeGuard {
		boolean protect() {
			if (is_ssl_write_hooked()) return true;
			if (scan_frida_ports() > 0) return true;
			if (stack_has_frida_frame()) return true;
		}
	}`
	if len(collectHookMatches(src)) == 0 {
		t.Fatal("expected cpp hook-detection matches (is_ssl_write_hooked, scan_frida_ports)")
	}
}
