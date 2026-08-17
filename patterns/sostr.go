package patterns

import "strings"

// SoScanKeywords mirrors the keyword list in the reference python scanner
// (t.py: KEYWORDS_TO_SCAN) that sweeps packaged .so files for hook / root /
// anti-debug detection strings. Extended with the cpp-derived detection
// dictionary from native.go so one sweep covers both sources.
var SoScanKeywords = []string{
	// t.py keywords
	"hook", "detected", "frida", "xposed", "root",
	"tamper", "integrity", "bypass", "ptrace", "debugger",
	// cpp/snitchtt + hook-framework extensions
	"magisk", "zygisk", "lsposed", "substrate", "dobby",
	"shadowhook", "whale", "gadget", "emulator", "memfd",
	"preload", "tracerpid", "tampered",
	// RASP / hardening / attestation / device-intel SDKs (see sdks.go)
	"talsec", "aheaditec", "appsealing", "appdome", "promon",
	"dexguard", "guardsquare", "secneo", "zimperium", "arxan",
	"verimatrix", "crowdstrike", "norton", "onespan", "nowsecure",
	"threatmetrix", "trustkit", "siftscience", "attestation",
	"playintegrity", "safetynet", "onhookdetected", "ontamperdetected",
	"isdebuggerconnected", "rasp",
	// cpp/ full native detection vocabulary (str_enc.h tables, /proc scans,
	// system properties, thread names, direct syscall wrappers)
	"frida-agent", "frida-helper", "frida-zymbiote", "frida_gadget_load",
	"frida_gadget_wait_for_debugger", "gum_interceptor_obtain",
	"gum_init_embedded", "gum-js", "gum-js-loop", "gum_js", "gum",
	"pool-frida", "gdbus", "gmain", "linjector", "libfrida-agent",
	"libgadget", "frida-gadget", "jit-cache", "rwxp", "zymbiote",
	"edxposed", "zygisknext", "libzygisk", "lspd", "pine", "libwhale",
	// root / hiding modules
	"magisk_daemon", "apatch", "shamiko", "hidemyapplist", "busybox",
	"sbin", "xbin", "debug_ramdisk", "su_binary", "selinux", "enforce",
	"permissive", "rootcloak", "hideroot",
	// /proc filesystem paths
	"proc", "cmdline", "comm", "mounts", "mountinfo", "maps", "status",
	"task", "fd", "tcp6", "net/tcp", "net/unix", "socket", "unix",
	// anti-debug / syscall
	"PTRACE_TRACEME", "tracepid", "tracer", "waitfordebugger", "syscall",
	"getdents64", "readlinkat", "openat", "gdb",
	// system properties / build state
	"ro.debuggable", "ro.secure", "ro.build.type", "ro.build.tags",
	"ro.boot.vbmeta", "ro.boot.verifiedbootstate", "init.svc.adbd",
	"test-keys", "userdebug", "eng", "bootloader", "verifiedbootstate",
	"vbmeta", "orange", "yellow",
	// adb
	"adb", "adbd", "adb_keys", "adb_port",
	// ssl / native crypto hooks
	"ssl_write", "ssl_read", "conscrypt", "tmpfs", "cacerts", "libc",
	// JNI / native layer
	"jnionload", "registernatives", "dlopen", "dlsym", "dladdr",
	"rtld_default", "getenv", "newglobalref",
	// snitchtt / DeviceTrust
	"snitchtt", "snitch", "snitchative", "sna_e", "snb_e", "devicetrust",
	"collectnativesignals", "threatlistener", "onalert",
	// frida-server / gadget system artifacts (master dict)
	"frida-server", "re.frida.server", "/tmp/frida-", "frida_agent_main",
	"gum_interceptor_replace", "gum_init", "27042", "27043", "27047",
	// anti-debug ptrace family
	"PTRACE_ATTACH", "PTRACE_DETACH", "wchan", "sys_ptrace", "tracerpid",
	// Flutter / Dart AOT framework
	"libapp.so", "libflutter.so", "flutter", "dart", "kernel_blob",
	"flutter_assets", "isolate_snapshot_data", "vm_snapshot_data",
	"Dart_Initialize", "dart:ui", "dart:io",
	// React Native / Hermes framework
	"libhermes.so", "libreactnativejni.so", "libfbjni.so", "libjsc.so",
	"index.android.bundle", "hermes", "reactnative", "jsi", "turbomodule",
	"catalyst", "jailmonkey",
	// Packers / commercial hardening wrappers
	"jiagu", "legu", "bangcle", "secshell", "dexshell", "baiduprotect",
	"tencent_stub", "dexprotector", "ijiami", "execmain", "stubapp",
	"proxyapplication", "applicationstub",
}

// SoScanRe is the case-insensitive filter applied to every string extracted
// from a .so. Reuses buildAnyRegex from native.go.
var SoScanRe = buildAnyRegex(SoScanKeywords)

// SoString is one printable string recovered from a section, with its virtual
// address. Mirrors one r2 `izj` entry.
type SoString struct {
	VAddr uint64
	Str   string
}

// ExtractSectionStrings recovers printable ASCII runs (>= minLen bytes) from a
// section's bytes, tagging each run with its virtual address (base + offset).
// This is the Go equivalent of r2's `izj` scan and, unlike a C-string scan, it
// also sees Dart AOT strings stored back-to-back without NUL terminators (the
// non-printable length/tag byte between them breaks the run).
func ExtractSectionStrings(data []byte, base uint64, minLen int) []SoString {
	if minLen < 1 {
		minLen = 1
	}
	var out []SoString
	start := -1
	for i := 0; i <= len(data); i++ {
		ok := i < len(data) && data[i] >= 0x20 && data[i] < 0x7f
		if ok {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			n := i - start
			if n >= minLen && n <= 4096 {
				out = append(out, SoString{VAddr: base + uint64(start), Str: string(data[start:i])})
			}
			start = -1
		}
	}
	return out
}

// MatchSoKeywords returns the SoScanKeywords present in text (case-insensitive),
// in dictionary order. Used to annotate a finding with which keywords fired.
func MatchSoKeywords(text string) []string {
	low := strings.ToLower(text)
	seen := map[string]bool{}
	var out []string
	for _, k := range SoScanKeywords {
		if !seen[k] && strings.Contains(low, strings.ToLower(k)) {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out
}

// Ref is one raw pointer found in the image that equals a string's vaddr.
type Ref struct {
	Offset  int64  // file offset of the reference slot
	Section string // owning section name
}

// SectionSpan is the file-offset range of one section, used to classify a
// reference slot by its owning section.
type SectionSpan struct {
	Name   string
	Offset uint64
	Size   uint64
}
