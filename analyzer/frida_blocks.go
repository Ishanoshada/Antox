package analyzer

// Generated-script templates. The generic blocks below are framework-level
// bypasses valid on any app (validated against the s8.js reference base), and
// the app-specific blocks are composed at generation time from the discovered
// hook targets. Block order in buildFridaScript mirrors s8.js.
//
// Placeholders:
//   @@CLASS@@   -> the class name to hook
//   @@METHODS@@ -> a JS array of method names
//   @@HELPER@@  -> hookVoid or hookReturnsFalse (defined in the header)

// fridaHeader opens Java.perform and defines the hook helpers the
// app-specific blocks use.
const fridaHeader = `Java.perform(function () {
    console.log("[ANTOX-HOOK] ========================================");
    console.log("[ANTOX-HOOK] antox fridahook bypass script");
    console.log("[ANTOX-HOOK] ========================================");

    // No-op every overload of a void method on a class (existence-guarded).
    function hookVoid(className, methodName, tag) {
        try {
            var cls = Java.use(className);
            if (!cls[methodName]) return;
            cls[methodName].overloads.forEach(function (ov) {
                ov.implementation = function () {
                    console.log("[" + tag + "] blocked " + methodName + "()");
                };
            });
        } catch (e) {}
    }

    // Make every overload of a boolean method return false.
    function hookReturnsFalse(className, methodName, tag) {
        try {
            var cls = Java.use(className);
            if (!cls[methodName]) return;
            cls[methodName].overloads.forEach(function (ov) {
                ov.implementation = function () {
                    console.log("[" + tag + "] " + methodName + "() -> false");
                    return false;
                };
            });
        } catch (e) {}
    }
`

// fridaFooter closes the Java.perform block and prints the completion banner.
const fridaFooter = `
    console.log("");
    console.log("[ANZLE-HOOK] ========================================");
    console.log("[ANZLE-HOOK] " + String.fromCharCode(0x2713) + " bypass script loaded");
    console.log("[ANZLE-HOOK] ========================================");
});
`

// fridaBlockTalsecCallbacks no-ops every RASP callback on a discovered
// ThreatDetected implementation (e.g. K0.h). Unlisted callbacks are harmless:
// hookVoid is existence-guarded.
const fridaBlockTalsecCallbacks = `
    // @@CLASS@@ implements ThreatListener.ThreatDetected (RASP callbacks).
    var RASP_CB = [
        "onRootDetected", "onEmulatorDetected", "onDebuggerDetected",
        "onHookDetected", "onTamperDetected", "onAutomationDetected",
        "onMultiInstanceDetected", "onObfuscationIssuesDetected",
        "onDeviceBindingDetected", "onLocationSpoofingDetected",
        "onTimeSpoofingDetected", "onScreenRecordingDetected",
        "onScreenshotDetected", "onUnsecureWifiDetected",
        "onUntrustedInstallationSourceDetected", "onSystemVPNDetected",
        "onADBEnabledDetected", "onMalwareDetected"
    ];
    RASP_CB.forEach(function (m) { hookVoid("@@CLASS@@", m, "RASP"); });
`

// fridaBlockNoop neutralizes a discovered detection entry-point class: every
// listed method is no-op'd (void) or made to return false (boolean).
// @@METHODS@@ already includes the surrounding [ ] brackets (fridaMethodList).
const fridaBlockNoop = `
    // @@CLASS@@ - app-specific detection entry points -> neutralized.
    var M = @@METHODS@@;
    M.forEach(function (m) { @@HELPER@@("@@CLASS@@", m, "APP"); });
`

// fridaBlockPorts blocks Frida's default TCP ports on ServerSocket/Socket.
const fridaBlockPorts = `
    // Frida default ports (27042-27050) - never bind/connect.
    try {
        var ServerSocket = Java.use("java.net.ServerSocket");
        var Socket = Java.use("java.net.Socket");
        var FRIDA_PORTS = [27042, 27043, 27044, 27045, 27046, 27047, 27048, 27049, 27050];

        function portOf(ep) {
            if (!ep || !ep.toString) return -1;
            var s = ep.toString();
            var m = s.match(/:(\d+)$/);
            return m ? parseInt(m[1]) : -1;
        }

        try {
            ServerSocket.$init.overload('int').implementation = function (port) {
                if (FRIDA_PORTS.indexOf(port) !== -1) {
                    console.log("[ANZLE-PORT] ServerSocket(" + port + ") -> ephemeral");
                    port = 0;
                }
                return this.$init(port);
            };
        } catch (e) {}

        try {
            Socket.connect.overload('java.net.SocketAddress').implementation = function (endpoint) {
                var port = portOf(endpoint);
                if (port !== -1 && FRIDA_PORTS.indexOf(port) !== -1) {
                    console.log("[ANZLE-PORT] blocked Socket.connect -> " + port);
                    return;
                }
                return this.connect(endpoint);
            };
        } catch (e) {}
        console.log("[ANZLE-HOOK] port bypass active");
    } catch (e) {}
`

// fridaBlockNetstat fakes Runtime.exec output for netstat and blocks su /
// busybox / magisk commands.
const fridaBlockNetstat = `
    // Runtime.exec: fake netstat, block su/busybox/magisk.
    try {
        var Runtime = Java.use("java.lang.Runtime");
        var ByteArrayInputStream = Java.use("java.io.ByteArrayInputStream");
        var fakeProcess = function (output) {
            var bytes = [];
            for (var i = 0; i < output.length; i++) bytes.push(output.charCodeAt(i));
            var Process = Java.use("java.lang.Process");
            var p = Process.$new();
            p.getInputStream.implementation = function () { return ByteArrayInputStream.$new(Java.array('byte', bytes)); };
            p.getErrorStream.implementation = function () { return ByteArrayInputStream.$new(Java.array('byte', [])); };
            p.waitFor.overload().implementation = function () { return 0; };
            p.exitValue.implementation = function () { return 0; };
            p.destroy.implementation = function () {};
            return p;
        };
        try {
            Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmds) {
                var cmd = cmds.join(" ");
                if (cmd.indexOf("netstat") !== -1) {
                    return fakeProcess("tcp        0      0 0.0.0.0:5555            0.0.0.0:*               LISTEN\n");
                }
                var blocked = ["su", "which su", "busybox", "magisk", "ps -A", "ps -e"];
                for (var i = 0; i < blocked.length; i++) {
                    if (cmd.indexOf(blocked[i]) !== -1) {
                        console.log("[ANZLE-CMD] blocked: " + cmd);
                        return fakeProcess("");
                    }
                }
                return this.exec(cmds);
            };
        } catch (e) {}
        try {
            Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
                if (cmd.indexOf("netstat") !== -1) {
                    return fakeProcess("tcp        0      0 0.0.0.0:5555            0.0.0.0:*               LISTEN\n");
                }
                return this.exec(cmd);
            };
        } catch (e) {}
        console.log("[ANZLE-HOOK] netstat/exec bypass active");
    } catch (e) {}
`

// fridaBlockDevMode forces development_settings_enabled to 0.
const fridaBlockDevMode = `
    // Developer-mode detection -> disabled.
    try {
        var Settings = Java.use("android.provider.Settings$Global");
        var Secure = Java.use("android.provider.Settings$Secure");
        var blockDev = function (cls) {
            try {
                cls.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (r, name) {
                    if (name === "development_settings_enabled") { console.log("[ANZLE-DEV] dev mode -> 0"); return 0; }
                    return this.getInt(r, name);
                };
            } catch (e) {}
            try {
                cls.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function (r, name, d) {
                    if (name === "development_settings_enabled") { console.log("[ANZLE-DEV] dev mode -> 0"); return 0; }
                    return this.getInt(r, name, d);
                };
            } catch (e) {}
        };
        blockDev(Settings);
        blockDev(Secure);
    } catch (e) {}
`

// fridaBlockEmulator spoofs Build properties and telephony identifiers.
const fridaBlockEmulator = `
    // Emulator detection -> spoof a real device.
    try {
        var Build = Java.use("android.os.Build");
        var spoof = {
            BRAND: "samsung", DEVICE: "beyond1", MODEL: "SM-G973F", PRODUCT: "beyond1lte",
            MANUFACTURER: "samsung", HARDWARE: "qcom", BOOTLOADER: "G973FXXU3ASG8",
            FINGERPRINT: "samsung/beyond1lte/beyond1:10/QP1A.190711.020/G973FXXU3ASG8:user/release-keys",
            TAGS: "release-keys", TYPE: "user", SERIAL: "R3CN8JTMV3K"
        };
        Object.keys(spoof).forEach(function (k) {
            try { Build[k].value = spoof[k]; } catch (e) {}
        });
        var TelephonyManager = Java.use("android.telephony.TelephonyManager");
        try { TelephonyManager.getNetworkOperatorName.implementation = function () { return "T-Mobile"; }; } catch (e) {}
        try { TelephonyManager.getSimOperatorName.implementation = function () { return "T-Mobile"; }; } catch (e) {}
        try { TelephonyManager.getDeviceId.implementation = function () { return "123456789012345"; }; } catch (e) {}
        try { TelephonyManager.getSubscriberId.implementation = function () { return "123456789012345"; }; } catch (e) {}
        try { TelephonyManager.getLine1Number.implementation = function () { return "+1234567890"; }; } catch (e) {}
    } catch (e) {}
`

// fridaBlockHookingDetect makes common isFridaRunning/detectFrida methods
// return false.
const fridaBlockHookingDetect = `
    // Hooking-detection helpers -> false.
    try {
        var detect = ["isFridaRunning", "detectFrida", "isHooked", "checkForFrida", "hasFrida", "fridaDetected", "isXposedInstalled", "hasXposed", "xposedDetected", "detectXposed", "detectMagisk", "isMagiskInstalled"];
        var Debug = Java.use("android.os.Debug");
        detect.forEach(function (m) {
            try {
                if (Debug[m]) {
                    Debug[m].implementation = function () { console.log("[ANZLE-HOOK] " + m + " -> false"); return false; };
                }
            } catch (e) {}
        });
    } catch (e) {}
`

// fridaBlockFiles makes File.exists hide frida agent paths and root paths.
const fridaBlockFiles = `
    // File.exists: hide frida/root paths.
    try {
        var File = Java.use("java.io.File");
        var fridaFiles = ["/data/local/tmp/frida-server", "/data/local/tmp/frida", "/data/local/tmp/re.frida.server", "/data/local/tmp/mytools", "/data/local/tmp/linjector", "/data/local/tmp/agent.so", "/data/local/tmp/hook.so"];
        var rootPaths = ["/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/app/Superuser.apk", "/system/xbin/daemonsu", "/vendor/bin/su", "/data/local/tmp/magisk", "/sbin/magisk", "/system/bin/failsafe/su", "/data/local/su", "/su/bin/su", "/data/adb/magisk", "/data/adb/modules", "/data/adb/lspd"];
        File.exists.implementation = function () {
            var path = this.getAbsolutePath();
            if (path) {
                for (var i = 0; i < fridaFiles.length; i++) {
                    if (path.indexOf(fridaFiles[i]) !== -1) { console.log("[ANZLE-FILE] hidden: " + path); return false; }
                }
                for (var j = 0; j < rootPaths.length; j++) {
                    if (path.indexOf(rootPaths[j]) !== -1) { console.log("[ANZLE-FILE] hidden root: " + path); return false; }
                }
            }
            return this.exists();
        };
    } catch (e) {}
`

// fridaBlockProcess filters /proc and ps output: TracerPid, zygote, frida.
const fridaBlockProcess = `
    // BufferedReader.readLine: hide TracerPid / zygote / frida processes.
    try {
        var BufferedReader = Java.use("java.io.BufferedReader");
        BufferedReader.readLine.implementation = function () {
            var line = this.readLine();
            if (!line) return line;
            var procs = ["frida", "frida-server", "frida-helper", "gmain", "gdbus", "gum-js", "pool-frida", "linjector", "mytools"];
            for (var i = 0; i < procs.length; i++) {
                if (line.indexOf(procs[i]) !== -1) {
                    console.log("[ANZLE-PROC] filtered: " + line);
                    return this.readLine();
                }
            }
            if (line.indexOf("TracerPid:") !== -1) {
                console.log("[ANZLE-PROC] TracerPid hidden");
                return "TracerPid:\t0";
            }
            if (line.indexOf("zygote") !== -1) {
                return "u:r:untrusted_app:s0:c7,c257,c512,c768";
            }
            return line;
        };
    } catch (e) {}
`

// fridaBlockRootLibs neutralizes known root-check libraries.
const fridaBlockRootLibs = `
    // Root-check helper libraries -> isRooted() false.
    try {
        var rootLibs = [
            "com.stericson.rootTools.RootTools",
            "com.scottyab.rootbeer.RootBeer",
            "eu.chainfire.supersu.SuperSU",
            "com.topjohnwu.magisk.utils",
            "com.joeykrim.rootcheck.RootCheck",
            "com.anttek.rootchecker.RootChecker"
        ];
        var rootMethods = ["isRooted", "isRootAvailable", "isMagiskInstalled", "detectRoot", "checkForSu", "hasSu", "isDeviceRooted"];
        rootLibs.forEach(function (lib) {
            try {
                var cls = Java.use(lib);
                rootMethods.forEach(function (m) {
                    try {
                        if (cls[m]) {
                            cls[m].implementation = function () { console.log("[ANZLE-ROOT] " + lib + "." + m + " -> false"); return false; };
                        }
                    } catch (e) {}
                });
            } catch (e) {}
        });
    } catch (e) {}
`

// fridaBlockSSL bypasses certificate validation and pinning.
const fridaBlockSSL = `
    // SSL pinning / certificate validation bypass.
    try {
        var arrayList = Java.use("java.util.ArrayList");
        try {
            var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
            if (TrustManagerImpl.checkTrustedRecursive) {
                TrustManagerImpl.checkTrustedRecursive.implementation = function () {
                    console.log("[ANZLE-SSL] TrustManagerImpl.checkTrustedRecursive bypassed");
                    return arrayList.$new();
                };
            }
        } catch (e) {}
        try {
            var okhttp3 = Java.use("okhttp3.CertificatePinner");
            if (okhttp3.check) {
                okhttp3.check.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
                    console.log("[ANZLE-SSL] okhttp3.CertificatePinner bypassed");
                    return;
                };
            }
        } catch (e) {}
        try {
            var WebViewClient = Java.use("android.webkit.WebViewClient");
            WebViewClient.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function (v, h, e) {
                console.log("[ANZLE-SSL] WebViewClient.onReceivedSslError proceed");
                h.proceed();
            };
        } catch (e) {}
    } catch (e) {}
`

// fridaBlockDebugger makes debugger-detection return false.
const fridaBlockDebugger = `
    // Debugger detection -> false.
    hookReturnsFalse("android.os.Debug", "isDebuggerConnected", "DEBUG");
    hookReturnsFalse("android.os.Debug", "waitingForDebugger", "DEBUG");
    try {
        var Process = Java.use("android.os.Process");
        try { Process.isDebuggerConnected.implementation = function () { return false; }; } catch (e) {}
    } catch (e) {}
`

// fridaBlockProps forces safe system-property values.
const fridaBlockProps = `
    // System properties -> safe values (debuggable, magisk, qemu, ...).
    try {
        var SystemProperties = Java.use("android.os.SystemProperties");
        var props = {
            "ro.debuggable": "0",
            "ro.secure": "1",
            "ro.build.tags": "release-keys",
            "ro.build.type": "user",
            "ro.kernel.qemu": "0",
            "ro.boot.verifiedbootstate": "green",
            "ro.boot.flash.locked": "1",
            "ro.boot.vbmeta.device_state": "locked",
            "ro.boot.veritymode": "enforcing",
            "ro.boot.secureboot": "1",
            "init.svc.magisk": "stopped",
            "service.adb.root": "0",
            "ro.sys.safemode": "0"
        };
        SystemProperties.get.overload('java.lang.String').implementation = function (key) {
            if (props.hasOwnProperty(key)) { console.log("[ANZLE-PROP] " + key + " -> " + props[key]); return props[key]; }
            if (key && (key.indexOf("frida") !== -1 || key.indexOf("gum") !== -1 || key.indexOf("linjector") !== -1 || key.indexOf("talsec") !== -1)) {
                return "";
            }
            return this.get(key);
        };
    } catch (e) {}
`

// fridaBlockPackages hides root/hook packages and fakes the installer.
const fridaBlockPackages = `
    // PackageManager: hide root/hook packages, fake installer.
    try {
        var PackageManager = Java.use("android.app.ApplicationPackageManager");
        var rootPkgs = ["com.koushikdutta.superuser", "eu.chainfire.supersu", "com.topjohnwu.magisk", "com.scottyab.rootbeer", "com.stericson.roottools", "com.joeykrim.rootcheck", "com.kingroot.kinguser", "com.kingo.root", "com.mgyun.root", "de.robv.android.xposed", "org.lsposed.manager"];
        PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkg, flags) {
            if (rootPkgs.indexOf(pkg) !== -1) {
                console.log("[ANZLE-PKG] hidden: " + pkg);
                var NameNotFoundException = Java.use("android.content.pm.PackageManager$NameNotFoundException");
                throw NameNotFoundException.$new(pkg);
            }
            return this.getPackageInfo(pkg, flags);
        };
        try {
            PackageManager.getInstallerPackageName.implementation = function (pkg) {
                return "com.android.vending";
            };
        } catch (e) {}
    } catch (e) {}
`

// fridaBlockSelfProtection hides frida/agent/rasp system properties.
const fridaBlockSelfProtection = `
    // System.getProperty: hide frida/agent/rasp properties.
    try {
        var System = Java.use("java.lang.System");
        System.getProperty.overload('java.lang.String').implementation = function (key) {
            if (key && (key.indexOf("frida") !== -1 || key.indexOf("gum") !== -1 || key.indexOf("agent") !== -1 || key.indexOf("linjector") !== -1 || key.indexOf("talsec") !== -1 || key.indexOf("rasp") !== -1)) {
                return null;
            }
            return this.getProperty(key);
        };
    } catch (e) {}
`

// fridaBlockThreads renames frida worker threads.
const fridaBlockThreads = `
    // Thread names: hide frida worker threads.
    try {
        var Thread = Java.use("java.lang.Thread");
        Thread.$init.overload('java.lang.ThreadGroup', 'java.lang.Runnable', 'java.lang.String', 'long').implementation = function (group, runnable, name, stackSize) {
            if (name) {
                var hidden = ["gmain", "gdbus", "gum-js", "pool-frida", "linjector", "frida", "gum"];
                for (var i = 0; i < hidden.length; i++) {
                    if (name.indexOf(hidden[i]) !== -1) { name = "Thread-" + Math.floor(Math.random() * 1000); break; }
                }
            }
            return this.$init(group, runnable, name, stackSize);
        };
    } catch (e) {}
`

// fridaBlockVPN makes isVpn return false.
const fridaBlockVPN = `
    // VPN detection -> false.
    try {
        var NetworkInfo = Java.use("android.net.NetworkInfo");
        try { NetworkInfo.isVpn.implementation = function () { return false; }; } catch (e) {}
    } catch (e) {}
`

// fridaBlockScreen blocks screen-capture intent.
const fridaBlockScreen = `
    // Screen capture -> blocked.
    try {
        var MediaProjectionManager = Java.use("android.media.projection.MediaProjectionManager");
        try { MediaProjectionManager.createScreenCaptureIntent.implementation = function () { return null; }; } catch (e) {}
    } catch (e) {}
`

// fridaBlockADB forces adb_enabled / development_settings_enabled to 0.
const fridaBlockADB = `
    // ADB / USB debugging -> disabled.
    try {
        var Settings = Java.use("android.provider.Settings$Global");
        Settings.getString.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (resolver, name) {
            if (name === "adb_enabled") { console.log("[ANZLE-ADB] adb_enabled -> 0"); return "0"; }
            if (name === "development_settings_enabled") { console.log("[ANZLE-ADB] dev settings -> 0"); return "0"; }
            return this.getString(resolver, name);
        };
    } catch (e) {}
`
