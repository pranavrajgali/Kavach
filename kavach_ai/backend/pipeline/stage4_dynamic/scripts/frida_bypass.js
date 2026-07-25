/**
 * Frida Hook Script for Kavach.ai Sandbox Detonation Pipeline
 * Bypasses root detection checks and disables SSL pinning/TrustManagers.
 */

Java.perform(function () {
    console.log("[Kavach-Sandbox] Injecting bypass hooks...");

    // ==========================================
    // 1. ROOT DETECTION BYPASS
    // ==========================================
    
    // Bypass common file checks (like looking for su, busybox, etc.)
    const File = Java.use("java.io.File");
    File.exists.implementation = function () {
        const path = this.getAbsolutePath();
        if (path.includes("su") || 
            path.includes("busybox") || 
            path.includes("Superuser") || 
            path.includes("SuperSU") || 
            path.includes("bin/su") || 
            path.includes("xbin/su") || 
            path.includes("daemonsu") ||
            path.includes("/system/app/Superuser.apk")) {
            console.log("[Kavach-Sandbox] Root check blocked: " + path);
            return false;
        }
        return this.exists();
    };

    // Bypass Runtime.exec root command execution (running "su", "which su", etc.)
    const Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
        if (cmd === "su" || cmd.includes("su") || cmd.includes("busybox")) {
            console.log("[Kavach-Sandbox] Blocked runtime execution of: " + cmd);
            throw Java.use("java.io.IOException").$new("Command execution blocked by sandbox");
        }
        return this.exec(cmd);
    };

    Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmdArray) {
        const cmdStr = cmdArray.join(" ");
        if (cmdStr.includes("su") || cmdStr.includes("busybox")) {
            console.log("[Kavach-Sandbox] Blocked runtime command array execution: " + cmdStr);
            throw Java.use("java.io.IOException").$new("Command execution blocked by sandbox");
        }
        return this.exec(cmdArray);
    };

    // Bypass System Properties checks (like checking build tags for test-keys)
    const SystemProperties = Java.use("android.os.SystemProperties");
    SystemProperties.get.overload('java.lang.String').implementation = function (key) {
        const val = this.get(key);
        if (key === "ro.build.tags" && val.includes("test-keys")) {
            console.log("[Kavach-Sandbox] ro.build.tags spoofed: release-keys");
            return "release-keys";
        }
        return val;
    };

    // ==========================================
    // 2. SSL PINNING BYPASS (TrustManager & OkHttp)
    // ==========================================

    // Custom TrustManager that accepts all certificates
    const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    const TrustManager = Java.registerClass({
        name: 'com.kavach.sandbox.TrustManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function (chain, authType) {},
            checkServerTrusted: function (chain, authType) {},
            getAcceptedIssuers: function () {
                return [];
            }
        }
    });

    // Hook SSLContext to force our custom TrustManager
    const SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;', 
        '[Ljavax.net.ssl.TrustManager;', 
        'java.security.SecureRandom'
    ).implementation = function (keyManager, trustManager, secureRandom) {
        console.log("[Kavach-Sandbox] Intercepting SSLContext.init to bypass pinning");
        return this.init(keyManager, [TrustManager.$new()], secureRandom);
    };

    // Hook OkHttp3 CertificatePinner if present in the APK runtime classloader
    try {
        const CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (hostname, peerCertificates) {
            console.log("[Kavach-Sandbox] OkHttp3 CertificatePinner check bypassed for: " + hostname);
            return;
        };
    } catch (e) {
        console.log("[Kavach-Sandbox] OkHttp3 CertificatePinner not found or hook failed (skipping)");
    }

    // ==========================================
    // 3. TELEMETRY COLLECTION HOOKS
    // ==========================================

    // Hook FileInputStream to log file reads
    try {
        const FileInputStream = Java.use("java.io.FileInputStream");
        FileInputStream.$init.overload('java.io.File').implementation = function (file) {
            const path = file.getAbsolutePath();
            if (path && (path.includes("/data/") || path.includes("/system/") || path.includes("/proc/") || path.includes("/sdcard/"))) {
                console.log("[Kavach-Sandbox] File read: " + path);
            }
            return this.$init(file);
        };
        FileInputStream.$init.overload('java.lang.String').implementation = function (path) {
            if (path && (path.includes("/data/") || path.includes("/system/") || path.includes("/proc/") || path.includes("/sdcard/"))) {
                console.log("[Kavach-Sandbox] File read: " + path);
            }
            return this.$init(path);
        };
    } catch (e) {
        console.log("[Kavach-Sandbox] FileInputStream hooks skipped: " + e);
    }

    // Hook FileOutputStream to log file writes
    try {
        const FileOutputStream = Java.use("java.io.FileOutputStream");
        FileOutputStream.$init.overload('java.io.File', 'boolean').implementation = function (file, append) {
            const path = file.getAbsolutePath();
            if (path && (path.includes("/data/") || path.includes("/system/") || path.includes("/proc/") || path.includes("/sdcard/"))) {
                console.log("[Kavach-Sandbox] File write: " + path);
            }
            return this.$init(file, append);
        };
        FileOutputStream.$init.overload('java.lang.String', 'boolean').implementation = function (path, append) {
            if (path && (path.includes("/data/") || path.includes("/system/") || path.includes("/proc/") || path.includes("/sdcard/"))) {
                console.log("[Kavach-Sandbox] File write: " + path);
            }
            return this.$init(path, append);
        };
    } catch (e) {
        console.log("[Kavach-Sandbox] FileOutputStream hooks skipped: " + e);
    }

    // Hook Socket.connect to capture outbound network connections
    try {
        const Socket = Java.use("java.net.Socket");
        Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function (endpoint, timeout) {
            try {
                const InetSocketAddress = Java.use('java.net.InetSocketAddress');
                if (endpoint.$className === 'java.net.InetSocketAddress' || endpoint.toString().indexOf(':') !== -1) {
                    const addr = Java.cast(endpoint, InetSocketAddress);
                    const host = addr.getHostString ? addr.getHostString() : addr.getHostName();
                    const port = addr.getPort();
                    console.log("[Kavach-Sandbox] Network connection: " + host + ":" + port);
                }
            } catch (err) {
                console.log("[Kavach-Sandbox] Socket parse warning: " + err);
            }
            return this.connect(endpoint, timeout);
        };
    } catch (e) {
        console.log("[Kavach-Sandbox] Socket.connect hook skipped: " + e);
    }

    // Hook System.loadLibrary to capture native library loads
    try {
        const System = Java.use("java.lang.System");
        System.loadLibrary.implementation = function (libName) {
            console.log("[Kavach-Sandbox] Native library loaded: " + libName);
            return this.loadLibrary(libName);
        };
    } catch (e) {
        console.log("[Kavach-Sandbox] System.loadLibrary hook skipped: " + e);
    }

    console.log("[Kavach-Sandbox] Hooks active!");
});
