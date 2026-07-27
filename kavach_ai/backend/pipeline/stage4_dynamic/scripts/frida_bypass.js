/**
 * Frida Hook Script for Kavach.ai Sandbox Detonation Pipeline
 * Bypasses root detection checks and disables SSL pinning/TrustManagers.
 * Includes safe try-catch wrappers to ensure stability of the instrumentation.
 */

Java.perform(function () {
    console.log("[Kavach-Sandbox] Injecting bypass hooks...");

    // Re-entrancy guard for file system / stream hooks
    const ThreadLocal = Java.use("java.lang.ThreadLocal");
    const ioGuard = ThreadLocal.$new();
    const BooleanClass = Java.use("java.lang.Boolean");
    const TRUE = BooleanClass.valueOf(true);
    const FALSE = BooleanClass.valueOf(false);
    
    function isGuardActive() {
        const val = ioGuard.get();
        return val !== null && val.toString() === "true";
    }
    
    function setGuardActive(active) {
        ioGuard.set(active ? TRUE : FALSE);
    }

    // ==========================================
    // 1. ROOT DETECTION BYPASS
    // ==========================================
    try {
        const File = Java.use("java.io.File");
        File.exists.implementation = function () {
            try {
                const path = this.getAbsolutePath();
                if (path && (
                    path.includes("su") || 
                    path.includes("busybox") || 
                    path.includes("Superuser") || 
                    path.includes("SuperSU") || 
                    path.includes("bin/su") || 
                    path.includes("xbin/su") || 
                    path.includes("daemonsu") ||
                    path.includes("/system/app/Superuser.apk")
                )) {
                    console.log("[Kavach-Sandbox] Root check blocked: " + path);
                    return false;
                }
            } catch (e) {
                console.log("[Kavach-Sandbox] Warning in File.exists hook: " + e);
            }
            return this.exists();
        };
    } catch (e) {
        console.log("[Kavach-Sandbox] File.exists hook setup skipped: " + e);
    }

    try {
        const Runtime = Java.use("java.lang.Runtime");
        
        Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
            try {
                if (cmd && (cmd === "su" || cmd.includes("su") || cmd.includes("busybox"))) {
                    console.log("[Kavach-Sandbox] Blocked runtime execution of: " + cmd);
                    throw Java.use("java.io.IOException").$new("Command execution blocked by sandbox");
                }
            } catch (e) {
                if (e && e.$className && typeof e.$className.includes === 'function' && e.$className.includes("java.io.IOException")) {
                    throw e;
                }
                console.log("[Kavach-Sandbox] Warning in Runtime.exec(String) hook: " + e);
            }
            return this.exec(cmd);
        };

        Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmdArray) {
            try {
                if (cmdArray) {
                    const cmdStr = cmdArray.join(" ");
                    if (cmdStr.includes("su") || cmdStr.includes("busybox")) {
                        console.log("[Kavach-Sandbox] Blocked runtime command array execution: " + cmdStr);
                        throw Java.use("java.io.IOException").$new("Command execution blocked by sandbox");
                    }
                }
            } catch (e) {
                if (e && e.$className && typeof e.$className.includes === 'function' && e.$className.includes("java.io.IOException")) {
                    throw e;
                }
                console.log("[Kavach-Sandbox] Warning in Runtime.exec(String[]) hook: " + e);
            }
            return this.exec(cmdArray);
        };
    } catch (e) {
        console.log("[Kavach-Sandbox] Runtime.exec hooks setup skipped: " + e);
    }

    try {
        const SystemProperties = Java.use("android.os.SystemProperties");
        SystemProperties.get.overload('java.lang.String').implementation = function (key) {
            try {
                const val = this.get(key);
                if (key === "ro.build.tags" && val && val.includes("test-keys")) {
                    console.log("[Kavach-Sandbox] ro.build.tags spoofed: release-keys");
                    return "release-keys";
                }
                return val;
            } catch (e) {
                console.log("[Kavach-Sandbox] Warning in SystemProperties.get hook: " + e);
                return this.get(key);
            }
        };
    } catch (e) {
        console.log("[Kavach-Sandbox] SystemProperties hook setup skipped: " + e);
    }

    // ==========================================
    // 2. SSL PINNING BYPASS (TrustManager & OkHttp)
    // ==========================================
    try {
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

        const SSLContext = Java.use('javax.net.ssl.SSLContext');
        SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;', 
            '[Ljavax.net.ssl.TrustManager;', 
            'java.security.SecureRandom'
        ).implementation = function (keyManager, trustManager, secureRandom) {
            try {
                console.log("[Kavach-Sandbox] Intercepting SSLContext.init to bypass pinning");
                return this.init(keyManager, [TrustManager.$new()], secureRandom);
            } catch (e) {
                console.log("[Kavach-Sandbox] Warning in SSLContext.init hook: " + e);
                return this.init(keyManager, trustManager, secureRandom);
            }
        };
    } catch (e) {
        console.log("[Kavach-Sandbox] SSLContext trust override hook skipped: " + e);
    }

    try {
        const CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (hostname, peerCertificates) {
            try {
                console.log("[Kavach-Sandbox] OkHttp3 CertificatePinner check bypassed for: " + hostname);
            } catch (e) {
                console.log("[Kavach-Sandbox] Warning in OkHttp3 check hook: " + e);
            }
            return;
        };
    } catch (e) {
        console.log("[Kavach-Sandbox] OkHttp3 CertificatePinner not found or hook skipped");
    }

    // ==========================================
    // 3. TELEMETRY COLLECTION HOOKS
    // ==========================================

    // FileInputStream (Reads)
    try {
        const FileInputStream = Java.use("java.io.FileInputStream");
        FileInputStream.$init.overload('java.io.File').implementation = function (file) {
            if (isGuardActive()) {
                return this.$init(file);
            }
            setGuardActive(true);
            try {
                if (file) {
                    const path = file.getAbsolutePath();
                    if (path && (path.includes("/data/") || path.includes("/system/") || path.includes("/proc/") || path.includes("/sdcard/"))) {
                        console.log("[Kavach-Sandbox] File read: " + path);
                    }
                }
            } catch (e) {
                console.log("[Kavach-Sandbox] Warning in FileInputStream(File) hook: " + e);
            } finally {
                setGuardActive(false);
            }
            return this.$init(file);
        };
        FileInputStream.$init.overload('java.lang.String').implementation = function (path) {
            if (isGuardActive()) {
                return this.$init(path);
            }
            setGuardActive(true);
            try {
                if (path && (path.includes("/data/") || path.includes("/system/") || path.includes("/proc/") || path.includes("/sdcard/"))) {
                    console.log("[Kavach-Sandbox] File read: " + path);
                }
            } catch (e) {
                console.log("[Kavach-Sandbox] Warning in FileInputStream(String) hook: " + e);
            } finally {
                setGuardActive(false);
            }
            return this.$init(path);
        };
    } catch (e) {
        console.log("[Kavach-Sandbox] FileInputStream hooks skipped: " + e);
    }

    // FileOutputStream (Writes)
    try {
        const FileOutputStream = Java.use("java.io.FileOutputStream");
        FileOutputStream.$init.overload('java.io.File', 'boolean').implementation = function (file, append) {
            if (isGuardActive()) {
                return this.$init(file, append);
            }
            setGuardActive(true);
            try {
                if (file) {
                    const path = file.getAbsolutePath();
                    if (path && (path.includes("/data/") || path.includes("/system/") || path.includes("/proc/") || path.includes("/sdcard/"))) {
                        console.log("[Kavach-Sandbox] File write: " + path);
                    }
                }
            } catch (e) {
                console.log("[Kavach-Sandbox] Warning in FileOutputStream(File, boolean) hook: " + e);
            } finally {
                setGuardActive(false);
            }
            return this.$init(file, append);
        };
        FileOutputStream.$init.overload('java.lang.String', 'boolean').implementation = function (path, append) {
            if (isGuardActive()) {
                return this.$init(path, append);
            }
            setGuardActive(true);
            try {
                if (path && (path.includes("/data/") || path.includes("/system/") || path.includes("/proc/") || path.includes("/sdcard/"))) {
                    console.log("[Kavach-Sandbox] File write: " + path);
                }
            } catch (e) {
                console.log("[Kavach-Sandbox] Warning in FileOutputStream(String, boolean) hook: " + e);
            } finally {
                setGuardActive(false);
            }
            return this.$init(path, append);
        };
    } catch (e) {
        console.log("[Kavach-Sandbox] FileOutputStream hooks skipped: " + e);
    }

    // Socket.connect (Network Sockets)
    try {
        const Socket = Java.use("java.net.Socket");
        Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function (endpoint, timeout) {
            try {
                const InetSocketAddress = Java.use('java.net.InetSocketAddress');
                if (endpoint && (endpoint.$className === 'java.net.InetSocketAddress' || InetSocketAddress.class.isInstance(endpoint))) {
                    const addr = Java.cast(endpoint, InetSocketAddress);
                    const host = addr.getHostString ? addr.getHostString() : addr.getHostName();
                    const port = addr.getPort();
                    console.log("[Kavach-Sandbox] Network connection: " + host + ":" + port);
                }
            } catch (err) {
                console.log("[Kavach-Sandbox] Socket connect parse warning: " + err);
            }
            return this.connect(endpoint, timeout);
        };
    } catch (e) {
        console.log("[Kavach-Sandbox] Socket.connect hook skipped: " + e);
    }

    // Runtime.load and Runtime.loadLibrary (Native JNI libraries)
    try {
        const RuntimeClass = Java.use("java.lang.Runtime");
        RuntimeClass.load.overload('java.lang.String').implementation = function (path) {
            try {
                if (path) {
                    console.log("[Kavach-Sandbox] Native library loaded: " + path);
                }
            } catch (e) {
                console.log("[Kavach-Sandbox] Warning in Runtime.load hook: " + e);
            }
            return this.load(path);
        };
        RuntimeClass.loadLibrary.overload('java.lang.String').implementation = function (libName) {
            try {
                if (libName) {
                    console.log("[Kavach-Sandbox] Native library loaded: " + libName);
                }
            } catch (e) {
                console.log("[Kavach-Sandbox] Warning in Runtime.loadLibrary hook: " + e);
            }
            return this.loadLibrary(libName);
        };
    } catch (e) {
        console.log("[Kavach-Sandbox] Runtime Native Load hooks skipped: " + e);
    }

    console.log("[Kavach-Sandbox] Hooks active!");
});
