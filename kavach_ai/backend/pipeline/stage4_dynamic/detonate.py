import os
import sys
import subprocess
import time
import logging
import zipfile
import shutil

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("KavachDetonator")

def _find_jdk_tool(tool_name):
    # Try finding on system path first
    tool_path = shutil.which(tool_name)
    if tool_path:
        return tool_path
        
    # Check default Windows directories
    java_dir = "C:\\Program Files\\Java"
    if os.path.exists(java_dir):
        for root, dirs, files in os.walk(java_dir):
            if f"{tool_name}.exe" in files:
                return os.path.join(root, f"{tool_name}.exe")
    return None

class DetonationOrchestrator:
    def __init__(self, adb_path="adb", frida_path="frida"):
        self.adb_path = adb_path
        
        # Dynamically search for frida executable in the active Python env scripts/bin folder first
        if frida_path == "frida":
            python_dir = os.path.dirname(sys.executable)
            local_frida = shutil.which("frida", path=python_dir)
            if not local_frida:
                # Try relative venv path (5 parent directories up from detonate.py)
                proj_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
                venv_frida = os.path.join(proj_root, "venv", "Scripts", "frida.exe")
                if os.path.exists(venv_frida):
                    local_frida = venv_frida
                else:
                    local_frida = shutil.which("frida")
            if local_frida:
                frida_path = local_frida
                
        self.frida_path = frida_path
        self.device_connected = self._check_device_connected()
        self.device_abi = self._get_device_abi() if self.device_connected else "arm64-v8a"
        self.root_bypass_detected = False
        self.ssl_bypass_detected = False
        self.active_admin_component = None
        self.files_accessed = []
        self.network_connections = []
        self.native_libraries = []

    def _check_device_connected(self):
        try:
            result = subprocess.run([self.adb_path, "devices"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
            lines = result.stdout.strip().split("\n")
            # First line is "List of devices attached", subsequent lines contain connected devices
            devices = []
            for line in lines[1:]:
                parts = line.strip().split()
                if len(parts) == 2 and parts[1] == "device":
                    devices.append(parts[0])
            if devices:
                logger.info(f"Connected Android device(s) found: {devices}")
                return True
            logger.warning("No Android devices found via ADB. Detonation will run in SIMULATION mode.")
            return False
        except Exception as e:
            logger.warning(f"ADB check failed ({e}). Detonation will run in SIMULATION mode.")
            return False

    def _get_device_abi(self):
        try:
            # Query standard ro.product.cpu.abi first
            res = subprocess.run(
                [self.adb_path, "shell", "getprop", "ro.product.cpu.abi"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5
            )
            abi = res.stdout.strip()
            if abi:
                logger.info(f"Detected device ABI: {abi}")
                return abi
            
            # Fall back to ro.product.cpu.abilist
            res = subprocess.run(
                [self.adb_path, "shell", "getprop", "ro.product.cpu.abilist"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5
            )
            abilist = res.stdout.strip()
            if abilist:
                abis = [a.strip() for a in abilist.split(",") if a.strip()]
                if abis:
                    logger.info(f"Detected device ABI from list: {abis[0]}")
                    return abis[0]
        except Exception as e:
            logger.warning(f"Failed to query device ABI ({e}). Defaulting to arm64-v8a.")
        
        return "arm64-v8a"

    def run_command(self, cmd, log_error=True):
        logger.info(f"Executing: {' '.join(cmd)}")
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
            if res.returncode != 0:
                if log_error:
                    logger.error(f"Command failed with code {res.returncode}: {res.stderr}")
                else:
                    logger.warning(f"Command execution finished with code {res.returncode}: {res.stderr.strip() or 'No error output'}")
            return res.returncode == 0, res.stdout, res.stderr
        except Exception as e:
            if log_error:
                logger.error(f"Failed to run command {cmd}: {e}")
            else:
                logger.warning(f"Failed to run command {cmd} (ignored): {e}")
            return False, "", str(e)

    def _resign_apk(self, apk_path):
        """
        Strips current signatures and signs the APK using jarsigner.
        This resolves INSTALL_PARSE_FAILED_NO_CERTIFICATES errors.
        """
        jarsigner = _find_jdk_tool("jarsigner")
        keytool = _find_jdk_tool("keytool")
        
        if not jarsigner or not keytool:
            logger.warning("JDK jarsigner or keytool not found. Resigning skipped.")
            return False
            
        logger.info(f"Attempting to strip and resign APK: {apk_path}")
        
        temp_unsigned = apk_path + ".unsigned"
        try:
            # 1. Strip existing META-INF signature files
            with zipfile.ZipFile(apk_path, 'r') as yin:
                with zipfile.ZipFile(temp_unsigned, 'w') as yout:
                    for item in yin.infolist():
                        filename = item.filename
                        if filename.startswith("META-INF/"):
                            if filename.endswith(".SF") or filename.endswith(".RSA") or filename.endswith(".DSA") or filename.endswith("MANIFEST.MF"):
                                continue
                        yout.writestr(item, yin.read(filename))
            
            # Replace original APK with stripped APK
            shutil.move(temp_unsigned, apk_path)
            
            # 2. Check or create debug keystore
            keystore_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "debug.keystore")
            if not os.path.exists(keystore_path):
                logger.info(f"Generating temporary keystore at: {keystore_path}")
                cmd = [
                    keytool, "-genkey", "-v", 
                    "-keystore", keystore_path, 
                    "-storepass", "android", 
                    "-alias", "androiddebugkey", 
                    "-keypass", "android", 
                    "-keyalg", "RSA", 
                    "-keysize", "2048", 
                    "-validity", "10000", 
                    "-dname", "CN=Android Debug,O=Android,C=US"
                ]
                subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            
            # 3. Sign the APK using jarsigner
            logger.info("Signing APK using jarsigner...")
            cmd = [
                jarsigner, "-keystore", keystore_path, 
                "-storepass", "android", 
                "-keypass", "android", 
                apk_path, "androiddebugkey"
            ]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if res.returncode != 0:
                logger.error(f"jarsigner signing failed: {res.stderr}")
                return False
                
            logger.info("APK signed successfully.")
            return True
            
        except Exception as e:
            logger.error(f"Failed to resign APK: {e}")
            if os.path.exists(temp_unsigned):
                try:
                    os.remove(temp_unsigned)
                except Exception:
                    pass
            return False

    def _check_apk_has_code(self, apk_path):
        """Inspects the APK's ZIP structure to verify it contains compiled Java bytecode (.dex)."""
        try:
            with zipfile.ZipFile(apk_path, 'r') as z:
                files = z.namelist()
                has_dex = any(f.endswith(".dex") for f in files)
                if not has_dex:
                    logger.error(f"APK Integrity Warning: The file '{os.path.basename(apk_path)}' contains NO compiled Dalvik bytecode (.dex files are missing). Android requires at least one classes.dex to execute.")
                    return False
            return True
        except Exception as e:
            logger.error(f"Failed to verify APK ZIP integrity: {e}")
            return False

    def _enable_accessibility_for_package(self, package_name):
        try:
            # Query services matching accessibility intent
            cmd = [
                self.adb_path, "shell", "pm", "query-services", 
                "-a", "android.accessibilityservice.AccessibilityService"
            ]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
            if res.returncode == 0 and res.stdout:
                # Look for lines containing our package name, e.g. "ServiceInfo{com.malicious.sms/com.malicious.sms.MyService}"
                for line in res.stdout.split("\n"):
                    if package_name in line and "ServiceInfo{" in line:
                        # Extract the package/class
                        start = line.find("ServiceInfo{") + len("ServiceInfo{")
                        end = line.find("}")
                        if start != -1 and end != -1:
                            service_id = line[start:end].strip()
                            logger.info(f"Detected Accessibility Service: {service_id}. Enabling via secure settings...")
                            
                            # Enable it
                            self.run_command([
                                self.adb_path, "shell", "settings", "put", "secure", 
                                "enabled_accessibility_services", service_id
                            ])
                            self.run_command([
                                self.adb_path, "shell", "settings", "put", "secure", 
                                "accessibility_enabled", "1"
                            ])
                            return True
            return False
        except Exception as e:
            logger.error(f"Failed to enable accessibility service: {e}")
            return False

    def _auto_activate_device_admin(self, package_name):
        try:
            # Query all receivers registered for the DEVICE_ADMIN_ENABLED action
            cmd = [
                self.adb_path, "shell", "cmd", "package", "query-receivers",
                "--brief", "-a", "android.app.action.DEVICE_ADMIN_ENABLED"
            ]
            success, stdout, stderr = self.run_command(cmd)
            if success and stdout:
                for line in stdout.splitlines():
                    line = line.strip()
                    if line.startswith(package_name + "/"):
                        logger.info(f"Auto-activating device admin for component: {line}")
                        self.run_command([
                            self.adb_path, "shell", "dpm", "set-active-admin",
                            "--user", "current", line
                        ])
                        self.active_admin_component = line
        except Exception as e:
            logger.error(f"Failed to auto-activate device administrator: {e}")

    def _dismiss_system_popups(self):
        try:
            logger.info("Dismissing any legacy warning or system dialog overlays...")
            # Keyevent 66 is ENTER/DPAD_CENTER which clicks OK on the default focused dialog button
            self.run_command([self.adb_path, "shell", "input", "keyevent", "66"])
        except Exception as e:
            logger.error(f"Failed to dismiss system popups: {e}")

    def _grant_malware_privileges(self, package_name):
        if not self.device_connected:
            return
        logger.info(f"Auto-granting overlay permissions (SYSTEM_ALERT_WINDOW) for {package_name}...")
        self.run_command([
            self.adb_path, "shell", "appops", "set", 
            package_name, "SYSTEM_ALERT_WINDOW", "allow"
        ])
        self._auto_activate_device_admin(package_name)
        self._enable_accessibility_for_package(package_name)

    def _strip_native_libraries(self, apk_path):
        """
        Strips the 'lib/' directory from the APK to bypass INSTALL_FAILED_NO_MATCHING_ABIS.
        This forces Android to treat the APK as a pure Java application.
        """
        logger.info(f"Stripping native libraries (lib/ directory) from APK: {apk_path}")
        temp_stripped = apk_path + ".stripped"
        try:
            with zipfile.ZipFile(apk_path, 'r') as yin:
                with zipfile.ZipFile(temp_stripped, 'w') as yout:
                    for item in yin.infolist():
                        # Exclude everything under lib/ folder
                        if item.filename.startswith("lib/"):
                            continue
                        yout.writestr(item, yin.read(item.filename))
            
            # Replace original APK with stripped APK
            shutil.move(temp_stripped, apk_path)
            return True
        except Exception as e:
            logger.error(f"Failed to strip native libraries from APK: {e}")
            if os.path.exists(temp_stripped):
                try:
                    os.remove(temp_stripped)
                except Exception:
                    pass
            return False

    def install_apk(self, apk_path):
        if not self.device_connected:
            logger.info("[Sim] Mock installing APK...")
            return True
            
        # Log initial check
        self._check_apk_has_code(apk_path)
        
        has_stripped = False
        has_resigned = False
        
        for attempt in range(3):
            logger.info(f"Attempting to install APK (attempt {attempt + 1}/3)...")
            success, stdout, stderr = self.run_command([self.adb_path, "install", "-r", "-g", apk_path])
            if success:
                logger.info("APK installed successfully.")
                return True
                
            err_msg = (stdout or "") + " " + (stderr or "")
            if "INSTALL_FAILED_NO_MATCHING_ABIS" in err_msg and not has_stripped:
                logger.warning("Install failed with ABI mismatch. Attempting to strip native libraries and retry...")
                if self._strip_native_libraries(apk_path):
                    has_stripped = True
                    # Stripping invalidates signature, so we MUST resign
                    logger.info("Successfully stripped native libraries. Resigning APK...")
                    if self._resign_apk(apk_path):
                        has_resigned = True
                    else:
                        logger.error("Resigning failed after stripping native libraries.")
                        break
                else:
                    logger.error("Failed to strip native libraries.")
                    break
            elif "INSTALL_PARSE_FAILED_NO_CERTIFICATES" in err_msg and not has_resigned:
                logger.warning("Install failed with certificate/signature error. Resigning APK...")
                if self._resign_apk(apk_path):
                    has_resigned = True
                else:
                    logger.error("Resigning failed.")
                    break
            else:
                logger.error(f"Installation failed with unresolvable or already-tried error: {err_msg}")
                break
                
        # If still failed, log check
        self._check_apk_has_code(apk_path)
        return False


    def uninstall_apk(self, package_name):
        if not self.device_connected:
            logger.info(f"[Sim] Mock uninstalling package: {package_name}")
            return True
        
        # If there is an active device admin component, disable it first as root to force deactivation
        if getattr(self, "active_admin_component", None):
            logger.info(f"Deactivating device administrator component: {self.active_admin_component}")
            self.run_command([
                self.adb_path, "shell",
                f"su -c 'pm disable {self.active_admin_component}'"
            ], log_error=False)
            # Give system a brief moment to update state
            time.sleep(1)
            
        success, _, _ = self.run_command([self.adb_path, "uninstall", package_name], log_error=False)
        return success

    def trigger_intents(self, package_name, has_launcher=True):
        """Send broadcasts and trigger activities to wake up sleeping banking trojans."""
        if not self.device_connected:
            logger.info("[Sim] Mock sending intents (BOOT_COMPLETED, BATTERY_LOW)...")
            return
        
        # Trigger BOOT_COMPLETED broadcast (include stopped packages flag: 0x00000020)
        self.run_command([
            self.adb_path, "shell", "am", "broadcast", 
            "-a", "android.intent.action.BOOT_COMPLETED", 
            "-p", package_name,
            "-f", "0x00000020"
        ])
        
        # Trigger BATTERY_LOW broadcast (include stopped packages flag: 0x00000020)
        self.run_command([
            self.adb_path, "shell", "am", "broadcast", 
            "-a", "android.intent.action.BATTERY_LOW", 
            "-p", package_name,
            "-f", "0x00000020"
        ])
        
        # Start the main launcher activity
        if has_launcher:
            self.run_command([
                self.adb_path, "shell", "monkey", 
                "-p", package_name, 
                "-c", "android.intent.category.LAUNCHER",
                "--ignore-crashes", "--ignore-timeouts", "--ignore-security-exceptions",
                "1"
            ], log_error=False)
            
            # Dismiss any initial system warnings / older version overlays
            time.sleep(1.5)
            self._dismiss_system_popups()

    def _read_frida_output(self, process):
        import threading
        def reader():
            try:
                for line in iter(process.stdout.readline, ''):
                    try:
                        line = line.strip()
                        if not line:
                            continue
                        logger.info(f"[Frida] {line}")
                        
                        # Check for bypasses
                        if "Root check blocked" in line or "Blocked runtime execution" in line or "ro.build.tags spoofed" in line:
                            self.root_bypass_detected = True
                        if "SSLContext.init" in line or "CertificatePinner check bypassed" in line:
                            self.ssl_bypass_detected = True
                        
                        # Check for file accesses
                        if "[Kavach-Sandbox] File read:" in line or "[Kavach-Sandbox] File write:" in line or "[Kavach-Sandbox] File accessed:" in line:
                            parts = line.split(":")
                            if len(parts) >= 2:
                                file_path = ":".join(parts[1:]).strip()
                                if file_path not in self.files_accessed:
                                    self.files_accessed.append(file_path)
                        
                        # Check for network connections
                        if "[Kavach-Sandbox] Network connection:" in line:
                            parts = line.split(":")
                            if len(parts) >= 2:
                                conn_str = ":".join(parts[1:]).strip()
                                if ":" in conn_str:
                                    host, port_str = conn_str.rsplit(":", 1)
                                    try:
                                        port = int(port_str)
                                        conn_obj = {"ip": host, "port": port, "protocol": "TCP"}
                                        if conn_obj not in self.network_connections:
                                            self.network_connections.append(conn_obj)
                                    except ValueError:
                                        pass
                        
                        # Check for native libraries loaded
                        if "[Kavach-Sandbox] Native library loaded:" in line:
                            parts = line.split(":")
                            if len(parts) >= 2:
                                lib_name = ":".join(parts[1:]).strip()
                                lib_path = f"/lib/{self.device_abi}/lib{lib_name}.so"
                                if lib_path not in self.native_libraries:
                                    self.native_libraries.append(lib_path)
                    except Exception as parse_err:
                        logger.error(f"Error parsing Frida log line: {parse_err}")
            except Exception as thread_err:
                logger.error(f"Frida output reader thread encountered an error: {thread_err}")
        
        t = threading.Thread(target=reader, daemon=True)
        t.start()

    def _ensure_frida_server_running(self):
        """Checks if frida-server is active on the connected device, and attempts to auto-start it if offline."""
        if not self.device_connected:
            return True
            
        try:
            # Check pgrep first
            res = subprocess.run(
                [self.adb_path, "shell", "pgrep", "-f", "frida-server"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5
            )
            if res.returncode == 0 and res.stdout.strip():
                logger.info("frida-server is already running on the device.")
                return True
        except Exception:
            pass
            
        logger.info("frida-server is not running on the device. Attempting to start it...")
        try:
            # Check existence of the binary
            res = subprocess.run(
                [self.adb_path, "shell", "ls", "/data/local/tmp/frida-server"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5
            )
            if "No such file" in res.stdout or "No such file" in res.stderr:
                logger.error("frida-server binary not found in /data/local/tmp/frida-server on target device.")
                return False
                
            # Spawn the server as a background daemon
            cmd = [
                self.adb_path, "shell",
                "su -c '/data/local/tmp/frida-server -D'"
            ]
            logger.info(f"Executing: {' '.join(cmd)}")
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Verify start status (up to 5 attempts)
            for _ in range(5):
                time.sleep(1)
                res = subprocess.run(
                    [self.adb_path, "shell", "pgrep", "-f", "frida-server"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=3
                )
                if res.returncode == 0 and res.stdout.strip():
                    logger.info("frida-server started successfully in the background.")
                    return True
            logger.warning("frida-server process did not start successfully. Check root privileges.")
            return False
        except Exception as e:
            logger.error(f"Failed to auto-start frida-server: {e}")
            return False

    def spawn_frida_session(self, package_name, script_path, has_launcher=True):
        if not self.device_connected:
            logger.info(f"[Sim] Mock spawning Frida session injecting: {script_path}")
            return None
        
        # Command: frida -U -f <package_name> -l <script_path>
        # Headless Command: frida -U -W <package_name> -l <script_path>
        if has_launcher:
            cmd = [
                self.frida_path, "-U", "-f", package_name,
                "-l", script_path
            ]
            logger.info(f"Spawning Frida process: {' '.join(cmd)}")
        else:
            cmd = [
                self.frida_path, "-U", "-W", package_name,
                "-l", script_path
            ]
            logger.info(f"Awaiting spawn of headless/service package: {' '.join(cmd)}")
            
        try:
            # We run this as a Popen process so it stays running in the background
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT, 
                text=True,
                errors="replace"
            )
            # Start background reader thread
            self._read_frida_output(process)
            return process
        except Exception as e:
            logger.error(f"Failed to spawn Frida: {e}")
            return None

    def detonate_apk(self, apk_path, package_name, script_path, duration_seconds=10):
        logger.info(f"Starting detonation sequence for {package_name}...")
        
        # 1. Install APK
        if not self.install_apk(apk_path):
            logger.error("Detonation aborted: Installation failed.")
            return False
            
        # Auto-grant overlay and accessibility privileges
        self._grant_malware_privileges(package_name)

        # Detect if the package has a launcher activity
        has_launcher = True
        if self.device_connected:
            try:
                res = subprocess.run(
                    [self.adb_path, "shell", "cmd", "package", "resolve-activity", "-c", "android.intent.category.LAUNCHER", package_name],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=5
                )
                output = (res.stdout or "") + (res.stderr or "")
                if "activityinfo" not in output.lower() or not output.strip():
                    has_launcher = False
                    logger.info(f"No launcher activity found for {package_name}. Configuring Frida to await package process spawn.")
            except Exception as e:
                logger.warning(f"Error checking launcher activity status: {e}")

        # 2. Spawn Frida Bypass script / Await listener
        self._ensure_frida_server_running()
        frida_process = self.spawn_frida_session(package_name, script_path, has_launcher=has_launcher)
        if frida_process is None:
            logger.error("Detonation aborted: Failed to spawn Frida process.")
            return False
            
        time.sleep(3) # Wait for hook injection / listener setup

        # If headless, wake up receivers now so the process spawns and triggers Frida's await attachment
        if not has_launcher:
            logger.info("Headless package detected. Sending intent broadcasts to force spawn process...")
            self.trigger_intents(package_name, has_launcher=False)

        # Check if Frida process terminated prematurely
        if frida_process.poll() is not None:
            logger.error("Detonation aborted: Frida process terminated unexpectedly. Ensure frida-server is running on the device.")
            return False

        # If standard app, trigger intents now to start the interface under hooks
        if has_launcher:
            self.trigger_intents(package_name)

        # 3. Wait for telemetry gathering duration
        logger.info(f"Observing behaviors for {duration_seconds} seconds...")
        for _ in range(duration_seconds):
            time.sleep(1)
            if frida_process.poll() is not None:
                logger.warning("Frida process disconnected prematurely during observation loop.")
                break

        # 4. Cleanup Frida
        if frida_process:
            logger.info("Terminating Frida background session...")
            frida_process.terminate()
            frida_process.wait()

        # 5. Uninstall application
        self.uninstall_apk(package_name)
        logger.info("Detonation sequence completed.")
        return True

if __name__ == "__main__":
    # Test script in simulation mode
    orchestrator = DetonationOrchestrator()
    dummy_apk = "mock_malware.apk"
    script = os.path.join(os.path.dirname(__file__), "scripts", "frida_bypass.js")
    orchestrator.detonate_apk(dummy_apk, "com.malicious.sms", script, duration_seconds=2)
