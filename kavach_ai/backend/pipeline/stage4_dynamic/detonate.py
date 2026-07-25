import os
import subprocess
import time
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("KavachDetonator")

class DetonationOrchestrator:
    def __init__(self, adb_path="adb", frida_path="frida"):
        self.adb_path = adb_path
        self.frida_path = frida_path
        self.device_connected = self._check_device_connected()
        self.root_bypass_detected = False
        self.ssl_bypass_detected = False
        self.files_accessed = []
        self.network_connections = []
        self.native_libraries = []

    def _check_device_connected(self):
        try:
            result = subprocess.run([self.adb_path, "devices"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
            lines = result.stdout.strip().split("\n")
            # First line is "List of devices attached", subsequent lines contain connected devices
            devices = [line for line in lines[1:] if line.strip() and "device" in line]
            if devices:
                logger.info(f"Connected Android device(s) found: {devices}")
                return True
            logger.warning("No Android devices found via ADB. Detonation will run in SIMULATION mode.")
            return False
        except Exception as e:
            logger.warning(f"ADB check failed ({e}). Detonation will run in SIMULATION mode.")
            return False

    def run_command(self, cmd):
        logger.info(f"Executing: {' '.join(cmd)}")
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
            if res.returncode != 0:
                logger.error(f"Command failed with code {res.returncode}: {res.stderr}")
            return res.returncode == 0, res.stdout, res.stderr
        except Exception as e:
            logger.error(f"Failed to run command {cmd}: {e}")
            return False, "", str(e)

    def install_apk(self, apk_path):
        if not self.device_connected:
            logger.info("[Sim] Mock installing APK...")
            return True
        success, stdout, _ = self.run_command([self.adb_path, "install", "-r", apk_path])
        return success

    def uninstall_apk(self, package_name):
        if not self.device_connected:
            logger.info(f"[Sim] Mock uninstalling package: {package_name}")
            return True
        success, _, _ = self.run_command([self.adb_path, "uninstall", package_name])
        return success

    def trigger_intents(self, package_name):
        """Send broadcasts and trigger activities to wake up sleeping banking trojans."""
        if not self.device_connected:
            logger.info("[Sim] Mock sending intents (BOOT_COMPLETED, BATTERY_LOW)...")
            return
        
        # Trigger BOOT_COMPLETED broadcast
        self.run_command([
            self.adb_path, "shell", "am", "broadcast", 
            "-a", "android.intent.action.BOOT_COMPLETED", 
            "-p", package_name
        ])
        
        # Trigger BATTERY_LOW broadcast
        self.run_command([
            self.adb_path, "shell", "am", "broadcast", 
            "-a", "android.intent.action.BATTERY_LOW", 
            "-p", package_name
        ])
        
        # Start the main launcher activity
        self.run_command([
            self.adb_path, "shell", "monkey", 
            "-p", package_name, 
            "-c", "android.intent.category.LAUNCHER", "1"
        ])

    def _read_frida_output(self, process):
        import threading
        def reader():
            for line in iter(process.stdout.readline, ''):
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
                        lib_path = f"/lib/arm64-v8a/lib{lib_name}.so"
                        if lib_path not in self.native_libraries:
                            self.native_libraries.append(lib_path)
        
        t = threading.Thread(target=reader, daemon=True)
        t.start()

    def spawn_frida_session(self, package_name, script_path):
        if not self.device_connected:
            logger.info(f"[Sim] Mock spawning Frida session injecting: {script_path}")
            return None
        
        # Command: frida -U -f <package_name> -l <script_path> --no-pause
        cmd = [
            self.frida_path, "-U", "-f", package_name,
            "-l", script_path, "--no-pause"
        ]
        logger.info(f"Spawning Frida process: {' '.join(cmd)}")
        try:
            # We run this as a Popen process so it stays running in the background
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT, 
                text=True
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

        # 2. Spawn Frida Bypass script
        frida_process = self.spawn_frida_session(package_name, script_path)
        time.sleep(3) # Wait for hook injection

        # 3. Detonate intents
        self.trigger_intents(package_name)

        # 4. Wait for telemetry gathering duration
        logger.info(f"Observing behaviors for {duration_seconds} seconds...")
        time.sleep(duration_seconds)

        # 5. Cleanup Frida
        if frida_process:
            logger.info("Terminating Frida background session...")
            frida_process.terminate()
            frida_process.wait()

        # 6. Uninstall application
        self.uninstall_apk(package_name)
        logger.info("Detonation sequence completed.")
        return True

if __name__ == "__main__":
    # Test script in simulation mode
    orchestrator = DetonationOrchestrator()
    dummy_apk = "mock_malware.apk"
    script = os.path.join(os.path.dirname(__file__), "scripts", "frida_bypass.js")
    orchestrator.detonate_apk(dummy_apk, "com.malicious.sms", script, duration_seconds=2)
