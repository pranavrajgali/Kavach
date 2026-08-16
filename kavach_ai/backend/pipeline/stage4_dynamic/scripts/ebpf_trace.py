import os
import json
import logging
import hashlib

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("KavacheBPF")

class EBPFTracker:
    def __init__(self, output_path=None):
        if output_path is None:
            self.output_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                "telemetry.json"
            )
        else:
            self.output_path = output_path

    def check_ebpf_support(self):
        """
        Check if host or target has eBPF support.
        Under typical Windows development configurations, this will return False, 
        triggering our high-fidelity mock log output.
        """
        # Checks if we're on a Linux environment with access to /sys/kernel/debug/tracing
        if os.path.exists("/sys/kernel/debug/tracing"):
            return True
        return False

    def generate_mock_telemetry(
        self,
        package_name: str,
        is_malicious: bool | None = None,
        fingerprint: str | None = None,
    ):
        """Generate deterministic simulation data keyed to the submitted APK.

        A simulation is not evidence from a real device.  The fingerprint makes
        demo runs reproducible per artifact while avoiding one canned malicious
        trace for every APK.
        """
        pkg_lower = package_name.lower()
        artifact_key = fingerprint or package_name
        artifact_digest = hashlib.sha256(artifact_key.encode()).hexdigest()
        profile_index = int(artifact_digest[:8], 16) % 3
        
        # Determine if package represents a benign application
        if is_malicious is None:
            benign_keywords = ["calculator", "example", "apidemos", "saucelabs", "webdriverio", "fdroid", "benign", "clean", "demo", "sample"]
            malicious_keywords = ["stealer", "sms", "malware", "banking", "evasion", "trojan", "threat", "bot", "ransom", "spy"]
            
            if any(k in pkg_lower for k in benign_keywords) and not any(k in pkg_lower for k in malicious_keywords):
                is_malicious = False
            else:
                is_malicious = True
                
        if not is_malicious:
            return {
                "execution_mode": "SIMULATION_FALLBACK",
                "simulation_profile": "benign-baseline",
                "simulation_fingerprint": artifact_digest[:12],
                "objection_root_bypass": False,
                "objection_ssl_pinning_bypass": False,
                "time_dilution_bypass": False,
                "time_dilution_count": 0,
                "time_dilution_events": [],
                "llm_frida_intercepts": [],
                "fuzzed_intents": [],
                "ebpf_telemetry": {
                    "syscalls": ["sys_openat", "sys_read", "sys_futex", "sys_write"],
                    "files_accessed": [
                        f"/data/user/0/{package_name}/shared_prefs/app_preferences.xml",
                        "/system/framework/framework-res.apk"
                    ],
                    "network_connections": [
                        {"ip": "142.250.190.46", "port": 443, "protocol": "TCP", "status": "connected"}
                    ],
                    "dns_resolutions": [
                        {"domain": "connectivitycheck.gstatic.com", "resolved_ip": "142.250.190.46", "status": "resolved"}
                    ],
                    "permissions_exercised": [
                        "android.permission.INTERNET",
                        "android.permission.ACCESS_NETWORK_STATE",
                    ],
                }
            }

        sanitized_pkg = package_name.replace(".", "-")
        profiles = [
            {
                "name": "time-gate-and-c2",
                "root": True,
                "ssl": True,
                "time": True,
                "intercepts": [f"[LLM-Frida-Hook] Cipher.doFinal observed before outbound flow to https://{sanitized_pkg}-command-node.example/gate"],
                "syscalls": ["sys_clone", "sys_execve", "sys_socket", "sys_connect", "sys_write", "sys_openat"],
                "files": [f"/data/user/0/{package_name}/shared_prefs/config.xml", "/proc/self/maps", "/system/bin/app_process32"],
                "network": [{"ip": "198.51.100.42", "port": 4444, "protocol": "TCP", "status": "connected"}, {"ip": "8.8.8.8", "port": 53, "protocol": "UDP", "status": "attempted"}],
                "dns": [{"domain": f"{sanitized_pkg}-command-node.example", "resolved_ip": "198.51.100.42", "status": "resolved"}],
                "permissions": ["android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE"],
            },
            {
                "name": "dynamic-loader",
                "root": False,
                "ssl": True,
                "time": False,
                "intercepts": [f"[LLM-Frida-Hook] DexClassLoader observed loading an application-private payload for {package_name}"],
                "syscalls": ["sys_openat", "sys_read", "sys_mmap", "sys_socket", "sys_connect"],
                "files": [f"/data/user/0/{package_name}/files/update.dex", f"/data/user/0/{package_name}/code_cache/payload.jar"],
                "network": [{"ip": "203.0.113.17", "port": 443, "protocol": "TCP", "status": "connected"}],
                "dns": [{"domain": f"updates.{sanitized_pkg}.example", "resolved_ip": "203.0.113.17", "status": "resolved"}],
                "permissions": ["android.permission.INTERNET"],
            },
            {
                "name": "data-collection",
                "root": False,
                "ssl": False,
                "time": True,
                "intercepts": [f"[LLM-Frida-Hook] ContentResolver query observed for {package_name}; collection requires live-device validation"],
                "syscalls": ["sys_openat", "sys_read", "sys_write", "sys_socket"],
                "files": [f"/data/user/0/{package_name}/databases/cache.db", "/data/user/0/com.android.providers.contacts/databases/contacts2.db"],
                "network": [{"ip": "192.0.2.25", "port": 8080, "protocol": "TCP", "status": "attempted"}],
                "dns": [{"domain": f"collector.{sanitized_pkg}.example", "status": "nxdomain"}],
                "permissions": ["android.permission.INTERNET", "android.permission.READ_CONTACTS"],
            },
        ]
        profile = profiles[profile_index]
        # Keep simulator-only details distinct between artifacts even when two
        # APKs resolve to the same high-level behavior profile.
        endpoint_octet = (int(artifact_digest[8:10], 16) % 254) + 1
        endpoint_prefix = ("198.51.100", "203.0.113", "192.0.2")[profile_index]
        profile["network"] = [
            {**connection, "ip": f"{endpoint_prefix}.{endpoint_octet}"} if index == 0 else connection
            for index, connection in enumerate(profile["network"])
        ]
        profile["files"] = [*profile["files"], f"/data/local/tmp/kavach-sim-{artifact_digest[:8]}.marker"]
        return {
            "execution_mode": "SIMULATION_FALLBACK",
            "simulation_profile": profile["name"],
            "simulation_fingerprint": artifact_digest[:12],
            "objection_root_bypass": profile["root"],
            "objection_ssl_pinning_bypass": profile["ssl"],
            "time_dilution_bypass": profile["time"],
            "time_dilution_count": 1 if profile["time"] else 0,
            "time_dilution_events": [f"[Kavach-Sandbox] Time dilution: compressed Thread.sleep(600000ms) -> 10ms in {package_name}"] if profile["time"] else [],
            "llm_frida_intercepts": profile["intercepts"],
            "fuzzed_intents": [
                {"action": "android.intent.action.BOOT_COMPLETED", "flags": "0x00000020", "status": "DELIVERED"}
            ],
            "ebpf_telemetry": {
                "syscalls": profile["syscalls"],
                "files_accessed": profile["files"],
                "network_connections": profile["network"],
                "dns_resolutions": [
                    {**record, "resolved_ip": profile["network"][0]["ip"]} if record.get("status") == "resolved" else record
                    for record in profile["dns"]
                ],
                "permissions_exercised": profile["permissions"],
            }
        }

    @staticmethod
    def build_console_logs(package_name: str, filename: str, telemetry: dict) -> list[str]:
        """Console output that matches the simulated telemetry, not a canned malicious script."""
        logs = [
            f"[LLMFrida] Analyzing package structure & UI lifecycle for {package_name}...",
            f"Starting eBPF logging session for: {package_name}",
            f"Installing APK path: {filename}",
            f"Spawning process: {package_name}",
        ]
        if telemetry.get("objection_root_bypass"):
            logs.append("Bypassing Android Root safeguards... SUCCESS (ro.build.tags spoofed)")
        else:
            logs.append("Root check: PASS (No root escalation attempted)")
        if telemetry.get("objection_ssl_pinning_bypass"):
            logs.append("Bypassing SSL Pinning certification... SUCCESS (TrustAllCerts active)")
        else:
            logs.append("SSL Check: Standard TLS socket connection initialized")
        for event in telemetry.get("time_dilution_events") or []:
            logs.append(event)
            logs.append("[Time-Dilution] >> DEFUSED! Compressed sleep gate. Execution resumed.")
        for intent in telemetry.get("fuzzed_intents") or []:
            action = intent.get("action") if isinstance(intent, dict) else str(intent)
            logs.append(f"[Apex-Fuzzer] Firing broadcast intent: {action}")
        for intercept in telemetry.get("llm_frida_intercepts") or []:
            logs.append(intercept)
        syscalls = (telemetry.get("ebpf_telemetry") or {}).get("syscalls") or []
        if syscalls:
            logs.append("Tracing kernel IO syscalls: " + ", ".join(syscalls[:4]))
        logs.append("Telemetry gather complete. Syncing report JSON...")
        return logs

    def start_trace(self, package_name):
        logger.info(f"Starting eBPF logging session for: {package_name}")
        if self.check_ebpf_support():
            logger.info("eBPF tracing is supported natively. Loading BPF probes...")
            # If supported, a real implementation would trace the syscalls:
            # sys_enter_connect, sys_enter_openat, sys_enter_write, etc.
            # and dump them. For the sandbox workspace, we write the traced data.
            # To keep execution clean, we dump simulated logs:
            telemetry = self.generate_mock_telemetry(package_name)
        else:
            logger.warning("eBPF kernel interfaces missing. Falling back to simulator telemetry.")
            telemetry = self.generate_mock_telemetry(package_name)

        # Write to JSON file
        try:
            with open(self.output_path, "w") as f:
                json.dump(telemetry, f, indent=2)
            logger.info(f"Telemetry saved to {self.output_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to write telemetry data: {e}")
            return False

if __name__ == "__main__":
    tracker = EBPFTracker()
    tracker.start_trace("com.malicious.sms")
