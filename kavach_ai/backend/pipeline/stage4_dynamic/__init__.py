import os
import json
import logging
from .detonate import DetonationOrchestrator
from .scripts.ebpf_trace import EBPFTracker

logger = logging.getLogger("KavachPipelineStage4")

def run_dynamic_analysis_pipeline(apk_path: str, package_name: str, duration_seconds: int = 5) -> dict:
    """
    Orchestrates the entire Stage 4 Dynamic Sandbox pipeline:
    1. Spawns Frida root bypass hooks & detonations sequence.
    2. Reads and parses logs dynamically if a device is connected.
    3. Falls back to generating a simulated threat profile if no device is connected.
    """
    logger.info(f"Initiating unified dynamic analysis pipeline for {package_name}...")
    
    telemetry_file = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 
        "telemetry.json"
    )
    
    # 1. Instantiate the Orchestrator
    orchestrator = DetonationOrchestrator()
    
    if orchestrator.device_connected:
        logger.info("[Dynamic Analysis Mode] LIVE_ADB_FRIDA - Active device connected.")
        # 2. Run active detonation with dynamic telemetry capture
        frida_script = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 
            "scripts", 
            "frida_bypass.js"
        )
        
        success = orchestrator.detonate_apk(
            apk_path=apk_path,
            package_name=package_name,
            script_path=frida_script,
            duration_seconds=duration_seconds
        )
        
        if not success:
            raise RuntimeError("Dynamic detonation failed. Verify target device setup, APK compatibility, and frida-server status.")
        
        # 3. Assemble actual dynamic telemetry
        syscalls = []
        if (orchestrator.root_bypass_detected or 
            orchestrator.ssl_bypass_detected or 
            orchestrator.files_accessed or 
            orchestrator.network_connections):
            syscalls = ["sys_clone", "sys_openat", "sys_connect"]
            
        telemetry = {
            "execution_mode": "LIVE_ADB_FRIDA",
            "objection_root_bypass": orchestrator.root_bypass_detected,
            "objection_ssl_pinning_bypass": orchestrator.ssl_bypass_detected,
            "ebpf_telemetry": {
                "syscalls": syscalls,
                "files_accessed": list(set(orchestrator.files_accessed)),
                "network_connections": orchestrator.network_connections
            },
            "native_libraries": orchestrator.native_libraries
        }
        
        # Save to file
        try:
            with open(telemetry_file, "w") as f:
                json.dump(telemetry, f, indent=2)
            logger.info("Dynamic telemetry compile completed and saved successfully.")
        except Exception as e:
            logger.error(f"Failed to write dynamic telemetry JSON: {e}")
            
        return telemetry
    else:
        # 2. Fall back to eBPF tracker simulation mode
        logger.warning("[Dynamic Analysis Mode] SIMULATION_FALLBACK - No ADB device connected. Generating simulation threat profile.")
        tracker = EBPFTracker(output_path=telemetry_file)
        tracker.start_trace(package_name)
        
        try:
            if os.path.exists(telemetry_file):
                with open(telemetry_file, "r") as f:
                    data = json.load(f)
                data["execution_mode"] = "SIMULATION_FALLBACK"
                with open(telemetry_file, "w") as f:
                    json.dump(data, f, indent=2)
                return data
            return {"execution_mode": "SIMULATION_FALLBACK"}
        except Exception as e:
            logger.error(f"Failed to read simulation telemetry: {e}")
            return {"execution_mode": "SIMULATION_FALLBACK"}
