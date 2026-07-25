import logging
import json
import sys
import os

# Ensure kavach_ai package is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from kavach_ai.backend.pipeline.stage4_dynamic import run_dynamic_analysis_pipeline

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

if __name__ == "__main__":
    print("\n=============================================")
    print("RUNNING KAVACH.AI DYNAMIC PIPELINE TEST")
    print("=============================================\n")
    
    # Run the unified pipeline
    telemetry = run_dynamic_analysis_pipeline(
        apk_path="mock_malware.apk",
        package_name="com.malicious.sms",
        duration_seconds=3
    )
    
    print("\n=============================================")
    print("PIPELINE RESULT PAYLOAD (BCNF READY)")
    print("=============================================\n")
    print(json.dumps(telemetry, indent=2))
    print("\n=============================================\n")
