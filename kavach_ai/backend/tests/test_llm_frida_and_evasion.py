import os
import pytest
from kavach_ai.backend.pipeline.stage4_dynamic.llm_frida_synthesizer import LLMFridaSynthesizer
from kavach_ai.backend.pipeline.stage4_dynamic.fuzzer import ApexIntentFuzzer
from kavach_ai.backend.pipeline.stage4_dynamic.detonate import DetonationOrchestrator
from kavach_ai.backend.pipeline.stage4_dynamic import run_dynamic_analysis_pipeline

def test_llm_frida_synthesizer_fallback():
    synthesizer = LLMFridaSynthesizer(api_key="mock_invalid_key")
    sinks = [
        {"class": "com.bank.Crypto", "method": "decryptKey", "reason": "Decrypt payload"}
    ]
    script = synthesizer.generate_hooks_from_sinks(sinks, package_name="com.bank.trojan")
    
    assert "Java.perform" in script
    assert "com.bank.Crypto" in script
    assert "decryptKey" in script
    assert "[LLM-Frida-Hook]" in script
    assert "javax.crypto.Cipher" in script
    assert "dalvik.system.DexClassLoader" in script

def test_apex_intent_fuzzer_critical_actions():
    fuzzer = ApexIntentFuzzer(adb_path="mock_adb")
    assert len(fuzzer.DEFAULT_CRITICAL_ACTIONS) >= 8
    assert "android.intent.action.BOOT_COMPLETED" in fuzzer.DEFAULT_CRITICAL_ACTIONS
    assert "android.provider.Telephony.SMS_RECEIVED" in fuzzer.DEFAULT_CRITICAL_ACTIONS

def test_frida_bypass_script_time_dilution():
    script_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "pipeline", "stage4_dynamic", "scripts", "frida_bypass.js"
    )
    assert os.path.exists(script_path)
    with open(script_path, "r", encoding="utf-8") as f:
        content = f.read()
        
    assert "Thread.sleep" in content
    assert "SystemClock.sleep" in content
    assert "Time dilution: compressed" in content
    assert "Root check blocked" in content or "su" in content

def test_detonation_orchestrator_initialization():
    orchestrator = DetonationOrchestrator(adb_path="mock_adb")
    assert hasattr(orchestrator, "time_dilution_count")
    assert hasattr(orchestrator, "llm_frida_intercepts")
    assert hasattr(orchestrator, "fuzzed_intents")
    assert hasattr(orchestrator, "synthesized_hooks_code")

def test_dynamic_pipeline_simulation_mode(monkeypatch):
    from kavach_ai.backend.pipeline.stage4_dynamic.detonate import DetonationOrchestrator
    monkeypatch.setattr(DetonationOrchestrator, "_check_device_connected", lambda self: False)
    telemetry = run_dynamic_analysis_pipeline(
        apk_path="mock_test.apk",
        package_name="com.bank.trojan",
        duration_seconds=1
    )
    assert telemetry is not None
    assert "execution_mode" in telemetry
    assert "time_dilution_bypass" in telemetry
    assert telemetry.get("time_dilution_bypass") is True
    assert "llm_frida_intercepts" in telemetry
