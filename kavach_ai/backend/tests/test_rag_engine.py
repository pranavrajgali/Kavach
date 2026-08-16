import pytest
import asyncio
from kavach_ai.backend.pipeline.stage6_synthesis.rag_engine import (
    HybridGraphRAG,
    generate_chat_rag_stream,
    classify_query_model
)

@pytest.mark.asyncio
async def test_hybrid_graphrag_pipeline():
    sample_hash = "test_apk_hash_1234567890abcdef"
    rag = HybridGraphRAG(sample_hash)

    # 1. Test Static Indexing
    static_payload = {
        "apk_details": {
            "name": "test_malware.apk",
            "package": "com.test.trojan",
            "hash": sample_hash
        },
        "triage": {
            "permissions": ["android.permission.SEND_SMS", "android.permission.INTERNET"],
            "permission_combinations": ["SMS_EXFILTRATION"]
        },
        "ml_metrics": {
            "slices": [
                {
                    "source_method": "com.test.trojan.SmsService->sendPayload",
                    "probability_score": 0.94,
                    "slice_text": "invoke-virtual {v0, v1}, Landroid/telephony/SmsManager;->sendTextMessage(...)V\ninvoke-virtual {v2}, Ljavax/crypto/Cipher;->doFinal()[B"
                }
            ]
        }
    }

    rag.index_static_findings(static_payload)
    status = rag.get_status()
    assert status["package_name"] == "com.test.trojan"
    assert status["total_nodes"] > 0
    assert "static" in status["indexed_stages"]

    # 2. Test Dynamic Enrichment
    dynamic_payload = {
        "llm_frida_intercepts": [
            "[LLM-Frida-Hook] Intercepted Cipher.doFinal() Decrypted Plaintext: https://malicious-c2.xyz/drop.php"
        ],
        "time_dilution_bypass": True,
        "time_dilution_count": 1,
        "syscalls": [
            {"name": "sys_connect", "args": "fd=4, ip=198.51.100.42:4444"}
        ]
    }
    rag.enrich_dynamic_telemetry(dynamic_payload)
    status_dyn = rag.get_status()
    assert "dynamic" in status_dyn["indexed_stages"]
    assert status_dyn["stats"]["frida_intercepts"] >= 1

    # 3. Test Seed and Expand Retrieval
    results = rag.seed_and_expand("How does it send SMS or connect to C2?")
    assert len(results) > 0
    node_labels = [r["label"] for r in results]
    assert any(l in node_labels for l in ["Method", "APISink", "FridaIntercept", "Permission"])

    # 4. Test Model Routing
    assert classify_query_model("Show me the Smali code and write a frida hook") == "llama-3.3-70b-versatile"
    assert classify_query_model("Summarize the overall risk score and MITRE tactics") == "llama-3.3-70b-versatile"

    # 5. Test Streaming Token Generator
    stream = generate_chat_rag_stream(sample_hash, "Explain C2 communication")
    tokens_received = []
    async for chunk in stream:
        tokens_received.append(chunk)
        if len(tokens_received) >= 3:
            break
    assert len(tokens_received) > 0
    assert any("data: " in t for t in tokens_received)
