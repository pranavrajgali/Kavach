import os
import sys
from pathlib import Path
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from peft import PeftModel

WEIGHTS_DIR = Path("kavach_ai/backend/pipeline/stage3_ml/weights")
BASE_MODEL_NAME = "cisco-ai/SecureBERT2.0-base"
FALLBACK_MODEL_NAME = "Ehije/SecureBERT"

def verify_exported_weights():
    print("==========================================================")
    print("[VERIFY] SecureBERT-2.0 Weights & Model Adapter Verification")
    print("==========================================================")

    if not WEIGHTS_DIR.exists():
        print(f"[FAIL] Weights directory '{WEIGHTS_DIR.resolve()}' does not exist.")
        return False

    files = [f.name for f in WEIGHTS_DIR.glob("*")]
    print(f"[FILES] Artifacts in weights folder ({len(files)} files):")
    for f in files:
        print(f"   - {f}")

    has_config = (WEIGHTS_DIR / "adapter_config.json").exists() or (WEIGHTS_DIR / "config.json").exists()
    has_weights = (
        (WEIGHTS_DIR / "adapter_model.safetensors").exists()
        or (WEIGHTS_DIR / "adapter_model.bin").exists()
        or (WEIGHTS_DIR / "model.safetensors").exists()
        or (WEIGHTS_DIR / "pytorch_model.bin").exists()
    )

    if not (has_config and has_weights):
        print("[WARN] Model weight files missing or incomplete.")
        return False

    print("\n[MODEL] Test-loading model adapters into PyTorch...")
    device = torch.device("cuda" if torch.cuda.is_available() else ("mps" if hasattr(torch.backends, "mps") and torch.backends.mps.is_available() else "cpu"))

    try:
        tokenizer = AutoTokenizer.from_pretrained(WEIGHTS_DIR)
    except Exception:
        tokenizer = AutoTokenizer.from_pretrained(FALLBACK_MODEL_NAME)

    try:
        base_model = AutoModelForSequenceClassification.from_pretrained(BASE_MODEL_NAME, num_labels=2)
    except Exception:
        base_model = AutoModelForSequenceClassification.from_pretrained(FALLBACK_MODEL_NAME, num_labels=2)

    try:
        model = PeftModel.from_pretrained(base_model, WEIGHTS_DIR)
        model.to(device)
        model.eval()

        test_text = "const-string v0, 'Lcom/malware/bot;->sendSms'\ninvoke-virtual {v0}, Landroid/telephony/SmsManager;->sendTextMessage"
        inputs = tokenizer(test_text, return_tensors="pt", truncation=True, max_length=512).to(device)
        with torch.no_grad():
            outputs = model(**inputs)
            probs = torch.softmax(outputs.logits, dim=-1)
            malware_prob = probs[0][1].item()

        print(f"[OK] Inference test succeeded! Sample Malware Probability: {malware_prob:.4f}")
        print("[DONE] Weights verification passed! Model is ready for backend deployment.\n")
        return True

    except Exception as e:
        print(f"[FAIL] Error loading model adapters: {e}")
        return False

if __name__ == "__main__":
    verify_exported_weights()
