# LLM Prompt Context: Plan 2 (Abhinav Mucharla)
## Track 2: Static, ML, & LLM Core

> [!IMPORTANT]  
> Before generating code, refer to the [Integration Roadmap](file:///c:/Users/Admin/Documents/Projects/Kavach/docs/plans/integration_roadmap.md) and the [BUILD_GUIDE.md](file:///c:/Users/Admin/Documents/Projects/Kavach/docs/BUILD_GUIDE.md) to understand chronological dependencies. SecureBERT-2.0 inference relies on sliced tokens from Stage 3, and Groq LLaMA-3 reports rely on the telemetry merger from Plan 3. Use mocks where required.

> **FOR THE LLM:** You are an AI coding assistant helping Abhinav Mucharla implement the **Static Analysis**, **SecureBERT ML Core**, **SHAP Explainability**, and **Groq LLM Report Generator** for Kavach.ai. Below are the context, exact requirements, directory structures, and code snippets to complete this track. Follow these guidelines strictly.

---

## 🛠️ Architecture & Directory Mapping
1. **Manifest Triage:** `kavach_ai/backend/pipeline/stage1_triage/triage.py`
2. **Decompiler & JNI Bridge:** `kavach_ai/backend/pipeline/stage2_static/decompile.py` & `jni_bridge.py`
3. **Dalvik CFG/DFG Program Slicing:** `kavach_ai/backend/pipeline/stage3_ml/slicing.py`
4. **SecureBERT-2.0 Model Core:** `kavach_ai/backend/pipeline/stage3_ml/model.py`
5. **PartitionSHAP Explainability:** `kavach_ai/backend/pipeline/stage5_explain/shap_attribution.py`
6. **LLaMA-3 Groq Report:** `kavach_ai/backend/pipeline/stage6_synthesis/report_gen.py`

---

## 📋 Step-by-Step Task List

### 🔬 Static Extraction (Stages 1, 2A & 3)
- [ ] **Manifest Parser:** Parse `AndroidManifest.xml` using `Androguard` to extract declared permissions, intent-filters, registered activities/receivers, and the main entry points.
- [ ] **APKTool / JADX Wrappers:** Invoke system commands to run APKTool (to extract Smali bytecode) and JADX (to retrieve Java source). Implement a fallback parser to extract raw Dalvik opcodes if decompilation crashes.
- [ ] **JNI Bridge Native Mapper:** Parse `.so` files from the APK (`lib/` folder), read exported symbols, and map them to native methods declared in the Java/Smali code.
- [ ] **Backward Program Slicing:** Build a backward Control Flow Graph (CFG) traversal starting from dangerous API sinks (e.g., `sendTextMessage`, `DexClassLoader.loadClass`, Accessibility service hooks) to extract execution slices (chains of operations).

### 🤖 ML Core & SHAP (Stages 4 & 5)
- [ ] **SecureBERT-2.0 Tokenizer:** Load the tokenizer from disk (`stage3_ml/weights/tokenizer/`) and tokenize the extracted program slices.
- [ ] **LoRA Adapter Weights:** Load PyTorch weights and execute SecureBERT model classification inside a 1.5-second processing window.
- [ ] **PartitionSHAP Attribution:** Implement SHAP scoring on the input tokens to find the contribution score of each Smali keyword to the final malware classification score.

### 🏋️ Offline Model Training & Fine-Tuning (Root `training/` directory)
- [ ] **Corpus Preprocessing (`training/preprocess.py`):** Ingest raw APK datasets (AMD, Drebin, AndroZoo), split at the APK level (70/15/15) to prevent leakage, run backward CFG slicing, and serialize slices to `.jsonl` files.
- [ ] **LoRA Fine-Tuning Setup (`training/train.py`):** Initialize PEFT/LoRA modules on SecureBERT-2.0 attention layers. Set up PyTorch DDP + AMP loops with weighted loss to handle class imbalances, then output saved weights/adapters to `kavach_ai/backend/pipeline/stage3_ml/weights/`.

### 📝 Groq Incident Report (Stage 6 Synthesis)
- [ ] **LLaMA-3 API Connection:** Connect to Groq API utilizing LLaMA-3-8b/70b.
- [ ] **Pydantic Validation (Instructor-style):** Constrain output to a clean JSON matching a Pydantic CERT-In incident schema.
- [ ] **Graceful Degradation:** Write a regex parser to recover incident details if Groq outputs malformed JSON.

---

## 💡 Code & Prompt Templates for LLM

### 🔍 Program Slicer Logic Structure
Traverse Dalvik instructions backwards to isolate dependency chains:
```python
def backward_slice(cfg, api_sink_node):
    visited = set()
    slice_instructions = []
    
    def traverse(node):
        if node in visited:
            return
        visited.add(node)
        slice_instructions.append(node.instruction)
        # Traverse predecessors in the control/data flow graph
        for pred in cfg.predecessors(node):
            traverse(pred)
            
    traverse(api_sink_node)
    return slice_instructions[::-1]  # Return chronologically
```

### 🧠 SecureBERT-2.0 PyTorch Inference Setup
Ensure GPU/CPU hardware compatibility and quick execution:
```python
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

def load_securebert_model(weights_dir):
    tokenizer = AutoTokenizer.from_pretrained(weights_dir)
    model = AutoModelForSequenceClassification.from_pretrained(weights_dir)
    model.eval()
    return model, tokenizer

def predict_malware(model, tokenizer, program_slice_text):
    inputs = tokenizer(program_slice_text, return_tensors="pt", truncation=True, max_length=512)
    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.softmax(outputs.logits, dim=-1)
    return probs[0][1].item()  # Malware probability


### 🏋️ LoRA Fine-Tuning Setup Template
# Example training loop using PEFT
from peft import LoraConfig, get_peft_model

def setup_lora_model(base_model):
    config = LoraConfig(
        r=8,
        lora_alpha=16,
        target_modules=["query", "value"],  # Target attention layers
        lora_dropout=0.05,
        bias="none",
        task_type="SEQ_CLS"
    )
    model = get_peft_model(base_model, config)
    model.print_trainable_parameters()
    return model
```

### 🦙 Groq Structured Report Generation
Ensure report JSON structure conforms to CERT-In requirements:
```python
from pydantic import BaseModel, Field
from groq import Groq
import os

class CertInReport(BaseModel):
    incident_type: str = Field(description="Type of malware, e.g. Banking Trojan")
    threat_level: str = Field(description="HIGH, MEDIUM, or LOW")
    indicators_of_compromise: list[str]
    compliance_violations: list[str] = Field(description="RBI or IT Act violations")

def generate_report(merged_telemetry_json):
    client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
    prompt = f"Analyze this APK telemetry data and compile a CERT-In incident report in JSON matching the schema:\n{merged_telemetry_json}"
    
    # Force json output
    chat_completion = client.chat.completions.create(
        messages=[{"role": "user", "content": prompt}],
        model="llama3-70b-8192",
        response_format={"type": "json_object"}
    )
    return chat_completion.choices[0].message.content
```

---

## 🎯 Verification Checklist for LLM
1. Model weights are correctly loaded from the directory without crashing.
2. The decompiler falls back gracefully to raw opcode scanner if APK obfuscation breaks JADX.
3. PartitionSHAP returns token attribution floats between -1.0 and 1.0.
4. Groq output parses into `CertInReport` and defaults to regex fallback on parse failure.
