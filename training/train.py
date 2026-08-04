import os
import sys
import json
import argparse
from pathlib import Path
import torch
from torch.utils.data import Dataset, DataLoader
from torch.optim import AdamW
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    get_linear_schedule_with_warmup
)
from peft import LoraConfig, get_peft_model, TaskType

# Model & Default Paths
DEFAULT_MODEL_NAME = "cisco-ai/SecureBERT2.0-base"
FALLBACK_MODEL_NAME = "Ehije/SecureBERT"
DEFAULT_TRAIN_DATA = "data/processed_slices.jsonl"
DEFAULT_OUTPUT_DIR = "kavach_ai/backend/pipeline/stage3_ml/weights"


class SmaliSliceDataset(Dataset):
    """Custom Dataset for loading Smali opcode slices and labels."""
    def __init__(self, data_path: str, tokenizer, max_length: int = 512):
        self.examples = []
        self.tokenizer = tokenizer
        self.max_length = max_length

        # Auto-resolve candidate data paths if specified path does not exist
        candidate_paths = [
            Path(data_path),
            Path("data/processed_slices.jsonl"),
            Path("training/data/dataset-v1/train.jsonl"),
            Path("data/train.jsonl"),
        ]

        resolved_path = None
        for candidate in candidate_paths:
            if candidate.exists() and candidate.is_file() and candidate.stat().st_size > 0:
                resolved_path = candidate
                break

        if resolved_path:
            print(f"[DATA] Loading dataset from: '{resolved_path.resolve()}'")
            with open(resolved_path, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    item = json.loads(line)
                    text = item.get("slice_text", item.get("code", item.get("text", item.get("slice", ""))))
                    label = item.get("label", item.get("is_malware", item.get("malicious", 0)))
                    if text:
                        self.examples.append((text, int(label)))
            print(f"[OK] Loaded {len(self.examples)} samples from dataset.")
        else:
            print(f"[WARN] Dataset file not found at '{data_path}'. Using dummy dataset for initial pipeline verification.")
            self.examples = [
                ("const-string v0, 'Lcom/malware/bot;->sendSms'", 1),
                ("invoke-virtual {v0}, Landroid/telephony/SmsManager;->sendTextMessage", 1),
                ("Ljava/lang/StringBuilder;->append", 0),
                ("Landroid/widget/TextView;->setText", 0),
            ] * 25

    def __len__(self):
        return len(self.examples)

    def __getitem__(self, idx):
        text, label = self.examples[idx]
        encoding = self.tokenizer(
            text,
            truncation=True,
            max_length=self.max_length,
            padding="max_length",
            return_tensors="pt"
        )
        return {
            "input_ids": encoding["input_ids"].squeeze(0),
            "attention_mask": encoding["attention_mask"].squeeze(0),
            "label": torch.tensor(label, dtype=torch.long)
        }


def detect_and_configure_device(requested_mode: str = "auto"):
    """
    Detects hardware capabilities and returns configured device + optimization settings.
    Modes supported:
      - 'cuda': NVIDIA GPU with AMP (Automatic Mixed Precision)
      - 'mps': Apple Silicon GPU (Metal Performance Shaders)
      - 'cpu': Standard multi-threaded CPU execution
    """
    mode = requested_mode.lower()
    
    if mode == "auto":
        if torch.cuda.is_available():
            mode = "cuda"
        elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
            mode = "mps"
        else:
            mode = "cpu"

    print(f"[DEVICE] Target Device Mode Selected: [{mode.upper()}]")

    if mode == "cuda":
        device = torch.device("cuda")
        torch.backends.cudnn.benchmark = True
        use_amp = True
        amp_dtype = torch.float16
        pin_memory = True
        print(f"[CUDA] Acceleration Active: {torch.cuda.get_device_name(0)}")
        print(f"       VRAM Total: {torch.cuda.get_device_properties(0).total_memory / (1024**3):.2f} GB")
    elif mode == "mps":
        device = torch.device("mps")
        use_amp = True
        amp_dtype = torch.float16
        pin_memory = False
        print("[MPS] Apple Silicon Metal Acceleration Active")
    else:
        device = torch.device("cpu")
        use_amp = False
        amp_dtype = torch.float32
        pin_memory = False
        num_threads = torch.get_num_threads()
        print(f"[CPU] Fallback Active (Threads: {num_threads})")

    return device, use_amp, amp_dtype, pin_memory


def load_base_model_and_tokenizer(model_name: str):
    """Loads tokenizer and base Transformer classification model."""
    print(f"[MODEL] Loading Tokenizer and Base Model: '{model_name}'...")
    try:
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)
    except Exception as e:
        print(f"[WARN] Primary model load failed ({e}). Falling back to '{FALLBACK_MODEL_NAME}'...")
        tokenizer = AutoTokenizer.from_pretrained(FALLBACK_MODEL_NAME)
        model = AutoModelForSequenceClassification.from_pretrained(FALLBACK_MODEL_NAME, num_labels=2)

    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token or "[PAD]"
        model.config.pad_token_id = tokenizer.pad_token_id

    return tokenizer, model


def apply_lora_peft(model):
    """Applies LoRA (Low-Rank Adaptation) adapter configuration."""
    print("[LORA] Applying LoRA/PEFT Adapters to Attention Layers...")
    
    # Try all-linear first (supports ModernBert, BERT, RoBERTa)
    try:
        lora_config = LoraConfig(
            task_type=TaskType.SEQ_CLS,
            r=8,
            lora_alpha=16,
            target_modules="all-linear",
            lora_dropout=0.05,
            bias="none"
        )
        model = get_peft_model(model, lora_config)
    except Exception as e:
        print(f"[WARN] 'all-linear' target_modules failed ({e}). Trying fallback layer names...")
        candidate_modules = ["in_proj", "out_proj", "Wqkv", "Wo", "query", "value", "key", "q_proj", "v_proj", "k_proj"]
        lora_config = LoraConfig(
            task_type=TaskType.SEQ_CLS,
            r=8,
            lora_alpha=16,
            target_modules=candidate_modules,
            lora_dropout=0.05,
            bias="none"
        )
        model = get_peft_model(model, lora_config)

    model.print_trainable_parameters()
    return model


def train_model(
    train_data_path: str = DEFAULT_TRAIN_DATA,
    output_dir: str = DEFAULT_OUTPUT_DIR,
    device_mode: str = "auto",
    epochs: int = 3,
    batch_size: int = 8,
    learning_rate: float = 2e-4
):
    """
    Main training execution function with dual GPU (CUDA / Apple MPS) & CPU support.
    """
    print("==========================================================")
    print("[KAVACH] SecureBERT-2.0 LoRA Fine-Tuning Pipeline")
    print("==========================================================")

    # 1. Device Setup
    device, use_amp, amp_dtype, pin_memory = detect_and_configure_device(device_mode)

    # 2. Tokenizer & Model
    tokenizer, base_model = load_base_model_and_tokenizer(DEFAULT_MODEL_NAME)
    model = apply_lora_peft(base_model)
    model.to(device)

    # 3. Dataset & Dataloader
    dataset = SmaliSliceDataset(train_data_path, tokenizer)
    dataloader = DataLoader(
        dataset,
        batch_size=batch_size,
        shuffle=True,
        pin_memory=pin_memory
    )

    # 4. Optimizer & Scheduler
    optimizer = AdamW(model.parameters(), lr=learning_rate, weight_decay=0.01)
    total_steps = len(dataloader) * epochs
    scheduler = get_linear_schedule_with_warmup(
        optimizer,
        num_warmup_steps=int(total_steps * 0.1),
        num_training_steps=total_steps
    )

    # 5. Training Loop
    from tqdm import tqdm
    print(f"\n[TRAIN] Starting Fine-Tuning Loop ({epochs} Epochs, {len(dataset)} Samples)...")
    scaler = torch.cuda.amp.GradScaler() if (use_amp and device.type == "cuda") else None

    for epoch in range(epochs):
        model.train()
        total_loss = 0.0
        
        progress_bar = tqdm(
            dataloader, 
            desc=f"Epoch {epoch + 1}/{epochs}", 
            unit="batch",
            leave=True
        )

        for step, batch in enumerate(progress_bar):
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["label"].to(device)

            optimizer.zero_grad()

            if use_amp:
                autocast_device = "cuda" if device.type == "cuda" else "cpu"
                with torch.amp.autocast(device_type=autocast_device, dtype=amp_dtype):
                    outputs = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels)
                    loss = outputs.loss
            else:
                outputs = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels)
                loss = outputs.loss

            if scaler is not None:
                scaler.scale(loss).backward()
                scaler.step(optimizer)
                scaler.update()
            else:
                loss.backward()
                optimizer.step()

            scheduler.step()
            total_loss += loss.item()

            current_lr = scheduler.get_last_lr()[0]
            progress_bar.set_postfix({
                "loss": f"{loss.item():.4f}", 
                "lr": f"{current_lr:.2e}"
            })

        avg_loss = total_loss / len(dataloader)
        print(f"[OK] Epoch {epoch + 1} Complete. Average Loss: {avg_loss:.4f}\n")

    # 6. Save Model Artifacts
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    print(f"[SAVE] Saving trained LoRA weights & tokenizer to: '{output_path.resolve()}'")
    model.save_pretrained(output_path)
    tokenizer.save_pretrained(output_path)
    print("[DONE] Training Complete! Model adapters are ready for backend inference.\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SecureBERT-2.0 LoRA Fine-Tuning Script")
    parser.add_argument("--data_path", type=str, default=DEFAULT_TRAIN_DATA, help="Path to preprocessed slices (.jsonl)")
    parser.add_argument("--output_dir", type=str, default=DEFAULT_OUTPUT_DIR, help="Directory to save trained weights")
    parser.add_argument("--device", type=str, default="auto", choices=["auto", "cuda", "mps", "cpu"], help="Hardware acceleration mode")
    parser.add_argument("--epochs", type=int, default=3, help="Number of training epochs")
    parser.add_argument("--batch_size", type=int, default=8, help="Training batch size")
    parser.add_argument("--lr", type=float, default=2e-4, help="Learning rate")

    args = parser.parse_args()

    train_model(
        train_data_path=args.data_path,
        output_dir=args.output_dir,
        device_mode=args.device,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.lr
    )

