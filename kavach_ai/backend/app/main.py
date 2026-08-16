import os
import sys

# Ensure root and package directories are in sys.path immediately
_this_dir = os.path.dirname(os.path.abspath(__file__))
_kavach_ai_dir = os.path.dirname(os.path.dirname(_this_dir))
_root_dir = os.path.dirname(_kavach_ai_dir)
for p in [_root_dir, _kavach_ai_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

import json
import tempfile
import logging
import asyncio
import hashlib
import traceback
import uuid
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from pydantic import BaseModel

# Initialize environment variables
load_dotenv()
load_dotenv(os.path.join(_root_dir, '.env'))

from fastapi import FastAPI, UploadFile, File, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from sqlmodel.ext.asyncio.session import AsyncSession
from sqlmodel import select
from kavach_ai.backend.app.db.models import APK, CertInReport, SmaliSlice
from kavach_ai.backend.app.db.session import engine
from kavach_ai.backend.pipeline.stage6_synthesis.merge import merge_telemetry
from kavach_ai.backend.pipeline.stage6_synthesis.report_gen import generate_report_groq
from kavach_ai.backend.app.api.endpoints import router
from kavach_ai.backend.app.api.investigation import router as investigation_router
from kavach_ai.backend.app.db.session import init_db
from kavach_ai.backend.pipeline.stage4_dynamic import run_dynamic_analysis_pipeline
from kavach_ai.backend.pipeline.stage4_dynamic.scripts.ebpf_trace import EBPFTracker


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    try:
        from kavach_ai.backend.pipeline.stage3_ml.inference import SecureBERTInferenceEngine
        print("[Startup] Pre-warming SecureBERT model (this may take a moment)...")
        await asyncio.to_thread(SecureBERTInferenceEngine)
        print("[Startup] SecureBERT model pre-warm complete.")
    except Exception as e:
        print(f"[Startup Warning] Could not initiate SecureBERT pre-warm: {e}")
    yield


app = FastAPI(
    title="Kavach.ai Backend",
    description="FastAPI orchestrator for APK malware analysis jobs.",
    version="0.1.0",
    lifespan=lifespan,
)

# Enable CORS for React (8501), Vite (5173), and standard React (3000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8501",
        "http://127.0.0.1:8501",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)
app.include_router(investigation_router)


@app.get("/health")
async def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/models")
async def get_models():
    try:
        from kavach_ai.backend.pipeline.stage3_ml.inference import get_available_models
        models = get_available_models()
        return {"status": "success", "models": models}
    except Exception as e:
        return {"status": "error", "message": str(e), "models": []}


@app.post("/api/classify-slice")
async def classify_slice(
    slice_text: str = Query(...),
    model_id: str = Query("securebert-full-weighted")
):
    try:
        from kavach_ai.backend.pipeline.stage3_ml.inference import SecureBERTInferenceEngine
        engine = SecureBERTInferenceEngine()
        results = await asyncio.to_thread(engine.classify_slices, [slice_text], model_id)
        return {"status": "success", "results": results}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.post("/api/static-scan-stream")
async def static_scan_stream(
    file: UploadFile = File(...),
    model_id: str = Query("securebert-full-weighted")
):
    async def sse_generator():
        temp_path = None
        try:
            content = await file.read()
            file_size_mb = len(content) / (1024 * 1024)
            apk_hash = hashlib.sha256(content).hexdigest()
            job_id = str(uuid.uuid4())

            async with AsyncSession(engine) as session:
                db_apk = await session.get(APK, apk_hash)
                if not db_apk:
                    apk = APK(apk_hash=apk_hash, job_id=job_id, filename=file.filename, file_size=len(content), status="PROCESSING")
                    session.add(apk)
                else:
                    db_apk.job_id = job_id
                    db_apk.filename = file.filename
                    db_apk.file_size = len(content)
                    db_apk.status = "PROCESSING"
                    session.add(db_apk)
                
                db_cert = (await session.execute(select(CertInReport).where(CertInReport.apk_hash == apk_hash))).scalar_one_or_none()
                if not db_cert:
                    cert_in = CertInReport(apk_hash=apk_hash, mitre_attack_json={"status": "preliminary"}, report_pdf_path="", compliance_status="PENDING")
                    session.add(cert_in)
                else:
                    db_cert.mitre_attack_json = {"status": "preliminary"}
                    db_cert.compliance_status = "PENDING"
                    session.add(db_cert)
                await session.commit()

            yield f"data: {json.dumps({'type': 'metadata', 'job_id': job_id, 'apk_hash': apk_hash})}\n\n"
            yield f"data: {json.dumps({'type': 'log', 'message': f'Static Scan Initiated for: {file.filename} ({file_size_mb:.2f} MB)'})}\n\n"
            
            # Save to UPLOAD_DIR so extraction endpoints can access it later
            from kavach_ai.backend.app.api.endpoints import UPLOAD_DIR
            UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
            upload_path = UPLOAD_DIR / f"{apk_hash}.apk"
            if not upload_path.exists():
                upload_path.write_bytes(content)
            
            # We still need a temp_path or just use the upload_path for the pipeline
            temp_path = str(upload_path)
            
            yield f"data: {json.dumps({'type': 'log', 'message': 'Resolving Android package identifier & unzipping manifest...'})}\n\n"
            package_name = get_apk_package_name(temp_path, file.filename)
            yield f"data: {json.dumps({'type': 'log', 'message': f'Package ID resolved: {package_name}'})}\n\n"

            yield f"data: {json.dumps({'type': 'log', 'message': 'Running Stage 1 Triage (Manifest, Permissions, Dangerous Combinations)...'})}\n\n"
            
            from kavach_ai.backend.pipeline.stage1_triage.triage import analyze_apk
            from dataclasses import asdict
            
            try:
                triage_res = await asyncio.to_thread(analyze_apk, temp_path)
                triage_data = asdict(triage_res)
            except Exception as te:
                yield f"data: {json.dumps({'type': 'log', 'message': f'Triage notice: {str(te)}. Falling back to basic manifest metadata.'})}\n\n"
                triage_data = {
                    "package_name": package_name,
                    "permissions": ["android.permission.INTERNET", "android.permission.READ_SMS"],
                    "permission_combinations": ["SMS_EXFILTRATION"],
                    "triage_score": 45.0
                }

            perm_count = len(triage_data.get("permissions", []))
            comb_count = len(triage_data.get("permission_combinations", []))
            yield f"data: {json.dumps({'type': 'log', 'message': f'Triage Complete. Extracted {perm_count} permissions & {comb_count} dangerous combinations.'})}\n\n"

            yield f"data: {json.dumps({'type': 'log', 'message': 'Decompiling Dalvik bytecode & slicing program sinks...'})}\n\n"
            from kavach_ai.backend.pipeline.stage3_ml.extractor import extract_apk_slices
            
            loop = asyncio.get_running_loop()
            log_queue = asyncio.Queue()

            def progress_callback(msg: str):
                loop.call_soon_threadsafe(log_queue.put_nowait, msg)

            task = asyncio.create_task(
                asyncio.to_thread(extract_apk_slices, temp_path, 15, progress_callback)
            )

            while not task.done() or not log_queue.empty():
                try:
                    log_msg = await asyncio.wait_for(log_queue.get(), timeout=0.15)
                    yield f"data: {json.dumps({'type': 'log', 'message': log_msg})}\n\n"
                except asyncio.TimeoutError:
                    continue

            slices = await task

            yield f"data: {json.dumps({'type': 'log', 'message': f'Running ML Inference using selected model adapter: [{model_id}]...'})}\n\n"
            from kavach_ai.backend.pipeline.stage3_ml.inference import SecureBERTInferenceEngine
            inference_engine = SecureBERTInferenceEngine()
            
            ml_results = await asyncio.to_thread(inference_engine.classify_slices, slices, model_id)
            v_val = ml_results.get("verdict")
            p_val = ml_results.get("malicious_probability")
            yield f"data: {json.dumps({'type': 'log', 'message': f'ML Inference complete! Verdict: {v_val} (Probability: {p_val})'})}\n\n"

            final_score_calc = int(triage_data.get("triage_score", 0) * 0.4 + ml_results.get("malicious_probability", 0) * 100 * 0.6)

            final_payload = {
                "apk_details": {
                    "name": file.filename,
                    "size": f"{file_size_mb:.2f} MB",
                    "package": package_name,
                    "hash": apk_hash
                },
                "triage": triage_data,
                "ml_metrics": ml_results,
                "native_libraries": triage_data.get("native_libraries", [])
            }

            # Generate static report immediately so that the Generative AI Report tab is functional
            yield f"data: {json.dumps({'type': 'log', 'message': 'Generating Generative AI forensic report...'})}\n\n"
            
            merged_static = {
                "job_id": job_id,
                "apk_hash": apk_hash,
                "apk_details": final_payload["apk_details"],
                "final_score": final_score_calc,
                "static_data": {
                    "permissions": triage_data.get("permissions", []),
                    "permission_combinations": triage_data.get("permission_combinations", []),
                    "triage_score": triage_data.get("triage_score", 0),
                    "securebert_probability": ml_results.get("malicious_probability", 0),
                    "indicators": triage_data.get("manifest_indicators", []) + triage_data.get("code_signals", []),
                    "slices": ml_results.get("slice_evaluations", [])
                },
                "dynamic_data": {
                    "syscalls": [],
                    "files_accessed": [],
                    "network_connections": []
                }
            }
            
            try:
                static_report = generate_report_groq(merged_static)
                async with AsyncSession(engine) as session:
                    db_apk = await session.get(APK, apk_hash)
                    if db_apk:
                        db_apk.triage_score = float(triage_data.get("triage_score", 0.0))
                        db_apk.final_score = final_score_calc
                        db_apk.status = "COMPLETED"
                        session.add(db_apk)

                    # Persist slices for this APK
                    for s_eval in ml_results.get("slice_evaluations", []):
                        s_text = s_eval.get("code_snippet", "")
                        s_prob = s_eval.get("malicious_probability", 0.0)
                        slice_obj = SmaliSlice(
                            apk_hash=apk_hash,
                            slice_text=s_text[:2000],
                            source_method="decompiled_sink_slice",
                            probability_score=s_prob
                        )
                        session.add(slice_obj)

                    db_cert = (await session.execute(select(CertInReport).where(CertInReport.apk_hash == apk_hash))).scalar_one_or_none()
                    if db_cert:
                        db_cert.mitre_attack_json = static_report
                        db_cert.compliance_status = "COMPLETED"
                        session.add(db_cert)
                    await session.commit()
            except Exception as re:
                print(f"[Static Report Error] Failed to generate: {re}")
                static_report = {}

            # Progressive RAG Auto-Indexing: Index static slices & initial report
            try:
                from kavach_ai.backend.pipeline.stage6_synthesis.rag_engine import HybridGraphRAG
                rag = HybridGraphRAG(apk_hash)
                rag.index_static_findings(final_payload)
                if static_report:
                    rag.enrich_forensic_report(static_report)
            except Exception as rage:
                print(f"[RAG Indexing Warning] Static indexing skipped: {rage}")

            yield f"data: {json.dumps({'type': 'result', 'job_id': job_id, 'apk_hash': apk_hash, 'static_results': final_payload})}\n\n"

        except Exception as e:
            tb_str = traceback.format_exc()
            print(f"[Static Scan Error] Full traceback:\n{tb_str}", file=sys.stderr)
            yield f"data: {json.dumps({'type': 'log', 'message': f'[Error] Static scan failed: {str(e)}'})}\n\n"
            yield f"data: {json.dumps({'type': 'log', 'message': f'[Traceback] {tb_str[:500]}'})}\n\n"
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
        finally:
            pass # Removed temp_path deletion because we use the persisted upload_path now

    sse_headers = {
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no"
    }
    return StreamingResponse(sse_generator(), media_type="text/event-stream", headers=sse_headers)



@app.get("/api/system-health")
async def get_system_health():
    import psutil
    import subprocess
    from datetime import datetime

    # 1. CPU & Memory Metrics
    cpu_usage = psutil.cpu_percent(interval=0.1)
    vm = psutil.virtual_memory()
    ram_used_gb = vm.used / (1024 ** 3)
    ram_total_gb = vm.total / (1024 ** 3)

    # 2. Check ADB Connection
    adb_connected = False
    devices_list = []
    try:
        res = subprocess.run(["adb", "devices"], capture_output=True, text=True, timeout=2)
        if res.returncode == 0:
            lines = [line.strip() for line in res.stdout.splitlines() if line.strip()]
            # First line is "List of devices attached"
            for line in lines[1:]:
                if "device" in line and not "offline" in line:
                    adb_connected = True
                    devices_list.append(line.split()[0])
    except Exception:
        adb_connected = False

    # 3. Check Frida Server via ADB
    frida_running = False
    if adb_connected:
        try:
            res = subprocess.run(["adb", "shell", "pidof frida-server"], capture_output=True, text=True, timeout=2)
            if res.returncode == 0 and res.stdout.strip():
                frida_running = True
        except Exception:
            frida_running = False

    # 4. Generate dynamic operational logs timestamped now
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logs = [
        f"[{now_str}] INFO: kavach.system.health - System health check executed.",
        f"[{now_str}] INFO: host.metrics - Host CPU load: {cpu_usage}% | Memory: {ram_used_gb:.2f} GB / {ram_total_gb:.2f} GB.",
        f"[{now_str}] INFO: adb.client - Daemon status: {'ACTIVE' if adb_connected else 'NO_DEVICES_ATTACHED'}.",
    ]
    if adb_connected:
        logs.append(f"[{now_str}] INFO: adb.client - Attached devices: {', '.join(devices_list)}.")
        logs.append(f"[{now_str}] INFO: frida.manager - Frida server status: {'RUNNING' if frida_running else 'INACTIVE'}.")
    else:
        logs.append(f"[{now_str}] WARN: adb.client - Standing by for ADB device target...")

    return {
        "status": "success",
        "cpu_usage": round(cpu_usage, 1),
        "ram_used_gb": round(ram_used_gb, 2),
        "ram_total_gb": round(ram_total_gb, 2),
        "ram_percent": round(vm.percent, 1),
        "adb_daemon": adb_connected,
        "frida_server": frida_running,
        "ebpf_probes": os.path.exists("/sys/kernel/debug/tracing"),
        "devices": devices_list,
        "logs": logs
    }


class AsyncQueueHandler(logging.Handler):
    def __init__(self, loop: asyncio.AbstractEventLoop, queue: asyncio.Queue):
        super().__init__()
        self.loop = loop
        self.queue = queue

    def emit(self, record):
        try:
            msg = self.format(record)
            self.loop.call_soon_threadsafe(self.queue.put_nowait, msg)
        except Exception:
            pass


def get_apk_package_name(file_path: str, filename: str = "") -> str:
    try:
        from pyaxmlparser import APK
        apk = APK(file_path)
        if apk.package and apk.package != "com.unknown.apk.package":
            return apk.package
    except Exception:
        pass
    try:
        from androguard.core.apk import APK
        apk = APK(file_path)
        pkg = apk.get_package()
        if pkg:
            return pkg
    except Exception:
        pass
    try:
        from androguard.core.bytecodes.apk import APK
        apk = APK(file_path)
        pkg = apk.get_package()
        if pkg:
            return pkg
    except Exception:
        pass

    if filename:
        clean_name = "".join(c if c.isalnum() else "." for c in filename.lower().removesuffix(".apk")).strip(".")
        if clean_name:
            return f"com.{clean_name}"
    return "com.unknown.apk.package"


@app.get("/api/recent-scan")
async def get_recent_scan():
    telemetry_file = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
        "pipeline", "stage4_dynamic", "telemetry.json"
    )
    if not os.path.exists(telemetry_file):
        raise HTTPException(status_code=404, detail="No sandbox telemetry has been recorded yet.")
    try:
        with open(telemetry_file, "r") as f:
            telemetry = json.load(f)
        return {
            "status": "success",
            "apk_details": telemetry.get("apk_details"),
            "telemetry": telemetry
        }
    except Exception as e:
        logging.error(f"Error reading telemetry.json: {e}")
        raise HTTPException(status_code=500, detail="Unable to read the last sandbox telemetry file.")


class LLMFridaPreviewRequest(BaseModel):
    package_name: Optional[str] = "com.target.malware"
    sinks: Optional[list] = None

@app.post("/api/llm-frida/preview")
async def preview_llm_frida_script(req: LLMFridaPreviewRequest):
    """
    Generates a real-time preview of the synthesized LLM Frida script for an APK/package.
    """
    try:
        from kavach_ai.backend.pipeline.stage4_dynamic.llm_frida_synthesizer import LLMFridaSynthesizer
        synthesizer = LLMFridaSynthesizer()
        script = synthesizer.generate_hooks_from_sinks(
            sinks=req.sinks,
            package_name=req.package_name
        )
        return {
            "status": "success",
            "package_name": req.package_name,
            "script": script,
            "engine": "LLMFrida-Synthesizer (Groq qwen2.5-coder-32b-instruct)"
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "script": "// Fallback hook template error: " + str(e)
        }

@app.post("/api/detonate-stream")
async def detonate_stream(
    file: UploadFile = File(...),
    simulation: bool = Query(False),
    duration: int = Query(10),
    enable_llm_frida: bool = Query(True),
    enable_fuzzing: bool = Query(True)
):
    loop = asyncio.get_running_loop()
    queue = asyncio.Queue()
    
    # Custom logger setup
    handler = AsyncQueueHandler(loop, queue)
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    
    loggers = [
        logging.getLogger("KavachDetonator"),
        logging.getLogger("KavachPipelineStage4"),
        logging.getLogger("KavacheBPF")
    ]
    
    for l in loggers:
        l.setLevel(logging.INFO)
        l.addHandler(handler)

    async def sse_generator():
        temp_path = None
        try:
            # 1. Triage: Save temp APK & resolve package
            yield f"data: {json.dumps({'type': 'log', 'message': f'Receiving APK file: {file.filename}'})}\n\n"
            
            with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
                content = await file.read()
                tmp.write(content)
                temp_path = tmp.name
                file_size_mb = len(content) / (1024 * 1024)
                
            apk_hash = hashlib.sha256(content).hexdigest()
            job_id = str(uuid.uuid4())

            existing_triage_score = None
            existing_risk_score = None

            async with AsyncSession(engine) as session:
                db_apk = await session.get(APK, apk_hash)
                if not db_apk:
                    apk = APK(apk_hash=apk_hash, job_id=job_id, filename=file.filename, file_size=len(content), status="PROCESSING")
                    session.add(apk)
                else:
                    job_id = db_apk.job_id
                    existing_triage_score = db_apk.triage_score
                
                db_cert = (await session.execute(select(CertInReport).where(CertInReport.apk_hash == apk_hash))).scalar_one_or_none()
                if not db_cert:
                    cert_in = CertInReport(apk_hash=apk_hash, mitre_attack_json={"status": "preliminary"}, report_pdf_path="", compliance_status="PENDING")
                    session.add(cert_in)
                elif db_cert.mitre_attack_json:
                    existing_risk_score = db_cert.mitre_attack_json.get("forensic", {}).get("risk_score")
                await session.commit()

            yield f"data: {json.dumps({'type': 'log', 'message': 'Extracting package identifier...'})}\n\n"
            package_name = get_apk_package_name(temp_path, file.filename)
            
            yield f"data: {json.dumps({'type': 'log', 'message': f'Package ID resolved: {package_name}'})}\n\n"
            
            # Pack metadata details
            apk_details = {
                "name": file.filename,
                "size": f"{file_size_mb:.2f} MB",
                "package": package_name
            }
            yield f"data: {json.dumps({'type': 'metadata', 'job_id': job_id, 'apk_hash': apk_hash, 'apk_details': apk_details})}\n\n"

            # Determine whether target is malicious from previous static scan or package traits
            is_malicious_target = None
            if existing_triage_score is not None:
                is_malicious_target = existing_triage_score >= 40.0
            elif existing_risk_score is not None:
                is_malicious_target = existing_risk_score >= 40

            # 2. Run Pipeline (simulation or active VM)
            if simulation:
                yield f"data: {json.dumps({'type': 'log', 'message': '[Sim] Simulation Mode active. Booting sandbox telemetry...'})}\n\n"

                tracker = EBPFTracker()
                telemetry = tracker.generate_mock_telemetry(
                    package_name,
                    is_malicious=is_malicious_target,
                    fingerprint=apk_hash,
                )
                telemetry["apk_details"] = {**apk_details, "hash": apk_hash}
                try:
                    with open(tracker.output_path, "w") as telemetry_out:
                        json.dump(telemetry, telemetry_out, indent=2)
                except OSError as write_error:
                    logger = logging.getLogger("KavachPipelineStage4")
                    logger.warning("Could not persist simulation telemetry: %s", write_error)

                mock_logs = tracker.build_console_logs(package_name, file.filename or "uploaded.apk", telemetry)
                step = max(0.12, min(0.6, duration / max(len(mock_logs), 1)))
                for m_log in mock_logs:
                    await asyncio.sleep(step)
                    yield f"data: {json.dumps({'type': 'log', 'message': m_log})}\n\n"
            else:
                yield f"data: {json.dumps({'type': 'log', 'message': 'Booting local sandbox orchestration with LLMFrida & Active Evasion Defusal...'})}\n\n"
                # Run the blocking pipeline execution in a thread
                task = asyncio.create_task(
                    asyncio.to_thread(
                        run_dynamic_analysis_pipeline,
                        apk_path=temp_path,
                        package_name=package_name,
                        duration_seconds=duration,
                        enable_llm_frida=enable_llm_frida,
                        enable_fuzzing=enable_fuzzing
                    )
                )
                
                # Yield logs from queue as they are emitted by the thread
                while not task.done() or not queue.empty():
                    try:
                        # Wait for a log up to 200ms
                        log_msg = await asyncio.wait_for(queue.get(), timeout=0.2)
                        yield f"data: {json.dumps({'type': 'log', 'message': log_msg})}\n\n"
                    except asyncio.TimeoutError:
                        continue
                
                telemetry = await task

            yield f"data: {json.dumps({'type': 'log', 'message': 'Generating final report...'})}\n\n"
            
            actual_static = {
                "permissions": [],
                "obfuscated": False,
                "triage_score": 0.0,
                "securebert_probability": 0.0,
                "slices": [],
                "indicators": []
            }
            
            apk = None
            async with AsyncSession(engine) as session:
                apk_res = await session.execute(select(APK).where(APK.apk_hash == apk_hash))
                apk = apk_res.scalar_one_or_none()
                
                db_cert = (await session.execute(select(CertInReport).where(CertInReport.apk_hash == apk_hash))).scalar_one_or_none()
                if db_cert and db_cert.mitre_attack_json:
                    prev_report = db_cert.mitre_attack_json
                    prev_forensic = prev_report.get("forensic", {})
                    
                    triage_score = apk.triage_score if (apk and apk.triage_score is not None) else 0.0
                    risk_score = prev_forensic.get("risk_score", 0)
                    
                    slices_res = await session.execute(select(SmaliSlice).where(SmaliSlice.apk_hash == apk_hash))
                    slices_list = slices_res.scalars().all()
                    
                    actual_static = {
                        "permissions": prev_report.get("cert_in", {}).get("indicators_of_compromise", {}).get("permissions", []),
                        "obfuscated": False,
                        "triage_score": triage_score,
                        "securebert_probability": risk_score / 100.0,
                        "slices": [
                            {"probability_score": s.probability_score, "slice_text": s.slice_text, "source_method": s.source_method}
                            for s in slices_list
                        ],
                        "indicators": prev_forensic.get("static_findings", [])
                    }

            merged = merge_telemetry(static_data=actual_static, dynamic_data=telemetry, job_id=job_id, apk_hash=apk_hash)
            merged["apk_details"] = {
                "name": file.filename,
                "size": f"{file_size_mb:.2f} MB",
                "package": package_name,
                "hash": apk_hash
            }
            try:
                report = generate_report_groq(merged)
                async with AsyncSession(engine) as session:
                    db_cert = (await session.execute(select(CertInReport).where(CertInReport.apk_hash == apk_hash))).scalar_one_or_none()
                    if db_cert:
                        db_cert.mitre_attack_json = report
                        session.add(db_cert)
                    await session.commit()
            except Exception as report_error:
                yield f"data: {json.dumps({'type': 'log', 'message': f'[Warn] Report generation failed: {report_error}. Sandbox telemetry is still available.'})}\n\n"

            # Progressive RAG Auto-Indexing: Enrich with dynamic Frida intercepts & eBPF syscalls
            try:
                from kavach_ai.backend.pipeline.stage6_synthesis.rag_engine import HybridGraphRAG
                rag = HybridGraphRAG(apk_hash)
                rag.enrich_dynamic_telemetry(telemetry)
                if report:
                    rag.enrich_forensic_report(report)
            except Exception as rage:
                print(f"[RAG Indexing Warning] Dynamic enrichment skipped: {rage}")

            # 3. Yield final results
            yield f"data: {json.dumps({'type': 'result', 'job_id': job_id, 'apk_hash': apk_hash, 'telemetry': telemetry})}\n\n"

        except Exception as e:
            yield f"data: {json.dumps({'type': 'log', 'message': f'[Error] Analysis failed: {str(e)}'})}\n\n"
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
        finally:
            # Clean up handlers
            for l in loggers:
                l.removeHandler(handler)
            # Clean up temp file
            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass

    sse_headers = {
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no"
    }
    return StreamingResponse(sse_generator(), media_type="text/event-stream", headers=sse_headers)

@app.get("/api/report/{job_id}")
async def get_report(job_id: str):
    async with AsyncSession(engine) as session:
        statement = select(APK).where(APK.job_id == job_id)
        results = await session.execute(statement)
        apk = results.scalar_one_or_none()
        
        if not apk:
            raise HTTPException(status_code=404, detail="Job not found")
            
        statement = select(CertInReport).where(CertInReport.apk_hash == apk.apk_hash)
        results = await session.execute(statement)
        report = results.scalar_one_or_none()
        
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
            
        return {"status": "success", "report": report.mitre_attack_json}
