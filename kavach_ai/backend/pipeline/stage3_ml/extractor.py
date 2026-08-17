from pathlib import Path
from typing import List, Callable, Optional
from kavach_ai.backend.pipeline.stage2_static.decompile import validate_apk, prepare_workspace, extract_raw_dex, extract_apk
from kavach_ai.backend.pipeline.stage3_ml.slicing import find_sinks, slice_sinks, DEFAULT_SINK_RULES, SliceLimits
from kavach_ai.backend.pipeline.stage3_ml.normalization import build_method_normalization_maps, serialize_program_slice


def extract_apk_slices(
    apk_path: str,
    max_slices: int = 15,
    log_callback: Optional[Callable[[str], None]] = None
) -> List[str]:
    """Extracts normalized Dalvik bytecode slices from an APK for SecureBERT inference with progress logging."""
    try:
        if log_callback:
            log_callback("Reading APK Dalvik bytecode & indexing DEX structures...")

        validated = validate_apk(apk_path)
        workspace = prepare_workspace(validated.apk_hash)
        
        # High-performance in-memory DEX parser
        raw_extraction = extract_raw_dex(validated, workspace.raw_dex_path)
        methods = raw_extraction.methods

        if not methods:
            # Fallback to extract_apk if raw dex extraction had no methods
            extraction = extract_apk(apk_path, run_jadx_analysis=False)
            methods = extraction.methods if extraction else ()

        if not methods:
            if log_callback:
                log_callback("No Dalvik methods found in APK DEX structures.")
            return []

        if log_callback:
            log_callback(f"Successfully parsed {len(methods)} Dalvik methods across classes.")

        method_lookup = {method.full_signature: method for method in methods}

        if log_callback:
            log_callback("Scanning method callgraph for sensitive security sinks...")

        sinks = find_sinks(methods, DEFAULT_SINK_RULES)
        if not sinks:
            if log_callback:
                log_callback("No dangerous sink rules matched in Dalvik methods.")
            return []

        if log_callback:
            log_callback(f"Identified {len(sinks)} security sink targets. Constructing backward slices...")

        slicing_result = slice_sinks(
            methods=methods,
            sinks=sinks,
            limits=SliceLimits(max_methods_per_slice=10, max_slice_instructions=200)
        )
        slices = slicing_result.slices

        if log_callback:
            log_callback(f"Generated {len(slices)} program slices. Normalizing instructions...")

        serialized_slices = []
        for program_slice in slices[:max_slices]:
            slice_text = serialize_program_slice(program_slice, methods)
            text = slice_text.normalized_slice_text
            if text and text.strip():
                serialized_slices.append(text.strip())

        if log_callback:
            log_callback(f"Finalized {len(serialized_slices)} normalized slices for SecureBERT input.")

        return serialized_slices
    except Exception as e:
        if log_callback:
            log_callback(f"[Error] Slice extraction encountered issue: {e}")
        print(f"[Slice Extractor] Error extracting slices from {apk_path}: {e}")
        return []

