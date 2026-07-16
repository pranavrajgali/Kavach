# Kavach.ai: Android Malware Detection and Forensic Reporting Pipeline

Kavach.ai is a banking-malware triage and forensic reporting pipeline designed to analyze Android applications. It runs lightweight triage filters, dynamic sandboxing, local ML classification, explainable attribution, and LLM-synthesized compliance reporting in an integrated Security Operations Center (SOC) dashboard.

This repository is organized to separate the offline training pipeline from the live, synchronous runtime analysis environment.

## Directory Structure

The workspace is organized as follows:

* docs: Project documentation, technical specifications, and team plans.
* docs/plans: Chronological roadmap and individual developer tracks.
* kavach_ai: Main application code (Streamlit frontend, FastAPI orchestrator, database layers, workers, and pipelines).

## Key Documentation

Please refer to these documents before starting development:

* Technical Architecture: Outlines training vs. runtime pipelines and FastAPI non-blocking design. Refer to [ARCHITECTURE.md](file:///c:/Users/Admin/Documents/Projects/Kavach/docs/ARCHITECTURE.md).
* Complete Build Guide: Specifies third-party tools, BCNF database schemas, features, and constraints. Refer to [BUILD_GUIDE.md](file:///c:/Users/Admin/Documents/Projects/Kavach/docs/BUILD_GUIDE.md).
* Team Integration Roadmap: Defines chronological task dependencies and mock integrations across tracks. Refer to [integration_roadmap.md](file:///c:/Users/Admin/Documents/Projects/Kavach/docs/plans/integration_roadmap.md).

## Developer Track Assignments

Each teammate is assigned a specific development track. Ensure you follow your individual step-by-step tasks and guidelines:

* Track 1 (Galipalli Pranav Raj): Dynamic Sandbox and Streamlit Frontend Lead. Integrates emulator sandboxing, Frida bypass scripts, eBPF logging, and front-end components. Refer to [plan_1_pranav_raj.md](file:///c:/Users/Admin/Documents/Projects/Kavach/docs/plans/plan_1_pranav_raj.md).
* Track 2 (Abhinav Mucharla): Static, ML, and LLM Core. Implements Androguard extraction, JNI mapping, backward program slicing, SecureBERT-2.0 inference, PartitionSHAP, and Groq LLaMA-3 reporting. Refer to [plan_2_abhinav.md](file:///c:/Users/Admin/Documents/Projects/Kavach/docs/plans/plan_2_abhinav.md).
* Track 3 (Pranav Krishna): FastAPI Backend, Database, and Task Queue Lead. Responsible for FastAPI endpoints, SQLModel BCNF models, Redis background workers, and telemetry merger. Refer to [plan_3_pranav_krishna.md](file:///c:/Users/Admin/Documents/Projects/Kavach/docs/plans/plan_3_pranav_krishna.md).
* Track 4 (Siri Chandana): Testing and UI Support Specialist. Handles FastAPI route testing, SQLModel transaction verification, pipeline mock testing, and Plotly visualization charts. Refer to [plan_4_siri.md](file:///c:/Users/Admin/Documents/Projects/Kavach/docs/plans/plan_4_siri.md).

## Phased Integration Timeline

Development is divided into five main phases:

1. Contracts and Database: Establish Pydantic contracts, SQLModel schemas, and initial FastAPI endpoints.
2. Parallel Analysis Track: Build the decompiler / slicing wrappers and dynamic sandbox Frida hooks in isolation.
3. ML Inference and Attribution: Set up the SecureBERT tokenizer, classification window, and PartitionSHAP calculations.
4. Telemetry Synthesis and Reports: Combine static and dynamic logs and trigger Groq report generation.
5. UI Integration and Testing: Connect Streamlit components to real endpoints and execute pytest verification.
