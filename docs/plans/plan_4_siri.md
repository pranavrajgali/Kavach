# LLM Prompt Context: Plan 4 (Siri Chandana)
## Track 4: Testing & UI Support Specialist

> [!IMPORTANT]  
> Before generating code, refer to the [Integration Roadmap](file:///c:/Users/Admin/Documents/Projects/Kavach/docs/plans/integration_roadmap.md) and the [BUILD_GUIDE.md](file:///c:/Users/Admin/Documents/Projects/Kavach/docs/BUILD_GUIDE.md) to understand chronological dependencies. End-to-end integration tests are Phase 6 and require all other tracks (FastAPI, static analysis, dynamic sandbox, database session) to be functional or completely mocked.
> **DO NOT modify or touch any other files in the workspace that are not explicitly listed in this plan.**

> **FOR THE LLM:** You are an AI coding assistant helping Siri Chandana implement the **Testing/QA suite** and **UI Helper Components (Plotly charts)** for Kavach.ai. Below are the context, exact requirements, directory structures, and code snippets to complete this track. Follow these guidelines strictly.

---

## 🛠️ Architecture & Directory Mapping
1. **API & Pipeline Tests:** `kavach_ai/backend/tests/test_endpoints.py` & `test_pipeline.py`
2. **UI Visual Helpers:** `kavach_ai/frontend/components/charts.py`

---

## 📋 Step-by-Step Task List

### 🧪 Quality Assurance & Test Suites (`kavach_ai/backend/tests/...`)
- [ ] **FastAPI Endpoint Tests:** Write unit tests using `pytest` and `TestClient` to call `/upload` (checking if `job_id` is successfully generated) and `/status/{job_id}`.
- [ ] **Database Integrity Tests:** Write unit tests verifying that state updates (`QUEUED` to `COMPLETED`) are properly serialized into the [APK](file:///c:/Users/Admin/Documents/Projects/Kavach/docs/BUILD_GUIDE.md) SQLModel schemas.
- [ ] **Mock Pipeline Trials:** Write test functions that mock Track 2's ML output and Track 1's eBPF JSON output to verify that the synthesis merger creates valid JSON payloads.
- [ ] **Mock LLM validation:** Write tests to check the CERT-In Groq prompt output validation logic under simulated network failures.

### 📊 UI helper Components (`kavach_ai/frontend/components/charts.py`)
- [ ] **Threat Meter Gauges:** Create custom Plotly gauge charts reflecting the final SecureBERT malware probability score (0% to 100%).
- [ ] **Permissions Risk Charts:** Create horizontal bar charts displaying high-risk permissions found in the Manifest (e.g., SMS read vs write) mapped to risk severity.

---

## 💡 Code & Prompt Templates for LLM

### 🧪 FastAPI Test Client (Pytest)
Ensure correct route responses and parameter validation:
```python
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_upload_endpoint():
    # Mocking APK file binary
    file_payload = {"file": ("test.apk", b"PK...", "application/vnd.android.package-archive")}
    response = client.post("/upload", files=file_payload)
    
    assert response.status_code == 200
    json_data = response.json()
    assert "job_id" in json_data
    assert json_data["status"] == "QUEUED"

def test_status_endpoint():
    response = client.get("/status/mock-job-id-123")
    assert response.status_code in [200, 404]
```

### 📊 Plotly Threat Score Gauge
Create a modern radial gauge indicating malware probability:
```python
import plotly.graph_objects as go
import streamlit as st

def render_threat_gauge(score: float):
    # score: value between 0.0 and 1.0 (malware probability)
    percentage = score * 100
    fig = go.Figure(go.Indicator(
        mode = "gauge+number",
        value = percentage,
        domain = {'x': [0, 1], 'y': [0, 1]},
        title = {'text': "Malware Probability Score", 'font': {'size': 20, 'color': '#e2e8f0'}},
        number = {'suffix': "%", 'font': {'color': '#ef4444' if percentage > 50 else '#3b82f6'}},
        gauge = {
            'axis': {'range': [None, 100], 'tickcolor': "#e2e8f0"},
            'bar': {'color': "#ef4444" if percentage > 50 else "#3b82f6"},
            'bgcolor': "rgba(255,255,255,0.05)",
            'borderwidth': 2,
            'bordercolor': "rgba(255,255,255,0.1)",
            'steps': [
                {'range': [0, 50], 'color': 'rgba(59, 130, 246, 0.1)'},
                {'range': [50, 100], 'color': 'rgba(239, 68, 68, 0.1)'}
            ]
        }
    ))
    
    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font={'color': "#e2e8f0"},
        height=280
    )
    st.plotly_chart(fig, use_container_width=True)
```

---

## 🎯 Verification Checklist for LLM
1. All pytest test cases run successfully via `pytest backend/tests/` command.
2. Threat gauge chart renders correctly in a test Streamlit view.
3. API test suite mocks db queries cleanly, preventing writes from leaking into production.
