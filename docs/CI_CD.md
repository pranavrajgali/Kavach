# Kavach.ai CI/CD Pipeline

## What is CI/CD?
Continuous Integration and Continuous Deployment (CI/CD) is our automated quality gate that runs every time code is pushed. For Kavach.ai, this means that before any new feature or bugfix merges into our `main` branch, an automated environment automatically checks out the code, installs all complex dependencies, lints the frontend, and runs backend tests to ensure the application remains stable and buildable.

## Our Pipeline
We use **GitHub Actions** as our primary CI/CD platform.

**Triggers**:
- `push` to `main` branch
- `pull_request` targeting `main` branch

**Workflow File**: `.github/workflows/test.yml`

Our pipeline is split into two parallel jobs to maximize speed:

### 1. Backend Verification (`backend-tests`)
- **Environment**: `ubuntu-latest`, Python 3.10
- **Steps**:
  - Checks out code (`actions/checkout@v4`).
  - Sets up Python 3.10 with `pip` caching (`actions/setup-python@v5`).
  - Installs lightweight test runner dependencies alongside our `kavach_ai` module (without build isolation to avoid compiling PyTorch/C-extensions in CI).
  - Explicitly runs a `Verify package import` sanity check to validate that `kavach_ai` is structurally sound.
  - Runs our test suite using `pytest` with `PYTHONPATH: .`.

### 2. Frontend Verification (`frontend-check`)
- **Environment**: `ubuntu-latest`, Node.js 24
- **Steps**:
  - Checks out code (`actions/checkout@v4`).
  - Sets up Node 24 with `npm` caching via `cache-dependency-path` targeting `kavach_ai/frontend/package-lock.json`.
  - Runs `npm ci` for deterministic dependency installation.
  - Runs `oxlint` (`npm run lint`) for lightning-fast code linting.
  - Validates TypeScript and builds via Vite (`npm run build`).

---

## Troubleshooting Log

Here is a running log of the actual issues we encountered while stabilizing the pipeline and their corresponding fixes:

### Problem: `pip install -e ./kavach_ai` failed building dependencies
- **Cause**: Standard `pip install` triggered build isolation, causing the CI runner to attempt building heavy C-extensions (like PyTorch and Androguard) from source, which timed out or failed.
- **Solution**: Added `--no-build-isolation` to the pip install command and explicitly requested just the necessary runtime testing libraries (`pytest`, `pytest-asyncio`, `httpx`, `fastapi`, etc.).

### Problem: `ModuleNotFoundError: No module named 'kavach_ai'`
- **Cause**: We initially set `PYTHONPATH: kavach_ai`. Python tried to look inside the `kavach_ai/` directory for *another* package named `kavach_ai/`, failing to resolve imports.
- **Solution**: Changed to `PYTHONPATH: .` so Python starts scanning from the repository root, correctly finding the top-level `kavach_ai` module. We also added an inline `python -c "import kavach_ai"` verification step to fail fast on import errors.

### Problem: `cache-package-json-path` warning on `setup-node`
- **Cause**: Using an invalid input key `cache-package-json-path` in `actions/setup-node@v4` caused the cache action to silently fall back to searching the repository root for `package-lock.json`, finding nothing.
- **Solution**: Updated the key to the correct `cache-dependency-path: kavach_ai/frontend/package-lock.json`.

### Problem: TypeScript `error TS2307: Cannot find module '@/lib/utils'`
- **Cause**: Although Vite resolved the `@/` alias successfully, `tsc` lacked `baseUrl` resolution to evaluate `"paths"` correctly.
- **Solution**: In `tsconfig.app.json` and `tsconfig.json`, added `"baseUrl": "."` and updated the imports in `button.tsx` to relative paths (`../../lib/utils`) where appropriate. 
*(Note: Later we cleaned this up by removing `baseUrl` entirely and strictly leveraging standard `paths` mapping to appease TypeScript 7+ deprecation warnings, and standardizing relative imports where TS aliases failed.)*

### Problem: `Cannot find module '../../lib/utils'` during Vite Build
- **Cause**: A global `.gitignore` rule (`lib/`) was aggressively ignoring `kavach_ai/frontend/src/lib/`. While `utils.ts` existed on local development machines, it was silently stripped from commits and entirely missing on the CI runner!
- **Solution**: Updated `.gitignore` from `lib/` to `/lib/` to restrict the ignore rule strictly to the project root, and explicitly `git add`'d the missing `utils.ts` file.

---

## Current Status
- **Passing**: Both backend test collections and frontend builds are succeeding cleanly on `ubuntu-latest`.
- **Known Limitations**:
  - We currently don't spin up full Docker or Postgres infrastructure in CI. For tests requiring the database, a mock or SQLite fallback must be used.
  - The pipeline doesn't build heavy production containers or deploy automatically to production targets yet (Continuous Deployment phase is pending).
