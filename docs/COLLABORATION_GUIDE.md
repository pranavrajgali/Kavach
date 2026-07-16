# Git and GitHub Collaboration Guide

This document outlines the professional team workflow for collaborating on the Kavach.ai codebase. We use a fork-and-pull model to ensure that the main codebase remains stable, audited, and tested.

## Workflow Overview

1. Fork the main repository.
2. Clone your personal fork to your local machine.
3. Configure the upstream remote to sync changes.
4. Create a descriptive feature branch for your track.
5. Code, test, and commit your changes.
6. Sync your fork with the upstream main branch.
7. Push your branch to your origin repository.
8. Submit a Pull Request (PR) for code review.

---

## Step-by-Step Instructions

### Step 1: Fork the Repository

Navigate to the main GitHub repository page. In the top right corner, click the "Fork" button. This creates a personal copy of the repository under your own GitHub account.

### Step 2: Clone Your Personal Fork

On your local machine, run the following command to download your personal copy (replace your-username with your actual GitHub username):

```bash
git clone https://github.com/your-username/Kavach.git
cd Kavach
```

### Step 3: Configure Upstream Remote

To keep your fork updated with the main project repository, add the original repository as an upstream remote:

```bash
git remote add upstream https://github.com/original-owner/Kavach.git
```

To verify your remotes are set up correctly, run:

```bash
git remote -v
```

You should see origin pointing to your personal fork and upstream pointing to the main project repository.

### Step 4: Create a Feature Branch

Never make changes directly to the main branch. Create a new branch dedicated to the feature or track you are working on:

```bash
git checkout -b feature/track-number-description
```

Example:

```bash
git checkout -b feature/track-3-fastapi-models
```

### Step 5: Make and Commit Changes

Write clean code, document your additions, and verify execution locally. When committing your work, write descriptive commit messages following the conventional format:

```bash
git add .
git commit -m "feat(backend): implement BCNF SQLModels for apk tracking"
```

Common message prefixes:
* feat: A new feature or endpoint.
* fix: A bug fix.
* docs: Documentation changes.
* test: Adding or modifying test suites.
* refactor: Restructuring code without changing functionality.

### Step 6: Sync Your Branch with Upstream

Before pushing your changes, fetch and merge the latest work done by your teammates on the main repository to prevent conflicts:

```bash
git checkout main
git pull upstream main
git checkout feature/track-number-description
git rebase main
```

If there are any merge conflicts, resolve them locally in your editor, add the resolved files, and run:

```bash
git rebase --continue
```

### Step 7: Push Your Feature Branch

Push your updated branch to your personal GitHub fork (origin):

```bash
git push origin feature/track-number-description
```

### Step 8: Submit a Pull Request

1. Navigate to the original GitHub repository.
2. You will see a banner prompting you to compare and create a Pull Request for your recently pushed branch. Click "Compare & pull request".
3. Write a clear description of what your changes accomplish, link any relevant plans, and submit.
4. Assign team members as reviewers.

---

## Code Collaboration Guidelines

* Write Automated Tests: When implementing backend logic or endpoints, verify your changes by writing or updating the test cases in the test suite. Refer to [plan_4_siri.md](file:///c:/Users/Admin/Documents/Projects/Kavach/docs/plans/plan_4_siri.md) for testing guidelines.
* Follow the Roadmap: Coordinate with the chronological dependencies outlined in [integration_roadmap.md](file:///c:/Users/Admin/Documents/Projects/Kavach/docs/plans/integration_roadmap.md). Do not use real integration until the dependent track has completed its phase. Use mock endpoints when appropriate.
* Build Specifications: Adhere to the schemas and configurations specified in the main [BUILD_GUIDE.md](file:///c:/Users/Admin/Documents/Projects/Kavach/docs/BUILD_GUIDE.md).
