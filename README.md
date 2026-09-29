# Closing Data Trust Gap in Agent Data Injection

## Repository Structure

This repository is organized to keep **our implementation, tests, experiments, external benchmarks, and documentation separate**.

```text
.
├── src/
├── tests/
├── benchmarks/
├── experiments/
├── scripts/
├── docs/
│
├── .gitignore
├── .env.example
├── requirements.txt
└── README.md
```

---

## `src/`

This contains **the code we are actually building for the FYP**.

Anything that is part of our own defense/pipeline should go here.

```text
src/
├── parser/
├── provenance/
├── trust_graph/
├── classifier/
└── pipeline/
```

### `parser/`

Responsible for parsing and normalizing the JSON/tool data that enters our system.

### `provenance/`

Contains the logic related to tracking where data came from and attaching provenance information to it.

### `trust_graph/`

Contains the implementation of the trust representation/graph used by our defense.

### `classifier/`

Contains the deterministic classifier that uses the available trust/provenance information to determine the risk/decision for incoming data.

### `pipeline/`

Connects the individual components together.

For example:

```text
Tool Response
     ↓
Parser
     ↓
Provenance
     ↓
Trust Graph
     ↓
Classifier
     ↓
Decision
```

**Rule:** If we are implementing it ourselves as part of the proposed defense, it belongs under `src/`.

---

# `tests/`

This contains tests for **our own code**.

```text
tests/
├── unit/
└── fixtures/
```

### `unit/`

Tests individual components independently.

For example:

```text
tests/unit/
├── test_parser.py
├── test_provenance.py
└── test_classifier.py
```

The initial development should start here.

We first want to verify that the classifier behaves correctly using simple, controlled test cases before introducing an LLM or a complete agent environment.

### `fixtures/`

Contains reusable test data.

For example, instead of writing the same JSON input inside multiple tests, we can keep predefined cases here:

```text
tests/fixtures/
└── classifier_cases.json
```

These can contain cases such as:

* Trusted data
* Untrusted data
* High-impact data
* Low-confidence data
* Missing provenance
* Malformed input
* Boundary cases

**Tests contain the testing logic. Fixtures contain the data used by those tests.**

---

# `benchmarks/`

This is for **integration with external benchmarks**, not for copying entire benchmarks into our repository.

Our planned external benchmarks include things such as:

* AgentDojo
* InjecAgent

For example:

```text
benchmarks/
└── adapters/
    ├── agentdojo.py
    └── injecagent.py
```

The benchmark itself remains an external dependency/resource.

Our adapter code goes here when we need to convert a benchmark's input/output format into the format expected by our system.

This keeps third-party benchmark code separate from our own implementation.

---

# `experiments/`

This is for running and organizing experiments.

Examples:

```text
experiments/
├── configs/
├── results/
└── logs/
```

This is where we can keep things such as:

* Experiment configurations
* Model/benchmark combinations
* Evaluation outputs
* Generated results
* Logs

Generated results should generally **not be treated as source code**.

---

# `scripts/`

These are utility programs used to operate the project.

Examples:

```text
scripts/
├── run_experiment.py
├── run_benchmark.py
├── calculate_metrics.py
└── prepare_data.py
```

The distinction is:

```text
src/       → actual defense implementation
tests/     → tests for our implementation
scripts/   → utilities for running/processing things
```

For example, `calculate_metrics.py` might calculate ASR, FPR, FNR, or utility from experiment results.

---

# `docs/`

Contains project documentation.

```text
docs/
├── FYP_Proposal.pdf
├── architecture/
└── evaluation/
```

The FYP proposal belongs here because it contains the project's research context, architecture, methodology, and other documentation.

As the architecture changes, additional technical documentation can be added here rather than putting it inside `src/`.

---

# Root Files

### `requirements.txt`

Contains the Python packages required by the project.

A developer can create their own environment and install the dependencies with:

```bash
pip install -r requirements.txt
```

The virtual environment itself is **not committed to GitHub**.

---

### `.gitignore`

Specifies files that Git should not track.

This includes things such as:

```text
.venv/
.env
__pycache__/
*.pyc
.vscode/
logs/
```

Most importantly, **API keys, credentials, virtual environments, and generated files should not be committed.**

---

### `.env.example`

Contains the names of environment variables required by the project without containing actual secrets.

For example:

```text
GROQ_API_KEY=
```

Each developer can create their own `.env` locally.

---

# Development Approach

We are intentionally building the system incrementally.

The initial workflow is:

```text
Simple controlled test cases
            ↓
       Classifier
            ↓
     Verify decisions
```

Then:

```text
JSON
 ↓
Parser
 ↓
Classifier
```

Then:

```text
Tool Response
 ↓
Parser
 ↓
Provenance / Trust
 ↓
Classifier
```

Then we introduce a controlled agent environment and eventually integrate external benchmarks such as AgentDojo and InjecAgent.

This means we **do not need the complete agent/LLM/benchmark system before testing individual components**.

The purpose of this structure is to keep each component independently testable and make it easier to identify whether a problem comes from our parser, provenance system, classifier, agent, or benchmark integration.
