<p align="center">

# ⚡ IncidentForge 2.0

### Intelligent Security Operations That Learn From Experience

**Detect. Recall. Investigate. Resolve. Learn.**

</p>

<p align="center">
  <strong>AI-Assisted Security Operations + Organizational Memory</strong>
</p>

<p align="center">

| 🛡️ Detection | 🤖 AI Investigation | 🧠 Hindsight Memory | 📊 ML Risk | 👤 Human Control |
| :-----------: | :-----------------: | :-----------------: | :--------: | :--------------: |

</p>

---

## 🧭 Overview

**IncidentForge 2.0** is an AI-assisted Security Operations platform that transforms raw security telemetry into structured investigations, risk-aware incidents, explainable analysis, and continuously improving organizational knowledge.

Unlike conventional SOC tools that treat every incident as an isolated event, IncidentForge introduces **persistent security experience** into the investigation lifecycle.

Every resolved investigation can contribute validated knowledge to organizational memory. When a related incident appears in the future, that experience can be recalled and used alongside current evidence.

> [!IMPORTANT]
> **IncidentForge doesn't just investigate incidents. It remembers what was learned from them.**

---

# 🧠 The IncidentForge Learning Loop

```text
┌───────────────────────────────────────────────────────────────┐
│                        INCIDENTFORGE                          │
│                                                               │
│   DETECT → RECALL → INVESTIGATE → RESOLVE → LEARN             │
│      ↑                                             │          │
│      │                                             │          │
│      └────────────── FUTURE INCIDENTS ─────────────┘          │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

### The idea is simple:

**Detect** suspicious activity.

↓

**Recall** relevant organizational experience.

↓

**Investigate** using current evidence and historical context.

↓

**Resolve** with analyst-controlled decisions.

↓

**Learn** from validated outcomes.

↓

**Recall again** when similar incidents appear.

---

# 🌐 Security Operations Overview

Modern security operations generate enormous amounts of telemetry, alerts, indicators, and investigation data.

The difficult part is not simply detecting suspicious activity.

Security analysts must continuously determine:

* What actually happened?
* Which events belong to the same incident?
* How severe is the activity?
* What evidence supports the conclusion?
* Has the organization encountered similar behavior before?
* What investigation path should be followed?
* What remediation has worked previously?
* What should be remembered for the next incident?

IncidentForge brings these capabilities together into a single investigation workflow.

```text
                         SECURITY DATA
                              │
                              ▼
                     ┌─────────────────┐
                     │ Schema Detection│
                     └────────┬────────┘
                              │
                              ▼
                     ┌─────────────────┐
                     │  Normalization  │
                     └────────┬────────┘
                              │
                              ▼
                     ┌─────────────────┐
                     │ Event Generation│
                     └────────┬────────┘
                              │
                              ▼
                     ┌─────────────────┐
                     │    Detection    │
                     └────────┬────────┘
                              │
                              ▼
                     ┌─────────────────┐
                     │   Correlation   │
                     └────────┬────────┘
                              │
                              ▼
                     ┌─────────────────┐
                     │Incident Creation│
                     └────────┬────────┘
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
             ┌─────────────┐     ┌──────────────┐
             │ ML Risk     │     │ Hindsight    │
             │ Score       │     │ Recall       │
             └──────┬──────┘     └──────┬───────┘
                    │                   │
                    └─────────┬─────────┘
                              ▼
                    ┌──────────────────┐
                    │ AI Investigation │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ Analyst Decision │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │    Resolution    │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ Hindsight Retain │
                    └────────┬─────────┘
                             │
                             ▼
                 ┌─────────────────────────┐
                 │ Organizational Memory   │
                 └─────────────────────────┘
```

---

# ⚠️ The Problem

Traditional security workflows are largely event-driven.

An alert arrives.

An analyst investigates it.

The incident is resolved.

Then another similar alert arrives and the process begins again.

The organization may have already encountered the same:

* attack technique
* persistence mechanism
* process chain
* phishing pattern
* indicator
* root cause
* investigation path
* remediation strategy

but that experience is often difficult to bring into the next investigation at the right moment.

IncidentForge treats previous investigations as a source of **operational knowledge**.

Instead of allowing valuable incident experience to disappear after resolution, the system can transform validated investigation outcomes into reusable organizational memory.

> [!NOTE]
> The objective is not simply to store more security data.
>
> **The objective is to make previous security experience useful during future investigations.**

---

# ⚙️ The IncidentForge Approach

IncidentForge combines five major capabilities:

| Capability                             | Purpose                                                                                                           |
| :------------------------------------- | :---------------------------------------------------------------------------------------------------------------- |
| 🔄 **Security Data Processing**        | Inspect, normalize, and transform security datasets into structured events.                                       |
| 🎯 **Detection & Correlation**         | Transform individual events into meaningful security incidents.                                                   |
| 📊 **ML-Based Risk Scoring**           | Provide an additional machine-learning risk signal for security activity.                                         |
| 🤖 **AI Investigation**                | Combine current evidence with contextual information to produce structured analysis and recommendations.          |
| 🧠 **Hindsight Organizational Memory** | Retain and recall previous validated investigations so future investigations benefit from accumulated experience. |

These capabilities are connected rather than operating as isolated features.

---

# 🧠 Organizational Memory

The defining capability of IncidentForge is its use of **Hindsight as an operational memory layer**.

```text
             CURRENT EVIDENCE
                    │
                    +
                    │
          HISTORICAL EXPERIENCE
                    │
                    ▼
              INVESTIGATION
                    │
                    ▼
              ANALYST REVIEW
                    │
                    ▼
                RESOLUTION
                    │
                    ▼
             VALIDATED LEARNING
                    │
                    ▼
          ORGANIZATIONAL MEMORY
                    │
                    │
                    ▼
             FUTURE INCIDENTS
```

The objective is not to store every raw telemetry record as memory.

Instead, the memory layer focuses on meaningful security experience such as:

* Incident patterns
* Attack behaviors
* Indicators
* Root causes
* Investigation procedures
* Analyst decisions
* Successful remediation
* Failed approaches
* Lessons learned
* Recurring attacker behavior

This gives organizational memory a clear operational purpose.

---

# 🔁 Memory Lifecycle

## 01 · Retain

After an investigation has been resolved and validated, useful knowledge can be retained.

```text
Incident
   ↓
Evidence
   ↓
Investigation
   ↓
Resolution
   ↓
Lessons Learned
   ↓
Hindsight Retain
```

---

## 02 · Recall

When a new incident is investigated, relevant historical experience can be retrieved.

```text
New Incident
     ↓
Current Evidence
     ↓
Hindsight Recall
     ↓
Relevant Historical Experience
```

---

## 03 · Investigate

The recalled context is presented alongside current evidence.

```text
┌─────────────────────┐
│   CURRENT EVIDENCE  │
└──────────┬──────────┘
           │
           +
           │
┌──────────▼──────────┐
│ HISTORICAL CONTEXT  │
└──────────┬──────────┘
           │
           ▼
   ┌────────────────┐
   │AI INVESTIGATION│
   └────────────────┘
```

---

## 04 · Learn

The investigation outcome can then become part of the organization's future experience.

```text
RECALL
  ↓
INVESTIGATE
  ↓
RESOLVE
  ↓
LEARN
  ↓
RECALL AGAIN
```

This creates a continuous learning cycle between historical experience and future investigations.

---

# 🧪 Example: Learning From a Previous Incident

Consider an investigation involving:

```text
Encoded PowerShell
        +
Scheduled Task Persistence
        +
Malicious Attachment
```

The investigation determines:

```text
Root Cause:
Malicious attachment execution

Persistence:
Scheduled task

Successful Remediation:
Endpoint isolation
Scheduled task removal
Credential reset
```

The validated outcome can become organizational memory.

Later, a new incident produces suspicious PowerShell activity.

Instead of beginning with only:

> Suspicious PowerShell execution detected.

IncidentForge can retrieve the relevant historical experience.

The investigator may then recognize that a previous investigation associated similar behavior with scheduled-task persistence following malicious attachment execution.

The historical information does not replace current evidence.

It provides additional context for the investigation.

> [!TIP]
> **Memory provides context. Current evidence remains the foundation.**

---

# 🔎 Memory Trace

IncidentForge is designed to make historical influence visible.

An investigation can expose information such as:

```text
╔══════════════════════════════════════════════════╗
║                HINDSIGHT MEMORY                  ║
╠══════════════════════════════════════════════════╣
║                                                  ║
║ Relevant historical incidents recalled: 2        ║
║                                                  ║
║ INC-0871                                         ║
║ PowerShell Persistence                           ║
║                                                  ║
║ Resolution:                                      ║
║ Scheduled task removal                           ║
║                                                  ║
║ Lesson:                                          ║
║ Inspect persistence mechanisms early             ║
║                                                  ║
║ ──────────────────────────────────────────────── ║
║                                                  ║
║ INC-0914                                         ║
║ Malicious Attachment                             ║
║                                                  ║
║ Resolution:                                      ║
║ Endpoint isolation + credential reset            ║
║                                                  ║
║ Lesson:                                          ║
║ Review parent-child process relationships        ║
║                                                  ║
║ ──────────────────────────────────────────────── ║
║                                                  ║
║ Historical context used for:                     ║
║                                                  ║
║ ✓ Investigation hypothesis                       ║
║ ✓ Investigation steps                            ║
║ ✓ Remediation guidance                           ║
║                                                  ║
╚══════════════════════════════════════════════════╝
```

This creates an explicit relationship between:

```text
Historical Memory
       ↓
Retrieved Context
       ↓
Investigation
       ↓
Recommendation
```

---

# 🚫 No Forced Memory

Historical memory should not be injected into an investigation simply because it exists.

If no relevant historical experience is found:

```text
Incident
   ↓
Hindsight Recall
   ↓
No Relevant Memory
   ↓
Current Evidence
   ↓
Investigation
```

The system can explicitly indicate:

> **No relevant historical memory found. Investigation proceeds using current evidence.**

This keeps historical context relevant rather than forcing unrelated memories into the reasoning process.

---

# 🔍 Evidence-Aware AI Investigation

IncidentForge separates different information categories so that an analyst can distinguish evidence from interpretation.

| Category                  | Meaning                                                       | Example                                                                                  |
| :------------------------ | :------------------------------------------------------------ | :--------------------------------------------------------------------------------------- |
| 🟢 **OBSERVED**           | Directly supported by current telemetry.                      | A PowerShell process executed on the endpoint.                                           |
| 🔵 **HISTORICAL CONTEXT** | Information retrieved from previous investigations.           | A similar PowerShell persistence pattern was identified in a previous incident.          |
| 🟡 **INFERRED**           | Reasoning based on available evidence and historical context. | The current activity warrants investigation of scheduled-task persistence.               |
| 🟣 **RECOMMENDED**        | Suggested next steps for analyst review.                      | Inspect scheduled-task creation events and correlate them with the PowerShell execution. |

This distinction provides a structured path from:

```text
EVIDENCE
   ↓
CONTEXT
   ↓
REASONING
   ↓
RECOMMENDATION
```

without presenting every AI-generated statement as an observed fact.

---

# 🔄 Security Data Pipeline

IncidentForge processes security data through a structured pipeline.

```text
┌─────────────────────┐
│       UPLOAD        │
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│  SCHEMA DETECTION   │
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│    NORMALIZATION    │
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│   EVENT GENERATION  │
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│      DETECTION      │
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│     CORRELATION     │
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ INCIDENT GENERATION │
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│    ML RISK SCORE    │
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│  HINDSIGHT RECALL   │
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│  AI INVESTIGATION   │
└─────────────────────┘
```

This explicit pipeline makes data movement and processing stages easier to understand, test, and troubleshoot.

---

# 🎯 Detection & Correlation

IncidentForge transforms individual security events into higher-level incidents.

The correlation layer provides the bridge between:

```text
Individual Events
       ↓
Related Activity
       ↓
Correlated Behavior
       ↓
Security Incident
```

This allows the investigation layer to reason about an incident rather than treating every telemetry record as an independent event.

---

# 📊 Machine Learning Risk Scoring

IncidentForge includes a machine-learning pipeline based on the **TON_IoT Network Dataset**.

The current baseline workflow is:

```text
TON_IoT Network Dataset
        ↓
Feature Extraction
        ↓
25 Network-Derived Features
        ↓
Stratified Train/Test Split
        ↓
StandardScaler
        ↓
Logistic Regression
        ↓
Risk Scoring
```

## Baseline Evaluation

| Metric        |     Result |
| :------------ | ---------: |
| **Precision** | **0.9728** |
| **Recall**    | **0.9450** |
| **F1**        | **0.9587** |
| **ROC-AUC**   | **0.9843** |
| **PR-AUC**    | **0.9943** |

> [!NOTE]
> These results describe the current baseline evaluation configuration and should be interpreted within the documented dataset, preprocessing, split, and evaluation methodology.

The ML component provides an additional risk signal; it is not intended to replace the broader detection, correlation, and analyst investigation workflow.

---

# 🧾 Explainability & Provenance

IncidentForge is designed around traceable system outputs.

Important values should have an understandable origin.

### 📌 Incident Counts

```text
Incident Count
      ↓
Dataset
      ↓
Normalization
      ↓
Detection
      ↓
Correlation
      ↓
Incident Records
```

### 📌 ML Risk

```text
Risk Score
      ↓
Extracted Features
      ↓
Preprocessing
      ↓
Model
      ↓
Prediction
```

### 📌 Investigation Recommendations

```text
Recommendation
      ↓
Current Evidence
      +
Historical Memory
      ↓
AI Investigator
```

This allows system behavior to be investigated rather than treating the dashboard as a collection of unexplained numbers.

---

# 🤖 Responsible AI

IncidentForge is designed around analyst-controlled security operations.

The AI layer is intended to:

* Investigate
* Summarize
* Correlate
* Explain
* Surface historical context
* Recommend next steps

The analyst remains responsible for consequential decisions.

```text
                     AI
                      │
          ┌───────────┼───────────┐
          │           │           │
          ▼           ▼           ▼
     Investigate    Explain    Recommend
          │           │           │
          └───────────┼───────────┘
                      ▼
                HUMAN ANALYST
                      │
                      ▼
                   DECISION
```

> [!IMPORTANT]
>
> ## AI investigates. Memory informs. Humans decide.

---

# 🛡️ Response Governance

IncidentForge emphasizes controlled response rather than unrestricted autonomous execution.

The architecture incorporates:

* Analyst approval
* Advisory AI
* Simulation-oriented response
* Allowlisted actions
* Audit events
* Non-destructive execution boundaries

This allows the investigation system to provide actionable recommendations while preserving human control over operational response.

---

# 🧬 Memory Integrity

Organizational memory becomes valuable only when it remains trustworthy.

IncidentForge therefore treats validated investigation outcomes as the basis for retained knowledge.

```text
Current Evidence
      ↓
Investigation
      ↓
AI Analysis
      ↓
Analyst Review
      ↓
Validated Resolution
      ↓
Lessons Learned
      ↓
Organizational Memory
```

The investigator should not automatically convert unsupported speculation into trusted organizational knowledge.

> **Memory represents validated operational experience, not simply generated text.**

---

# 🧯 Failure Handling

Security systems must remain understandable when individual components fail.

IncidentForge accounts for failure conditions including:

* Hindsight unavailable
* Hindsight timeout
* Invalid datasets
* Unsupported schemas
* Empty datasets
* Malformed records
* Duplicate uploads
* Empty memory recall
* LLM unavailable
* Model unavailable
* No detections

### Graceful degradation

```text
              HINDSIGHT SERVICE
                      │
                      X
                      │
                      ▼
              MEMORY UNAVAILABLE
                      │
                      ▼
             INVESTIGATION CONTINUES
                      │
                      ▼
             MEMORY STATUS: DEGRADED
```

The memory layer is intended to enhance the security workflow without becoming a single point of failure for the entire investigation platform.

---

# 🏗️ Architecture

```text
                         SECURITY DATA
                              │
                              ▼
                    ┌──────────────────┐
                    │ Data Processing  │
                    │ & Normalization  │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │    Detection     │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │   Correlation    │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │    Incident      │
                    └────────┬─────────┘
                             │
                  ┌──────────┴──────────┐
                  │                     │
                  ▼                     ▼
           ┌─────────────┐       ┌─────────────┐
           │ ML Risk     │       │  Hindsight  │
           │ Scoring     │       │   Recall    │
           └──────┬──────┘       └──────┬──────┘
                  │                     │
                  └──────────┬──────────┘
                             ▼
                    ┌──────────────────┐
                    │ AI Investigator  │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ Analyst Review   │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │    Resolution    │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ Hindsight Retain │
                    └────────┬─────────┘
                             │
                             ▼
                 ┌────────────────────────┐
                 │ ORGANIZATIONAL MEMORY  │
                 └────────────┬───────────┘
                              │
                              ▼
                       FUTURE INCIDENTS
```

---

# 📁 Project Structure

```text
IncidentForge-2.0/
│
├── backend/
├── dashboard/
│
├── datasets/
│   └── public/
│       └── TON_IoT/
│
├── ai-investigator/
├── detection/
├── correlation/
├── pipeline/
├── response-engine/
├── ml/
│
├── docs/
│   ├── architecture.md
│   ├── hindsight.md
│   ├── memory-model.md
│   ├── demo.md
│   ├── dataset-pipeline.md
│   └── evaluation.md
│
├── tests/
│
├── .env.example
├── pyproject.toml
└── README.md
```

The project is organized around distinct responsibilities including:

* Data processing
* Detection
* Correlation
* Machine learning
* AI investigation
* Organizational memory
* Response governance
* Testing
* Documentation

---

# 🔬 Core Investigation Workflow

```text
01  Upload Security Data
          ↓
02  Detect & Normalize Schema
          ↓
03  Generate Security Events
          ↓
04  Detect Suspicious Activity
          ↓
05  Correlate Related Events
          ↓
06  Create Security Incident
          ↓
07  Calculate ML Risk
          ↓
08  Recall Historical Experience
          ↓
09  Investigate With AI
          ↓
10  Review Evidence & Context
          ↓
11  Analyst Decision
          ↓
12  Resolve Incident
          ↓
13  Retain Validated Learning
          ↓
14  Improve Future Investigations
```

---

# 🧠 A Security System With Memory

The difference can be represented simply.

### Conventional workflow

```text
Incident
   ↓
Investigation
   ↓
Resolution
   ↓
Next Incident
   ↓
Investigation
```

### IncidentForge workflow

```text
Incident
   ↓
Investigation
   ↓
Resolution
   ↓
Learning
   ↓
Organizational Memory
   ↓
Next Incident
   ↓
Historical Recall
   ↓
Contextual Investigation
   ↓
Resolution
   ↓
New Learning
```

> **The system creates a feedback loop between what the organization has experienced and what it investigates next.**

---

# 🧩 Design Principles

| Principle                   | Meaning                                                                                                    |
| :-------------------------- | :--------------------------------------------------------------------------------------------------------- |
| 🔍 **Evidence First**       | Current security evidence remains the foundation of every investigation.                                   |
| 🧠 **Memory With Purpose**  | The memory layer focuses on useful investigation experience rather than indiscriminately storing raw data. |
| 🧾 **Explainable Context**  | Historical information and current evidence remain distinguishable.                                        |
| 👤 **Human Control**        | AI provides analysis and recommendations while analysts remain responsible for consequential decisions.    |
| 🧯 **Graceful Degradation** | Failure of an optional service should not unnecessarily break the complete investigation workflow.         |
| 🔁 **Reproducibility**      | Data processing, model evaluation, and system behavior should be reproducible from documented workflows.   |
| 🧬 **Continuous Learning**  | Resolved incidents can contribute to future organizational knowledge.                                      |

---

# 📚 Documentation

Detailed technical documentation is organized under `docs/`.

| Document                      | Description                                                                                |
| :---------------------------- | :----------------------------------------------------------------------------------------- |
| 🏗️ `docs/architecture.md`    | System components, boundaries, and data flow.                                              |
| 🧠 `docs/hindsight.md`        | Memory architecture, recall, retention, and integration.                                   |
| 🧬 `docs/memory-model.md`     | What constitutes organizational knowledge and how investigation experience is represented. |
| 🔄 `docs/dataset-pipeline.md` | Dataset ingestion, normalization, processing, and event generation.                        |
| 🎬 `docs/demo.md`             | End-to-end workflow for running the system.                                                |
| 📊 `docs/evaluation.md`       | Machine-learning and system evaluation methodology.                                        |

---

# 🚀 Quick Start

## 01 · Clone the repository

```bash
git clone https://github.com/hasinivinnakota/IncidentForge-2.0.git
cd IncidentForge-2.0
```

## 02 · Configure the environment

```bash
cp .env.example .env
```

Configure the required services and credentials according to the project documentation.

## 03 · Install dependencies

```bash
pip install -e .
```

## 04 · Run the application

Use the documented application startup command for the current project configuration.

## 05 · Run tests

```bash
pytest
```

---

# 🛠️ Development

IncidentForge is structured so that individual subsystems can be developed and tested independently.

```text
┌──────────────────────────────┐
│       DATA INGESTION         │
├──────────────────────────────┤
│ Schema Detection             │
│ Normalization                │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│          DETECTION           │
├──────────────────────────────┤
│ Rules                        │
│ Event Analysis               │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│         CORRELATION          │
├──────────────────────────────┤
│ Incident Construction        │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│             ML               │
├──────────────────────────────┤
│ Feature Engineering          │
│ Training                     │
│ Risk Scoring                 │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│      AI INVESTIGATION        │
├──────────────────────────────┤
│ Evidence                     │
│ Historical Context           │
│ Recommendations              │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│          HINDSIGHT           │
├──────────────────────────────┤
│ Retain                       │
│ Recall                       │
│ Organizational Memory        │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│           RESPONSE           │
├──────────────────────────────┤
│ Governance                   │
│ Approval                     │
│ Audit                        │
└──────────────────────────────┘
```

---

# ✨ Current Capabilities

IncidentForge brings together:

|     | Capability                        |
| :-: | :-------------------------------- |
| 🗂️ | Security dataset ingestion         |
|  🔎 | Schema detection                  |
|  🔄 | Data normalization                |
|  ⚡  | Event generation                 |
|  🎯 | Detection engineering             |
|  🔗 | Event correlation                 |
|  🚨 | Incident creation                 |
|  📊 | ML-based risk scoring             |
|  🤖 | AI-assisted investigation         |
|  🧠 | Hindsight-based historical recall |
|  🧬 | Organizational memory             |
|  💡 | Memory-aware recommendations      |
|  🔍 | Evidence-aware investigation      |
|  👤 | Analyst-controlled response       |
| 🛡️ | Response governance                |
|  🧾 | Auditability                      |
|  🧯 | Failure handling                  |
|  🧪 | Automated testing                 |
|  📚 | Technical documentation           |

---

# 🚀 Future Direction

IncidentForge's architecture provides a foundation for progressively richer organizational security intelligence.

Potential future directions include:

* More sophisticated incident memory representations
* Improved memory validation
* Richer historical investigation traces
* Expanded dataset adapters
* Additional detection strategies
* More detailed analyst feedback loops
* Improved investigation explainability
* Broader security telemetry integrations
* Continuous evaluation of memory usefulness
* Stronger measurement of investigation efficiency and quality

The long-term objective is not simply to build a smarter alert dashboard.

> **It is to build a security system that can accumulate, preserve, and reuse organizational experience.**

---

# 💭 Philosophy

Security teams continuously learn.

Every investigation produces information about:

* attacker behavior
* infrastructure
* detection patterns
* investigation techniques
* root causes
* remediation
* mistakes
* successful decisions
* lessons worth remembering

That knowledge should not disappear when an incident is closed.

IncidentForge turns the incident lifecycle into a learning lifecycle:

```text
             ┌─────────────────────────┐
             │      SECURITY DATA      │
             └────────────┬────────────┘
                          ▼
                     DETECTION
                          ▼
                    INVESTIGATION
                          ▼
                     RESOLUTION
                          ▼
                   LESSONS LEARNED
                          ▼
                ORGANIZATIONAL MEMORY
                          │
                          │
                          ▼
                  FUTURE INCIDENT
                          │
                          ▼
                    HINDSIGHT RECALL
                          │
                          ▼
                  BETTER CONTEXT
                          │
                          ▼
                    INVESTIGATION
                          │
                          └───────────────┐
                                          │
                                          ▼
                                   NEW KNOWLEDGE
                                          │
                                          └───────►
                                          
```

---

# ⚡ IncidentForge 2.0

<p align="center">

## **Security Operations That Learn From Experience.**

### Detect. Recall. Investigate. Resolve. Learn.

</p>

<p align="center">

**AI investigates. Memory informs. Humans decide.**

</p>

---

<p align="center">
  <sub>IncidentForge 2.0 — Turning incident response into organizational learning.</sub>
</p>


