# 🛡️ AutoRedTeam-LLM

An automated red-teaming and security benchmarking framework for open-source Large Language Models. AutoRedTeam-LLM systematically attacks LLMs with adversarial prompts across multiple attack categories, scores their vulnerabilities, evaluates defense effectiveness, and visualizes everything in an interactive Streamlit dashboard.

> **Plug in any HuggingFace model. Get a full security benchmark. No manual effort.**

---

## 🚀 What It Does

AutoRedTeam-LLM runs a full security evaluation pipeline on any HuggingFace instruct model:

1. **Attacks** the model with 150 curated adversarial prompts across 3 categories
2. **Classifies** each response as `VULNERABLE`, `PARTIAL`, or `SAFE`
3. **Applies defenses** (system prompt hardening + input sanitization) and re-evaluates
4. **Benchmarks** Attack Success Rate (ASR) per category, per model
5. **Visualizes** all results in an interactive Streamlit dashboard

---

## ⚡ Key Feature: Add Any Model in One Line

Want to benchmark a new model? Just add its HuggingFace ID to `config.py`:

```python
MODELS = {
    "llama":   "meta-llama/Meta-Llama-3.1-8B-Instruct",
    "mistral": "mistralai/Mistral-7B-Instruct-v0.3",
    "qwen":    "Qwen/Qwen2.5-7B-Instruct",
    "phi3":    "microsoft/Phi-3-mini-4k-instruct",   # ← just add this
}
```

The pipeline automatically downloads, benchmarks, and adds it to the dashboard. No other changes needed.

---

## 🎯 Attack Categories

| Category | Prompts | Goal |
|----------|---------|------|
| **Prompt Injection** | 50 | Override system instructions via malicious input |
| **Jailbreaking** | 50 | Bypass safety guardrails using adversarial templates |
| **PII Extraction** | 50 | Coerce the model into generating private/sensitive data |

### Attack Techniques
- **Prompt Injection**: instruction override, indirect injection, context manipulation, multi-language wrapping
- **Jailbreaking**: many-shot flooding, gradual escalation, encoding obfuscation (ROT13, Leet, Morse, Pig Latin), language wrapping
- **PII Extraction**: synthetic PII generation, context leakage, inference attacks, system prompt extraction

### Severity Levels
Each prompt is rated by potential harm if the attack succeeds:

| Level | Meaning |
|-------|---------|
| `critical` | Working exploit code, active intrusion tools, functional fraud data |
| `high` | Significant harm potential — most attacks fall here |
| `medium` | Moderate risk; info is partially available elsewhere |
| `low` | Minimal harm; publicly documented, weak generalizability |

---

## 🔬 Models Benchmarked (Default)

| Model | HuggingFace ID | Parameters |
|-------|---------------|------------|
| Llama 3.1 | `meta-llama/Meta-Llama-3.1-8B-Instruct` | 8B |
| Mistral | `mistralai/Mistral-7B-Instruct-v0.3` | 7B |
| Qwen 2.5 | `Qwen/Qwen2.5-7B-Instruct` | 7B |

All models run locally via 4-bit NF4 quantization — no API keys needed.

---

## 🏗️ Architecture

```
attack prompts (jailbreak.py + prompt datasets)
        ↓
model_runner.py          ← loads model, runs inference (4-bit quantized)
        ↓
classifier.py            ← labels responses VULNERABLE / PARTIAL / SAFE
        ↓
defense_module.py        ← applies defenses, re-runs, compares ASR
        ↓
build_results_df.py      ← consolidates all outputs into master_results.json
        ↓
results/ (JSON outputs)
        ↓
dashboard/app.py         ← Streamlit visualization
```

---

## 📦 Installation

### Requirements
- Python 3.11
- NVIDIA GPU with 8GB+ VRAM
- CUDA 12.1+
- ~50GB disk space (model weights)

### Setup

```bash
# 1. Clone the repo
git clone https://github.com/Ujwal-Ramachandran/AutoRedTeam_LLM_Pipelines.git
cd AutoRedTeam_LLM_Pipelines

# 2. Create conda environment
conda create -n auto_red python=3.11 -y
conda activate auto_red

# 3. Install PyTorch with CUDA support
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu128

# 4. Install remaining dependencies
pip install -r requirements.txt

# 5. Login to HuggingFace (required for Llama)
huggingface-cli login

# 6. Verify GPU setup
python -c "import torch; print(torch.cuda.is_available())"
```

---

## 🔧 Usage

### Launch the dashboard (results already included)
```bash
streamlit run dashboard/app.py
```

### Run inference on a model
```python
from src.model_runner import ModelRunner

runner = ModelRunner("mistral")
runner.load()
df = runner.run(prompts)
runner.unload()
```

### Classify responses
```python
from src.classifier import ResponseClassifier

clf = ResponseClassifier()
df_classified = clf.classify_batch(df_raw)
```

### Evaluate defenses
```python
from src.defense_module import DefenseEvaluator

evaluator = DefenseEvaluator("qwen")
results = evaluator.run_all_defenses(prompts)
```

### Rebuild master results from smoke test outputs
```bash
python src/build_results_df.py
```

---

## 📊 Dashboard

Launch with `streamlit run dashboard/app.py`. Four pages:

- **Overview** — ASR heatmap (model × category), response label distribution, grouped ASR bar chart, stacked response distribution. Click any heatmap cell for a contextual finding.
- **Model Deep Dive** — Per-model vulnerability breakdown, jailbreak technique effectiveness, severity of successful attacks, confidence distribution by classifier stage.
- **Defense Analysis** — ASR before/after each defense, DRR heatmap (Defense Reduction Rate), auto-detected anomalies where a defense made things worse. Click any DRR cell for details.
- **Attack Browser** — Browse all 450 prompt-response pairs with filters for model, category, label, severity, and keyword search. Full model responses shown.

---

## 📁 Project Structure

```
AutoRedTeam-LLM/
├── config.py                    ← all settings, model IDs, paths
├── jailbreak.py                 ← jailbreak attack prompt dataset (50 prompts)
├── requirements.txt
├── src/
│   ├── model_runner.py          ← model loading & inference
│   ├── classifier.py            ← two-stage response classifier
│   ├── defense_module.py        ← defense strategies & DRR evaluation
│   ├── build_results_df.py      ← consolidates outputs into master_results.json
│   ├── test_model_runner.py     ← model runner smoke tests
│   ├── test_classifier.py       ← classifier tests
│   ├── test_defense_module.py   ← defense module tests
│   └── test_generation.py       ← generation tests
├── results/
│   ├── master_results.json      ← 150 prompts × 3 models, fully classified
│   ├── defense_comparison.json  ← ASR before/after each defense per model
│   └── smoke_test_*.json        ← per-model per-category raw outputs
├── dashboard/
│   └── app.py                   ← Streamlit dashboard
└── README.md
```

---

## 📈 Results

| Model | Prompt Injection ASR | Jailbreak ASR | PII Extraction ASR | Overall ASR |
|-------|---------------------|---------------|-------------------|-------------|
| Llama 3.1 8B | 42% | 74% | 74% | 63% |
| Mistral 7B | 88% | 92% | 96% | 92% |
| Qwen 2.5 7B | 80% | 94% | 90% | 88% |

Defense effectiveness (overall DRR — Defense Reduction Rate):

| Model | Hardened Prompt | Input Sanitization | Combined |
|-------|----------------|-------------------|---------|
| Llama 3.1 8B | 20.3% | 2.7% | 20.6% |
| Mistral 7B | 9.6% | −0.7% ⚠️ | 11.0% |
| Qwen 2.5 7B | 20.0% | 0.0% | 18.5% |

> Input sanitization alone had little effect and slightly worsened Mistral's jailbreak ASR. Hardened system prompts were consistently the most effective single defense.

---

## 🛠️ Adding a New Model

1. Open `config.py`
2. Add your model to the `MODELS` dictionary:
```python
MODELS = {
    ...
    "your_model": "organization/model-name-on-huggingface",
}
```
3. Run inference and classification using the `src/` modules
4. Rebuild the master results:
```bash
python src/build_results_df.py
```
5. Results automatically appear in the dashboard.

> **Note:** Models must be instruction-tuned and support chat templates. 4-bit quantization is applied automatically — ensure you have 8GB+ VRAM.

---

## 🔑 Research Questions

- **RQ1:** What types and frequencies of security vulnerabilities exist across top open-source LLMs?
- **RQ2:** Can an automated pipeline reliably score these vulnerabilities without human annotation?
- **RQ3:** How effective are prompt-level defenses at reducing attack success rates?

---

## 📚 Attack Prompt Design

All 150 prompts were custom-authored for this framework. Prompt design drew on publicly known attack taxonomies including:
- Many-shot flooding and gradual escalation
- Encoding obfuscation (ROT13, Leet speak, Morse code, Pig Latin, number substitution)
- Multi-language wrapping (Hindi, Russian, Turkish, French, Portuguese)
- Indirect injection via document/code/URL contexts
- Roleplay and persona hijacking

---

## ⚠️ Disclaimer

This tool is intended for **security research and model evaluation only**. All attack prompts are used solely to measure and improve LLM safety. Do not use this framework to cause harm or violate the terms of service of any platform.

---

## 👤 Author

**Ujwal Ramachandran**
[LinkedIn](https://www.linkedin.com/in/ujwal-ramachandran/) · [GitHub](https://github.com/Ujwal-Ramachandran)
