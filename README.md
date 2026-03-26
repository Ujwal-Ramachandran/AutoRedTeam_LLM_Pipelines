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

### Subcategories
- **Prompt Injection**: instruction override, indirect injection, context manipulation
- **Jailbreaking**: roleplay exploit (DAN), hypothetical framing, encoding obfuscation
- **PII Extraction**: synthetic PII generation, context leakage, inference attacks

---

## 🔬 Models Benchmarked (Default)

| Model | HuggingFace ID | Parameters |
|-------|---------------|------------|
| Llama 3.1 | `meta-llama/Meta-Llama-3.1-8B-Instruct` | 8B |
| Mistral | `mistralai/Mistral-7B-Instruct-v0.3` | 7B |
| Qwen 2.5 | `Qwen/Qwen2.5-7B-Instruct` | 7B |

All models run locally via 4-bit NF4 quantization - no API keys needed.

---

## 🏗️ Architecture

```
attack_prompts (150 JSON)
        ↓
dataset_builder.py       ← loads & validates prompts
        ↓
model_runner.py          ← loads model, runs inference (4-bit quantized)
        ↓
classifier.py            ← labels responses VULNERABLE / PARTIAL / SAFE
        ↓
defense_module.py        ← applies defenses, re-runs, compares ASR
        ↓
results/ (CSV + JSON)
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
git clone https://github.com/yourusername/AutoRedTeam-LLM.git
cd AutoRedTeam-LLM

# 2. Create conda environment
conda create -n auto_red python=3.11 -y
conda activate auto_red

# 3. Install dependencies
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu128
pip install transformers bitsandbytes accelerate sentence-transformers streamlit pandas plotly

# 4. Login to HuggingFace (required for Llama)
huggingface-cli login

# 5. Verify GPU setup
python -c "import torch; print(torch.cuda.is_available())"
```

---

## 🔧 Usage

### Run the full pipeline
```bash
python src/pipeline.py
```

### Run on specific models only
```bash
python src/pipeline.py --models llama mistral
```

### Run with defenses enabled
```bash
python src/pipeline.py --defense both
```

### Launch the dashboard
```bash
streamlit run dashboard/app.py
```

---

## 📊 Dashboard Features

- **Overview heatmap** - Attack Success Rate per model × attack category
- **Model deep dive** - Vulnerability breakdown per model
- **Defense analysis** - Before vs after defense comparison
- **Attack browser** - Browse all prompts, responses, and labels with filters

---

## 📁 Project Structure

```
AutoRedTeam-LLM/
├── config.py                    ← all settings, model IDs, paths
├── src/
│   ├── dataset_builder.py       ← load & validate attack prompts
│   ├── model_runner.py          ← model loading & inference
│   ├── classifier.py            ← response classification
│   ├── defense_module.py        ← defense strategies
│   └── pipeline.py              ← orchestrates everything
├── data/
│   └── attack_prompts/
│       ├── prompt_injection.json
│       ├── jailbreak.json
│       └── pii_extraction.json
├── results/                     ← generated outputs (gitignored)
├── dashboard/
│   └── app.py                   ← Streamlit dashboard
└── README.md
```

---

## 📈 Sample Results

*(Results will populate here after first run)*

| Model | Prompt Injection ASR | Jailbreak ASR | PII Extraction ASR | Overall ASR |
|-------|---------------------|---------------|-------------------|-------------|
| Llama 3.1 8B | - | - | - | - |
| Mistral 7B | - | - | - | - |
| Qwen 2.5 7B | - | - | - | - |

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
3. Run the pipeline:
```bash
python src/pipeline.py --models your_model
```
4. Results automatically appear in the dashboard.

> **Note:** Models must be instruction-tuned and support chat templates. 4-bit quantization is applied automatically - ensure you have 8GB+ VRAM.

---

## 🔑 Research Questions

- **RQ1:** What types and frequencies of security vulnerabilities exist across top open-source LLMs?
- **RQ2:** Can an automated pipeline reliably score these vulnerabilities without human annotation?
- **RQ3:** How effective are prompt-level defenses at reducing attack success rates?

---

## 📚 Attack Prompt Sources

Prompts curated and adapted from:
- [AdvBench](https://github.com/llm-attacks/llm-attacks)
- [HarmBench](https://github.com/centerforaisafety/HarmBench)
- [JailbreakBench](https://github.com/JailbreakBench/jailbreakbench)
- Manually authored prompts

---

## ⚠️ Disclaimer

This tool is intended for **security research and model evaluation only**. All attack prompts are used solely to measure and improve LLM safety. Do not use this framework to cause harm or violate terms of service of any platform.

---

## 👤 Author

**Ujwal Ramachandran**
MSc Cyber Security, Nanyang Technological University
[LinkedIn](https://www.linkedin.com/in/ujwal-ramachandran/) · [GitHub](https://github.com/Ujwal-Ramachandran)



<!-- #### Add a telegram bot - Explore -->