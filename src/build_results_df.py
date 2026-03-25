"""
build_results_df.py - Consolidate all smoke test outputs into one master results DataFrame.

Reads every smoke_test_*.json file from results/, runs the classifier on each
response, enriches each row with technique and severity from the attack dataset,
and saves a single master_results.json.

Each row in the output represents one prompt run against one model and contains:
    prompt_id           - unique prompt identifier (e.g. jb_001)
    model               - which LLM was tested
    category            - attack category (jailbreak / prompt_injection / pii_extraction)
    subcategory         - attack subcategory (many_shot, crescendo, etc.)
    technique           - specific technique name from the attack dataset
    severity            - high / medium / low (from attack dataset)
    prompt_text         - the full attack prompt
    # response_preview    - first 300 chars of the model response
    response_text       - full model response
    defense_active      - whether a defence was active during this run
    label               - VULNERABLE / PARTIAL / SAFE
    confidence          - classifier confidence (0.0 - 1.0)
    classification_stage- rule_based / embedding
    guardrail_bypassed  - True if label == VULNERABLE (attack fully succeeded)
    attack_partial      - True if label == PARTIAL (model helped despite disclaimer)

Run from project root:
    python src/build_results_df.py
"""

import importlib.util
import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent))
import config
from classifier import ResponseClassifier

# ── Load attack dataset for technique / severity lookup ───────────────────────

def _load_attack_lookup() -> dict[str, dict]:
    """
    Return a dict mapping prompt_id → {technique, severity, notes}
    by importing jailbreak.py from the project root.
    """
    root = Path(__file__).parent.parent
    spec = importlib.util.spec_from_file_location("jailbreak", root / "jailbreak.py")
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    lookup = {}
    for prompt in mod.ALL_PROMPTS:
        lookup[prompt["id"]] = {
            "technique": prompt.get("technique", ""),
            "severity":  prompt.get("severity",  ""),
            "notes":     prompt.get("notes",     ""),
        }
    return lookup


def build() -> pd.DataFrame:
    """
    Read all smoke_test_*.json files, classify every response, enrich with
    attack metadata, and pivot to one row per prompt with each model's
    response, label, and confidence as separate columns.
    """
    smoke_files = sorted(config.RESULTS_DIR.glob("smoke_test_*.json"))

    if not smoke_files:
        print("No smoke_test_*.json files found in results/.")
        print("Run: python src/test_model_runner.py --prompts jailbreak --model <model>")
        return pd.DataFrame()

    print(f"Found {len(smoke_files)} smoke test file(s):")
    for f in smoke_files:
        print(f"  {f.name}")

    attack_lookup = _load_attack_lookup()
    clf           = ResponseClassifier()
    all_frames    = []

    # ── Classify each file ────────────────────────────────────────────────────
    for path in smoke_files:
        print(f"\nClassifying: {path.name} ...")
        df = pd.read_json(path)

        labels, stages, confs = [], [], []
        for _, row in df.iterrows():
            label, stage, conf = clf.classify(row["response_text"], row["category"])
            labels.append(label)
            stages.append(stage)
            confs.append(round(conf, 4))

        df["label"]                = labels
        df["confidence"]           = confs
        df["classification_stage"] = stages
        df["guardrail_bypassed"]   = df["label"] == "VULNERABLE"
        df["attack_partial"]       = df["label"] == "PARTIAL"
        # df["response_preview"]     = df["response_text"].str.slice(0, 300)
        all_frames.append(df)

    long = pd.concat(all_frames, ignore_index=True)
    models = sorted(long["model"].unique())

    # ── Enrich long frame with attack metadata ────────────────────────────────
    long["technique"] = long["prompt_id"].map(
        lambda pid: attack_lookup.get(pid, {}).get("technique", "unknown")
    )
    long["severity"] = long["prompt_id"].map(
        lambda pid: attack_lookup.get(pid, {}).get("severity", "unknown")
    )
    long["notes"] = long["prompt_id"].map(
        lambda pid: attack_lookup.get(pid, {}).get("notes", "")
    )

    # ── Build wide (one row per prompt) ───────────────────────────────────────
    # Static columns — identical across all models for a given prompt
    static_cols = ["prompt_id", "category", "subcategory", "technique",
                   "severity", "prompt_text", "notes"]
    static = (
        long[static_cols]
        .drop_duplicates(subset="prompt_id")
        .set_index("prompt_id")
    )

    # Per-model columns
    model_frames = []
    for model in models:
        m = long[long["model"] == model].set_index("prompt_id")
        per_model = m[[
            # "response_preview",
            "response_text",
            "label",
            "confidence",
            "classification_stage",
            "guardrail_bypassed",
            "attack_partial",
        ]].rename(columns=lambda c: f"{model}_{c}")
        model_frames.append(per_model)

    wide = static.join(model_frames, how="left").reset_index()

    # ── Save ──────────────────────────────────────────────────────────────────
    out_path = config.RESULTS_DIR / "master_results.json"
    wide.to_json(out_path, orient="records", indent=2, force_ascii=False)

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{'='*65}")
    print(f"  Master results: {len(wide)} prompts × {len(models)} models")
    print(f"  Models: {', '.join(models)}")
    print(f"{'='*65}")

    # Per-model ASR from long frame
    print(f"\n  {'Model':<20} {'Total':>6} {'VULN':>6} {'PARTIAL':>8} {'SAFE':>6}  {'ASR':>6}")
    print(f"  {'-'*58}")
    for model in models:
        grp     = long[long["model"] == model]
        total   = len(grp)
        vuln    = (grp["label"] == "VULNERABLE").sum()
        partial = (grp["label"] == "PARTIAL").sum()
        safe    = (grp["label"] == "SAFE").sum()
        asr     = vuln / total if total else 0
        print(f"  {model:<20} {total:>6} {vuln:>6} {partial:>8} {safe:>6}  {asr:>5.0%}")

    # Per-technique ASR (jailbreak only, across all models)
    jb = long[long["category"] == "jailbreak"]
    if not jb.empty:
        print(f"\n  Jailbreak ASR by technique (all models combined):")
        print(f"  {'Technique':<30} {'Total':>6} {'VULN':>6}  {'ASR':>6}")
        print(f"  {'-'*50}")
        for tech, grp in jb.groupby("technique"):
            total = len(grp)
            vuln  = (grp["label"] == "VULNERABLE").sum()
            asr   = vuln / total if total else 0
            print(f"  {tech:<30} {total:>6} {vuln:>6}  {asr:>5.0%}")

    print(f"\n  Saved → {out_path}\n")
    return wide


if __name__ == "__main__":
    build()
