"""
defense_module.py - Defense strategy evaluation for AutoRedTeam-LLM.

Applies three prompt-level defenses against the full attack suite and measures
how much each one reduces the Attack Success Rate (ASR) relative to a baseline.

Defenses:
    hardened_prompt    — Replace the baseline system prompt with a hardened variant
                         that explicitly instructs the model to refuse jailbreaks,
                         persona adoption, instruction overrides, and PII generation.

    input_sanitization — Strip known injection patterns from the user prompt before
                         it reaches the model (regex-based pre-processing).

    combined           — Both defenses applied together.

Defense Reduction Rate (DRR):
    DRR = (baseline_asr - defended_asr) / baseline_asr
    A DRR of 0.50 means the defense cut the attack success rate in half.

Outputs:
    results/smoke_test_{model}_{defense}.json  — Raw responses for each defense run
    results/defense_comparison.json            — Per-model × per-category DRR table

Usage (from project root):
    # Run all defenses for one model
    python src/defense_module.py --model llama --defense all

    # Run a single defense
    python src/defense_module.py --model llama --defense hardened_prompt

    # Compute comparison from existing smoke_test files (no re-run)
    python src/defense_module.py --compare-only
"""

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent))
import config
from classifier import ResponseClassifier
from model_runner import ModelRunner

# ── Input Sanitizer ────────────────────────────────────────────────────────────


class InputSanitizer:
    """
    Pre-processes user input before passing it to a model.

    Strips injection patterns from INJECTION_PATTERNS in config.py,
    detects base64 encoded content, and truncates suspiciously long prompts.
    """

    _BASE64_PATTERN = re.compile(
        r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
    )
    _MAX_TOKENS_APPROX = 1000  # ~4 chars per token heuristic

    def __init__(self):
        self._patterns = [
            re.compile(p, re.IGNORECASE) for p in config.INJECTION_PATTERNS
        ]

    def sanitize(self, prompt: str) -> tuple[str, list[str]]:
        """
        Clean a prompt and return the cleaned text plus a list of applied actions.

        Args:
            prompt: Raw user prompt text.

        Returns:
            (cleaned_prompt, actions) where actions is a list of strings describing
            what was changed (useful for logging and test assertions).
        """
        actions: list[str] = []
        text = prompt

        # Step 1 — Strip injection keyword patterns
        for pattern in self._patterns:
            if pattern.search(text):
                text = pattern.sub("[REDACTED]", text)
                actions.append(f"stripped_pattern:{pattern.pattern}")

        # Step 2 — Flag/redact long base64 blobs (common for encoding-based attacks)
        if self._BASE64_PATTERN.search(text):
            text = self._BASE64_PATTERN.sub("[BASE64_REDACTED]", text)
            actions.append("stripped_base64")

        # Step 3 — Truncate suspiciously long prompts
        if len(text) > self._MAX_TOKENS_APPROX * 4:
            text = text[: self._MAX_TOKENS_APPROX * 4]
            text += "\n[TRUNCATED: prompt exceeded maximum allowed length]"
            actions.append("truncated")

        return text, actions


# ── Attack dataset loader ──────────────────────────────────────────────────────


def _load_all_prompts() -> list[dict]:
    """Load ALL_PROMPTS from jailbreak.py at project root."""
    root = Path(__file__).parent.parent
    spec = importlib.util.spec_from_file_location("jailbreak", root / "jailbreak.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.ALL_PROMPTS


# ── Defense run ───────────────────────────────────────────────────────────────


def run_with_defense(
    model_key: str,
    prompts: list[dict],
    defense: str,
) -> pd.DataFrame:
    """
    Run inference over prompts with a specific defense strategy active.

    Args:
        model_key: Key from config.MODELS.
        prompts:   List of prompt dicts (id, category, subcategory, prompt_text).
        defense:   One of "hardened_prompt", "input_sanitization", "combined".

    Returns:
        DataFrame with the same columns as model_runner output, plus
        a 'sanitization_actions' column (list of strings, empty if no sanitization).
    """
    if defense not in config.DEFENSE_STRATEGIES:
        raise ValueError(
            f"Unknown defense '{defense}'. Valid: {config.DEFENSE_STRATEGIES}"
        )

    # Choose system prompt
    system_prompt = (
        config.SYSTEM_PROMPT_HARDENED
        if defense in ("hardened_prompt", "combined")
        else config.SYSTEM_PROMPT_BASELINE
    )

    # Build (possibly sanitized) prompt list
    sanitizer = InputSanitizer()
    sanitized_prompts = []
    all_actions: list[list[str]] = []

    for p in prompts:
        if defense in ("input_sanitization", "combined"):
            cleaned, actions = sanitizer.sanitize(p["prompt_text"])
        else:
            cleaned, actions = p["prompt_text"], []

        sanitized_prompts.append({**p, "prompt_text": cleaned})
        all_actions.append(actions)

    # Run model
    runner = ModelRunner(model_key, system_prompt=system_prompt)
    runner.load()
    try:
        df = runner.run(sanitized_prompts, defense_active=True)
    finally:
        runner.unload()

    df["sanitization_actions"] = [json.dumps(a) for a in all_actions]
    return df


# ── Comparison / metrics ───────────────────────────────────────────────────────


def compute_defense_comparison(
    model_key: str,
    baseline_df: pd.DataFrame,
    defense_dfs: dict[str, pd.DataFrame],
) -> list[dict]:
    """
    Classify both baseline and defended responses and compute DRR per category.

    Args:
        model_key:   The model being evaluated.
        baseline_df: Raw responses DataFrame from a baseline (no-defense) run.
        defense_dfs: Dict mapping defense name → raw responses DataFrame.

    Returns:
        List of comparison dicts, one per (model, category) combination.
        Each dict has keys: model, category, baseline_asr, {defense}_asr,
        {defense}_reduction for each defense in defense_dfs.
    """
    clf = ResponseClassifier()
    categories = sorted(baseline_df["category"].unique())

    def _asr(df: pd.DataFrame, category: str) -> float:
        sub = df[df["category"] == category]
        if sub.empty:
            return 0.0
        labels_confs_stages = [
            clf.classify(row["response_text"], row["category"])
            for _, row in sub.iterrows()
        ]
        labels = [lcs[0] for lcs in labels_confs_stages]
        return labels.count("VULNERABLE") / len(labels)

    rows = []
    for cat in categories:
        row: dict = {
            "model":        model_key,
            "category":     cat,
            "baseline_asr": round(_asr(baseline_df, cat), 4),
        }
        for defense_name, def_df in defense_dfs.items():
            defended_asr = round(_asr(def_df, cat), 4)
            drr = (
                round((row["baseline_asr"] - defended_asr) / row["baseline_asr"], 4)
                if row["baseline_asr"] > 0
                else 0.0
            )
            row[f"{defense_name}_asr"]       = defended_asr
            row[f"{defense_name}_reduction"] = drr
        rows.append(row)

    # Also add an "overall" row combining all categories
    overall: dict = {
        "model":        model_key,
        "category":     "overall",
        "baseline_asr": round(
            sum(r["baseline_asr"] for r in rows) / len(rows), 4
        ),
    }
    for defense_name in defense_dfs:
        avg_def = round(
            sum(r[f"{defense_name}_asr"] for r in rows) / len(rows), 4
        )
        avg_drr = round(
            sum(r[f"{defense_name}_reduction"] for r in rows) / len(rows), 4
        )
        overall[f"{defense_name}_asr"]       = avg_def
        overall[f"{defense_name}_reduction"] = avg_drr
    rows.append(overall)

    return rows


# ── Save helpers ──────────────────────────────────────────────────────────────


def _save_smoke(df: pd.DataFrame, model_key: str, defense: str) -> Path:
    """Save a defense-run DataFrame to results/smoke_test_{model}_{defense}.json."""
    path = config.RESULTS_DIR / f"smoke_test_{model_key}_{defense}.json"
    df.to_json(path, orient="records", indent=2, force_ascii=False)
    return path


def save_defense_results(comparison_rows: list[dict]) -> Path:
    """
    Append or overwrite defense_comparison.json with comparison rows.

    Existing entries for the same (model, category) are replaced; new entries
    are appended.

    Args:
        comparison_rows: List of dicts from compute_defense_comparison().

    Returns:
        Path to the saved file.
    """
    out_path = config.DEFENSE_RESULTS_FILE

    # Load existing results so we can merge
    existing: list[dict] = []
    if out_path.exists():
        existing = json.loads(out_path.read_text(encoding="utf-8"))

    # Build lookup of existing rows by (model, category)
    lookup: dict[tuple, int] = {
        (r["model"], r["category"]): i for i, r in enumerate(existing)
    }

    for row in comparison_rows:
        key = (row["model"], row["category"])
        if key in lookup:
            existing[lookup[key]] = row
        else:
            existing.append(row)
            lookup[key] = len(existing) - 1

    out_path.write_text(
        json.dumps(existing, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return out_path


# ── Compare-only mode ─────────────────────────────────────────────────────────


def compare_from_existing_files() -> None:
    """
    Build defense_comparison.json by reading existing smoke_test_*.json files.

    Expects files named:
        smoke_test_{model}.json              ← baseline (no defense suffix)
        smoke_test_{model}_{defense}.json    ← defense runs

    Any model / defense combinations found are included automatically.
    """
    smoke_files = sorted(config.RESULTS_DIR.glob("smoke_test_*.json"))
    if not smoke_files:
        print("No smoke_test_*.json files found in results/.")
        return

    # Group files by model
    baselines: dict[str, pd.DataFrame] = {}
    defended: dict[str, dict[str, pd.DataFrame]] = {}

    for path in smoke_files:
        stem = path.stem  # e.g. "smoke_test_llama_hardened_prompt"
        parts = stem[len("smoke_test_"):]  # remove prefix

        # Identify defense suffix (if any)
        matched_defense = None
        for d in config.DEFENSE_STRATEGIES:
            if parts.endswith(f"_{d}"):
                matched_defense = d
                model_key = parts[: -(len(d) + 1)]
                break

        if matched_defense is None:
            # Baseline file — model key is the remainder
            model_key = parts
            baselines[model_key] = pd.read_json(path)
        else:
            defended.setdefault(model_key, {})[matched_defense] = pd.read_json(path)

    if not baselines:
        print("No baseline smoke_test files found (files without a defense suffix).")
        return

    all_rows: list[dict] = []
    for model_key, baseline_df in baselines.items():
        if model_key not in defended:
            print(f"  No defense runs found for '{model_key}' — skipping.")
            continue

        print(f"\nComputing comparison for '{model_key}' ...")
        rows = compute_defense_comparison(model_key, baseline_df, defended[model_key])
        all_rows.extend(rows)

        # Print summary table
        print(f"\n  {'Category':<20} {'Baseline':>9}", end="")
        for d in defended[model_key]:
            print(f"  {d:>22} {'DRR':>6}", end="")
        print()
        print(f"  {'-'*80}")
        for row in rows:
            print(f"  {row['category']:<20} {row['baseline_asr']:>8.0%}", end="")
            for d in defended[model_key]:
                print(
                    f"  {row[f'{d}_asr']:>21.0%} {row[f'{d}_reduction']:>5.0%}", end=""
                )
            print()

    if all_rows:
        out = save_defense_results(all_rows)
        print(f"\n  Saved → {out}")


# ── CLI ───────────────────────────────────────────────────────────────────────


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run defense strategies and measure ASR reduction."
    )
    parser.add_argument(
        "--model",
        choices=list(config.MODELS),
        help="Model to evaluate. Required unless --compare-only.",
    )
    parser.add_argument(
        "--defense",
        choices=config.DEFENSE_STRATEGIES + ["all"],
        default="all",
        help="Defense strategy to apply (default: all).",
    )
    parser.add_argument(
        "--prompts",
        choices=["jailbreak", "prompt_injection", "pii_extraction", "all"],
        default="all",
        help="Which attack category to test (default: all).",
    )
    parser.add_argument(
        "--compare-only",
        action="store_true",
        help="Skip inference. Read existing smoke_test files and recompute comparison.",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    if args.compare_only:
        compare_from_existing_files()
        return

    if not args.model:
        print("Error: --model is required unless --compare-only is set.")
        return

    # Load prompts
    all_prompts = _load_all_prompts()
    if args.prompts != "all":
        all_prompts = [p for p in all_prompts if p["category"] == args.prompts]

    defenses_to_run = (
        config.DEFENSE_STRATEGIES if args.defense == "all" else [args.defense]
    )

    # Check for existing baseline
    baseline_path = config.RESULTS_DIR / f"smoke_test_{args.model}.json"
    if not baseline_path.exists():
        print(
            f"Baseline file not found: {baseline_path}\n"
            "Run test_model_runner.py first to generate baseline results."
        )
        return

    baseline_df = pd.read_json(baseline_path)
    defense_dfs: dict[str, pd.DataFrame] = {}

    for defense in defenses_to_run:
        print(f"\n{'='*65}")
        print(f"  Running defense: {defense}  |  model: {args.model}")
        print(f"{'='*65}")

        df = run_with_defense(args.model, all_prompts, defense)
        save_path = _save_smoke(df, args.model, defense)
        print(f"\n  Raw responses saved → {save_path}")
        defense_dfs[defense] = df

    # Compute and save comparison
    print(f"\nComputing defense comparison for '{args.model}' ...")
    rows = compute_defense_comparison(args.model, baseline_df, defense_dfs)
    out = save_defense_results(rows)

    # Print summary
    print(f"\n{'='*65}")
    print(f"  Defense Comparison — {args.model}")
    print(f"{'='*65}")
    print(f"  {'Category':<20} {'Baseline':>9}", end="")
    for d in defense_dfs:
        label = d[:10]
        print(f"  {label+' ASR':>14} {'DRR':>6}", end="")
    print()
    print(f"  {'-'*70}")
    for row in rows:
        print(f"  {row['category']:<20} {row['baseline_asr']:>8.0%}", end="")
        for d in defense_dfs:
            print(
                f"  {row[f'{d}_asr']:>13.0%} {row[f'{d}_reduction']:>5.0%}", end=""
            )
        print()
    print(f"\n  Saved → {out}\n")


if __name__ == "__main__":
    main()
