"""
model_runner.py - Model loading and inference for AutoRedTeam-LLM.

Loads HuggingFace instruct models with 4-bit NF4 quantization and runs
adversarial prompts through them, saving raw responses to results/.

Usage (from pipeline):
    from src.model_runner import run_model
    df = run_model("llama", prompts)

Usage (standalone):
    runner = ModelRunner("mistral")
    runner.load()
    df = runner.run(prompts)
    runner.unload()
"""

import gc
import logging
import sys
from pathlib import Path

import pandas as pd
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

# Allow importing config from project root regardless of cwd
sys.path.insert(0, str(Path(__file__).parent.parent))
import config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# Columns written to the checkpoint and final results CSV
RAW_COLUMNS = [
    "prompt_id",
    "model",
    "category",
    "subcategory",
    "prompt_text",
    "response_text",
    "defense_active",
    "error",
]


class ModelRunner:
    """
    Loads a single HuggingFace instruct model with 4-bit NF4 quantization
    and runs adversarial prompts through it.

    Typical lifecycle:
        runner = ModelRunner("llama")
        runner.load()
        df = runner.run(prompts)
        runner.unload()
    """

    def __init__(self, model_key: str, system_prompt: str = config.SYSTEM_PROMPT_BASELINE):
        """
        Args:
            model_key:     Key from config.MODELS (e.g. "llama", "mistral", "qwen").
            system_prompt: System prompt prepended to every inference call.
                           Pass config.SYSTEM_PROMPT_HARDENED for defense runs.
        """
        if model_key not in config.MODELS:
            raise ValueError(
                f"Unknown model key '{model_key}'. Available: {list(config.MODELS)}"
            )

        self.model_key = model_key
        self.model_id = config.MODELS[model_key]
        self.system_prompt = system_prompt
        self.model = None
        self.tokenizer = None

    # ── Loading / Unloading ────────────────────────────────────────────────────

    def load(self) -> None:
        """Load model and tokenizer into VRAM with 4-bit NF4 quantization."""
        logger.info(f"Loading {self.model_key} ({self.model_id}) ...")

        bnb_config = BitsAndBytesConfig(**config.QUANTIZATION_CONFIG)

        self.tokenizer = AutoTokenizer.from_pretrained(
            self.model_id,
            local_files_only=config.LOCAL_FILES_ONLY,
        )
        try:
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_id,
                quantization_config=bnb_config,
                device_map="auto",
                torch_dtype=torch.float16,
                low_cpu_mem_usage=True,
                local_files_only=config.LOCAL_FILES_ONLY,
            )
        except torch.cuda.OutOfMemoryError as e:
            free, total = torch.cuda.mem_get_info()
            raise RuntimeError(
                f"CUDA OOM while loading '{self.model_key}'. "
                f"GPU has {free / 1e9:.1f} GB free of {total / 1e9:.1f} GB total. "
                "Ensure no other Python/Jupyter processes are holding GPU memory "
                "(check nvidia-smi), then retry."
            ) from e
        self.model.eval()
        logger.info(f"Model '{self.model_key}' loaded successfully.")

    def unload(self) -> None:
        """Delete model and tokenizer from memory and free CUDA cache."""
        del self.model
        del self.tokenizer
        self.model = None
        self.tokenizer = None
        gc.collect()
        torch.cuda.empty_cache()
        logger.info(f"Model '{self.model_key}' unloaded. CUDA cache cleared.")

    # ── Inference ──────────────────────────────────────────────────────────────

    def _infer(self, prompt_text: str) -> str:
        """
        Run a single deterministic inference call.

        Args:
            prompt_text: The user-turn content.

        Returns:
            The model's generated response as a stripped string.
        """
        torch.manual_seed(config.RANDOM_SEED)

        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user",   "content": prompt_text},
        ]

        tokenized = self.tokenizer.apply_chat_template(
            messages,
            add_generation_prompt=True,
            return_tensors="pt",
        )
        # apply_chat_template may return a BatchEncoding or a plain tensor
        input_ids = (tokenized.input_ids if hasattr(tokenized, "input_ids") else tokenized).to(self.model.device)

        with torch.no_grad():
            output_ids = self.model.generate(
                input_ids,
                max_new_tokens=config.MAX_NEW_TOKENS,
                do_sample=config.DO_SAMPLE,
                pad_token_id=self.tokenizer.eos_token_id,
            )

        # Decode only the newly generated tokens (strip the input prefix)
        new_tokens = output_ids[0][input_ids.shape[-1]:]
        raw = self.tokenizer.decode(new_tokens, skip_special_tokens=True).strip()
        return self._normalize_response(raw)

    @staticmethod
    def _normalize_response(response: str) -> str:
        """
        Standardise trivial model outputs to a fixed refusal marker.

        Mistral-v0.1 and similar weaker models sometimes produce an empty string
        or a bare '...' when they decline a prompt without generating a real
        refusal message.  Downstream (classifier.py) treats REFUSAL_MARKER the
        same as any other refusal phrase, so this keeps the CSV readable and the
        classifier logic simple.

        Args:
            response: Raw decoded model output (already stripped).

        Returns:
            The original response, or config.REFUSAL_MARKER if the response
            carries no meaningful content.
        """
        # Tokens that count as "no real output"
        _TRIVIAL = {"", "...", "…", "....", ".....", ". . .", "n/a", "-"}
        if response.lower() in _TRIVIAL:
            return config.REFUSAL_MARKER
        return response

    # ── Main Run ───────────────────────────────────────────────────────────────

    def run(self, prompts: list[dict], defense_active: bool = False) -> pd.DataFrame:
        """
        Run inference over a list of attack prompts.

        Each prompt dict must contain at minimum:
            id, category, subcategory, prompt_text

        A checkpoint is saved to results/ every 10 prompts so a crash does not
        lose all progress. The full DataFrame is returned at the end.

        Args:
            prompts:        List of prompt dicts (from dataset_builder or hardcoded test).
            defense_active: Flag recorded in output; set True for defense-mode runs.

        Returns:
            DataFrame with columns: prompt_id, model, category, subcategory,
            prompt_text, response_text, defense_active, error
        """
        if self.model is None:
            raise RuntimeError("Model is not loaded. Call load() before run().")

        records: list[dict] = []
        total = len(prompts)

        for i, prompt in enumerate(prompts):
            prompt_id   = prompt["id"]
            prompt_text = prompt["prompt_text"]
            response    = ""
            error       = ""

            # ── Inference with error handling ──────────────────────────────
            try:
                response = self._infer(prompt_text)

            except torch.cuda.OutOfMemoryError:
                logger.warning(f"[{prompt_id}] CUDA OOM - skipping prompt.")
                error = "CUDA_OOM"
                torch.cuda.empty_cache()

            except Exception as exc:
                # Retry once before giving up
                logger.warning(f"[{prompt_id}] Inference error ({exc}) - retrying once ...")
                try:
                    response = self._infer(prompt_text)
                except Exception as exc2:
                    logger.error(f"[{prompt_id}] Retry failed: {exc2}")
                    error = str(exc2)

            # Safety net: normalize here too in case _infer raised and left response=""
            response = self._normalize_response(response)

            records.append({
                "prompt_id":      prompt_id,
                "model":          self.model_key,
                "category":       prompt.get("category", ""),
                "subcategory":    prompt.get("subcategory", ""),
                "prompt_text":    prompt_text,
                "response_text":  response,
                "defense_active": defense_active,
                "error":          error,
            })

            logger.info(f"[{self.model_key}] {i + 1}/{total} completed - {prompt_id}")

            # Checkpoint every 10 prompts
            if (i + 1) % 10 == 0:
                self._checkpoint(records)

        return pd.DataFrame(records, columns=RAW_COLUMNS)

    # ── Checkpointing ──────────────────────────────────────────────────────────

    def _checkpoint(self, records: list[dict]) -> None:
        """
        Overwrite the per-model checkpoint file with all records collected so far.
        This is a crash-recovery mechanism - the final save is done by pipeline.py.

        Args:
            records: All records collected so far in the current run() call.
        """
        checkpoint_path = config.RESULTS_DIR / f"checkpoint_{self.model_key}.json"
        pd.DataFrame(records, columns=RAW_COLUMNS).to_json(
            checkpoint_path, orient="records", indent=2, force_ascii=False
        )
        logger.info(f"Checkpoint saved ({len(records)} records) → {checkpoint_path}")


# ── Convenience function ───────────────────────────────────────────────────────


def run_model(
    model_key: str,
    prompts: list[dict],
    system_prompt: str = config.SYSTEM_PROMPT_BASELINE,
    defense_active: bool = False,
) -> pd.DataFrame:
    """
    Load model, run all prompts, unload, and return results.

    This is the main entry point used by pipeline.py. The model is always
    unloaded (even on exception) to free VRAM before the next model loads.

    Args:
        model_key:     Key from config.MODELS.
        prompts:       List of prompt dicts.
        system_prompt: System prompt to use (baseline or hardened).
        defense_active: Whether a defense strategy is active.

    Returns:
        DataFrame of raw inference results.
    """
    runner = ModelRunner(model_key, system_prompt)
    runner.load()
    try:
        df = runner.run(prompts, defense_active=defense_active)
    finally:
        runner.unload()
    return df
