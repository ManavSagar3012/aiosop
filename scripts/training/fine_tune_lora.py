"""Step D launcher: fine-tune an anchored-reasoning model with LoRA.

Halts deliberately unless both:
  1. A real trace-corpus directory produces >= 500 TrainingRows with
     mixed feedback (not all-ok synthetic traces), AND
  2. The caller passes --held-out-accuracy >= the configured floor, from a
     dataset produced by `HeldoutEvaluator` on THIS corpus.

Stays torch-free in import: heavy deps are imported inside main() so the file
is loadable for testing without GPU/CUDA environment.
"""

from __future__ import annotations

import argparse
import json
import sys

REQUIRED_MIN_ROWS = 500
REQUIRED_MIN_ACCURACY = 0.65  # plausibility floor for a fine-tune run


def parse_args(argv):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--traces-dir", required=True)
    p.add_argument("--eval-report", required=True, help="heldout_evaluator JSON")
    p.add_argument("--out-model", required=True)
    p.add_argument("--base-model", default="mistralai/Mistral-7B-Instruct-v0.2")
    p.add_argument("--epochs", type=int, default=2)
    p.add_argument("--dry-run", action="store_true")
    return p.parse_args(argv)


def load_rows(traces_dir: str) -> int:
    from ai_osop.training.dataset_builder import build_rows_from_traces

    rows = list(build_rows_from_traces(traces_dir))
    if len(rows) < REQUIRED_MIN_ROWS:
        sys.stderr.write(f"abort fine-tune: only {len(rows)} rows; need >= {REQUIRED_MIN_ROWS}\n")
        sys.exit(3)
    ok = sum(1 for r in rows if r.feedback_score >= 0.9)
    fail = sum(1 for r in rows if r.feedback_score <= 0.5)
    if fail == 0:
        sys.stderr.write(
            "abort fine-tune: zero sub-0.5 rows — corpus is not real, it's flat "
            "(synthetic). Label real failures before training.\n"
        )
        sys.exit(3)
    return len(rows)


def check_eval_floor(report_path: str) -> None:
    with open(report_path, "r", encoding="utf-8") as fh:
        report = json.load(fh)
    accuracy = report.get("action_accuracy", 0.0)
    if accuracy < REQUIRED_MIN_ACCURACY:
        sys.stderr.write(
            f"abort fine-tune: heldout accuracy {accuracy:.2f} below floor "
            f"{REQUIRED_MIN_ACCURACY:.2f}\n"
        )
        sys.exit(2)
    sys.stdout.write(f"eval gate passed: accuracy={accuracy:.2f}\n")


def main(argv):
    args = parse_args(argv)
    n = load_rows(args.traces_dir)
    check_eval_floor(args.eval_report)
    sys.stdout.write(
        f"plan: {n} rows, base_model={args.base_model}, "
        f"epochs={args.epochs}, out={args.out_model}\n"
    )
    if args.dry_run:
        sys.stdout.write("dry-run; no training performed\n")
        return 0

    # Heavy deps loaded lazily so this file imports cleanly without CUDA:
    try:
        import torch  # noqa: F401
        from peft import LoraConfig, get_peft_model  # noqa: F401
        from transformers import AutoModelForCausalLM, AutoTokenizer, Trainer  # noqa: F401
    except ImportError:
        sys.stderr.write(
            "fine-tune requires training extras: pip install torch transformers peft\n"
        )
        return 4

    sys.stderr.write(
        "Training body intentionally unimplemented — wire to your compute. "
        "This launcher is the gate.\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
