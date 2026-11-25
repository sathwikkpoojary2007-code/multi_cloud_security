"""Train and save the baseline risk triage model."""

import argparse
from pathlib import Path

from ml.risk_model import EVALUATION_PATH, MODEL_PATH, train_model


def main(argv=None):
    parser = argparse.ArgumentParser(description="Train the synthetic baseline security risk triage model.")
    parser.add_argument("--output", type=Path, default=MODEL_PATH)
    parser.add_argument("--evaluation", type=Path, default=EVALUATION_PATH)
    parser.add_argument("--reviewed-csv", type=Path, help="Optional human-reviewed labels to include in training")
    parser.add_argument("--seed", type=int, default=20261028)
    args = parser.parse_args(argv)
    model, metrics = train_model(args.output, args.evaluation, args.reviewed_csv, args.seed)
    print(f"Trained {model['model_name']} v{model['version']}")
    print(f"Training set: {model['training_data']}")
    print(f"Saved: {args.output.resolve()}")
    print(f"Held-out synthetic accuracy: {metrics['accuracy']:.1%} ({metrics['examples']} simulated examples)")
    print(f"Evaluation: {args.evaluation.resolve()}")
    print("Synthetic accuracy is not a real-world performance claim. The model only prioritizes review.")


if __name__ == "__main__":
    main()
