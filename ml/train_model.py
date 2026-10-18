"""Train and save the baseline risk triage model."""

import argparse
from pathlib import Path

from ml.risk_model import MODEL_PATH, train_model


def main(argv=None):
    parser = argparse.ArgumentParser(description="Train the synthetic baseline security risk triage model.")
    parser.add_argument("--output", type=Path, default=MODEL_PATH)
    args = parser.parse_args(argv)
    model = train_model(args.output)
    print(f"Trained {model['model_name']} v{model['version']}")
    print(f"Training set: {model['training_data']}")
    print(f"Saved: {args.output.resolve()}")
    print("This baseline model prioritizes review; it never executes remediation.")


if __name__ == "__main__":
    main()
