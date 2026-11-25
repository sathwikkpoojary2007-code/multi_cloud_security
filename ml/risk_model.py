"""Synthetic-data Gaussian Naive Bayes risk triage model.

The model is advisory. Synthetic accuracy is not evidence of cloud detection
accuracy, and neither ML nor an LLM authorizes remediation.
"""

import csv
import json
import math
import random
from functools import lru_cache
from pathlib import Path


MODEL_PATH = Path(__file__).with_name("model.json")
EVALUATION_PATH = Path(__file__).with_name("evaluation.json")
DIMENSIONS = (
    "exposure", "privilege", "encryption", "logging",
    "network_security", "identity_security", "configuration_security",
)
FEATURES = DIMENSIONS
CLASSES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
WEIGHTS = (0.25, 0.15, 0.15, 0.10, 0.15, 0.10, 0.10)


def _features(resource):
    security = resource.get("security", {})
    return [
        max(0.0, min(1.0, float(security.get(name, 0.0) or 0.0)))
        for name in DIMENSIONS
    ]


def generate_synthetic_examples(count=10000, seed=20261028):
    """Generate reproducible simulated posture vectors and planted labels.

    These examples model a known synthetic scoring policy. They are useful for
    exercising training/evaluation, not for claiming real-cloud accuracy.
    """
    rng = random.Random(seed)
    rows = []
    for _ in range(count):
        # Mix clean, single-control, and compound misconfiguration patterns.
        pattern = rng.random()
        if pattern < 0.30:
            dims = [rng.betavariate(1.2, 16) for _ in DIMENSIONS]
        elif pattern < 0.65:
            dims = [rng.betavariate(1.5, 9) for _ in DIMENSIONS]
            dims[rng.randrange(len(DIMENSIONS))] = rng.uniform(0.65, 1.0)
        else:
            dims = [rng.betavariate(2.2, 2.8) for _ in DIMENSIONS]
            if rng.random() < 0.30:
                dims[0] = rng.uniform(0.85, 1.0)

        planted_risk = sum(value * weight for value, weight in zip(dims, WEIGHTS))
        # The label is generated from hidden simulation policy, never from the
        # application's rules, risk_score, finding count, or benchmark output.
        if dims[0] >= 0.90 and planted_risk >= 0.20:
            label = "CRITICAL"
        elif planted_risk >= 0.55:
            label = "CRITICAL"
        elif planted_risk >= 0.32:
            label = "HIGH"
        elif planted_risk >= 0.12:
            label = "MEDIUM"
        else:
            label = "LOW"
        rows.append((label, dims))
    return rows


def _reviewed_examples(csv_path):
    """Load optional human-reviewed labels with strict feature validation."""
    rows = []
    with Path(csv_path).open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        required = set(DIMENSIONS) | {"risk_band"}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError("Reviewed CSV requires risk_band and all seven feature columns: " + ", ".join(DIMENSIONS))
        for line, row in enumerate(reader, start=2):
            label = str(row.get("risk_band", "")).strip().upper()
            if label not in CLASSES:
                raise ValueError(f"Invalid risk_band on CSV line {line}: {label!r}")
            try:
                values = [float(row[name]) for name in DIMENSIONS]
            except (TypeError, ValueError) as error:
                raise ValueError(f"Invalid feature value on CSV line {line}") from error
            if any(not math.isfinite(value) or not 0 <= value <= 1 for value in values):
                raise ValueError(f"Feature values must be finite numbers from 0 to 1 on CSV line {line}")
            rows.append((label, values))
    return rows


def _fit(rows):
    classes = {}
    for label in CLASSES:
        values = [features for row_label, features in rows if row_label == label]
        if not values:
            raise ValueError(f"Training data must include at least one {label} example")
        means = [sum(row[i] for row in values) / len(values) for i in range(len(FEATURES))]
        variances = [
            max(sum((row[i] - mean) ** 2 for row in values) / len(values), 0.0025)
            for i, mean in enumerate(means)
        ]
        classes[label] = {
            "prior": len(values) / len(rows), "means": means,
            "variances": variances, "count": len(values),
        }
    return classes


def _predict(features, classes):
    log_scores = {}
    for label, params in classes.items():
        score = math.log(params["prior"])
        for value, mean, variance in zip(features, params["means"], params["variances"]):
            score += -0.5 * math.log(2 * math.pi * variance)
            score -= ((value - mean) ** 2) / (2 * variance)
        log_scores[label] = score
    peak = max(log_scores.values())
    probs = {label: math.exp(score - peak) for label, score in log_scores.items()}
    total = sum(probs.values()) or 1
    probs = {label: probability / total for label, probability in probs.items()}
    return max(probs, key=probs.get), probs


def _evaluation(rows, classes):
    matrix = {actual: {predicted: 0 for predicted in CLASSES} for actual in CLASSES}
    correct = 0
    for actual, features in rows:
        predicted, _ = _predict(features, classes)
        matrix[actual][predicted] += 1
        correct += predicted == actual
    total = len(rows)
    per_class = {}
    for label in CLASSES:
        tp = matrix[label][label]
        fp = sum(matrix[actual][label] for actual in CLASSES if actual != label)
        fn = sum(matrix[label][predicted] for predicted in CLASSES if predicted != label)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        per_class[label] = {"precision": round(precision, 4), "recall": round(recall, 4), "support": sum(matrix[label].values())}
    return {
        "evaluation_type": "held-out synthetic simulation; not real cloud validation",
        "examples": total,
        "accuracy": round(correct / total, 4) if total else 0,
        "per_class": per_class,
        "confusion_matrix": matrix,
    }


def train_model(output_path=MODEL_PATH, evaluation_path=EVALUATION_PATH, reviewed_csv=None, seed=20261028):
    generated = generate_synthetic_examples(seed=seed)
    rng = random.Random(seed + 1)
    rng.shuffle(generated)
    split = int(len(generated) * 0.8)
    training = generated[:split]
    holdout = generated[split:]
    reviewed = _reviewed_examples(reviewed_csv) if reviewed_csv else []
    training.extend(reviewed)
    classes = _fit(training)
    metrics = _evaluation(holdout, classes)
    model = {
        "model_name": "MultiCloudSecurity Synthetic Posture Triage",
        "version": "2.0.0",
        "algorithm": "Gaussian Naive Bayes",
        "training_data": f"{len(generated)} generated synthetic scenarios; {len(reviewed)} reviewed labels",
        "features": list(FEATURES),
        "classes": classes,
        "limitations": "Advisory prototype trained on simulated posture labels. Held-out synthetic accuracy is not real-world cloud detection accuracy. Unknown evidence is not a PASS; human approval and provider-state verification are required for fixes.",
    }
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(model, indent=2), encoding="utf-8")
    evaluation_path = Path(evaluation_path)
    evaluation_path.parent.mkdir(parents=True, exist_ok=True)
    evaluation_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    if output_path.resolve() == MODEL_PATH.resolve():
        _load_saved_model.cache_clear()
    return model, metrics


@lru_cache(maxsize=1)
def _load_saved_model():
    return json.loads(MODEL_PATH.read_text(encoding="utf-8"))


def load_model():
    if not MODEL_PATH.exists():
        train_model()
    return _load_saved_model()


def predict_resource(resource):
    model = load_model()
    prediction, probs = _predict(_features(resource), model["classes"])
    evaluated = set(resource.get("evaluated_dimensions", []))
    coverage = round(100 * len(evaluated.intersection(DIMENSIONS)) / len(DIMENSIONS), 1)
    return {
        "model": model["model_name"], "version": model["version"],
        "risk_band": prediction, "confidence": round(probs[prediction], 4),
        "class_probabilities": {key: round(value, 4) for key, value in probs.items()},
        "evidence_coverage": coverage,
        "assessment_type": "advisory ML triage; rules and benchmarks remain authoritative",
        "limitations": model["limitations"],
    }


def model_metadata():
    model = load_model()
    result = {key: model[key] for key in ("model_name", "version", "algorithm", "training_data", "features", "limitations")}
    if EVALUATION_PATH.exists():
        try:
            result["evaluation"] = json.loads(EVALUATION_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            result["evaluation"] = None
    else:
        result["evaluation"] = None
    return result
