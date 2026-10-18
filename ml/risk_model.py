"""Small auditable Gaussian Naive Bayes model for risk triage.

Training examples are synthetic and curated. The output helps order review; it
does not authorize or execute remediation.
"""

import json
import math
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = Path(__file__).with_name("model.json")
DIMENSIONS = (
    "exposure", "privilege", "encryption", "logging",
    "network_security", "identity_security", "configuration_security",
)
FEATURES = DIMENSIONS + ("risk_score", "finding_count")
CLASSES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def _features(resource):
    security = resource.get("security", {})
    dimensions = [float(security.get(name, 0.0) or 0.0) for name in DIMENSIONS]
    risk = resource.get("risk_score")
    risk = float(risk) if isinstance(risk, (int, float)) else 0.0
    return dimensions + [risk, min(len(resource.get("findings", [])), 10)]


def _training_examples():
    # Curated synthetic examples exercise clean, partial, severe, and compound
    # control failures. Replace or supplement these with reviewed labels before
    # treating the model as a validated production detector.
    examples = [
        ("LOW", [0, 0, 0, 0, 0, 0, 0], 0),
        ("LOW", [.02, 0, .02, 0, 0, 0, 0], 0),
        ("LOW", [0, .03, 0, .02, 0, 0, 0], 0),
        ("LOW", [.05, 0, .03, .04, .03, 0, .02], 0),
        ("LOW", [0, 0, 0, 0, .06, .02, .03], 0),
        ("LOW", [.08, .05, .03, .06, .04, .04, .02], 0),
        ("MEDIUM", [.25, 0, 0, 0, 0, 0, 0], 1),
        ("MEDIUM", [0, .35, 0, 0, 0, 0, 0], 1),
        ("MEDIUM", [0, 0, .35, 0, .1, 0, 0], 1),
        ("MEDIUM", [.2, 0, .2, .2, 0, 0, 0], 1),
        ("MEDIUM", [0, .2, 0, .3, .25, 0, 0], 1),
        ("MEDIUM", [.3, .2, .15, .15, .2, .1, .1], 2),
        ("HIGH", [1, 0, 0, 0, .2, 0, 0], 1),
        ("HIGH", [.7, .2, .5, .5, .4, 0, .2], 2),
        ("HIGH", [.5, .7, .4, .7, .6, .4, .3], 2),
        ("HIGH", [.8, .1, .7, .5, .5, .3, .4], 2),
        ("HIGH", [.6, .5, .3, .8, .7, .4, .5], 3),
        ("HIGH", [.9, .4, .4, .4, .5, .6, .3], 3),
        ("CRITICAL", [1, .8, .8, .8, 1, .7, .8], 4),
        ("CRITICAL", [1, .6, 1, .8, .9, .7, .6], 4),
        ("CRITICAL", [.9, 1, .8, 1, .9, 1, .7], 5),
        ("CRITICAL", [1, .7, .9, 1, 1, .8, .9], 5),
        ("CRITICAL", [.8, .9, 1, .8, 1, 1, 1], 4),
        ("CRITICAL", [1, 1, .7, .9, .8, .9, .8], 6),
    ]
    weights = [.25, .15, .15, .10, .15, .10, .10]
    rows = []
    for label, dims, finding_count in examples:
        risk_score = round(sum(a * b for a, b in zip(dims, weights)) * 100, 2)
        rows.append((label, dims + [risk_score, finding_count]))
    return rows


def train_model(output_path=MODEL_PATH):
    rows = _training_examples()
    classes = {}
    for label in CLASSES:
        values = [features for row_label, features in rows if row_label == label]
        means = [sum(row[i] for row in values) / len(values) for i in range(len(FEATURES))]
        variances = []
        for i, mean in enumerate(means):
            variance = sum((row[i] - mean) ** 2 for row in values) / len(values)
            variances.append(max(variance, 0.01))
        classes[label] = {
            "prior": len(values) / len(rows),
            "means": means,
            "variances": variances,
            "count": len(values),
        }
    model = {
        "model_name": "MultiCloudSecurity Risk Triage NB",
        "version": "1.0.0",
        "algorithm": "Gaussian Naive Bayes",
        "training_data": "24 curated synthetic examples",
        "features": list(FEATURES),
        "classes": classes,
        "limitations": "Synthetic training data; review model recommendations and replace with validated labels before production decisions.",
    }
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(model, indent=2), encoding="utf-8")
    return model


def load_model():
    if not MODEL_PATH.exists():
        return train_model()
    return json.loads(MODEL_PATH.read_text(encoding="utf-8"))


def predict_resource(resource):
    model = load_model()
    features = _features(resource)
    log_scores = {}
    for label, params in model["classes"].items():
        score = math.log(params["prior"])
        for value, mean, variance in zip(features, params["means"], params["variances"]):
            score += -0.5 * math.log(2 * math.pi * variance)
            score -= ((value - mean) ** 2) / (2 * variance)
        log_scores[label] = score
    peak = max(log_scores.values())
    probs = {label: math.exp(score - peak) for label, score in log_scores.items()}
    total = sum(probs.values()) or 1
    probs = {label: probability / total for label, probability in probs.items()}
    prediction = max(probs, key=probs.get)
    return {
        "model": model["model_name"],
        "version": model["version"],
        "risk_band": prediction,
        "confidence": round(probs[prediction], 4),
        "class_probabilities": {key: round(value, 4) for key, value in probs.items()},
        "limitations": model["limitations"],
    }


def model_metadata():
    model = load_model()
    return {key: model[key] for key in ("model_name", "version", "algorithm", "training_data", "features", "limitations")}
