"""Shared runtime for SafeGuard's trained text classifiers.

Both joblib artifacts use the same bundle shape (TF-IDF vectorizer plus one
binary classifier per taxonomy label). Loading and prediction policy belongs
here so individual intelligence services cannot silently use different model
paths, thresholds, warning handling, or fallback behaviour.
"""
from __future__ import annotations

import os
import warnings
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ModelPrediction:
    model_name: str
    version: str
    artifact: str
    available: bool
    scores: dict[str, float]


class JoblibTextClassifier:
    """Safe adapter for one multi-label joblib bundle."""

    def __init__(self, *, model_name: str, path: str | Path, threshold: float = 0.5) -> None:
        self.model_name = model_name
        self.path = str(path)
        self.threshold = threshold
        self.version = f"unavailable:{Path(path).name}"
        self._available = False
        self._vectorizer = None
        self._models: dict[str, object] = {}
        self._labels: list[str] = []
        try:
            import joblib

            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                bundle = joblib.load(path)
            self._vectorizer = bundle["vectorizer"]
            self._models = bundle["models"]
            self._labels = list(bundle.get("classes", self._models.keys()))
            self.version = str(bundle.get("version") or f"joblib:{Path(path).name}")
            self._available = True
        except Exception:  # noqa: BLE001 - optional artifacts must never block startup
            self._available = False

    @property
    def available(self) -> bool:
        return self._available

    def predict(self, text: str) -> ModelPrediction:
        if not text or not text.strip() or not self._available:
            return ModelPrediction(
                model_name=self.model_name, version=self.version,
                artifact=Path(self.path).name, available=self._available, scores={},
            )
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                matrix = self._vectorizer.transform([text])
                scores: dict[str, float] = {}
                for label in self._labels:
                    model = self._models[label]
                    probabilities = model.predict_proba(matrix)[0]
                    classes = list(model.classes_)
                    probability = float(probabilities[classes.index(1)]) if 1 in classes else 0.0
                    if probability >= self.threshold:
                        scores[label] = round(probability, 4)
        except Exception:  # noqa: BLE001 - inference failure gets a safe empty result
            scores = {}
        return ModelPrediction(
            model_name=self.model_name, version=self.version,
            artifact=Path(self.path).name, available=self._available, scores=scores,
        )


class UnifiedModelRuntime:
    """Load and expose both trained classifiers from one backend boundary."""

    version = "model-runtime.v1"

    def __init__(self, root: str | Path | None = None, threshold: float = 0.5) -> None:
        # services/ -> app/ -> backend/ -> project root
        root_path = Path(root) if root else Path(__file__).resolve().parents[3]
        pattern_path = os.environ.get(
            "SAFEGUARD_PATTERN_MODEL_PATH",
            str(root_path / "models" / "safeguard_pattern_classifier_v2.joblib"),
        )
        behaviour_path = os.environ.get(
            "SAFEGUARD_BEHAVIOUR_MODEL_PATH",
            str(root_path / "models" / "safeguard_behaviour_classifier.joblib"),
        )
        self.pattern_classifier = JoblibTextClassifier(
            model_name="pattern", path=pattern_path, threshold=threshold,
        )
        self.behaviour_classifier = JoblibTextClassifier(
            model_name="behaviour", path=behaviour_path, threshold=threshold,
        )

    def predict(self, text: str) -> dict[str, ModelPrediction]:
        return {
            "pattern": self.pattern_classifier.predict(text),
            "behaviour": self.behaviour_classifier.predict(text),
        }

    def manifest(self) -> dict[str, object]:
        return {
            "runtime_version": self.version,
            "models": {
                "pattern": {
                    "version": self.pattern_classifier.version,
                    "artifact": Path(self.pattern_classifier.path).name,
                    "available": self.pattern_classifier.available,
                },
                "behaviour": {
                    "version": self.behaviour_classifier.version,
                    "artifact": Path(self.behaviour_classifier.path).name,
                    "available": self.behaviour_classifier.available,
                },
            },
        }


unified_model_runtime = UnifiedModelRuntime()
