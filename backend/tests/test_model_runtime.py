from pathlib import Path

from app.services.model_runtime import UnifiedModelRuntime, unified_model_runtime


def test_unified_runtime_exposes_both_model_contracts():
    manifest = unified_model_runtime.manifest()

    assert manifest["runtime_version"] == "model-runtime.v1"
    assert set(manifest["models"]) == {"pattern", "behaviour"}
    predictions = unified_model_runtime.predict("support asks for PIN and urgent payment")
    assert set(predictions) == {"pattern", "behaviour"}
    assert all(prediction.model_name in {"pattern", "behaviour"} for prediction in predictions.values())


def test_unified_runtime_falls_back_when_artifacts_are_missing(tmp_path: Path):
    runtime = UnifiedModelRuntime(root=tmp_path)

    assert runtime.pattern_classifier.available is False
    assert runtime.behaviour_classifier.available is False
    assert runtime.predict("ordinary message")["pattern"].scores == {}
    assert runtime.predict("ordinary message")["behaviour"].scores == {}
