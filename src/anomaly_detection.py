from math import isfinite
from numbers import Real

from sklearn.ensemble import IsolationForest

from src.feature_extraction import FEATURE_NAMES


def detect_anomalies(
    events,
    feature_rows,
    contamination="auto",
    random_state=42,
    n_estimators=100,
):
    """Detect unusual security events using Isolation Forest.

    Returns:
        (results, errors)
    """

    results = []
    errors = []

    if len(events) != len(feature_rows):
        return [], [
            "Events and feature rows must have the same length."
        ]

    if len(events) < 2:
        return [], [
            "At least two events are required for anomaly detection."
        ]

    if not 1 <= n_estimators:
        return [], [
            "n_estimators must be at least 1."
        ]

    if contamination != "auto":
        if (
            not isinstance(contamination, Real)
            or isinstance(contamination, bool)
            or not 0 < contamination <= 0.5
        ):
            return [], [
                "Contamination must be 'auto' or a value "
                "between 0 and 0.5."
            ]

    validated_rows = []

    for index, row in enumerate(feature_rows):
        if not isinstance(row, dict):
            errors.append(
                f"Feature row {index + 1} must be a dictionary."
            )
            continue

        missing = [
            name for name in FEATURE_NAMES
            if name not in row
        ]

        extra = [
            name for name in row
            if name not in FEATURE_NAMES
        ]

        if missing or extra:
            errors.append(
                f"Feature row {index + 1} has an invalid schema. "
                f"Missing: {missing}; Extra: {extra}"
            )
            continue

        values = []

        for name in FEATURE_NAMES:
            value = row[name]

            if (
                not isinstance(value, Real)
                or isinstance(value, bool)
                or not isfinite(value)
            ):
                errors.append(
                    f"Feature row {index + 1}: "
                    f"'{name}' must be a finite numeric value."
                )
                break

            values.append(value)

        else:
            validated_rows.append(values)

    if errors:
        return [], errors

    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
    )

    try:
        model.fit(validated_rows)

        predictions = model.predict(validated_rows)
        raw_scores = model.decision_function(validated_rows)

    except (ValueError, TypeError) as exc:
        return [], [
            f"Anomaly detection failed: {exc}"
        ]

    for event, prediction, raw_score in zip(
        events,
        predictions,
        raw_scores,
    ):
        is_anomaly = int(prediction == -1)

        results.append({
            "event_id": event.event_id,
            "is_anomaly": is_anomaly,
            "classification": (
                "anomaly" if is_anomaly else "normal"
            ),
            "anomaly_score": round(float(-raw_score), 6),
        })

    return results, errors