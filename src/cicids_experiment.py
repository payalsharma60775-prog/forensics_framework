from pathlib import Path

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)


DATA_PATH = Path(
    "data/external_dataset/MachineLearningCVE/"
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
)

RANDOM_STATE = 42
SAMPLE_SIZE = 10000
TEST_SIZE = 0.30


def run_experiment(data_path=DATA_PATH):
    print("=" * 60)
    print("CIC-IDS2017 NETWORK ANOMALY EXPERIMENT")
    print("=" * 60)

    print("\nLoading dataset...")

    df = pd.read_csv(data_path, low_memory=False)

    # Clean column names and labels
    df.columns = df.columns.str.strip()
    df["Label"] = df["Label"].astype(str).str.strip()

    # Remove invalid numeric values
    df = df.replace([float("inf"), float("-inf")], float("nan"))

    # Ground-truth labels: 0 = BENIGN, 1 = Attack
    y = (df["Label"] != "BENIGN").astype(int)

    # Exclude the label column from model features
    X = df.drop(columns=["Label"])

    # Keep numeric network-flow features only
    X = X.select_dtypes(include=["number"])

    # Replace missing values
    X = X.fillna(0)

    # Sample manageable dataset
    if len(X) > SAMPLE_SIZE:
        sampled_indices = df.sample(
            n=SAMPLE_SIZE,
            random_state=RANDOM_STATE,
        ).index

        X = X.loc[sampled_indices]
        y = y.loc[sampled_indices]

    print(f"Records analyzed: {len(X)}")
    print(f"Numeric features: {X.shape[1]}")
    print(f"Benign records: {(y == 0).sum()}")
    print(f"Attack records: {(y == 1).sum()}")

    # Split dataset into training and testing portions
    from sklearn.model_selection import train_test_split

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    # Train only on benign traffic
    X_train_benign = X_train[y_train == 0]

    print(f"\nTraining records (benign only): {len(X_train_benign)}")
    print(f"Testing records: {len(X_test)}")

    model = IsolationForest(
        n_estimators=100,
        contamination="auto",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )

    print("\nTraining Isolation Forest...")
    model.fit(X_train_benign)

    # Isolation Forest: -1 anomaly, 1 normal
    predictions = model.predict(X_test)

    # Convert predictions into binary classification
    y_pred = (predictions == -1).astype(int)

    # Calculate evaluation metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)

    tn, fp, fn, tp = confusion_matrix(
        y_test,
        y_pred,
        labels=[0, 1],
    ).ravel()

    fpr = fp / (fp + tn) if (fp + tn) else 0
    fnr = fn / (fn + tp) if (fn + tp) else 0

    print("\n" + "=" * 60)
    print("EXPERIMENT RESULTS")
    print("=" * 60)

    print(f"Accuracy : {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall  : {recall:.4f}")
    print(f"F1 Score: {f1:.4f}")
    print(f"FPR     : {fpr:.4f}")
    print(f"FNR     : {fnr:.4f}")

    print("\nConfusion Matrix:")
    print(f"TN: {tn} | FP: {fp}")
    print(f"FN: {fn} | TP: {tp}")

    print("\nInterpretation:")
    print("TN = Benign traffic correctly identified")
    print("FP = Benign traffic incorrectly flagged")
    print("FN = Attacks missed by the model")
    print("TP = Attacks correctly flagged")

    # Save experiment results
    results = {
        "dataset": "CIC-IDS2017 Friday Afternoon DDoS",
        "records_analyzed": int(len(X)),
        "features_used": int(X.shape[1]),
        "training_records": int(len(X_train_benign)),
        "testing_records": int(len(X_test)),
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1),
        "fpr": float(fpr),
        "fnr": float(fnr),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }

    output_path = Path("data/processed/cicids_experiment_results.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    import json

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(results, file, indent=4)

    print(f"\nResults saved to: {output_path}")
    print("\nExperiment completed.")


if __name__ == "__main__":
    run_experiment()