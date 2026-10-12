"""
Training script for TraceRoot Isolation Forest anomaly detector.

Trains on baseline npm package features extracted from real npm release histories
(traceroot_real_features.csv) and persists the trained model artifact for inference.
"""

import argparse
import sys
from pathlib import Path
import numpy as np

# Ensure backend root is on sys.path if run directly
current_dir = Path(__file__).resolve().parent
backend_dir = current_dir.parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.ml.anomaly_detector import AnomalyDetector, DEFAULT_MODEL_PATH
from app.ml.feature_extraction import load_features_from_csv


def find_default_csv_path() -> Path:
    """Find traceroot_real_features.csv in workspace root or parents."""
    candidates = [
        backend_dir.parent / "traceroot_real_features.csv",
        backend_dir / "traceroot_real_features.csv",
        Path("traceroot_real_features.csv"),
    ]
    for c in candidates:
        if c.is_file():
            return c.resolve()
    # Fallback to backend_dir.parent
    return (backend_dir.parent / "traceroot_real_features.csv").resolve()


def train_and_persist(
    csv_path: Path | str,
    output_path: Path | str,
    n_estimators: int = 100,
    contamination: float = 0.1,
    random_state: int = 42,
) -> dict:
    """
    Train Isolation Forest model on CSV and save artifact.

    Args:
        csv_path: Path to CSV dataset
        output_path: Target path for .joblib model artifact
        n_estimators: Number of trees in ensemble
        contamination: Expected anomaly ratio
        random_state: Random seed

    Returns:
        Summary dict of training and evaluation statistics
    """
    csv_file = Path(csv_path)
    output_file = Path(output_path)

    if not csv_file.is_file():
        raise FileNotFoundError(f"Feature CSV not found at: {csv_file}")

    print("=" * 60)
    print("TraceRoot ML Anomaly Detector Training")
    print("=" * 60)
    print(f"Loading data from: {csv_file}")

    # Load all rows to display full dataset stats
    all_features = load_features_from_csv(csv_file, usable_only=False)
    usable_features = [
        f for f in all_features
        if all(f.feature_availability.get(k, False) for k in [
            "days_since_previous_release",
            "release_gap_ratio",
            "package_age_days",
            "release_frequency_90d",
        ])
    ]

    total_count = len(all_features)
    usable_count = len(usable_features)
    excluded_count = total_count - usable_count

    print(f"Total packages in CSV:      {total_count}")
    print(f"Usable packages for train: {usable_count}")
    print(f"Excluded packages (gap):   {excluded_count}")

    if usable_count < 2:
        raise ValueError(f"Insufficient usable training samples: {usable_count}")

    # Initialize and train
    print("\nTraining Isolation Forest...")
    print(f"  Estimators:    {n_estimators}")
    print(f"  Contamination: {contamination}")
    print(f"  Random State:  {random_state}")

    detector = AnomalyDetector(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
    )
    train_meta = detector.train(usable_features)
    print(f"Training successful: {train_meta['training_samples']} samples fitted.")

    # Evaluate on training data
    predictions = detector.predict_batch(usable_features)
    scores = [p.anomaly_score for p in predictions if p.anomaly_score is not None]
    anomalous_pkgs = [p for p in predictions if p.is_anomalous]

    scores_arr = np.array(scores)
    score_min = float(np.min(scores_arr))
    score_p25 = float(np.percentile(scores_arr, 25))
    score_median = float(np.median(scores_arr))
    score_p75 = float(np.percentile(scores_arr, 75))
    score_max = float(np.max(scores_arr))

    print("\nTraining Set Anomaly Distribution:")
    print(f"  Total Evaluated: {len(scores)}")
    print(f"  Normal:          {len(scores) - len(anomalous_pkgs)}")
    print(f"  Anomalous:       {len(anomalous_pkgs)} ({len(anomalous_pkgs)/len(scores)*100:.1f}%)")
    print(f"  Score Min:       {score_min:.4f}")
    print(f"  Score 25%:       {score_p25:.4f}")
    print(f"  Score Median:    {score_median:.4f}")
    print(f"  Score 75%:       {score_p75:.4f}")
    print(f"  Score Max:       {score_max:.4f}")

    # Top anomalies
    anomalous_pkgs.sort(key=lambda x: x.anomaly_score or 0.0, reverse=True)
    top_5 = anomalous_pkgs[:5]
    print("\nTop 5 Most Anomalous Packages in Training Set:")
    for idx, a in enumerate(top_5, 1):
        print(f"  {idx}. {a.package_name}@{a.supplied_version}: score={a.anomaly_score:.4f}")

    # Persist model
    print(f"\nPersisting model artifact to: {output_file}")
    detector.save_model(output_file)

    # Verification round-trip
    loaded = AnomalyDetector.load_model(output_file)
    test_pred = loaded.predict(usable_features[0])
    orig_pred = detector.predict(usable_features[0])
    assert test_pred.anomaly_score == orig_pred.anomaly_score, "Model persistence mismatch"
    print("Persistence verification passed: model reloaded and validated.")
    print("=" * 60)

    return {
        "csv_path": str(csv_file),
        "output_path": str(output_file),
        "total_rows": total_count,
        "usable_rows": usable_count,
        "anomalies_detected": len(anomalous_pkgs),
        "score_min": score_min,
        "score_median": score_median,
        "score_max": score_max,
    }


def main():
    parser = argparse.ArgumentParser(description="Train Isolation Forest on npm package release features.")
    parser.add_argument(
        "--csv",
        type=str,
        default=str(find_default_csv_path()),
        help="Path to traceroot_real_features.csv",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=str(DEFAULT_MODEL_PATH),
        help="Destination path for .joblib model artifact",
    )
    parser.add_argument(
        "--estimators",
        type=int,
        default=100,
        help="Number of Isolation Forest trees",
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.1,
        help="Expected contamination proportion (0.0 to 0.5)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility",
    )

    args = parser.parse_args()
    train_and_persist(
        csv_path=args.csv,
        output_path=args.output,
        n_estimators=args.estimators,
        contamination=args.contamination,
        random_state=args.seed,
    )


if __name__ == "__main__":
    main()
