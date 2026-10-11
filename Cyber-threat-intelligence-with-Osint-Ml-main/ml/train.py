import os
from config import Config
from ml.model import ThreatTextClassifier


if __name__ == "__main__":
    clf = ThreatTextClassifier(model_path=Config.MODEL_PATH)
clf.train_from_csv(Config.SAMPLE_DATA)
print(f"Model trained and saved to: {Config.MODEL_PATH}")