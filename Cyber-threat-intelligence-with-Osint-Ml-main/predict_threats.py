import os
import json
from osint.enrich import enrich_indicator_batch
from ml.model import ThreatTextClassifier

# -----------------------------
# CONFIGURATION
# -----------------------------
MODEL_PATH = "ml/models/threat_model.joblib"
IPINFO_TOKEN = None  # Put your IPINFO API token here if you have one

# -----------------------------
# INITIALIZE MODEL
# -----------------------------
classifier = ThreatTextClassifier(model_path=MODEL_PATH)
if not classifier.ensure_model():
    print("Model not trained yet. Please train first using train_from_csv().")
    exit()

# -----------------------------
# FUNCTION TO PREDICT THREATS
# -----------------------------
def predict_osint_threats(indicators: list[str]):
    results = enrich_indicator_batch(indicators, ipinfo_token=IPINFO_TOKEN)
    
    for item in results['items']:
        print(f"\nIndicator: {item['indicator']} ({item['type']})")
        print("Enrichment Summary:")
        print(json.dumps(item['summary'], indent=2))

        # Use the text (or indicator itself) for ML prediction
        # You can customize this: here we just predict from the indicator text
        pred, proba = classifier.predict(item['indicator'])
        print(f"ML Prediction: {pred} (Confidence: {proba:.2f})")

# -----------------------------
# MAIN SCRIPT
# -----------------------------
if __name__ == "__main__":
    print("=== Cyber Threat Prediction Tool ===")
    user_input = input("Enter IPs, URLs, or Domains (comma-separated):\n")
    indicators = [i.strip() for i in user_input.split(",") if i.strip()]

    if not indicators:
        print("No indicators entered. Exiting.")
        exit()

    predict_osint_threats(indicators)
