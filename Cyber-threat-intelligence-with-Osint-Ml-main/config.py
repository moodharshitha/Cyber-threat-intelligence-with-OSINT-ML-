import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or "dev_secret_key"
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))

    # Paths
    MODEL_PATH = os.path.join(BASE_DIR, "ml", "models", "threat_model.pkl")
    SAMPLE_DATA = os.path.join(BASE_DIR, "ml", "sample_data", "threat-reports.csv")

    # IPinfo token (optional)
    IPINFO_TOKEN = os.environ.get("IPINFO_TOKEN") or None
