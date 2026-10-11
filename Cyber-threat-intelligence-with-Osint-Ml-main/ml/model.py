import os
import pandas as pd
from joblib import dump, load
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline


class ThreatTextClassifier:
    def __init__(self, model_path: str):
        self.model_path = model_path
        self._clf = None
        if os.path.exists(model_path):
            self._clf = load(model_path)

    def ensure_model(self):
        if self._clf is None and os.path.exists(self.model_path):
            self._clf = load(self.model_path)
        return self._clf is not None

    def train_from_csv(self, csv_path: str):
        df = pd.read_csv(csv_path)
        df = df.dropna(subset=['text', 'label'])
        X = df['text'].astype(str).tolist()
        y = df['label'].astype(str).tolist()

        pipe = Pipeline([
            ('tfidf', TfidfVectorizer(ngram_range=(1, 2), min_df=1, max_df=0.95)),
            ('clf', LogisticRegression(max_iter=1000))
        ])
        pipe.fit(X, y)

        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        dump(pipe, self.model_path)
        self._clf = pipe
        return self

    def predict(self, text: str):
        if not self.ensure_model():
            raise RuntimeError("Model not available. Train first.")

        if hasattr(self._clf, 'predict_proba'):
            probs = self._clf.predict_proba([text])[0]
            labels = self._clf.classes_
            idx = probs.argmax()
            return labels[idx], float(probs[idx])

        # Fallback for models without predict_proba
        pred = self._clf.predict([text])[0]
        return pred, 1.0
