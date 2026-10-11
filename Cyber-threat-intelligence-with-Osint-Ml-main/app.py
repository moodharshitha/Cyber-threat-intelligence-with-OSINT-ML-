from flask import Flask, render_template, request, jsonify
from config import Config
from osint.enrich import enrich_indicator_batch
from ml.model import ThreatTextClassifier
import os

app = Flask(__name__)
app.config.from_object(Config)

# Ensure model exists (auto-train on first run)
classifier = ThreatTextClassifier(model_path=app.config['MODEL_PATH'])
if not os.path.exists(app.config['MODEL_PATH']):
    classifier.train_from_csv(app.config['SAMPLE_DATA'])


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/lookup', methods=['GET', 'POST'])
def lookup():
    results = None
    if request.method == 'POST':
        raw = request.form.get('indicators', '').strip()
        values = [line.strip() for line in raw.splitlines() if line.strip()]
        enriched = enrich_indicator_batch(values, ipinfo_token=app.config.get('IPINFO_TOKEN'))

        # Add ML predictions to each indicator
        for item in enriched['items']:
            pred, proba = classifier.predict(item['indicator'])
            item['ml_prediction'] = {"prediction": pred, "probability": round(float(proba), 2)}

        results = enriched

    return render_template('lookup.html', results=results)


@app.route('/analyze', methods=['GET', 'POST'])
def analyze():
    output = None
    if request.method == 'POST':
        text = request.form.get('report_text', '').strip()
        if text:
            pred, proba = classifier.predict(text)
            output = {"prediction": pred, "probability": round(float(proba), 4)}
    return render_template('analyze.html', output=output)


# Simple JSON API for programmatic use
@app.route('/api/lookup', methods=['POST'])
def api_lookup():
    data = request.get_json(force=True)
    indicators = data.get('indicators', [])
    results = enrich_indicator_batch(indicators, ipinfo_token=app.config.get('IPINFO_TOKEN'))

    # Add ML predictions
    for item in results['items']:
        pred, proba = classifier.predict(item['indicator'])
        item['ml_prediction'] = {"prediction": pred, "probability": round(float(proba), 2)}

    return jsonify(results)


if __name__ == '__main__':
    app.run(debug=True)
