"""Thin wrapper around the existing TF-IDF + Multinomial Naive Bayes model.

All numbers returned here come straight from the pickled scikit-learn objects
(predict / predict_proba / feature_log_prob_). Nothing is invented.
"""
import json
import pickle
from pathlib import Path

from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS

# Risk bands requested for the UI (applied to the model's spam probability).
SAFE_MAX = 30
SUSPICIOUS_MAX = 60


def risk_level(score: int) -> str:
    if score <= SAFE_MAX:
        return "safe"
    if score <= SUSPICIOUS_MAX:
        return "suspicious"
    return "high"


def confidence_label(confidence_pct: float) -> str:
    if confidence_pct >= 80:
        return "High"
    if confidence_pct >= 60:
        return "Medium"
    return "Low"


class SpamModel:
    def __init__(self, model_dir: Path):
        self.model_dir = Path(model_dir)
        with open(self.model_dir / "spam_model.pkl", "rb") as f:
            self.model = pickle.load(f)
        with open(self.model_dir / "vectorizer.pkl", "rb") as f:
            self.vectorizer = pickle.load(f)
        self._terms = self.vectorizer.get_feature_names_out()
        # Naive Bayes log-odds per term: positive => pushes towards SPAM.
        self._log_odds = self.model.feature_log_prob_[1] - self.model.feature_log_prob_[0]
        self._preprocess = self.vectorizer.build_preprocessor()
        self._tokenize = self.vectorizer.build_tokenizer()

    # ---- metadata -----------------------------------------------------------
    def metrics(self):
        """Evaluation metrics written by train_model.py (None if the file is missing)."""
        path = self.model_dir / "metrics.json"
        if not path.exists():
            return None
        with open(path) as f:
            return json.load(f)

    def info(self):
        return {
            "algorithm": "Multinomial Naive Bayes",
            "vectorizer": "TF-IDF (unigrams + bigrams, English stop words)",
            "vocabulary_size": int(len(self.vectorizer.vocabulary_)),
        }

    # ---- prediction ---------------------------------------------------------
    def _vocabulary_coverage(self, text: str):
        words = {w for w in self._tokenize(self._preprocess(text)) if w not in ENGLISH_STOP_WORDS}
        known = {w for w in words if w in self.vectorizer.vocabulary_}
        return len(known), len(words)

    def _top_terms(self, features, limit=6):
        """Terms of this email that moved the score most, towards spam / towards not-spam."""
        row = features.tocoo()
        contributions = [
            (self._terms[col], float(value * self._log_odds[col]))
            for col, value in zip(row.col, row.data)
        ]
        spam = sorted((c for c in contributions if c[1] > 0), key=lambda c: -c[1])[:limit]
        ham = sorted((c for c in contributions if c[1] < 0), key=lambda c: c[1])[:limit]
        fmt = lambda items: [{"term": t, "weight": round(abs(w), 3)} for t, w in items]
        return {"spam": fmt(spam), "ham": fmt(ham)}

    def predict(self, text: str) -> dict:
        features = self.vectorizer.transform([text])
        prediction = int(self.model.predict(features)[0])
        probabilities = self.model.predict_proba(features)[0]
        classes = list(self.model.classes_)
        spam_p = float(probabilities[classes.index(1)])
        ham_p = float(probabilities[classes.index(0)])
        confidence = max(spam_p, ham_p) * 100
        score = round(spam_p * 100)
        known, total = self._vocabulary_coverage(text)

        return {
            "prediction": "spam" if prediction == 1 else "not_spam",
            "spam_probability": round(spam_p * 100, 2),
            "not_spam_probability": round(ham_p * 100, 2),
            "confidence": round(confidence, 2),
            "confidence_label": confidence_label(confidence),
            "risk_score": score,
            "risk_level": risk_level(score),
            "algorithm": "Multinomial Naive Bayes + TF-IDF",
            "vocabulary_coverage": {"recognized": known, "total": total,
                                    "vocabulary_size": int(len(self.vectorizer.vocabulary_))},
            "no_recognized_terms": features.nnz == 0,
            "top_terms": self._top_terms(features),
        }
