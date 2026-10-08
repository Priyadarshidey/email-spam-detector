"""Train the spam model and save it together with real evaluation metrics.

Algorithm and preprocessing are unchanged from the original project:
TF-IDF (unigrams + bigrams, English stop words, 5000 features) -> Multinomial Naive Bayes.

New: evaluation metrics (accuracy / precision / recall / F1 / confusion matrix)
are written to model/metrics.json so the website can display them.
Nothing in that file is hand-written; it is all computed here.
"""
import json
import pickle
import warnings
from datetime import datetime, timezone

import pandas as pd
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score, confusion_matrix, f1_score, precision_score, recall_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_predict, train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline

VECTORIZER_PARAMS = dict(lowercase=True, stop_words="english", ngram_range=(1, 2), max_features=5000)


def scores(y_true, y_pred):
    """Metrics for the spam class (label 1), as percentages."""
    return {
        "accuracy": round(accuracy_score(y_true, y_pred) * 100, 2),
        "precision": round(precision_score(y_true, y_pred, zero_division=0) * 100, 2),
        "recall": round(recall_score(y_true, y_pred, zero_division=0) * 100, 2),
        "f1": round(f1_score(y_true, y_pred, zero_division=0) * 100, 2),
    }


data = pd.read_csv("spam.csv")
data["label"] = data["label"].map({"ham": 0, "spam": 1})
data.dropna(inplace=True)

X_train, X_test, y_train, y_test = train_test_split(
    data["message"], data["label"], test_size=0.2, random_state=42
)

vectorizer = TfidfVectorizer(**VECTORIZER_PARAMS)
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

model = MultinomialNB()
model.fit(X_train_vec, y_train)

predictions = model.predict(X_test_vec)
print("Model trained successfully!")
print("Accuracy:", round(accuracy_score(y_test, predictions) * 100, 2), "%")

with open("model/spam_model.pkl", "wb") as f:
    pickle.dump(model, f)

with open("model/vectorizer.pkl", "wb") as f:
    pickle.dump(vectorizer, f)

print("Model files saved in the model folder.")

# ---- Evaluation metrics for the website -------------------------------------
# A single 20% hold-out is very small for a tiny dataset, so we also report
# 5-fold stratified cross-validation, which uses every row for testing once.
holdout = scores(y_test, predictions)
tn, fp, fn, tp = confusion_matrix(y_test, predictions, labels=[0, 1]).ravel()

n_splits = int(min(5, data["label"].value_counts().min()))
cv_pipeline = make_pipeline(TfidfVectorizer(**VECTORIZER_PARAMS), MultinomialNB())
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    cv_pred = cross_val_predict(
        cv_pipeline, data["message"], data["label"],
        cv=StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42),
    )
cv_tn, cv_fp, cv_fn, cv_tp = confusion_matrix(data["label"], cv_pred, labels=[0, 1]).ravel()

metrics = {
    "algorithm": "Multinomial Naive Bayes",
    "vectorizer": "TF-IDF (unigrams + bigrams, English stop words, max 5000 features)",
    "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    "sklearn_version": sklearn.__version__,
    "dataset": {
        "total": int(len(data)),
        "spam": int((data["label"] == 1).sum()),
        "ham": int((data["label"] == 0).sum()),
        "train": int(len(X_train)),
        "test": int(len(X_test)),
        "vocabulary": int(len(vectorizer.vocabulary_)),
    },
    "holdout": {**holdout, "support": int(len(y_test)),
                "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}},
    "cross_validation": {**scores(data["label"], cv_pred), "folds": n_splits,
                         "support": int(len(data)),
                         "confusion_matrix": {"tn": int(cv_tn), "fp": int(cv_fp),
                                              "fn": int(cv_fn), "tp": int(cv_tp)}},
}

with open("model/metrics.json", "w") as f:
    json.dump(metrics, f, indent=2)

print("Metrics saved to model/metrics.json")
print("Hold-out :", holdout)
print("CV       :", metrics["cross_validation"])
