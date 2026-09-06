"""
Deux petits modèles ML entraînés sur les données Wazuh :

1. SeverityClassifier : prédit la catégorie de sévérité (Low/Medium/High/Critical)
   à partir du texte de la description + des groupes de règles.

2. VolumePredictor : prédit le nombre d'alertes attendues sur la prochaine
   fenêtre horaire, à partir de l'historique récent (features de type "lag").
"""
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor
from sklearn.pipeline import Pipeline

from wazuh_client import severity_bucket


class SeverityClassifier:
    def __init__(self):
        self.pipeline = None
        self.classes_ = None

    def _make_text(self, df: pd.DataFrame) -> pd.Series:
        return (df["description"].fillna("") + " " + df["groups"].fillna("")).str.lower()

    def fit(self, df: pd.DataFrame):
        df = df.copy()
        df["severity"] = df["level"].apply(severity_bucket)
        X = self._make_text(df)
        y = df["severity"]

        self.pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(max_features=300, ngram_range=(1, 2))),
            ("clf", RandomForestClassifier(n_estimators=200, random_state=42, class_weight="balanced")),
        ])
        self.pipeline.fit(X, y)
        self.classes_ = self.pipeline.named_steps["clf"].classes_
        return self

    def predict(self, description: str, groups: str = "") -> dict:
        text = pd.Series([f"{description} {groups}".lower()])
        proba = self.pipeline.predict_proba(text)[0]
        pred = self.pipeline.predict(text)[0]
        return {
            "predicted_severity": pred,
            "probabilities": dict(zip(self.classes_, [round(float(p), 3) for p in proba], strict=True)),
        }

    def score_report(self, df: pd.DataFrame) -> dict:
        df = df.copy()
        df["severity"] = df["level"].apply(severity_bucket)
        X = self._make_text(df)
        acc = self.pipeline.score(X, df["severity"])
        return {"train_accuracy": round(float(acc), 3), "n_samples": len(df)}


class VolumePredictor:
    def __init__(self, n_lags: int = 6):
        self.n_lags = n_lags
        self.model = None
        self.hourly_series = None

    def _build_hourly_series(self, df: pd.DataFrame) -> pd.Series:
        ts = df["timestamp"]
        if ts.dt.tz is not None:
            ts = ts.dt.tz_localize(None)
        tmp = df.copy()
        tmp["timestamp"] = ts
        s = tmp.set_index("timestamp").resample("1h").size()
        if len(s) > 1:
            s = s.iloc[:-1]
        return s

    def _build_supervised(self, series: pd.Series):
        X, y = [], []
        values = series.values
        for i in range(self.n_lags, len(values)):
            X.append(values[i - self.n_lags:i])
            y.append(values[i])
        return np.array(X), np.array(y)

    def fit(self, df: pd.DataFrame):
        series = self._build_hourly_series(df)
        self.hourly_series = series
        if len(series) <= self.n_lags:
            self.model = None
            return self
        X, y = self._build_supervised(series)
        self.model = RandomForestRegressor(n_estimators=200, random_state=42)
        self.model.fit(X, y)
        return self

    def predict_next(self, n_steps: int = 6) -> list:
        if self.hourly_series is None or len(self.hourly_series) < self.n_lags:
            return [0] * n_steps

        history = list(self.hourly_series.values[-self.n_lags:])
        preds = []

        if self.model is None:
            avg = float(np.mean(history)) if history else 0
            return [round(avg, 1)] * n_steps

        for _ in range(n_steps):
            x = np.array(history[-self.n_lags:]).reshape(1, -1)
            pred = max(0, float(self.model.predict(x)[0]))
            preds.append(round(pred, 1))
            history.append(pred)

        return preds

    def history_for_chart(self, last_n: int = 48) -> dict:
        if self.hourly_series is None:
            return {"labels": [], "values": []}
        s = self.hourly_series.tail(last_n)
        return {
            "labels": [t.strftime("%d/%m %Hh") for t in s.index],
            "values": [int(v) for v in s.values],
        }
