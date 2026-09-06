import os
import threading
import time
from datetime import datetime

import pandas as pd
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
from pydantic import BaseModel

from wazuh_client import fetch_alerts, severity_bucket
from ml_models import SeverityClassifier, VolumePredictor

app = FastAPI(title="Wazuh Stats & ML Dashboard")
templates = Jinja2Templates(directory="templates")

REFRESH_INTERVAL_SECONDS = int(os.getenv("REFRESH_INTERVAL_SECONDS", "300"))
HISTORY_DAYS = int(os.getenv("HISTORY_DAYS", "14"))

state = {
    "df": pd.DataFrame(),
    "severity_model": None,
    "volume_model": None,
    "last_refresh": None,
    "error": None,
}
_lock = threading.Lock()


def refresh_data():
    try:
        df = fetch_alerts(days=HISTORY_DAYS)
        sev_model = SeverityClassifier()
        vol_model = VolumePredictor()
        if not df.empty:
            sev_model.fit(df)
            vol_model.fit(df)
        with _lock:
            state["df"] = df
            state["severity_model"] = sev_model
            state["volume_model"] = vol_model
            state["last_refresh"] = datetime.utcnow().isoformat()
            state["error"] = None
    except Exception as e:
        with _lock:
            state["error"] = str(e)


def background_refresh_loop():
    while True:
        refresh_data()
        time.sleep(REFRESH_INTERVAL_SECONDS)


@app.on_event("startup")
def startup_event():
    refresh_data()
    t = threading.Thread(target=background_refresh_loop, daemon=True)
    t.start()


@app.get("/api/health")
def health():
    return {"status": "ok", "last_refresh": state["last_refresh"], "error": state["error"]}


@app.get("/api/stats")
def get_stats():
    df = state["df"]
    if df.empty:
        raise HTTPException(status_code=503, detail="Données non disponibles pour le moment")

    total = len(df)
    df = df.copy()
    df["severity"] = df["level"].apply(severity_bucket)
    severity_counts = df["severity"].value_counts().to_dict()
    top_rules = (
        df.groupby(["rule_id", "description"]).size()
        .sort_values(ascending=False)
        .head(5)
        .reset_index(name="count")
        .to_dict(orient="records")
    )
    top_agents = df["agent_name"].value_counts().head(5).to_dict()

    return {
        "total_alerts": total,
        "severity_distribution": severity_counts,
        "top_rules": top_rules,
        "top_agents": top_agents,
        "last_refresh": state["last_refresh"],
    }


@app.get("/api/volume-history")
def volume_history(last_n: int = Query(48, ge=1, le=500)):
    vol_model = state["volume_model"]
    if vol_model is None:
        raise HTTPException(status_code=503, detail="Modèle non disponible")
    return vol_model.history_for_chart(last_n=last_n)


@app.get("/api/predict-volume")
def predict_volume(n_hours: int = Query(6, ge=1, le=48)):
    vol_model = state["volume_model"]
    if vol_model is None:
        raise HTTPException(status_code=503, detail="Modèle non disponible")
    preds = vol_model.predict_next(n_steps=n_hours)
    return {"n_hours": n_hours, "predicted_counts": preds}


class SeverityRequest(BaseModel):
    description: str
    groups: str = ""


@app.post("/api/predict-severity")
def predict_severity(payload: SeverityRequest):
    sev_model = state["severity_model"]
    if sev_model is None or sev_model.pipeline is None:
        raise HTTPException(status_code=503, detail="Modèle non disponible")
    return sev_model.predict(payload.description, payload.groups)


@app.get("/api/model-info")
def model_info():
    sev_model = state["severity_model"]
    df = state["df"]
    if sev_model is None or sev_model.pipeline is None or df.empty:
        raise HTTPException(status_code=503, detail="Modèle non disponible")
    return sev_model.score_report(df)


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})
