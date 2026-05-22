from fastapi import FastAPI
from fastapi import UploadFile
from fastapi import File
from fastapi.middleware.cors import CORSMiddleware
import shutil

from extractor import extract_features

from predict import predict_behavior

# ==========================================
# FASTAPI
# ==========================================

app = FastAPI()
app.add_middleware(

    CORSMiddleware,

    allow_origins=["*"],

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"],
)
# ==========================================
# HOME
# ==========================================

@app.get("/")

def home():

    return {

        "message": "Network Behavior Analysis API Running"
    }

# ==========================================
# PREDICT
# ==========================================

@app.post("/predict")

async def predict(

        file: UploadFile = File(...)
):

    try:

        # ==========================================
        # SAVE PCAP
        # ==========================================

        pcap_path = file.filename

        with open(

                pcap_path,

                "wb"
        ) as buffer:

            shutil.copyfileobj(

                file.file,

                buffer
            )

        # ==========================================
        # EXTRACT FEATURES
        # ==========================================

        extract_features(

            pcap_path,

            "flows.csv"
        )

        # ==========================================
        # PREDICT
        # ==========================================

        results = predict_behavior(

            "flows.csv"
        )

        # ==========================================
        # ATTACK SUMMARY
        # ==========================================

        attack_summary = {}

        for r in results:

            attack = r["attack_prediction"]

            attack_summary[attack] = (

                attack_summary.get(attack, 0) + 1
            )

        # ==========================================
        # DOMINANT ATTACK
        # ==========================================

        dominant_attack = "Normal Traffic"

        if len(attack_summary) > 0:

            dominant_attack = max(

                attack_summary,

                key=attack_summary.get
            )

        # ==========================================
        # RESPONSE
        # ==========================================

        return {

            "status": "success",

            "total_flows": len(results),

            "dominant_attack": dominant_attack,

            "attack_summary": attack_summary,

            "sample_predictions": results[:10]
        }

    except Exception as e:

        return {

            "status": "error",

            "message": str(e)
        }
