import pandas as pd
import numpy as np
import joblib

# ==========================================
# LOAD MODEL
# ==========================================

model = joblib.load(

    "behavior_model_new.pkl"
)

encoder = joblib.load(

    "label_encoder_new.pkl"
)

# ==========================================
# FEATURES
# ==========================================

features = [

    "Flow Duration",

    "Flow Bytes/s",

    "Flow Packets/s",

    "SYN Flag Count",

    "ACK Flag Count",

    "Packet Length Mean",

    "Average Packet Size",

    "Protocol"
]

# ==========================================
# PREDICT FUNCTION
# ==========================================

def predict_behavior(csv_file):

    df = pd.read_csv(csv_file)

    X = df[features]

    X.replace([np.inf, -np.inf], 0, inplace=True)

    X.fillna(0, inplace=True)

    # ==========================================
    # ML PREDICTION
    # ==========================================

    predictions = model.predict(X)

    probabilities = model.predict_proba(X)

    results = []

    # ==========================================
    # LOOP
    # ==========================================

    for i in range(len(df)):

        prediction = encoder.inverse_transform(

            [predictions[i]]

        )[0]

        confidence = round(

            float(np.max(probabilities[i]) * 100),

            2
        )

        # ==========================================
        # SEVERITY
        # ==========================================

        severity = "Low"

        if confidence > 90:

            severity = "High"

        elif confidence > 70:

            severity = "Medium"

        # ==========================================
        # FEATURE VALUES
        # ==========================================

        protocol = int(

            df.iloc[i]["Protocol"]
        )

        packets_sec = float(

            df.iloc[i]["Flow Packets/s"]
        )

        bytes_sec = float(

            df.iloc[i]["Flow Bytes/s"]
        )

        syn_count = int(

            df.iloc[i]["SYN Flag Count"]
        )

        dst_port = int(

            df.iloc[i]["Dst Port"]
        )

        src_ip = str(

            df.iloc[i]["Src IP"]
        )

        dst_ip = str(

            df.iloc[i]["Dst IP"]
        )

        # ==========================================
        # PROTOCOL NAME
        # ==========================================

        protocol_name = "OTHER"

        if protocol == 6:

            protocol_name = "TCP"

        elif protocol == 17:

            protocol_name = "UDP"

        elif protocol == 1:

            protocol_name = "ICMP"

        # ==========================================
        # RULE ENGINE
        # ==========================================

        # HTTP FLOOD

        if protocol == 6 and dst_port in [80, 443] and packets_sec > 20:

            rule_detection = "Possible HTTP Flood"

        # UDP FLOOD

        elif protocol == 17 and packets_sec > 20:

            rule_detection = "Possible UDP Flood"

        # SYN FLOOD

        elif protocol == 6 and syn_count > 100:

            rule_detection = "Possible SYN Flood"

        # TCP FLOOD

        elif protocol == 6 and packets_sec > 500:

            rule_detection = "Possible TCP Flood"

        # BRUTE FORCE

        elif dst_port in [21, 22, 23, 3389] and packets_sec < 100:

            rule_detection = "Possible Brute Force Attack"

        # GENERAL DOS

        elif packets_sec > 30:

            rule_detection = "Possible DoS Attack"
        # ==========================================
        # FINAL ATTACK
        # ==========================================

        final_attack = str(prediction)

        if (

            prediction == "BENIGN"

            and

            rule_detection != "Normal Traffic"
        ):

            final_attack = rule_detection

        # ==========================================
        # OUTPUT
        # ==========================================

        results.append({

            "source_ip": src_ip,

            "destination_ip": dst_ip,

            "protocol": protocol_name,

            "destination_port": dst_port,

            "attack_prediction": str(final_attack),

            "confidence": float(confidence),

            "severity": str(severity),

            "traffic_analysis": {

                "packets_per_second": round(

                    packets_sec,

                    2
                ),

                "bytes_per_second": round(

                    bytes_sec,

                    2
                ),

                "syn_flags": syn_count
            }
        })

    return results