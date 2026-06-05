import pandas as pd
from sklearn.ensemble import IsolationForest

class ThreatHunter:
    def detect_anomalies(self, grid_data, cloud_data):
        """AI model to find unusual behavior"""
        print("Running AI anomaly detection...")
        # Combine data and detect patterns
        data = pd.DataFrame([grid_data, cloud_data])
        model = IsolationForest(contamination=0.1)
        data["risk_score"] = model.fit_predict(data.select_dtypes(include='number'))
        return data.to_dict("records")
      
