import pandas as pd
import numpy as np
import logging
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
from core.logger import setup_logger

logger = setup_logger()

class ThreatHunter:
    def __init__(self):
        self.model = None
        self.label_encoders = {}
        self.baseline_created = False

    def _prepare_data(self, grid_data, cloud_data):
        """Combine and clean data from both modules for AI processing"""
        all_issues = []

        # Add grid security issues
        for issue in grid_data.get("security_issues", []):
            all_issues.append({
                "source": "smart_grid",
                "ip": issue.get("ip", "unknown"),
                "issue_type": issue.get("issue", "unknown"),
                "risk_level": issue.get("risk", "Low"),
                "is_known_issue": 1  # Mark as known risk from scanning
            })

        # Add cloud audit findings
        for issue in cloud_data.get("issues", []):
            all_issues.append({
                "source": "cloud",
                "ip": "cloud_resource",
                "issue_type": issue.get("issue", "unknown"),
                "risk_level": issue.get("risk", "Low"),
                "is_known_issue": 1
            })

        # Create DataFrame
        df = pd.DataFrame(all_issues) if all_issues else pd.DataFrame()

        if df.empty:
            logger.info("No data available for AI analysis")
            return None

        # Convert text data to numbers for the AI model
        for col in ["source", "issue_type", "risk_level"]:
            if col in df.columns:
                self.label_encoders[col] = LabelEncoder()
                df[col + "_encoded"] = self.label_encoders[col].fit_transform(df[col])

        return df

    def _create_baseline(self, df):
        """Build a profile of what 'normal/expected' activity looks like"""
        if df is None or len(df) < 2:
            return

        # Select numerical features for training
        features = [col for col in df.columns if col.endswith("_encoded") or col == "is_known_issue"]
        
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.1,  # Assume 10% of activity may be unusual
            random_state=42
        )
        self.model.fit(df[features])
        self.baseline_created = True
        logger.info("AI baseline profile created successfully")

    def detect_anomalies(self, grid_data, cloud_data):
        """Main method: find unusual patterns and hidden threats"""
        print("\n🧠 Running AI Threat Hunting & Anomaly Detection...")
        
        df = self._prepare_data(grid_data, cloud_data)
        anomalies = []

        if df is None:
            return {"status": "no_data", "threats_found": 0, "details": []}

        # Create baseline if first run
        if not self.baseline_created:
            self._create_baseline(df.copy())
            return {
                "status": "baseline_created",
                "message": "Normal behavior profile built. Next scan will detect anomalies.",
                "threats_found": 0,
                "details": []
            }

        # Detect anomalies
        features = [col for col in df.columns if col.endswith("_encoded") or col == "is_known_issue"]
        df["anomaly_score"] = self.model.decision_function(df[features])
        df["is_anomaly"] = self.model.predict(df[features])

        # Collect results
        for _, row in df.iterrows():
            if row["is_anomaly"] == -1:  # -1 = unusual/suspicious
                anomalies.append({
                    "confidence": round(abs(row["anomaly_score"]) * 100, 2),
                    "source": row.get("source", "unknown"),
                    "description": "Unusual activity pattern detected",
                    "possible_impact": "May indicate unknown threat, misconfiguration, or unusual behavior",
                    "recommendation": "Investigate this resource immediately, check logs and access rights"
                })

        result = {
            "module": "AI Threat Hunting & Analytics",
            "baseline_ready": self.baseline_created,
            "total_events_analyzed": len(df),
            "unknown_threats_found": len(anomalies),
            "details": anomalies,
            "status": "completed"
        }

        print(f"✅ AI analysis done. Found {len(anomalies)} potential hidden threats.")
        return result
        
