# fuzzer/train._anomaly.py
import joblib
from sklearn.ensemble import IsolationForest
import numpy as np
import os

current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
models_dir = os.path.join(project_root, 'models')

normal_traffic = np.array([[2500, 0.10, 150], [2600, 0.12, 160], [2450, 0.09, 155]])
model = IsolationForest(contamination=0.1, random_state=42)
model.fit(normal_traffic)


model_path = os.path.join(models_dir, 'anomaly_config_detector.pkl')
joblib.dump(model, model_path)

print(f"✅ Теперь точно сохранено тут: {model_path}")

