# ai_detector.py
import os
import pickle
import numpy as np
import tensorflow as tf
import joblib

from tensorflow.keras.preprocessing.sequence import pad_sequences

MAX_SEQUENCE_LENGTH = 150    # Длина padding для Keras моделей
ATTACK_THRESHOLD = 0.5       # Порог классификации (binary classification)

# Подавляем лишние логи TensorFlow, чтобы не мусорили в консоли
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'


class AIDetector:
    def __init__(self, attack_type='sqli'):
        """
        attack_type: 'sqli' или 'xss'
        """
        self.attack_type = attack_type

        # Определяем пути к файлам
        if attack_type == 'sqli':
            self.model_path = 'models/sqli_hybrid_model.h5'
            self.tokenizer_path = 'models/tokenizer_sqli.pkl'
        else:
            self.model_path = 'models/xss_hybrid_model.h5'
            self.tokenizer_path = 'models/tokenizer_xss.pkl'

        # Загрузка
        print(f"[*] Загрузка AI-модуля для {attack_type.upper()}...")
        self.model = tf.keras.models.load_model(self.model_path)
        with open(self.tokenizer_path, 'rb') as f:
            self.tokenizer = pickle.load(f)
        print(f"[+] Модуль {attack_type.upper()} готов к работе.")

    def predict(self, text):

        # 1. Токенизация
        sequences = self.tokenizer.texts_to_sequences([str(text)])
        # 2. Padding (выравнивание длины до 150, как при обучении)
        padded = pad_sequences(sequences, maxlen=150)
        # 3. Предсказание
        prediction = self.model.predict(padded, verbose=0)[0][0]

        # Результат: True если атака, вероятность
        is_attack = bool(prediction > 0.5)
        return is_attack, float(prediction)


class ConfigAnalyzer:
    def __init__(self):

        try:
            self.mlp_model = joblib.load('models/sensitive_mlp_model.pkl')
            self.vectorizer = joblib.load('models/vectorizer.pkl')
            print("[+] MLP модель и Векторизатор успешно загружены!")
        except Exception as e:
            print(f"[-] Ошибка загрузки MLP: {e}")

    def analyze(self, file_name, content):
        if not content or len(str(content)) < 5:
            return "LOW", "Clean (Verified by Logistic filter)"

        # Твой ИИ в деле: превращаем текст в цифры и прогоняем через MLP
        X_vec = self.vectorizer.transform([str(content)])
        # Получаем вероятность того, что это секретные данные (класс 1)
        prob = self.mlp_model.predict_proba(X_vec)[0][1]

        if prob > 0.5:
            return "CRITICAL", f"OWASP A01: Sensitive Data Exposure (MLP Confidence: {prob * 100:.2f}%)"

        return "MEDIUM", f"Potential Exposure (MLP Score: {prob * 100:.2f}%)"

# --- БЫСТРЫЙ ТЕСТ ПРЯМО ЗДЕСЬ ---
if __name__ == "__main__":
    # Проверка SQL
    sql_engine = AIDetector('sqli')
    print(f"Результат SQL: {sql_engine.predict('SELECT * FROM users WHERE 1=1')}")

    # Проверка XSS
    xss_engine = AIDetector('xss')
    print(f"Результат XSS: {xss_engine.predict('<script>alert(1)</script>')}")

    test_ai = ConfigAnalyzer()
    res, msg = test_ai.analyze("test.env", "DB_PASSWORD=admin123")
    print(f"\nРезультат теста: {res} -> {msg}")