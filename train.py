import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

print(" İslenmis veri matrisi (islenmis_trafik.csv) yükleniyor...")

try:
    df = pd.read_csv("islenmis_trafik.csv")
except FileNotFoundError:
    print(" HATA: 'islenmis_trafik.csv' dosyası bulunamadı. lutfen dizini kontrol edin.")
    exit()

print(f"Toplam {len(df)} satirlik ag trafigi verisi egitime aliniyor...")

model = IsolationForest(contamination=0.001, random_state=42)

print("Yapay zeka agın normal sinirlarini ogreniyor. Lutfen bekleyin...")
model.fit(df)

joblib.dump(model, "anomaly_model.joblib")

print("BAŞARILI: Model başarıyla eğitildi ve 'anomaly_model.joblib' adıyla diske kaydedildi.")
