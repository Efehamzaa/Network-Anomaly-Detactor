import joblib
import pandas as pd
from sklearn.preprocessing import StandardScaler

print("Ham Veri Yukleniyor ...")
df=pd.read_csv("normal_trafik.csv")

print("Kaynak ve Hedef IP adresleri tablodan temizleniyor ...")
df=df.drop(['Kaynak_IP' , 'Hedef_IP'] , axis=1)

print("TCP Bayrakları matematiksel matrise donusturuluyor...")
df=pd.get_dummies(df , columns=['TCP_Bayrak'] , drop_first=False , dtype=int)

print("sayisal veriler standartlastiriliyor ...")
scaler=StandardScaler()
olceklenecek_sutunlar= ['Zaman' , 'Protokol' , 'Hedef_Port' ,'Boyut']
df[olceklenecek_sutunlar]= scaler.fit_transform(df[olceklenecek_sutunlar])

print("\n --- İslenmis veri Seti (ilk 5 satir) ---")
print(df.head())

df.to_csv("islenmis_trafik.csv" , index=False)
joblib.dump(scaler, "scaler_motoru.joblib")
print(" Terazi motoru 'scaler_motoru.joblib' olarak kaydedildi.")
print("\n BASARİLİ: Veri seti Makine Ogrenmesi (ML) icin hazirlandi ve 'islenmis_trafik.csv' olarak kaydedildi!")
