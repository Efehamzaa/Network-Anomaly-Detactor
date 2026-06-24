import joblib
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP
import time

print("[*] Canli Avci uyaniyor... Sistemler kontrol ediliyor.")

# 1. BEYNI VE TERAZIYI YUKLE
try:
    model = joblib.load("anomaly_model.joblib")
    scaler = joblib.load("scaler_motoru.joblib")
    print("[+] Yapay zeka modeli ve Terazi motoru basariyla RAM'e yuklendi.")
except FileNotFoundError:
    print("[-] OLUMCUL HATA: Model veya terazi dosyasi bulunamadi! Onceki gunleri tamamlayin.")
    exit()

# SUTUN UYUMSUZLUGU KALKANI
try:
    sablon_df = pd.read_csv("islenmis_trafik.csv", nrows=1)
    beklenen_sutunlar = sablon_df.columns.tolist()
    print(f"[+] 13 Sutunluk ag matrisi sablonu basariyla dogrulandi.")
except FileNotFoundError:
    print("[-] HATA: 'islenmis_trafik.csv' bulunamadi. Sablon dogrulamasi basarisiz!")
    exit()


def paket_analizi(paket):
    if IP in paket:
        # 2. CANLI VERIYI PARCALA
        zaman = time.time()
        protokol = paket[IP].proto
        hedef_port = paket[TCP].dport if TCP in paket else (paket[UDP].dport if UDP in paket else 0)
        boyut = len(paket)
        
        tcp_bayrak = paket[TCP].sprintf('%TCP.flags%') if TCP in paket else "YOK"
        if tcp_bayrak == "" or tcp_bayrak == " ":
            tcp_bayrak = "YOK"

        # 3. TEK BIR PAKETI ANLIK TABLOYA CEVIR
        tek_paket_veri = {
            'Zaman': [zaman],
            'Protokol': [protokol],
            'Hedef_Port': [hedef_port],
            'Boyut': [boyut],
            'TCP_Bayrak': [tcp_bayrak]
        }
        df_paket = pd.DataFrame(tek_paket_veri)

        # 4. ONE-HOT ENCODING UYGULA
        df_paket = pd.get_dummies(df_paket, columns=['TCP_Bayrak'], dtype=int)

        # 5. EKSIK SUTUNLAR TUZAGINI YOK ET (Reindex)
        df_paket = df_paket.reindex(columns=beklenen_sutunlar, fill_value=0)

        # 6. MEVCUT TERAZIDEN GECIR (.transform)
        olceklenecek_sutunlar = ['Zaman', 'Protokol', 'Hedef_Port', 'Boyut']
        df_paket[olceklenecek_sutunlar] = scaler.transform(df_paket[olceklenecek_sutunlar])

        # 7. BEYNE SOR (Tahmin Et)
        tahmin = model.predict(df_paket)[0]

        # 8. KARAR MEKANIZMASI VE ALARM PROTOKOLU
        if tahmin == -1:
            # Kirmizi Alarm Basimi
            print(f"\033[91m[!!!] ANOMALI/SALDIRI TESPIT EDILDI! | Port: {hedef_port} | Boyut: {boyut} Byte | Bayrak: {tcp_bayrak}\033[0m")
        else:
            # Standart Akis Basimi
            print(f"[+] Normal Trafik Akisi | Port: {hedef_port} | Boyut: {boyut} Byte")


# 9. AVCIYI AGA SALIM
print("\n[!] DIKKAT: Yapay zeka canli ag hattina baglandi. Av basliyor...")
sniff(prn=paket_analizi, store=False)
