from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import time
import pandas as pd
import sys

paket_verileri = []
baslangic_zamani = time.time()

def paket_analizi(paket):
    if paket.haslayer(IP):
        kaynak_ip = paket[IP].src
        hedef_ip = paket[IP].dst
        protokol = paket[IP].proto
        paket_boyutu = len(paket)
        zaman_damgasi = round(time.time() - baslangic_zamani, 2)

        tcp_bayrak = "YOK"
        hedef_port = 0

        if paket.haslayer(TCP):
            hedef_port = paket[TCP].dport
            tcp_bayrak = str(paket[TCP].flags)
        elif paket.haslayer(UDP):
            hedef_port = paket[UDP].dport

        # DİKKAT: Anahtar ve değer arasında NOKTA değil İKİ NOKTA ÜST ÜSTE var.
        oznitelik = {
            "Zaman": zaman_damgasi,
            "Kaynak_IP": kaynak_ip,
            "Hedef_IP": hedef_ip,
            "Protokol": protokol,
            "Hedef_Port": hedef_port,
            "Boyut" : paket_boyutu,
            "TCP_Bayrak" : tcp_bayrak
        }

        paket_verileri.append(oznitelik)
        print(f"{zaman_damgasi}sn | {kaynak_ip} -> {hedef_ip}:{hedef_port} | Boyut: {paket_boyutu} | Bayrak: {tcp_bayrak}")

print(" Gelişmiş sniffer başlatıldı... Durdurmak için CTRL+C yapın.")

try:
    sniff(iface="wlan0", prn=paket_analizi)
except KeyboardInterrupt:
    print("\n[!] CTRL+C algılandı. Dinleme durduruluyor...")
finally:
    print(" Kapanış protokolü: Veriler matrise dönüştürülüyor...")
    if len(paket_verileri) > 0:
        df = pd.DataFrame(paket_verileri)
        df.to_csv("normal_trafik.csv", index=False)
        print("\n--- İlk 5 Satır Özeti ---")
        print(df.head())
        print("\n BAŞARILI: 'normal_trafik.csv' diske yazıldı!")
    else:
        print(" HATA: Hiç paket yakalanamadı.")
    sys.exit(0)
