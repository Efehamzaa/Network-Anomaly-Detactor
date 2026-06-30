# Network Anomaly Detector (Yapay Zeka Tabanlı Hibrit IDS)

Bu proje, ağ trafiğini gerçek zamanlı olarak dinleyen ve **Makine Öğrenmesi (Isolation Forest)** ile **İmza Tabanlı (Signature-based)** tespit yöntemlerini birleştirerek siber saldırıları anında yakalayan bir Saldırı Tespit Sistemidir (IDS). 

Nesne Yönelimli Programlama (OOP) mantığıyla modüler hale getirilmiş ve veri bilimi standartlarına uygun olarak tasarlanmıştır.

## 🚀 Temel Özellikler
* **Gerçek Zamanlı Ağ Dinleme:** Scapy kullanılarak `promiscuous` (karmaşık) modda canlı trafik analizi.
* **Hibrit Tespit Motoru:**
  * *Yapay Zeka (Anomaly Detection):* Scikit-Learn `Isolation Forest` modeli ile daha önce görülmemiş (Zero-day) anormalliklerin tespiti.
  * *Siber İmza (Signature Detection):* Anormal TCP bayrak kombinasyonlarının (Örn: XMAS, FPU, SYN Flood) deterministik olarak yakalanması.
* **Dinamik Veri İşleme:** Pandas kullanılarak canlı paketlerin anlık olarak matematiksel matrislere (DataFrame) çevrilmesi, eksik sütunların dinamik olarak tamamlanması ve `StandardScaler` ile ölçeklenmesi.
* **Sürekli Loglama:** Tespit edilen tehditlerin `alerts.log` dosyasına saniye saniye işlenmesi.

## 🛠️ Teknoloji Yığını
* **Python 3.10+**
* **Veri Bilimi:** `pandas`, `scikit-learn`, `joblib`
* **Ağ & Siber Güvenlik:** `scapy`

## 📂 Proje Yapısı
```text
├── live_detector.py      # Gerçek zamanlı ağ dinleme ve tespit motoru (Ana Modül)
├── train.py              # Yapay zeka modelini eğiten betik
├── preprocess.py         # Ham ağ verisini ML formatına (One-Hot vb.) çeviren motor
├── advanced_sniffer.py   # Eğitim verisi toplamak için kullanılan gelişmiş sniffer
├── requirements.txt      # Proje bağımlılıkları
