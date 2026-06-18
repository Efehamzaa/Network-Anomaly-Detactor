from scapy.all import sniff

def paket_analizi(paket):
	if paket.haslayer('IP'):
		kaynak_ip = paket['IP'].src
		hedef_ip = paket['IP'].dst
		protokol = paket['IP'].proto
		print(f"Yakalandi: {kaynak_ip}->{hedef_ip} (Protokol No: {protokol})")

print(f"wlan0 dinleniyor ... ilk 15 paket bekleniyor...")
sniff(iface="wlan0", prn=paket_analizi , count=15)
print("Dinleme Tamamlandi.")
