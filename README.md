# Basit Ağ Sniffer

Bu depo, [Scapy](https://scapy.net/) kullanarak IP paketlerini dinleyen basit bir Python uygulaması içerir. Uygulama, ağ trafiğinden geçen IP paketlerinin kaynak ve hedef adreslerini ve protokol türünü (TCP, UDP, ICMP vb.) ekrana yazdırır.

## Gereksinimler

- Python 3.9+
- scapy

Gerekli bağımlılığı kurmak için:

```bash
pip install scapy
```

> **Not:** Paket yakalama işlemleri yönetici ayrıcalıkları gerektirebilir. Linux ve macOS üzerinde `sudo` ile çalıştırmanız gerekebilir.

## Kullanım

```bash
python sniffer.py [-i INTERFACE] [-c COUNT]
```

- `-i / --interface`: Dinlenecek ağ arayüzü. Belirtilmezse Scapy uygun bir arayüz seçer.
- `-c / --count`: Yakalanacak paket sayısı. Varsayılan olarak sınırsızdır ve Ctrl+C ile durdurabilirsiniz.

Örnek komut:

```bash
sudo python sniffer.py -i eth0
```

Bu komut `eth0` arayüzündeki IP paketlerini yakalayarak her paketin kaynak adresini, hedef adresini ve protokolünü terminale yazdırır.
