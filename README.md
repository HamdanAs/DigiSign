# Digital Signature Verification System with RSA and QRIS

Aplikasi web untuk membuat dan memverifikasi tanda tangan digital menggunakan algoritma RSA dan QRIS.

## 🚀 Fitur

- ✅ Generate pasangan kunci RSA (2048-bit)
- ✅ Hash pesan dengan SHA-256
- ✅ Buat digital signature
- ✅ Generate QRIS berisi signature
- ✅ Verifikasi keaslian pesan

## 📦 Instalasi

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Jalankan aplikasi:
```bash
streamlit run app.py
```

3. Buka browser di `http://localhost:8501`

## 🔐 Cara Penggunaan

### Pengirim
1. Klik "Generate Pasangan Kunci RSA"
2. Masukkan pesan yang akan ditandatangani
3. Klik "Tanda Tangani Pesan & Buat QRIS"
4. Download QRIS dan kirim ke penerima

### Penerima
1. Masukkan data dari QRIS (pesan, signature, public key)
2. Klik "Verifikasi Signature"
3. Lihat hasil verifikasi

## 🛠️ Tech Stack

- Python 3.8+
- Streamlit
- PyCryptodome (RSA & SHA-256)
- qrcode (QR Code generation)
- Pillow (Image processing)

## 📁 Struktur Project

```
UAS/
├── app.py              # Main Streamlit application
├── crypto/
│   ├── __init__.py
│   ├── rsa_utils.py    # RSA key utilities
│   └── signature.py    # Digital signature functions
├── qris/
│   ├── __init__.py
│   └── qr_generator.py # QRIS generation
├── requirements.txt
└── README.md
```
