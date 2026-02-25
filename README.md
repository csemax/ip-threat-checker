# 🔐 IP Threat Intelligence Checker

Sistem berbasis web untuk menganalisis dan mengkorelasikan tingkat ancaman sebuah IP Address menggunakan multi-source Threat Intelligence API.

Project ini mengintegrasikan:

- 🛡️ VirusTotal API
- 🚨 AbuseIPDB API
- 📊 Correlation & Risk Scoring Engine
- 🌐 Flask Web Interface
- 🗄️ SQLite Database (History & Analytics)

---

## 📌 Deskripsi

IP Threat Intelligence Checker adalah aplikasi web yang digunakan untuk:

- Melakukan pengecekan IP Address terhadap database ancaman global
- Menggabungkan hasil dari beberapa sumber Threat Intelligence
- Menghitung skor risiko akhir (Final Threat Score)
- Menyimpan riwayat scan
- Menampilkan statistik dan dashboard analitik

Sistem ini dikembangkan sebagai implementasi konsep Cyber Threat Intelligence (CTI) berbasis integrasi multi-source API.

## 🚀 Fitur Utama

### ✅ Single IP Check
- Validasi IP
- Analisis VirusTotal
- Analisis AbuseIPDB
- Perhitungan Final Risk Score
- Klasifikasi Risiko (SAFE / LOW / MEDIUM / HIGH)

### 📊 Correlation Engine
Menggabungkan:
- Vendor malicious ratio
- Abuse confidence score
- Jumlah laporan abuse
- Weighting logic untuk menghasilkan final_score (0–100)

### 📁 History & Database
- Penyimpanan hasil scan
- Detail vendor per scan
- Statistik keseluruhan
- Riwayat scan terbaru

### 📈 Dashboard Statistik
- Total scan
- Unique IP
- Distribusi risk level
- Scan hari ini

---

## 🏗️ Arsitektur Sistem

```
User Input
    ↓
Flask Controller
    ↓
Threat Intelligence Layer
    ├── VirusTotal API
    ├── AbuseIPDB API
    ↓
Correlation Engine
    ↓
SQLite Database
    ↓
Web Dashboard / Detail View
```

## 🛠️ Teknologi yang Digunakan

- Python 3.10+
- Flask
- SQLite3
- HTML5 / Bootstrap
- VirusTotal Public API
- AbuseIPDB API

---

## 📦 Instalasi

### 1️⃣ Clone Repository

```bash
git clone https://github.com/username/ip-threat-checker.git
cd ip-threat-checker
```

### 2️⃣ Buat Virtual Environment

```bash
python -m venv venv
venv\Scripts\activate  # Windows
```

### 3️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

Jika belum ada requirements.txt:

```bash
pip install flask requests python-dotenv
```

---

## 🔑 Konfigurasi API

Buat file `.env` atau edit `config.py`:

```
VT_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
```

---

## ▶️ Menjalankan Aplikasi

```bash
python app.py
```

Akses melalui:

```
http://127.0.0.1:5000
```

---

## 🗄️ Database

Database SQLite akan otomatis dibuat di:

```
instance/ip_checker.db
```

Struktur tabel utama:

- scan_history
- scan_details

---

## 📊 Contoh Output

- Final Score: 58 / 100
- Risk Level: MEDIUM
- Source Used:
  - ✔ VirusTotal
  - ✔ AbuseIPDB
- Vendor detection breakdown

---

## 🎯 Tujuan Pengembangan

Project ini dibuat untuk:

- Implementasi konsep Cyber Threat Intelligence
- Pembelajaran integrasi multi-API
- Analisis korelasi ancaman IP
- Laporan Praktik Kerja Lapangan (PKL)

---

## 🔒 Konsep Threat Intelligence

Sistem ini menerapkan:

- Indicator of Compromise (IoC) analysis
- Multi-source validation
- Risk correlation scoring
- Confidence-based classification

---

## 📜 License

Project ini dibuat untuk tujuan edukasi dan pembelajaran.
