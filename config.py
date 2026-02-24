"""
config.py - Konfigurasi Aplikasi
Pegadaian IP Checker System
"""

import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Kelas konfigurasi utama"""

    # Flask Config
    SECRET_KEY = os.getenv('SECRET_KEY', 'pegadaian-ip-checker-secret-2024')
    DEBUG = True

    # VirusTotal API Config
    # Daftar gratis di: https://www.virustotal.com/gui/join-us
    VT_API_KEY = os.getenv('VT_API_KEY', 'YOUR_API_KEY_HERE')
    VT_BASE_URL = 'https://www.virustotal.com/api/v3'

    ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')
    ABUSEIPDB_BASE_URL = 'https://api.abuseipdb.com/api/v2'

    # Rate Limiting (Free API: 4 requests/menit)
    VT_RATE_LIMIT = 4
    VT_RATE_PERIOD = 60  # detik

    ABUSE_RATE_LIMIT = 1000  # free tier lebih besar
    ABUSE_RATE_PERIOD = 86400  # 24 jam

    # Database
    DATABASE_PATH = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        'instance',
        'ip_checker.db'
    )

    # Risk Level Thresholds
    RISK_HIGH_THRESHOLD = 5      # >= 5 vendor deteksi = HIGH
    RISK_MEDIUM_THRESHOLD = 1    # >= 1 vendor deteksi = MEDIUM
    # 0 vendor deteksi = SAFE