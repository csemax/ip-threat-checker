"""
database.py - Database Handler
Mengelola koneksi dan operasi database SQLite
"""

import sqlite3
import os
from datetime import datetime
from config import Config


class Database:
    """Kelas untuk mengelola database SQLite"""

    def __init__(self):
        """Inisialisasi database"""
        # Pastikan folder instance ada
        os.makedirs(os.path.dirname(Config.DATABASE_PATH), exist_ok=True)
        self.db_path = Config.DATABASE_PATH
        self.init_db()

    def get_connection(self):
        """Membuat koneksi database"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Agar bisa akses kolom by name
        conn.execute("PRAGMA journal_mode=WAL")  # Better concurrency
        return conn

    def init_db(self):
        """Membuat tabel jika belum ada"""
        conn = self.get_connection()
        cursor = conn.cursor()

        # Tabel riwayat scan
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                scan_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                malicious INTEGER DEFAULT 0,
                suspicious INTEGER DEFAULT 0,
                harmless INTEGER DEFAULT 0,
                undetected INTEGER DEFAULT 0,
                total_vendors INTEGER DEFAULT 0,
                risk_level TEXT DEFAULT 'UNKNOWN',
                country TEXT DEFAULT '-',
                as_owner TEXT DEFAULT '-',
                network TEXT DEFAULT '-',
                raw_response TEXT,
                scan_type TEXT DEFAULT 'single'
            )
        ''')

        # Tabel detail per vendor
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_details (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                vendor_name TEXT NOT NULL,
                category TEXT DEFAULT 'undetected',
                result TEXT DEFAULT 'clean',
                method TEXT DEFAULT 'blacklist',
                FOREIGN KEY (scan_id) REFERENCES scan_history(id)
                    ON DELETE CASCADE
            )
        ''')

        # Index untuk performa query
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_ip_address 
            ON scan_history(ip_address)
        ''')

        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_scan_date 
            ON scan_history(scan_date)
        ''')

        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_risk_level 
            ON scan_history(risk_level)
        ''')

        conn.commit()
        conn.close()
        print(f"[DB] Database initialized at {self.db_path}")

    def save_scan(self, scan_data: dict) -> int:
        """
        Menyimpan hasil scan ke database

        Args:
            scan_data: Dictionary berisi hasil scan

        Returns:
            int: ID record yang baru disimpan
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO scan_history 
            (ip_address, scan_date, malicious, suspicious, harmless, 
             undetected, total_vendors, risk_level, country, as_owner, 
             network, raw_response, scan_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_data.get('ip_address'),
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            scan_data.get('malicious', 0),
            scan_data.get('suspicious', 0),
            scan_data.get('harmless', 0),
            scan_data.get('undetected', 0),
            scan_data.get('total_vendors', 0),
            scan_data.get('risk_level', 'UNKNOWN'),
            scan_data.get('country', '-'),
            scan_data.get('as_owner', '-'),
            scan_data.get('network', '-'),
            scan_data.get('raw_response', ''),
            scan_data.get('scan_type', 'single')
        ))

        scan_id = cursor.lastrowid

        # Simpan detail per vendor
        vendor_details = scan_data.get('vendor_details', [])
        for detail in vendor_details:
            cursor.execute('''
                INSERT INTO scan_details 
                (scan_id, vendor_name, category, result, method)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                scan_id,
                detail.get('vendor_name', ''),
                detail.get('category', 'undetected'),
                detail.get('result', 'clean'),
                detail.get('method', 'blacklist')
            ))

        conn.commit()
        conn.close()
        return scan_id

    def get_history(self, limit=100, offset=0) -> list:
        """Mengambil riwayat scan"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM scan_history 
            ORDER BY scan_date DESC 
            LIMIT ? OFFSET ?
        ''', (limit, offset))

        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return rows

    def get_scan_by_id(self, scan_id: int) -> dict:
        """Mengambil detail scan berdasarkan ID"""
        conn = self.get_connection()
        cursor = conn.cursor()

        # Ambil data scan
        cursor.execute('SELECT * FROM scan_history WHERE id = ?', (scan_id,))
        scan = cursor.fetchone()

        if not scan:
            conn.close()
            return None

        scan_dict = dict(scan)

        # Ambil detail vendor
        cursor.execute('''
            SELECT * FROM scan_details 
            WHERE scan_id = ? 
            ORDER BY category, vendor_name
        ''', (scan_id,))

        scan_dict['details'] = [dict(row) for row in cursor.fetchall()]

        conn.close()
        return scan_dict

    def search_ip(self, ip_address: str) -> list:
        """Mencari riwayat scan berdasarkan IP"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM scan_history 
            WHERE ip_address LIKE ? 
            ORDER BY scan_date DESC
        ''', (f'%{ip_address}%',))

        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return rows

    def get_statistics(self) -> dict:
        """Mengambil statistik keseluruhan"""
        conn = self.get_connection()
        cursor = conn.cursor()

        stats = {}

        # Total scan
        cursor.execute('SELECT COUNT(*) as total FROM scan_history')
        stats['total_scans'] = cursor.fetchone()['total']

        # Unique IPs
        cursor.execute(
            'SELECT COUNT(DISTINCT ip_address) as total FROM scan_history'
        )
        stats['unique_ips'] = cursor.fetchone()['total']

        # Per risk level
        cursor.execute('''
            SELECT risk_level, COUNT(*) as count 
            FROM scan_history 
            GROUP BY risk_level
        ''')
        risk_counts = {row['risk_level']: row['count']
                       for row in cursor.fetchall()}
        stats['high_risk'] = risk_counts.get('HIGH', 0)
        stats['medium_risk'] = risk_counts.get('MEDIUM', 0)
        stats['low_risk'] = risk_counts.get('LOW', 0)
        stats['safe'] = risk_counts.get('SAFE', 0)

        # Recent scans (5 terakhir)
        cursor.execute('''
            SELECT * FROM scan_history 
            ORDER BY scan_date DESC 
            LIMIT 5
        ''')
        stats['recent_scans'] = [dict(row) for row in cursor.fetchall()]

        # Scan hari ini
        cursor.execute('''
            SELECT COUNT(*) as total FROM scan_history 
            WHERE DATE(scan_date) = DATE('now')
        ''')
        stats['today_scans'] = cursor.fetchone()['total']

        conn.close()
        return stats

    def delete_scan(self, scan_id: int) -> bool:
        """Menghapus record scan"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('DELETE FROM scan_details WHERE scan_id = ?', (scan_id,))
        cursor.execute('DELETE FROM scan_history WHERE id = ?', (scan_id,))

        conn.commit()
        affected = cursor.rowcount
        conn.close()
        return affected > 0

    def clear_history(self) -> int:
        """Menghapus semua riwayat"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('DELETE FROM scan_details')
        cursor.execute('DELETE FROM scan_history')

        conn.commit()
        affected = cursor.rowcount
        conn.close()
        return affected