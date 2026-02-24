"""
app.py - Main Application
Pegadaian IP Security Checker
Sistem Automasi Pengecekan IP menggunakan VirusTotal API

Author: Fariz Ubaidillah - PKL Pegadaian 2026
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from config import Config
from database import Database
from vt_client import VirusTotalClient
from ip_validator import IPValidator
import json
import csv
from io import StringIO
from flask import Response

# ==========================================
# INISIALISASI APP
# ==========================================
app = Flask(__name__)
app.config.from_object(Config)

# Inisialisasi komponen
db = Database()
vt = VirusTotalClient()
validator = IPValidator()


# ==========================================
# ROUTES - HALAMAN WEB
# ==========================================

@app.route('/')
def index():
    """Halaman Dashboard"""
    stats = db.get_statistics()
    api_valid = vt.check_api_key() if Config.VT_API_KEY != 'YOUR_API_KEY_HERE' else False
    return render_template('index.html', stats=stats, api_valid=api_valid)


@app.route('/single-check', methods=['GET', 'POST'])
def single_check():
    """Halaman Pengecekan Single IP"""
    result = None
    error = None
    ip_input = ''

    if request.method == 'POST':
        ip_input = request.form.get('ip_address', '').strip()

        # Validasi IP
        validation = validator.validate(ip_input)

        if not validation['valid']:
            error = validation['message']
        else:
            # Cek ke VirusTotal
            result = vt.check_ip(ip_input)

            if result['success']:
                # Simpan ke database
                result['scan_type'] = 'single'
                scan_id = db.save_scan(result)
                result['scan_id'] = scan_id
                flash(f'IP {ip_input} berhasil dicek!', 'success')
            else:
                error = result.get('error', 'Terjadi kesalahan')

    return render_template(
        'single_check.html',
        result=result,
        error=error,
        ip_input=ip_input
    )


@app.route('/bulk-check', methods=['GET', 'POST'])
def bulk_check():
    """Halaman Pengecekan Bulk IP"""
    results = []
    errors = []
    ip_input = ''

    if request.method == 'POST':
        ip_input = request.form.get('ip_list', '').strip()
        file = request.files.get('ip_file')

        # Jika ada file yang diupload
        if file and file.filename != '':
            try:
                file_content = file.read().decode('utf-8')
                # Gabungkan isi file dengan textarea
                if ip_input:
                    ip_input += "\n" + file_content
                else:
                    ip_input = file_content
            except Exception:
                errors.append("Gagal membaca file. Pastikan format UTF-8.")
        if not ip_input:
            errors.append('Masukkan minimal 1 IP address')
        else:
            # Parse dan validasi semua IP
            parsed_ips = validator.parse_bulk(ip_input)

            valid_ips = [p for p in parsed_ips if p['valid']]
            invalid_ips = [p for p in parsed_ips if not p['valid']]

            # Tampilkan error untuk IP yang tidak valid
            for inv in invalid_ips:
                errors.append(f"{inv['ip']}: {inv['message']}")

            # Cek setiap IP yang valid
            for ip_data in valid_ips:
                result = vt.check_ip(ip_data['ip'])

                if result['success']:
                    result['scan_type'] = 'bulk'
                    scan_id = db.save_scan(result)
                    result['scan_id'] = scan_id
                    results.append(result)
                else:
                    errors.append(
                        f"{ip_data['ip']}: {result.get('error', 'Error')}")

            if results:
                flash(
                    f'{len(results)} IP berhasil dicek!', 'success')

    return render_template(
        'bulk_check.html',
        results=results,
        errors=errors,
        ip_input=ip_input
    )


@app.route('/history')
def history():
    """Halaman Riwayat Scan"""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page

    search = request.args.get('search', '').strip()

    if search:
        scans = db.search_ip(search)
    else:
        scans = db.get_history(limit=per_page, offset=offset)

    return render_template(
        'history.html',
        scans=scans,
        search=search,
        page=page
    )

@app.route("/export_history")
def export_history():
    import csv
    import io

    db = Database()
    scans = db.get_history(limit=1000, offset=0)

    output = io.StringIO()
    writer = csv.writer(output)

    # Header CSV
    writer.writerow([
        "ID",
        "IP Address",
        "Risk Level",
        "Malicious",
        "Suspicious",
        "Harmless",
        "Country",
        "AS Owner",
        "Scan Type",
        "Scan Date"
    ])

    # Data rows
    for scan in scans:
        writer.writerow([
            scan["id"],
            scan["ip_address"],
            scan["risk_level"],
            scan["malicious"],
            scan["suspicious"],
            scan["harmless"],
            scan["country"],
            scan["as_owner"],
            scan["scan_type"],
            scan["scan_date"]
        ])

    output.seek(0)

    return Response(
        output,
        mimetype="text/csv",
        headers={
            "Content-Disposition":
            "attachment; filename=scan_history.csv"
        }
    )


@app.route('/detail/<int:scan_id>')
def detail(scan_id):
    """Halaman Detail Scan"""
    scan = db.get_scan_by_id(scan_id)

    if not scan:
        flash('Data scan tidak ditemukan', 'error')
        return redirect(url_for('history'))

    return render_template('detail.html', scan=scan)


@app.route('/delete/<int:scan_id>', methods=['POST'])
def delete_scan(scan_id):
    """Hapus record scan"""
    db.delete_scan(scan_id)
    flash('Record berhasil dihapus', 'success')
    return redirect(url_for('history'))


@app.route('/clear-history', methods=['POST'])
def clear_history():
    """Hapus semua riwayat"""
    count = db.clear_history()
    flash(f'{count} record berhasil dihapus', 'success')
    return redirect(url_for('history'))


# ==========================================
# API ENDPOINTS (untuk AJAX / Integrasi)
# ==========================================

@app.route('/api/check-ip', methods=['POST'])
def api_check_ip():
    """API endpoint untuk cek IP via AJAX"""
    data = request.get_json()

    if not data or 'ip' not in data:
        return jsonify({'error': 'IP address diperlukan'}), 400

    ip = data['ip'].strip()
    validation = validator.validate(ip)

    if not validation['valid']:
        return jsonify({'error': validation['message']}), 400

    result = vt.check_ip(ip)

    if result['success']:
        result['scan_type'] = 'api'
        scan_id = db.save_scan(result)
        result['scan_id'] = scan_id
        # Hapus raw_response dari API response (terlalu besar)
        result.pop('raw_response', None)
        result.pop('vendor_details', None)

    return jsonify(result)


@app.route('/api/validate-ip', methods=['POST'])
def api_validate_ip():
    """API endpoint untuk validasi IP"""
    data = request.get_json()

    if not data or 'ip' not in data:
        return jsonify({'error': 'IP address diperlukan'}), 400

    result = validator.validate(data['ip'])
    return jsonify(result)


@app.route('/api/stats')
def api_stats():
    """API endpoint untuk statistik"""
    stats = db.get_statistics()
    return jsonify(stats)


# ==========================================
# TEMPLATE FILTERS
# ==========================================

@app.template_filter('risk_color')
def risk_color_filter(risk_level):
    """Filter Jinja2 untuk warna berdasarkan risk level"""
    colors = {
        'HIGH': 'danger',
        'MEDIUM': 'warning',
        'LOW': 'info',
        'SAFE': 'success',
        'UNKNOWN': 'secondary'
    }
    return colors.get(risk_level, 'secondary')


@app.template_filter('risk_icon')
def risk_icon_filter(risk_level):
    """Filter Jinja2 untuk icon berdasarkan risk level"""
    icons = {
        'HIGH': 'bi-exclamation-triangle-fill',
        'MEDIUM': 'bi-exclamation-circle-fill',
        'LOW': 'bi-info-circle-fill',
        'SAFE': 'bi-shield-check',
        'UNKNOWN': 'bi-question-circle'
    }
    return icons.get(risk_level, 'bi-question-circle')


# ==========================================
# ERROR HANDLERS
# ==========================================

@app.errorhandler(404)
def not_found(e):
    return render_template('base.html', error='Halaman tidak ditemukan'), 404


@app.errorhandler(500)
def server_error(e):
    return render_template('base.html', error='Server error'), 500


# ==========================================
# MAIN
# ==========================================

if __name__ == '__main__':
    print("=" * 60)
    print("  PEGADAIAN IP SECURITY CHECKER")
    print("  Sistem Automasi Pengecekan IP - VirusTotal API")
    print("=" * 60)

    # Cek API key
    if Config.VT_API_KEY == 'YOUR_API_KEY_HERE':
        print("\n⚠️  WARNING: API Key belum dikonfigurasi!")
        print("  1. Daftar di https://www.virustotal.com/gui/join-us")
        print("  2. Copy API Key dari profil")
        print("  3. Set di config.py atau environment variable VT_API_KEY")
        print()

    print(f"\n🌐 Server berjalan di: http://127.0.0.1:5000")
    print(f"📁 Database: {Config.DATABASE_PATH}\n")

    app.run(
        host='127.0.0.1',
        port=5000,
        debug=True
    )