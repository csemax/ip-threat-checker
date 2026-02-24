"""
ip_validator.py - Modul Validasi IP Address
Memvalidasi format IPv4 dan IPv6
"""

import re
import ipaddress


class IPValidator:
    """Kelas untuk validasi IP Address"""

    @staticmethod
    def validate_ipv4(ip: str) -> bool:
        """
        Validasi format IPv4 address

        Args:
            ip: String IP address

        Returns:
            bool: True jika valid
        """
        try:
            addr = ipaddress.IPv4Address(ip.strip())
            # Tolak private/reserved IP karena tidak ada di VirusTotal
            if addr.is_private:
                return False
            if addr.is_reserved:
                return False
            if addr.is_loopback:
                return False
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def validate_ipv6(ip: str) -> bool:
        """Validasi format IPv6 address"""
        try:
            addr = ipaddress.IPv6Address(ip.strip())
            if addr.is_private or addr.is_reserved or addr.is_loopback:
                return False
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def validate(ip: str) -> dict:
        """
        Validasi IP address (IPv4 atau IPv6)

        Returns:
            dict: {valid: bool, type: str, message: str}
        """
        ip = ip.strip()

        if not ip:
            return {
                'valid': False,
                'type': None,
                'message': 'IP address tidak boleh kosong'
            }

        # Cek IPv4
        try:
            addr = ipaddress.IPv4Address(ip)
            if addr.is_private:
                return {
                    'valid': False,
                    'type': 'IPv4',
                    'message': f'{ip} adalah Private IP (tidak bisa dicek di VirusTotal)'
                }
            if addr.is_loopback:
                return {
                    'valid': False,
                    'type': 'IPv4',
                    'message': f'{ip} adalah Loopback address'
                }
            if addr.is_reserved:
                return {
                    'valid': False,
                    'type': 'IPv4',
                    'message': f'{ip} adalah Reserved IP'
                }
            return {
                'valid': True,
                'type': 'IPv4',
                'message': 'Valid public IPv4 address'
            }
        except ipaddress.AddressValueError:
            pass

        # Cek IPv6
        try:
            addr = ipaddress.IPv6Address(ip)
            if addr.is_private or addr.is_loopback or addr.is_reserved:
                return {
                    'valid': False,
                    'type': 'IPv6',
                    'message': f'{ip} bukan public IPv6 address'
                }
            return {
                'valid': True,
                'type': 'IPv6',
                'message': 'Valid public IPv6 address'
            }
        except ipaddress.AddressValueError:
            pass

        return {
            'valid': False,
            'type': None,
            'message': f'"{ip}" bukan format IP address yang valid'
        }

    @staticmethod
    def parse_bulk(text: str) -> list:
        """
        Parse input bulk IP (dipisah newline, koma, atau spasi)

        Returns:
            list of dict: [{ip, valid, type, message}, ...]
        """
        # Split by newline, comma, semicolon, or whitespace
        ips = re.split(r'[,;\s\n]+', text.strip())
        ips = [ip.strip() for ip in ips if ip.strip()]

        results = []
        seen = set()

        for ip in ips:
            if ip in seen:
                continue
            seen.add(ip)

            validation = IPValidator.validate(ip)
            validation['ip'] = ip
            results.append(validation)

        return results