"""Create local demo TLS certificates and a matching ESP32 config template."""
import argparse
import ipaddress
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

p = argparse.ArgumentParser()
p.add_argument('--host', required=True, help='LAN IP or DNS name used by the ESP32')
p.add_argument('--mode', type=int, choices=[0, 1, 2], default=0)
a = p.parse_args()
if any(c in a.host for c in ['"', '\n', '\r', '/', '\\', ':']):
    p.error('Use an IPv4 address or plain DNS hostname')
root = Path(__file__).resolve().parents[1]
runtime = root / 'runtime'
config = root / 'firmware/AEGIS_Gate/config.h'
if any((runtime / n).exists() for n in ['ca.pem', 'server.pem', 'server-key.pem']) or config.exists():
    p.error('Existing TLS/config files found; preserve them or move them aside explicitly before regenerating')
os.umask(0o077)
runtime.mkdir(exist_ok=True)
now = datetime.now(timezone.utc)
ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'AEGIS local prototype CA')])
ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
      .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
      .not_valid_after(now + timedelta(days=3650)).add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
      .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
      .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
      .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), critical=True)
      .sign(ca_key, hashes.SHA256()))
try:
    san = x509.IPAddress(ipaddress.ip_address(a.host))
except ValueError:
    san = x509.DNSName(a.host)
server = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, a.host)]))
          .issuer_name(ca_name).public_key(server_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=365))
          .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
          .add_extension(x509.SubjectAlternativeName([san]), critical=False)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()), critical=False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
          .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, None, None), critical=True)
          .sign(ca_key, hashes.SHA256()))
ca_pem = ca.public_bytes(serialization.Encoding.PEM).decode()
(runtime / 'ca.pem').write_text(ca_pem)
(runtime / 'server.pem').write_bytes(server.public_bytes(serialization.Encoding.PEM))
(runtime / 'server-key.pem').write_bytes(server_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
# CA private key intentionally not persisted: generate a fresh CA if replacing the certificate.
text = (root / 'firmware/AEGIS_Gate/config.example.h').read_text()
text = text.replace('#define AEGIS_MODE 0', f'#define AEGIS_MODE {a.mode}')
text = text.replace('https://192.168.1.10:8443', f'https://{a.host}:8443')
text = text.replace('PASTE_YOUR_CA_CERTIFICATE_HERE', ca_pem)
config.write_text(text)
print('Created local TLS files and config.h. Edit only Wi-Fi credentials and key slot as needed.')
print('Server certificate host:', a.host, '; explicitly selected mode:', a.mode)
