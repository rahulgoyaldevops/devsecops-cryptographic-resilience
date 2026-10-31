"""
Certificate Generator for Test Suite
Creates:
1. Valid Enterprise P-384 Certificate
2. Intentionally Degenerate / Weak Key (Simulating eMudhra 2026 flaw) for CI test
"""
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# 1. Generate Valid Enterprise Certificate
valid_private_key = ec.generate_private_key(ec.SECP384R1())
valid_subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Enterprise Security Platform"),
    x509.NameAttribute(NameOID.COMMON_NAME, "valid-ca.internal.net"),
])

valid_cert = x509.CertificateBuilder().subject_name(
    valid_subject
).issuer_name(
    valid_subject
).public_key(
    valid_private_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.now(datetime.timezone.utc)
).not_valid_after(
    datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
).sign(valid_private_key, hashes.SHA384())

with open("samples/valid-certs/valid-enterprise-p384.crt", "wb") as f:
    f.write(valid_cert.public_bytes(serialization.Encoding.PEM))

# 2. Generate Weak Certificate simulating known revoked serial
revoked_subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Untrusted Intermediate Corp"),
    x509.NameAttribute(NameOID.COMMON_NAME, "compromised-intermediate-ca.net"),
])

# Use revoked serial 0x5f3a2c89b147d3e0
revoked_cert = x509.CertificateBuilder().subject_name(
    revoked_subject
).issuer_name(
    revoked_subject
).public_key(
    valid_private_key.public_key()
).serial_number(
    0x5f3a2c89b147d3e0
).not_valid_before(
    datetime.datetime.now(datetime.timezone.utc)
).not_valid_after(
    datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)
).sign(valid_private_key, hashes.SHA384())

with open("samples/weak-certs/simulated-revoked-intermediate.crt", "wb") as f:
    f.write(revoked_cert.public_bytes(serialization.Encoding.PEM))

print("Generated sample certificates successfully.")
