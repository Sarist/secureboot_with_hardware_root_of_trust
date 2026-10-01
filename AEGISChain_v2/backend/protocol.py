"""Canonical v2 report: fixed-width bytes; all integer fields use big endian."""
import hashlib
import struct
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes

PROTOCOL = 'AEGISChain-v2'
DOMAIN = PROTOCOL.encode() + b'\0'
MODES = {'atecc': 1, 'software_demo': 2}
DISABLED_VALUE = -2147483648

class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)

class Report(StrictModel):
    protocol: Literal['AEGISChain-v2']
    hardware_id: str = Field(pattern=r'^[0-9A-F]{12}$')
    atecc_serial: str = Field(pattern=r'^[0-9A-F]{18}$')
    gate_hash: str = Field(pattern=r'^[0-9a-f]{64}$')
    payload_hash: str = Field(pattern=r'^[0-9a-f]{64}$')
    payload_version: int = Field(ge=1, le=2147483647)
    mode: Literal['atecc', 'software_demo']
    temperature_state: int = Field(ge=0, le=3)
    temperature_milli: int = Field(ge=-2147483648, le=2147483647)
    voltage_state: int = Field(ge=0, le=3)
    voltage_milli: int = Field(ge=-2147483648, le=2147483647)

    @model_validator(mode='after')
    def validate_sensor_representation(self):
        for name in ('temperature', 'voltage'):
            state, value = getattr(self, name + '_state'), getattr(self, name + '_milli')
            if (state == 0) != (value == DISABLED_VALUE):
                raise ValueError('Disabled sensors require sentinel; enabled sensors require a value')
        if self.mode == 'atecc' and self.atecc_serial == '0' * 18:
            raise ValueError('Hardware mode requires an ATECC identity')
        return self

class SignedReport(Report):
    challenge_id: str = Field(pattern=r'^[0-9a-f]{32}$')
    nonce: str = Field(pattern=r'^[0-9a-f]{64}$')

class ChallengeResponse(SignedReport):
    expires_in: Literal[30]

class Approval(SignedReport):
    authenticated: Literal[True]
    minimum_payload_version: int = Field(ge=1, le=2147483647)
    scope: Literal['application_gate_poc']

class VerifyRequest(StrictModel):
    hardware_id: str = Field(pattern=r'^[0-9A-F]{12}$')
    challenge_id: str = Field(pattern=r'^[0-9a-f]{32}$')
    signature: str = Field(pattern=r'^[0-9a-f]{128}$')

def digest_report(row):
    r = SignedReport.model_validate({k: row[k] for k in SignedReport.model_fields})
    data = (DOMAIN + r.hardware_id.encode('ascii') + bytes.fromhex(r.atecc_serial)
            + bytes.fromhex(r.challenge_id) + bytes.fromhex(r.nonce)
            + bytes.fromhex(r.gate_hash) + bytes.fromhex(r.payload_hash)
            + struct.pack('>IBBiBi', r.payload_version, MODES[r.mode], r.temperature_state,
                          r.temperature_milli, r.voltage_state, r.voltage_milli))
    return hashlib.sha256(data).digest()

def public_key(value):
    raw = bytes.fromhex(value)
    if len(raw) != 65 or raw[0] != 4:
        raise ValueError('Expected SEC1 uncompressed P-256 public key')
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)

def verify_signature(row, signature, key):
    raw = bytes.fromhex(signature)
    if len(raw) != 64:
        raise ValueError('Expected raw 64-byte r||s signature')
    der = utils.encode_dss_signature(int.from_bytes(raw[:32], 'big'), int.from_bytes(raw[32:], 'big'))
    public_key(key).verify(der, digest_report(row), ec.ECDSA(utils.Prehashed(hashes.SHA256())))
