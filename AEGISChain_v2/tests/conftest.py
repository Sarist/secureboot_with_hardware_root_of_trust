import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from backend.server import create_app
from backend.store import SQLiteStore
from backend.protocol import DISABLED_VALUE

@pytest.fixture
def env(tmp_path):
    key=ec.generate_private_key(ec.SECP256R1())
    row=dict(hardware_id='AABBCCDDEEFF',atecc_serial='01238B9993793ACCEE',
             public_key=key.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint).hex(),
             mode='software_demo',approved_gate_hash='ab'*32,approved_payload_hash='cd'*32,minimum_payload_version=2,enabled=True,
             require_temperature=False,require_voltage=False,temperature_min=0,temperature_max=70000,voltage_min=3000,voltage_max=3600)
    report=dict(protocol='AEGISChain-v2',hardware_id=row['hardware_id'],atecc_serial=row['atecc_serial'],gate_hash=row['approved_gate_hash'],
                payload_hash=row['approved_payload_hash'],payload_version=2,mode=row['mode'],temperature_state=0,temperature_milli=DISABLED_VALUE,
                voltage_state=0,voltage_milli=DISABLED_VALUE)
    store=SQLiteStore(tmp_path/'test.db');store.enroll(row);now=[100.0]
    return dict(key=key,row=row,report=report,store=store,now=now,client=TestClient(create_app(store,lambda:now[0])))
