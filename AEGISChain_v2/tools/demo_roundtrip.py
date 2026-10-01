"""Explicit host simulator. Re-enrolls only test identity DE0000000002."""
import argparse,json,ssl,sys
from pathlib import Path
import httpx
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec,utils
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.protocol import PROTOCOL,DISABLED_VALUE,Approval,digest_report
from backend.store import make_store
p=argparse.ArgumentParser();p.add_argument('--url',default='https://127.0.0.1:8443');p.add_argument('--ca',default='runtime/ca.pem');a=p.parse_args()
if not a.url.startswith('https://'):p.error('HTTPS required')
key=ec.generate_private_key(ec.SECP256R1())
row=dict(hardware_id='DE0000000002',atecc_serial='000000000000000000',
         public_key=key.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint).hex(),
         mode='software_demo',approved_gate_hash='ab'*32,approved_payload_hash='cd'*32,minimum_payload_version=1,enabled=True,
         require_temperature=False,require_voltage=False,temperature_min=0,temperature_max=70000,voltage_min=3000,voltage_max=3600)
make_store().enroll(row)
report=dict(protocol=PROTOCOL,hardware_id=row['hardware_id'],atecc_serial=row['atecc_serial'],gate_hash=row['approved_gate_hash'],
            payload_hash=row['approved_payload_hash'],payload_version=1,mode=row['mode'],temperature_state=0,temperature_milli=DISABLED_VALUE,
            voltage_state=0,voltage_milli=DISABLED_VALUE)
with httpx.Client(base_url=a.url,verify=ssl.create_default_context(cafile=a.ca),timeout=10) as client:
    response=client.post('/api/v2/device/challenge',json=report);response.raise_for_status();challenge=response.json()
    r,s=utils.decode_dss_signature(key.sign(digest_report(challenge),ec.ECDSA(utils.Prehashed(hashes.SHA256()))))
    proof=dict(hardware_id=row['hardware_id'],challenge_id=challenge['challenge_id'],signature=(r.to_bytes(32,'big')+s.to_bytes(32,'big')).hex())
    response=client.post('/api/v2/device/verify',json=proof);response.raise_for_status();approved=Approval.model_validate(response.json())
    for field,value in report.items():assert getattr(approved,field)==value
    assert approved.challenge_id==challenge['challenge_id'] and approved.nonce==challenge['nonce']
    assert client.post('/api/v2/device/verify',json=proof).status_code==401
    print('HOST SIMULATOR: v2 HTTPS signature and report binding PASS; replay rejected. No physical handoff performed.')
