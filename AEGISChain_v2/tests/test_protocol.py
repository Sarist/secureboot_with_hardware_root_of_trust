from concurrent.futures import ThreadPoolExecutor
import json
import pytest
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec,utils
from backend.protocol import digest_report,verify_signature,DISABLED_VALUE

CH='/api/v2/device/challenge';VE='/api/v2/device/verify'
def challenge(e,**changes): return e['client'].post(CH,json=e['report']|changes)
def proof(e,report,key=None):
    r,s=utils.decode_dss_signature((key or e['key']).sign(digest_report(report),ec.ECDSA(utils.Prehashed(hashes.SHA256()))))
    return dict(hardware_id=report['hardware_id'],challenge_id=report['challenge_id'],signature=(r.to_bytes(32,'big')+s.to_bytes(32,'big')).hex())

def test_success_replay_audit(env):
    report=challenge(env).json();req=proof(env,report)
    result=env['client'].post(VE,json=req)
    assert result.status_code==200
    for k,v in env['report'].items(): assert result.json()[k]==v
    assert result.json()['authenticated'] is True
    assert env['client'].post(VE,json=req).status_code==401
    with env['store'].connect() as db:
        row=json.loads(db.execute('SELECT record FROM aegis_v2_audit').fetchone()[0])
    assert row['authentication_result']=='accepted'
    verify_signature(row['report'],row['signature'],row['public_key'])

def test_atomic_concurrent_replay(env):
    req=proof(env,challenge(env).json())
    with ThreadPoolExecutor(max_workers=2) as p:
        codes=list(p.map(lambda _:env['client'].post(VE,json=req).status_code,range(2)))
    assert sorted(codes)==[200,401]

@pytest.mark.parametrize('change',[
    {'hardware_id':'001122334455'},{'atecc_serial':'0123456789ABCDEF01'},
    {'gate_hash':'ef'*32},{'payload_hash':'ef'*32},{'mode':'atecc'},{'payload_version':1},
    {'temperature_state':2,'temperature_milli':80000},{'voltage_state':2,'voltage_milli':2000},
    {'temperature_state':3,'temperature_milli':0},{'voltage_state':3,'voltage_milli':0},
    {'temperature_state':1,'temperature_milli':90000},{'voltage_state':1,'voltage_milli':9000}])
def test_reject_policy(env,change): assert challenge(env,**change).status_code==403

def test_disabled(env):
    env['store'].enroll(env['row']|{'enabled':False});assert challenge(env).status_code==403

@pytest.mark.parametrize('sensor',['temperature','voltage'])
def test_required_sensor_cannot_be_disabled(env,sensor):
    env['store'].enroll(env['row']|{'require_'+sensor:True});assert challenge(env).status_code==403

@pytest.mark.parametrize('change',[
 {'atecc_serial':'0123456789ABCDEF01'},{'nonce':'11'*32},{'gate_hash':'11'*32},{'payload_hash':'11'*32},
 {'payload_version':3},{'mode':'atecc'},{'temperature_state':1,'temperature_milli':10000},
 {'voltage_state':1,'voltage_milli':3300}])
def test_signed_data_binding(env,change):
    report=challenge(env).json();bad=proof(env,report|change)
    assert env['client'].post(VE,json=bad).status_code==401
    assert env['client'].post(VE,json=proof(env,report)).status_code==401

def test_wrong_private_key(env):
    req=proof(env,challenge(env).json(),ec.generate_private_key(ec.SECP256R1()))
    assert env['client'].post(VE,json=req).status_code==401

def test_invalid_signature(env):
    req=proof(env,challenge(env).json())|{'signature':'00'*64}
    assert env['client'].post(VE,json=req).status_code==401

def test_expiry(env):
    req=proof(env,challenge(env).json());env['now'][0]+=30
    assert env['client'].post(VE,json=req).status_code==401

@pytest.mark.parametrize('change',[{'enabled':False},{'minimum_payload_version':3},{'approved_payload_hash':'ee'*32},
 {'atecc_serial':'0123456789ABCDEF01'},{'require_temperature':True},{'mode':'atecc'}])
def test_identity_change_during_challenge(env,change):
    req=proof(env,challenge(env).json());env['store'].enroll(env['row']|change)
    assert env['client'].post(VE,json=req).status_code==403

def test_public_key_rotation(env):
    req=proof(env,challenge(env).json())
    key=ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint).hex()
    env['store'].enroll(env['row']|{'public_key':key});assert env['client'].post(VE,json=req).status_code==403

def test_wrong_device_challenge(env):
    req=proof(env,challenge(env).json())|{'hardware_id':'001122334455'}
    assert env['client'].post(VE,json=req).status_code==401

def test_unknown_challenge(env):
    assert env['client'].post(VE,json={'hardware_id':env['row']['hardware_id'],'challenge_id':'00'*16,'signature':'00'*64}).status_code==401

def test_independent_challenges(env):
    reports=[challenge(env).json() for _ in range(2)]
    assert reports[0]['challenge_id']!=reports[1]['challenge_id']
    for r in reports: assert env['client'].post(VE,json=proof(env,r)).status_code==200

def test_capacity_cleanup(env):
    for _ in range(4): assert challenge(env).status_code==200
    assert challenge(env).status_code==429
    env['now'][0]+=31;assert challenge(env).status_code==200

@pytest.mark.parametrize('change',[{'hardware_id':'bad'},{'protocol':'AEGIS-AUTH-v1'},{'payload_version':True},
 {'payload_version':'2'},{'payload_version':0},{'extra':1},{'temperature_state':0,'temperature_milli':0}])
def test_strict_requests(env,change): assert challenge(env,**change).status_code==422

def test_malformed_signature(env):
    req=proof(env,challenge(env).json())|{'signature':'00'};assert env['client'].post(VE,json=req).status_code==422

def test_v1_not_accepted(env): assert env['client'].post('/api/v1/device/challenge',json=env['report']).status_code==404

def test_audit_failure_no_approval(env,monkeypatch):
    req=proof(env,challenge(env).json())
    def fail(_):raise RuntimeError('database unavailable')
    monkeypatch.setattr(env['store'],'record',fail)
    with pytest.raises(RuntimeError):env['client'].post(VE,json=req)
    assert env['client'].post(VE,json=req).status_code==401

def test_hardware_mode_protocol_with_simulated_key(env):
    # Tests protocol mode/serial binding, not a physical secure-element signature.
    env['store'].enroll(env['row']|{'mode':'atecc'})
    report=challenge(env,mode='atecc').json()
    result=env['client'].post(VE,json=proof(env,report))
    assert result.status_code==200 and result.json()['mode']=='atecc'
