"""Compile and exercise the SAME response, encoding and final policy headers used on ESP32."""
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
import pytest
from backend.protocol import digest_report, DISABLED_VALUE
ROOT=Path(__file__).resolve().parents[1]

@pytest.fixture(scope='session')
def native(tmp_path_factory):
    compiler=shutil.which('g++') or shutil.which('clang++')
    header=Path(os.environ.get('ARDUINOJSON_INCLUDE',str(Path.home()/'Arduino/libraries/ArduinoJson/src')))
    if not compiler or not (header/'ArduinoJson.h').exists():
        pytest.skip('Native C++ tests require g++/clang++ and ARDUINOJSON_INCLUDE')
    exe=tmp_path_factory.mktemp('native')/'check'
    subprocess.run([compiler,'-std=c++17','-I'+str(ROOT/'libraries/AEGISCore/src'),'-I'+str(header),str(ROOT/'tests/native.cpp'),'-o',str(exe)],check=True)
    return exe

def run(native,kind,value):
    return subprocess.check_output([str(native),kind],input=json.dumps(value),text=True).strip()

@pytest.fixture
def exchange(env):
    report=env['report'];id='01'*16;nonce='02'*32
    signed=report|{'challenge_id':id,'nonce':nonce}
    response=signed|{'authenticated':True,'minimum_payload_version':2,'scope':'application_gate_poc'}
    return dict(report=report,response=response,id=id,nonce=nonce)

def test_actual_encoding_matches_backend(native,exchange):
    raw=bytes.fromhex(run(native,'encode',exchange))
    assert hashlib.sha256(raw).digest()==digest_report(exchange['response'])

def test_valid_approval(native,exchange):assert run(native,'approval',exchange)=='ALLOW'

@pytest.mark.parametrize('change',[
 {'authenticated':False},{'authenticated':1},{'authenticated':'true'},{'extra':True},
 {'hardware_id':'001122334455'},{'atecc_serial':'0'*18},{'gate_hash':'ef'*32},{'payload_hash':'ef'*32},
 {'payload_version':1},{'payload_version':'2'},{'payload_version':2.5},{'mode':'atecc'},
 {'challenge_id':'03'*16},{'nonce':'03'*32},{'scope':'secure_boot'},{'minimum_payload_version':3},
 {'minimum_payload_version':0},{'minimum_payload_version':True},{'temperature_state':1},{'voltage_milli':3300}])
def test_malformed_or_mismatched_approval_blocks(native,exchange,change):
    exchange['response']|=change;assert run(native,'approval',exchange)=='BLOCK'

@pytest.mark.parametrize('field',['authenticated','scope','nonce','gate_hash','minimum_payload_version'])
def test_missing_approval_fields(native,exchange,field):
    del exchange['response'][field];assert run(native,'approval',exchange)=='BLOCK'

def test_challenge_schema(native,exchange):
    exchange['response']=exchange['report']|{'challenge_id':exchange['id'],'nonce':exchange['nonce'],'expires_in':30}
    assert run(native,'challenge',exchange)=='ALLOW'
    exchange['response']['expires_in']='30';assert run(native,'challenge',exchange)=='BLOCK'

def test_invalid_json(native):
    assert subprocess.check_output([str(native),'approval'],input='{',text=True)=='BLOCK'

@pytest.mark.parametrize('failed_stage',range(7))
def test_each_final_stage_required(native,failed_stage):
    checks=[True]*7;checks[failed_stage]=False;assert run(native,'checks',checks)=='BLOCK'

def test_all_stages_pass(native): assert run(native,'checks',[True]*7)=='ALLOW'

@pytest.mark.parametrize('version,floor,highest,expected',[(1,2,0,'BLOCK'),(2,1,3,'BLOCK'),(0,1,0,'BLOCK'),(3,2,3,'ALLOW')])
def test_local_rollback(native,version,floor,highest,expected):
    assert run(native,'version',dict(version=version,floor=floor,highest=highest))==expected

@pytest.mark.parametrize('state,value,required,expected',[(0,DISABLED_VALUE,False,'ALLOW'),(0,DISABLED_VALUE,True,'BLOCK'),
 (1,3300,True,'ALLOW'),(1,2800,True,'BLOCK'),(2,3300,True,'BLOCK'),(3,0,True,'BLOCK'),(0,3300,False,'BLOCK')])
def test_sensor_policy(native,state,value,required,expected):
    assert run(native,'sensor',dict(state=state,value=value,required=required,min=3000,max=3600))==expected

@pytest.mark.parametrize('change',[{}, {'present':False},{'consumed':False},{'software_reset':False},
 {'factory_restored':False},{'image_valid':False},{'actual_hash':'bb'*32},{'actual_version':1},{'magic':0}])
def test_one_shot_payload_ticket(native,change):
    t=dict(magic=0xAE615202,version=2,hash='aa'*32,present=True,consumed=True,software_reset=True,
           factory_restored=True,image_valid=True,actual_hash='aa'*32,actual_version=2)
    assert run(native,'ticket',t|change)==('BLOCK' if change else 'ALLOW')
