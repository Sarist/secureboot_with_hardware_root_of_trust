"""Real loopback TLS, plus explicitly labeled hardware-I/O fault simulations."""
import os
import shutil
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path
import httpx
import pytest
from test_protocol import proof
from test_native import native,run
ROOT=Path(__file__).resolve().parents[1]

@pytest.fixture
def tls_server(env,tmp_path):
    staging=tmp_path/'tls';(staging/'tools').mkdir(parents=True)
    (staging/'firmware/AEGIS_Gate').mkdir(parents=True)
    shutil.copy(ROOT/'tools/setup_tls.py',staging/'tools/setup_tls.py')
    shutil.copy(ROOT/'firmware/AEGIS_Gate/config.example.h',staging/'firmware/AEGIS_Gate/config.example.h')
    subprocess.run([sys.executable,str(staging/'tools/setup_tls.py'),'--host','127.0.0.1','--mode','2'],check=True,capture_output=True)
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    process_env=os.environ|{'PYTHONPATH':str(ROOT),'AEGIS_STORE':'sqlite','AEGIS_DB':env['store'].path}
    url=f'https://127.0.0.1:{port}'
    log=(staging/'server.log').open('w')
    proc=subprocess.Popen([sys.executable,'-m','uvicorn','backend.server:app','--host','127.0.0.1','--port',str(port),'--workers','1',
                           '--ssl-keyfile',str(staging/'runtime/server-key.pem'),'--ssl-certfile',str(staging/'runtime/server.pem')],
                          cwd=ROOT,env=process_env,stdout=log,stderr=log)
    ctx=ssl.create_default_context(cafile=str(staging/'runtime/ca.pem'))
    try:
        with httpx.Client(base_url=url,verify=ctx,trust_env=False,timeout=1) as client:
            for _ in range(100):
                try:
                    if client.get('/health').status_code==200:break
                except httpx.HTTPError:time.sleep(.05)
            else:raise AssertionError('HTTPS server did not start')
        yield url,ctx,proc
    finally:
        if proc.poll() is None:proc.terminate();proc.wait(timeout=10)
        log.close()

def test_https_round_trip_and_replay(tls_server,env):
    url,ctx,_=tls_server
    with httpx.Client(base_url=url,verify=ctx,trust_env=False,timeout=5) as client:
        report=client.post('/api/v2/device/challenge',json=env['report']).json()
        request=proof(env,report)
        approval=client.post('/api/v2/device/verify',json=request)
        assert approval.status_code==200 and approval.json()['authenticated'] is True
        assert client.post('/api/v2/device/verify',json=request).status_code==401

def test_untrusted_tls_blocks(tls_server,native):
    url,_,_=tls_server
    with pytest.raises(httpx.ConnectError):httpx.get(url+'/health',trust_env=False,timeout=2)
    assert run(native,'checks',[True,True,True,True,True,False,False])=='BLOCK'

def test_unavailable_server_blocks(tls_server,native):
    url,ctx,proc=tls_server;proc.terminate();proc.wait(timeout=10)
    with pytest.raises(httpx.ConnectError):httpx.get(url+'/health',verify=ctx,trust_env=False,timeout=2)
    assert run(native,'checks',[True,True,True,True,True,False,False])=='BLOCK'

@pytest.mark.parametrize('fault',['wifi_failure','wifi_timeout','tls_timeout','server_timeout'])
def test_simulated_network_failure_never_completes_gate(native,fault):
    # Hardware Wi-Fi is not controllable on host. Exercise actual final gate policy
    # with the flags left unset by these failing stages; physical checks listed separately.
    assert run(native,'checks',[True,True,True,True,True,False,False])=='BLOCK'
