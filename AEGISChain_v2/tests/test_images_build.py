import hashlib
import struct
import subprocess
import sys
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from image import inspect_image
from build_flash import layout
from test_native import native

def fixture_image():
    header=bytearray(24);header[0]=0xe9;header[1]=1;header[23]=1
    payload=bytearray(0x120);payload[0x100:0x110]=b'AEGIS-PAYLOAD-2\0';struct.pack_into('<I',payload,0x110,2)
    image=header+struct.pack('<II',0x3f400020,len(payload))+payload
    checksum=0xef
    for v in payload:checksum^=v
    image+=b'\0'*(((len(image)+16)&~15)-len(image)-1)+bytes([checksum])
    image+=hashlib.sha256(image).digest()
    return bytes(image)

def test_padding_does_not_affect_hash():
    data=fixture_image();assert inspect_image(data,True)==inspect_image(data+b'\xff'*8192,True)
    assert inspect_image(data,True)==inspect_image(data+b'\x01'*4096,True)

def test_version_is_embedded():assert inspect_image(fixture_image(),True)['version']==2

@pytest.mark.parametrize('case',['empty','magic','truncated','segment_overflow','checksum','digest','payload_bytes'])
def test_corrupted_image_rejected(case):
    data=bytearray(fixture_image())
    if case=='empty':data=bytearray()
    elif case=='magic':data[0]=0
    elif case=='truncated':data=data[:-1]
    elif case=='segment_overflow':struct.pack_into('<I',data,28,0xfffffffc)
    elif case=='checksum':data[-33]^=1
    elif case=='digest':data[-1]^=1
    elif case=='payload_bytes':data[100]^=1
    with pytest.raises(ValueError):inspect_image(data,True)

def test_native_image_bounds(native,tmp_path):
    data=fixture_image();p=tmp_path/'image.bin';p.write_bytes(data+b'\xff'*2048)
    assert int(subprocess.check_output([str(native),'image',str(p)]))==inspect_image(data)['length']
    p.write_bytes(data[:-1]);assert subprocess.check_output([str(native),'image',str(p)])==b'0'

def test_flash_layout_preserves_nvs():
    rows=layout();assert rows['nvs']==dict(type='data',subtype='nvs',offset=0x9000,size=0x5000)
    assert rows['aegis']['offset']==0x10000 and rows['payload']['offset']==0x190000
    assert rows['aegis']['subtype']=='factory' and rows['payload']['subtype']=='ota_0'

def test_success_string_only_payload_source():
    marker='Booted'+' successfully'
    gate=ROOT/'firmware/AEGIS_Gate/AEGIS_Gate.ino';payload=ROOT/'firmware/AEGIS_Payload/AEGIS_Payload.ino'
    assert marker not in gate.read_text();assert payload.read_text().count(marker)==1
    assert payload.read_text().index('esp_ota_set_boot_partition')<payload.read_text().index(marker)
    assert payload.read_text().index('aegisTicketAllows')<payload.read_text().index(marker)

def test_no_provisioning_or_insecure_tls():
    source=(ROOT/'firmware/AEGIS_Gate/ECCX08.cpp').read_text()
    for name in ['writeConfiguration(', 'writeSlot(', 'generatePrivateKey(', '::lock(', '::write(']: assert name not in source
    assert 'if (!allowed || dataLength > 64) return 0;' in source
    gate=(ROOT/'firmware/AEGIS_Gate/AEGIS_Gate.ino').read_text()
    assert 'setInsecure' not in gate
    assert gate.count('esp_ota_set_boot_partition(payloadPartition)')==1

@pytest.mark.parametrize('corruption',['none','offset','content','extra'])
def test_flash_plan_rejects_unsafe_manifest(tmp_path,monkeypatch,corruption):
    import json
    import build_flash as helper
    root=tmp_path;build=root/'build';build.mkdir()
    entries=[]
    for name,offset in [('AEGIS_Gate/AEGIS_Gate.ino.bootloader.bin',0x1000),
                        ('AEGIS_Gate/AEGIS_Gate.ino.partitions.bin',0x8000),
                        ('factory_otadata.bin',0xe000),('AEGIS_Gate/AEGIS_Gate.ino.bin',0x10000),
                        ('AEGIS_Payload/AEGIS_Payload.ino.bin',0x190000)]:
        file=build/name;file.parent.mkdir(exist_ok=True);file.write_bytes(b'\xff'*16)
        entries.append(dict(offset=offset,path='build/'+name,sha256=hashlib.sha256(file.read_bytes()).hexdigest()))
    if corruption=='offset':entries[0]['offset']=0x9000
    if corruption=='content':(root/entries[0]['path']).write_bytes(b'changed')
    if corruption=='extra':entries.append(entries[0].copy())
    (build/'manifest.json').write_text(json.dumps(dict(partitions=layout(),files=entries)))
    monkeypatch.setattr(helper,'ROOT',root)
    def no_process(*a,**kw):raise AssertionError('Dry run must not access serial hardware')
    monkeypatch.setattr(helper.subprocess,'run',no_process)
    if corruption=='none':helper.flash('COM_TEST',False)
    else:
        with pytest.raises(ValueError):helper.flash('COM_TEST',False)
