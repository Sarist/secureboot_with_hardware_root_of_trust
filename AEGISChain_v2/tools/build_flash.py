"""Build two apps; derive offsets from CSV; flash only on explicit --execute.
Never use Arduino's merged.bin: its otadata initializer selects OTA0 directly.
"""
import argparse
import csv
import hashlib
import json
import shutil
import struct
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from image import inspect_image
ROOT=Path(__file__).resolve().parents[1]
CSV=ROOT/'partitions/aegis_dual.csv'

def layout():
    rows={}
    for row in csv.reader(CSV.read_text().splitlines()):
        if not row or row[0].strip().startswith('#'): continue
        name,kind,sub,offset,size,*_=map(str.strip,row)
        rows[name]={'type':kind,'subtype':sub,'offset':int(offset,0),'size':int(size,0)}
    ordered=sorted(rows.values(),key=lambda r:r['offset'])
    for i,row in enumerate(ordered):
        if row['offset']%4096 or row['size']%4096 or row['offset']+row['size']>4*1024*1024: raise ValueError('Invalid 4MB partition layout')
        if i and ordered[i-1]['offset']+ordered[i-1]['size']>row['offset']: raise ValueError('Overlapping partitions')
    assert rows['nvs']['offset']==0x9000 and rows['nvs']['size']==0x5000
    return rows

def decode_table(data):
    rows={}
    for at in range(0,len(data)-31,32):
        if data[at:at+2]!=b'\xaa\x50': break
        _,kind,sub,off,size,label,flags=struct.unpack_from('<HBBII16sI',data,at)
        rows[label.rstrip(b'\0').decode()]={'type':kind,'subtype':sub,'offset':off,'size':size}
    return rows

def build(version):
    rows=layout();build_dir=ROOT/'build';build_dir.mkdir(exist_ok=True)
    for project in ['AEGIS_Gate','AEGIS_Payload']:
        staged=build_dir/'staged'/project
        shutil.copytree(ROOT/'firmware'/project,staged,dirs_exist_ok=True)
        # Do not retain an old private config after operator removes it from source.
        if not (ROOT/'firmware'/project/'config.h').exists() and (staged/'config.h').exists(): (staged/'config.h').unlink()
        shutil.copyfile(CSV,staged/'partitions.csv')
        cmd=['arduino-cli','compile','--fqbn','esp32:esp32:esp32','--libraries',str(ROOT/'libraries'),
             '--build-path',str(build_dir/project),'--build-property','upload.maximum_size=1572864']
        if project=='AEGIS_Payload': cmd+=['--build-property',f'compiler.cpp.extra_flags=-DPAYLOAD_VERSION={version}']
        subprocess.run(cmd+[str(staged)],check=True)
    table=(build_dir/'AEGIS_Gate/AEGIS_Gate.ino.partitions.bin').read_bytes()
    if table!=(build_dir/'AEGIS_Payload/AEGIS_Payload.ino.partitions.bin').read_bytes(): raise ValueError('Partition tables differ')
    parsed=decode_table(table)
    for name,row in rows.items():
        if parsed[name]['offset']!=row['offset'] or parsed[name]['size']!=row['size']: raise ValueError('Compiled table differs from CSV')
    if parsed['aegis']['subtype']!=0 or parsed['payload']['subtype']!=16: raise ValueError('Factory/OTA subtype mismatch')
    files=[(0x1000,build_dir/'AEGIS_Gate/AEGIS_Gate.ino.bootloader.bin'),
           (0x8000,build_dir/'AEGIS_Gate/AEGIS_Gate.ino.partitions.bin')]
    # Erased otadata selects factory, unlike Arduino boot_app0.bin.
    empty=build_dir/'factory_otadata.bin';empty.write_bytes(b'\xff'*rows['otadata']['size'])
    files.append((rows['otadata']['offset'],empty))
    images={}
    for project,name in [('AEGIS_Gate','aegis'),('AEGIS_Payload','payload')]:
        file=build_dir/project/(project+'.ino.bin');data=file.read_bytes()
        info=inspect_image(data,payload=name=='payload')
        if len(data)>rows[name]['size'] or info['length']!=len(data): raise ValueError('Image too large or unexpected trailing data')
        images[name]=info;files.append((rows[name]['offset'],file))
    manifest={'format':'AEGISChain-build-v2','partitions':rows,'images':images,
              'files':[{'offset':off,'path':str(file.relative_to(ROOT)),'sha256':hashlib.sha256(file.read_bytes()).hexdigest()} for off,file in files]}
    (build_dir/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps(images,indent=2));print('Built. Flash only using this helper; NOT IDE Upload or merged.bin.')

def flash(port,execute):
    rows=layout();manifest=json.loads((ROOT/'build/manifest.json').read_text())
    if manifest['partitions']!=rows: raise ValueError('Partition layout changed; rebuild first')
    expected={
        'build/AEGIS_Gate/AEGIS_Gate.ino.bootloader.bin':(0x1000,0x7000),
        'build/AEGIS_Gate/AEGIS_Gate.ino.partitions.bin':(0x8000,0x1000),
        'build/factory_otadata.bin':(rows['otadata']['offset'],rows['otadata']['size']),
        'build/AEGIS_Gate/AEGIS_Gate.ino.bin':(rows['aegis']['offset'],rows['aegis']['size']),
        'build/AEGIS_Payload/AEGIS_Payload.ino.bin':(rows['payload']['offset'],rows['payload']['size'])}
    manifest_paths={e['path'].replace('\\','/') for e in manifest['files']}
    expected_paths={p.replace('\\','/') for p in expected}
    if len(manifest['files'])!=len(expected) or manifest_paths!=expected_paths:
        raise ValueError('Unexpected flash manifest entries')
    expected_lookup={k.replace('\\','/'):v for k,v in expected.items()}
    pairs=[]
    for entry in manifest['files']:
        file=(ROOT/entry['path']).resolve()
        if not file.is_relative_to(ROOT/'build'): raise ValueError('Invalid manifest path')
        path_key=entry['path'].replace('\\','/')
        offset,capacity=expected_lookup[path_key]
        if entry['offset']!=offset or file.stat().st_size>capacity: raise ValueError('Unsafe flash offset/size')
        if hashlib.sha256(file.read_bytes()).hexdigest()!=entry['sha256']: raise ValueError('Build artifact changed; rebuild first')
        pairs += [hex(entry['offset']),str(file)]
    command=[sys.executable,'-m','esptool','--chip','esp32','--port',port,'--baud','460800','--after','hard-reset',
             'write-flash','--flash-mode','keep','--flash-freq','keep','--flash-size','keep']+pairs
    print('Flash plan:');print(subprocess.list2cmdline(command))
    print('NVS at 0x9000..0xdfff is excluded. otadata is reset to factory. No eFuse/ATECC operations.')
    if not execute: print('Dry run only. Add --execute after reviewing.');return
    backup=ROOT/'runtime/backups'/datetime.now().strftime('%Y%m%d-%H%M%S');backup.mkdir(parents=True,exist_ok=False)
    base=[sys.executable,'-m','esptool','--chip','esp32','--port',port,'--after','no-reset']
    table=backup/'partition-table.bin'
    subprocess.run(base+['read-flash','0x8000','0x1000',str(table)],check=True)
    old=decode_table(table.read_bytes())
    blank=all(b==255 for b in table.read_bytes())
    if not blank and (not old.get('nvs') or old['nvs']['offset']!=0x9000 or old['nvs']['size']!=0x5000):
        raise ValueError('Existing NVS layout differs; stop for a deliberate migration')
    subprocess.run(base+['read-flash','0x9000','0x5000',str(backup/'nvs.bin')],check=True)
    print('Private NVS backup saved locally; do not share:',backup)
    subprocess.run(command,check=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser();sub=parser.add_subparsers(dest='action',required=True)
    b=sub.add_parser('build');b.add_argument('--payload-version',type=int,default=1)
    f=sub.add_parser('flash');f.add_argument('--port',required=True);f.add_argument('--execute',action='store_true')
    a=parser.parse_args()
    if a.action=='build':
        if not 1<=a.payload_version<=2147483647: parser.error('Invalid payload version')
        build(a.payload_version)
    else: flash(a.port,a.execute)
