"""Local operator enrollment; a v2 trust decision, not automatic migration."""
import argparse
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.protocol import Report, public_key, DISABLED_VALUE
from backend.store import make_store
p=argparse.ArgumentParser()
for name in ['id','atecc-serial','public-key','gate-hash','payload-hash']:
    p.add_argument('--'+name,required=True)
p.add_argument('--mode',choices=['atecc','software_demo'],required=True)
p.add_argument('--minimum-payload-version',type=int,required=True)
p.add_argument('--disabled',action='store_true')
p.add_argument('--require-temperature',action='store_true');p.add_argument('--require-voltage',action='store_true')
p.add_argument('--temperature-min',type=int,default=0);p.add_argument('--temperature-max',type=int,default=70000)
p.add_argument('--voltage-min',type=int,default=3000);p.add_argument('--voltage-max',type=int,default=3600)
a=p.parse_args()
public_key(a.public_key)
Report(protocol='AEGISChain-v2',hardware_id=a.id,atecc_serial=a.atecc_serial,gate_hash=a.gate_hash,payload_hash=a.payload_hash,
       payload_version=a.minimum_payload_version,mode=a.mode,temperature_state=0,temperature_milli=DISABLED_VALUE,voltage_state=0,voltage_milli=DISABLED_VALUE)
if a.temperature_min>a.temperature_max or a.voltage_min>a.voltage_max: p.error('Invalid sensor ranges')
row=dict(hardware_id=a.id,atecc_serial=a.atecc_serial,public_key=a.public_key,mode=a.mode,approved_gate_hash=a.gate_hash,
         approved_payload_hash=a.payload_hash,minimum_payload_version=a.minimum_payload_version,enabled=not a.disabled,
         require_temperature=a.require_temperature,require_voltage=a.require_voltage,temperature_min=a.temperature_min,
         temperature_max=a.temperature_max,voltage_min=a.voltage_min,voltage_max=a.voltage_max)
make_store().enroll(row)
print('Enrolled',a.id,'as',a.mode,'with explicit v2 gate/payload/version/sensor policy')
