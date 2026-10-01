"""Verify a JSON-exported v2 audit row; does not authenticate the database itself."""
import argparse,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.protocol import verify_signature
p=argparse.ArgumentParser();p.add_argument('report');a=p.parse_args()
row=json.loads(Path(a.report).read_text())
# Supabase exports an outer row containing the audit record.
if 'record' in row:row=row['record']
verify_signature(row['report'],row['signature'],row['public_key'])
print('Report signature valid under included public key. Server timestamp/result are not device-signed.')
