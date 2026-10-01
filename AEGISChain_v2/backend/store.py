import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parents[1] / '.env')

def timestamp():
    return datetime.now(timezone.utc).isoformat()

class SQLiteStore:
    def __init__(self, path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS aegis_v2_identities (hardware_id TEXT PRIMARY KEY, record TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS aegis_v2_audit (id INTEGER PRIMARY KEY, record TEXT NOT NULL)')
    def connect(self):
        return sqlite3.connect(self.path)
    def get(self, hardware_id):
        with self.connect() as db:
            row = db.execute('SELECT record FROM aegis_v2_identities WHERE hardware_id=?', (hardware_id,)).fetchone()
            return json.loads(row[0]) if row else None
    def enroll(self, row):
        old = self.get(row['hardware_id'])
        row = row | {'revision': uuid.uuid4().hex, 'created_at': old['created_at'] if old else timestamp(), 'updated_at': timestamp()}
        with self.connect() as db:
            db.execute('INSERT OR REPLACE INTO aegis_v2_identities VALUES (?,?)', (row['hardware_id'], json.dumps(row)))
    def record(self, row):
        with self.connect() as db:
            db.execute('INSERT INTO aegis_v2_audit(record) VALUES (?)', (json.dumps(row),))

class SupabaseStore:
    def __init__(self):
        from supabase import create_client
        self.client = create_client(os.environ['SUPABASE_URL'], os.environ['SUPABASE_KEY'])
    def get(self, hardware_id):
        rows = self.client.table('aegis_v2_identities').select('*').eq('hardware_id', hardware_id).execute().data
        return rows[0] if rows else None
    def enroll(self, row):
        old = self.get(row['hardware_id'])
        row = row | {'revision': uuid.uuid4().hex, 'created_at': old['created_at'] if old else timestamp(), 'updated_at': timestamp()}
        self.client.table('aegis_v2_identities').upsert(row).execute()
    def record(self, row):
        self.client.table('aegis_v2_audit').insert({'record': row}).execute()

def make_store():
    mode = os.getenv('AEGIS_STORE', 'sqlite')
    if mode == 'supabase': return SupabaseStore()
    if mode != 'sqlite': raise RuntimeError('Invalid AEGIS_STORE')
    return SQLiteStore(os.getenv('AEGIS_DB', str(Path(__file__).resolve().parents[1] / 'runtime/aegis-v2.db')))
