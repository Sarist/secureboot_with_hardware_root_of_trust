-- v2 uses separate tables: does not overwrite v1 identities or audit history.
CREATE TABLE IF NOT EXISTS public.aegis_v2_identities (
 hardware_id TEXT PRIMARY KEY CHECK (hardware_id ~ '^[0-9A-F]{12}$'),
 atecc_serial TEXT NOT NULL CHECK (atecc_serial ~ '^[0-9A-F]{18}$'),
 public_key TEXT NOT NULL CHECK (public_key ~ '^04[0-9a-f]{128}$'),
 mode TEXT NOT NULL CHECK (mode IN ('atecc','software_demo')),
 approved_payload_hash TEXT NOT NULL CHECK (approved_payload_hash ~ '^[0-9a-f]{64}$'),
 approved_gate_hash TEXT NOT NULL CHECK (approved_gate_hash ~ '^[0-9a-f]{64}$'),
 minimum_payload_version INTEGER NOT NULL CHECK (minimum_payload_version>0),
 enabled BOOLEAN NOT NULL, require_temperature BOOLEAN NOT NULL, require_voltage BOOLEAN NOT NULL,
 temperature_min INTEGER NOT NULL, temperature_max INTEGER NOT NULL,
 voltage_min INTEGER NOT NULL, voltage_max INTEGER NOT NULL,
 revision TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL,
 CHECK (temperature_min<=temperature_max), CHECK (voltage_min<=voltage_max)
);
CREATE TABLE IF NOT EXISTS public.aegis_v2_audit (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 record JSONB NOT NULL
);
ALTER TABLE public.aegis_v2_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.aegis_v2_audit ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.aegis_v2_identities, public.aegis_v2_audit FROM anon, authenticated;
-- Service-role key stays on backend. Never store a device private key here.
