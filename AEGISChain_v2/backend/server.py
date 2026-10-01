"""One-worker, application-gate authentication service. No public enrollment API."""
import secrets
import threading
import time
from cryptography.exceptions import InvalidSignature
from fastapi import FastAPI, HTTPException
from .protocol import Report, VerifyRequest, ChallengeResponse, Approval, PROTOCOL, verify_signature
from .store import make_store, timestamp

TTL = 30

def policy_error(row, report):
    if not row: return 'unknown identity'
    if not row['enabled']: return 'disabled identity'
    for key in ['atecc_serial', 'mode']:
        if row[key] != report[key]: return key + ' not approved'
    if row['approved_payload_hash'] != report['payload_hash']: return 'payload hash not approved'
    if row['approved_gate_hash'] != report['gate_hash']: return 'gate hash not approved'
    if report['payload_version'] < row['minimum_payload_version']: return 'payload downgrade'
    for sensor in ['temperature', 'voltage']:
        state, value = report[sensor + '_state'], report[sensor + '_milli']
        if state not in (0, 1): return sensor + ' tamper/error'
        if row['require_' + sensor] and state != 1: return sensor + ' sensor required'
        if state == 1 and not row[sensor + '_min'] <= value <= row[sensor + '_max']:
            return sensor + ' out of server range'
    return None

def create_app(store=None, clock=time.monotonic):
    app = FastAPI(title='AEGISChain dual-firmware gate', version='2.0')
    app.state.store = store
    pending = {}
    mutex = threading.Lock()
    def db():
        with mutex:
            if app.state.store is None: app.state.store = make_store()
            return app.state.store
    def reject(code, message):
        raise HTTPException(code, message)

    @app.get('/health')
    def health():
        return {'status': 'ok', 'protocol': PROTOCOL, 'scope': 'application_gate_poc'}

    @app.post('/api/v2/device/challenge', response_model=ChallengeResponse)
    def challenge(req: Report):
        report = req.model_dump()
        row = db().get(req.hardware_id)
        reason = policy_error(row, report)
        if reason: reject(403, reason)
        with mutex:
            now = clock()
            for key in list(pending):
                if pending[key]['deadline'] <= now: del pending[key]
            if len(pending) >= 1024 or sum(x['report']['hardware_id'] == req.hardware_id for x in pending.values()) >= 4:
                reject(429, 'challenge capacity reached')
            report |= {'challenge_id': secrets.token_hex(16), 'nonce': secrets.token_hex(32)}
            pending[report['challenge_id']] = {'report': report, 'identity': row, 'deadline': now + TTL}
        return report | {'expires_in': TTL}

    @app.post('/api/v2/device/verify', response_model=Approval)
    def verify(req: VerifyRequest):
        with mutex:
            saved = pending.pop(req.challenge_id, None)
        if not saved: reject(401, 'unknown or consumed challenge')
        report = saved['report']
        def record(result):
            db().record({'timestamp': timestamp(), 'report': report, 'signature': req.signature,
                         'public_key': saved['identity']['public_key'], 'identity_revision': saved['identity']['revision'],
                         'authentication_result': result})
        if saved['deadline'] <= clock() or report['hardware_id'] != req.hardware_id:
            record('expired_or_wrong_device'); reject(401, 'expired or wrong-device challenge')
        row = db().get(req.hardware_id)
        if not row or row != saved['identity']:
            record('identity_changed'); reject(403, 'identity changed during challenge')
        reason = policy_error(row, report)
        if reason:
            record('policy_rejected'); reject(403, reason)
        try:
            verify_signature(report, req.signature, row['public_key'])
        except (ValueError, InvalidSignature):
            record('invalid_signature'); reject(401, 'invalid signature')
        # Recheck deadline after verification and before issuing approval.
        if saved['deadline'] <= clock():
            record('expired'); reject(401, 'expired challenge')
        if db().get(req.hardware_id) != row:
            record('identity_changed'); reject(403, 'identity changed during verification')
        record('accepted')  # storage failure prevents approval
        return report | {'authenticated': True, 'minimum_payload_version': row['minimum_payload_version'],
                         'scope': 'application_gate_poc'}
    return app

app = create_app()
