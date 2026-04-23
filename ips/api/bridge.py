from __future__ import annotations

import threading
from wsgiref.simple_server import make_server

from flask import Flask, jsonify, request, session

from ips.security.auth import APIKeyRBAC, Authz, SessionAuthManager, require_role
from ips.utils.config import API_HOST, API_PORT, SESSION_COOKIE_NAME, SESSION_COOKIE_SECURE, SESSION_SECRET


class BridgeServer:
    def __init__(self, engine):
        self.engine = engine
        self.app = create_app(engine)
        self._server = None
        self._thread = None

    def start(self, host: str = API_HOST, port: int = API_PORT):
        if self._thread and self._thread.is_alive():
            return
        self._server = make_server(host, port, self.app)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None


def create_app(engine) -> Flask:
    app = Flask(__name__)
    app.secret_key = SESSION_SECRET
    app.config['SESSION_COOKIE_NAME'] = SESSION_COOKIE_NAME
    app.config['SESSION_COOKIE_SECURE'] = SESSION_COOKIE_SECURE
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

    api_keys = APIKeyRBAC()
    sessions = SessionAuthManager()
    authz = Authz(api_keys=api_keys, sessions=sessions)

    @app.get('/health')
    def health():
        return jsonify({'status': 'ok', 'engine_running': engine.running})

    @app.get('/health/metrics')
    def health_metrics():
        return jsonify(engine.get_health())

    @app.post('/auth/login')
    def login():
        payload = request.get_json(silent=True) or {}
        username = str(payload.get('username', '')).strip()
        password = str(payload.get('password', ''))
        ident = sessions.authenticate(username, password)
        if ident is None:
            return jsonify({'ok': False, 'error': 'invalid_credentials'}), 401
        session.clear()
        session['username'] = ident['username']
        session['role'] = ident['role']
        session['display_name'] = ident['name']
        session['must_change_password'] = ident.get('must_change_password', False)
        engine.audit.record('auth', 'login', target=username, details={'method': 'session'})
        return jsonify({'ok': True, 'user': ident})

    @app.post('/auth/logout')
    def logout():
        username = session.get('username', 'anonymous')
        session.clear()
        engine.audit.record('auth', 'logout', target=username, details={'method': 'session'})
        return jsonify({'ok': True})

    @app.get('/auth/me')
    def whoami():
        ident = authz.identity_from_request(request, session)
        return jsonify({'authenticated': ident is not None, 'identity': ident})

    @app.post('/auth/change-password')
    @require_role(authz, 'viewer')
    def change_password():
        payload = request.get_json(silent=True) or {}
        username = session.get('username')
        old_password = str(payload.get('old_password', ''))
        new_password = str(payload.get('new_password', ''))
        if not username:
            return jsonify({'ok': False, 'error': 'session_required'}), 401
        if len(new_password) < 10:
            return jsonify({'ok': False, 'error': 'weak_password'}), 400
        ok = sessions.change_password(username, old_password, new_password)
        if ok:
            session['must_change_password'] = False
            engine.audit.record('auth', 'change_password', target=username)
        return jsonify({'ok': ok})

    @app.get('/status')
    def status():
        return jsonify(engine.get_status())

    @app.get('/stats')
    def stats():
        return jsonify(engine.get_stats())

    @app.get('/performance')
    def performance():
        return jsonify(engine.get_performance())

    @app.get('/threats/recent')
    def recent_threats():
        return jsonify(engine.get_threats()[-25:])

    @app.get('/blocked')
    def blocked():
        return jsonify(engine.threat_handler.blocked_details())

    @app.route('/control/start', methods=['POST'])
    @require_role(authz, 'operator')
    def start_engine():
        engine.start()
        engine.audit.record('api', 'control.start', details={'remote': request.remote_addr})
        return jsonify({'running': engine.running})

    @app.route('/control/stop', methods=['POST'])
    @require_role(authz, 'operator')
    def stop_engine():
        engine.stop()
        engine.audit.record('api', 'control.stop', details={'remote': request.remote_addr})
        return jsonify({'running': engine.running})

    @app.route('/control/unblock/<ip>', methods=['POST'])
    @require_role(authz, 'operator')
    def unblock(ip: str):
        ok = engine.threat_handler.unblock_ip(ip)
        engine.audit.record('api', 'control.unblock', target=ip, status='ok' if ok else 'failed')
        return jsonify({'ok': ok, 'blocked': engine.threat_handler.blocked_details()})

    @app.route('/control/unblock_all', methods=['POST'])
    @require_role(authz, 'admin')
    def unblock_all():
        count = engine.threat_handler.clear_all()
        engine.audit.record('api', 'control.unblock_all', details={'cleared': count})
        return jsonify({'cleared': count})

    @app.get('/policy')
    def policy():
        return jsonify(engine.policy.summary())

    @app.get('/profiles')
    def profiles():
        return jsonify(engine.policy.profiles())

    @app.post('/profiles/activate/<name>')
    @require_role(authz, 'admin')
    def activate_profile(name: str):
        ok = engine.activate_profile(name)
        return jsonify({'ok': ok, 'active': engine.policy.summary()})

    @app.get('/intel/summary')
    def intel_summary():
        return jsonify(engine.intel.summary())

    @app.post('/intel/reload')
    @require_role(authz, 'admin')
    def reload_intel():
        return jsonify(engine.reload_intel())

    @app.get('/audit/recent')
    def audit_recent():
        limit = int(request.args.get('limit', '50'))
        return jsonify(engine.get_audit(limit=limit))

    @app.get('/management/snapshot')
    def management_snapshot():
        return jsonify(engine.management_snapshot())

    @app.get('/ha/status')
    def ha_status():
        return jsonify(engine.get_ha_status())

    @app.post('/ha/heartbeat')
    @require_role(authz, 'operator')
    def ha_heartbeat():
        payload = request.get_json(silent=True) or {}
        node = str(payload.get('node', 'peer')).strip() or 'peer'
        return jsonify(engine.record_ha_heartbeat(node))

    @app.post('/suricata/import')
    @require_role(authz, 'operator')
    def import_suricata():
        payload = request.get_json(silent=True) or {}
        path = str(payload.get('path', '')).strip()
        limit = int(payload.get('limit', 100))
        alerts = engine.import_suricata_alerts(path, limit=limit)
        return jsonify({'ok': True, 'count': len(alerts), 'alerts': alerts})

    return app
