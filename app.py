"""
Clipper Platform API — Production Single-File Entry Point
Runs on Railway with PostgreSQL and Redis managed services.
"""
import os, sys, json, uuid, hashlib, hmac, secrets, re, logging
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import Flask, jsonify, request, g, send_from_directory

# ─── Logging ──────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger(__name__)

# ─── Config ───────────────────────────────────────────────────
class Config:
    PLATFORM_NAME     = os.environ.get('PLATFORM_NAME', 'Clipper')
    PLATFORM_DOMAIN   = os.environ.get('PLATFORM_DOMAIN', 'clipper.com')
    SUPPORT_EMAIL     = os.environ.get('SUPPORT_EMAIL', 'support@clipper.com')
    VERSION           = '1.0.0'
    SECRET_KEY        = os.environ.get('SECRET_KEY', 'dev-secret-change-in-prod')
    JWT_SECRET        = os.environ.get('JWT_SECRET', 'dev-jwt-change-in-prod')
    JWT_ACCESS_MINS   = int(os.environ.get('JWT_ACCESS_MINS', '60'))
    JWT_REFRESH_DAYS  = int(os.environ.get('JWT_REFRESH_DAYS', '30'))
    DATABASE_URL      = os.environ.get('DATABASE_URL', '')
    REDIS_URL         = os.environ.get('REDIS_URL', 'redis://localhost:6379')
    PLATFORM_FEE_PCT  = float(os.environ.get('PLATFORM_FEE_PCT', '15.0'))
    MIN_WITHDRAWAL    = int(os.environ.get('MIN_WITHDRAWAL_KOBO', '100000'))
    MAX_WITHDRAWAL    = int(os.environ.get('MAX_WITHDRAWAL_KOBO', '50000000'))
    MIN_CREATOR_AGE   = int(os.environ.get('MIN_CREATOR_AGE', '18'))
    CLEARING_DAYS     = int(os.environ.get('CLEARING_DAYS', '14'))
    ALLOWED_ORIGINS   = os.environ.get('ALLOWED_ORIGINS', '*').split(',')
    ENV               = os.environ.get('FLASK_ENV', 'production')
    DEBUG             = ENV == 'development'
    UPLOAD_PATH       = os.environ.get('UPLOAD_PATH', '/tmp/uploads')
    PAYSTACK_SECRET   = os.environ.get('PAYSTACK_SECRET_KEY', '')

cfg = Config()

# ─── Database ─────────────────────────────────────────────────
try:
    import psycopg2
    import psycopg2.extras
    _DB_URL = cfg.DATABASE_URL
    _db_pool = None

    def get_db():
        global _db_pool
        if _db_pool is None or _db_pool.closed:
            _db_pool = psycopg2.connect(_DB_URL, cursor_factory=psycopg2.extras.RealDictCursor)
            _db_pool.autocommit = True
        return _db_pool

    def db_exec(query, params=None):
        conn = get_db()
        try:
            cur = conn.cursor()
            cur.execute(query, params)
            return cur
        except psycopg2.OperationalError:
            global _db_pool
            _db_pool = None
            conn = get_db()
            cur = conn.cursor()
            cur.execute(query, params)
            return cur

    def db_fetch(query, params=None):
        cur = db_exec(query, params)
        return cur.fetchall()

    def db_one(query, params=None):
        cur = db_exec(query, params)
        return cur.fetchone()

    logger.info("psycopg2 loaded")
except ImportError:
    logger.error("psycopg2 not available — database will not work")
    def get_db(): raise RuntimeError("No database driver")
    def db_exec(q, p=None): raise RuntimeError("No database driver")
    def db_fetch(q, p=None): return []
    def db_one(q, p=None): return None

# ─── Redis ────────────────────────────────────────────────────
try:
    import redis as redis_lib
    _redis = redis_lib.from_url(cfg.REDIS_URL, decode_responses=True)
    _redis.ping()
    logger.info("Redis connected")

    def cache_get(key): return _redis.get(key)
    def cache_set(key, val, ex=None): _redis.set(key, val, ex=ex)
    def cache_del(key): _redis.delete(key)
    def cache_incr(key): return _redis.incr(key)
    def cache_expire(key, secs): _redis.expire(key, secs)

except Exception as e:
    logger.warning(f"Redis unavailable: {e}")
    _cache = {}
    def cache_get(key): return _cache.get(key)
    def cache_set(key, val, ex=None): _cache[key] = val
    def cache_del(key): _cache.pop(key, None)
    def cache_incr(key): _cache[key] = int(_cache.get(key, 0)) + 1; return _cache[key]
    def cache_expire(key, secs): pass

# ─── JWT & Auth Helpers ───────────────────────────────────────
try:
    import jwt as pyjwt
    def make_access_token(user_id, role):
        now = datetime.now(timezone.utc)
        return pyjwt.encode({'sub': user_id, 'role': role, 'iat': now,
            'exp': now + timedelta(minutes=cfg.JWT_ACCESS_MINS), 'type': 'access'},
            cfg.JWT_SECRET, algorithm='HS256')
    def decode_access_token(token):
        try:
            p = pyjwt.decode(token, cfg.JWT_SECRET, algorithms=['HS256'])
            return p if p.get('type') == 'access' else None
        except: return None
except ImportError:
    def make_access_token(u, r): return f"demo-token-{u}"
    def decode_access_token(t): return None

def hash_pw(pw):
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 310000)
    return salt.hex() + ':' + key.hex()

def verify_pw(pw, stored):
    try:
        s, k = stored.split(':')
        return secrets.compare_digest(hashlib.pbkdf2_hmac('sha256', pw.encode(), bytes.fromhex(s), 310000), bytes.fromhex(k))
    except: return False

def hash_token(t): return hashlib.sha256(t.encode()).hexdigest()
def gen_token(n=48): return secrets.token_urlsafe(n)
def make_refresh_token():
    t = gen_token(64); return t, hash_token(t)

def get_bearer():
    h = request.headers.get('Authorization', '')
    return h[7:] if h.startswith('Bearer ') else None

def current_user():
    if hasattr(g, '_user'): return g._user
    token = get_bearer()
    if not token: return None
    if cache_get(f'revoked:{hash_token(token)}'): return None
    payload = decode_access_token(token)
    if not payload: return None
    user = db_one("SELECT id,email,role,status,email_verified FROM users WHERE id=%s AND deleted_at IS NULL", (payload['sub'],))
    if not user or user['status'] in ('suspended','banned','deleted'): return None
    g._user = dict(user)
    return g._user

def require_auth(f):
    @wraps(f)
    def w(*a, **kw):
        u = current_user()
        if not u: return jsonify({'error':'unauthorized'}), 401
        g._user = u; return f(*a, **kw)
    return w

def require_role(*roles):
    def dec(f):
        @wraps(f)
        def w(*a, **kw):
            u = current_user()
            if not u: return jsonify({'error':'unauthorized'}), 401
            if u['role'] not in roles: return jsonify({'error':'forbidden','message':f'Required: {", ".join(roles)}'}), 403
            g._user = u; return f(*a, **kw)
        return w
    return dec

def require_staff(f):
    return require_role('super_admin','moderator','finance_admin','support_agent')(f)

def vj(*required):
    def dec(f):
        @wraps(f)
        def w(*a, **kw):
            if not request.is_json: return jsonify({'error':'validation_error','message':'JSON required'}), 422
            d = request.get_json(silent=True)
            if d is None: return jsonify({'error':'validation_error','message':'Invalid JSON'}), 422
            missing = [x for x in required if not d.get(x)]
            if missing: return jsonify({'error':'validation_error','message':f'Missing: {", ".join(missing)}','fields':missing}), 422
            g.data = d; return f(*a, **kw)
        return w
    return dec

def rate_limit(limit, window, prefix='api'):
    def dec(f):
        @wraps(f)
        def w(*a, **kw):
            ip = request.headers.get('X-Forwarded-For', request.remote_addr or 'x').split(',')[0].strip()
            key = f'rl:{prefix}:{ip}'
            try:
                n = cache_incr(key)
                if n == 1: cache_expire(key, window)
                if n > limit: return jsonify({'error':'rate_limited'}), 429
            except: pass
            return f(*a, **kw)
        return w
    return dec

def audit(user_id, action, resource_type=None, resource_id=None):
    try:
        db_exec("INSERT INTO audit_logs(user_id,action,resource_type,resource_id,ip_address) VALUES(%s,%s,%s,%s,%s)",
            (user_id, action, resource_type, str(resource_id) if resource_id else None, request.remote_addr))
    except: pass

# ─── Flask App ────────────────────────────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY'] = cfg.SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024
os.makedirs(cfg.UPLOAD_PATH, exist_ok=True)

@app.after_request
def cors(response):
    origin = request.headers.get('Origin', '')
    allowed = cfg.ALLOWED_ORIGINS
    if '*' in allowed or origin in allowed or cfg.DEBUG:
        response.headers['Access-Control-Allow-Origin'] = origin or '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,PATCH,DELETE,OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization,X-Request-ID'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Max-Age'] = '86400'
    return response

@app.before_request
def handle_options():
    if request.method == 'OPTIONS':
        from flask import make_response
        r = make_response(); r.status_code = 204
        r.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin','*')
        r.headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,PATCH,DELETE,OPTIONS'
        r.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization,X-Request-ID'
        r.headers['Access-Control-Allow-Credentials'] = 'true'
        return r

@app.errorhandler(404)
def e404(e): return jsonify({'error':'not_found'}), 404
@app.errorhandler(500)
def e500(e): logger.error(f"500: {e}", exc_info=True); return jsonify({'error':'internal_error'}), 500

# ─── HEALTH ───────────────────────────────────────────────────
@app.route('/health')
def health():
    checks = {'api': 'ok'}
    status = 200
    try:
        db_one("SELECT 1")
        checks['database'] = 'ok'
    except Exception as e:
        checks['database'] = f'error: {e}'
        status = 503
    try:
        _redis.ping()
        checks['redis'] = 'ok'
    except:
        checks['redis'] = 'unavailable'
    return jsonify({'status': 'healthy' if status==200 else 'degraded',
        'platform': cfg.PLATFORM_NAME, 'version': cfg.VERSION, 'checks': checks}), status

@app.route('/api/v1/config/public')
def public_config():
    return jsonify({'platform_name': cfg.PLATFORM_NAME, 'platform_domain': cfg.PLATFORM_DOMAIN,
        'support_email': cfg.SUPPORT_EMAIL, 'primary_currency': 'NGN',
        'monetary_divisor': 100, 'min_creator_age': cfg.MIN_CREATOR_AGE,
        'min_withdrawal_kobo': cfg.MIN_WITHDRAWAL})

# ─── AUTH ─────────────────────────────────────────────────────
@app.route('/api/v1/auth/register', methods=['POST'])
@rate_limit(10, 3600, 'register')
@vj('email','password','role')
def register():
    d = g.data
    email = d['email'].lower().strip()
    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        return jsonify({'error':'validation_error','message':'Invalid email'}), 422
    if len(d['password']) < 8:
        return jsonify({'error':'validation_error','message':'Password too short'}), 422
    if d['role'] not in ('creator','brand'):
        return jsonify({'error':'validation_error','message':'Role must be creator or brand'}), 422
    if db_one("SELECT id FROM users WHERE email=%s", (email,)):
        return jsonify({'error':'conflict','message':'Email already registered'}), 409

    ref_code = gen_token(6).upper()
    while db_one("SELECT id FROM users WHERE referral_code=%s", (ref_code,)):
        ref_code = gen_token(6).upper()

    referred_by = None
    if d.get('referral_code'):
        r = db_one("SELECT id FROM users WHERE referral_code=%s", (d['referral_code'].upper(),))
        if r: referred_by = r['id']

    uid = str(uuid.uuid4())
    try:
        db_exec("INSERT INTO users(id,email,password_hash,role,status,referral_code,referred_by) VALUES(%s,%s,%s,%s,'pending_verification',%s,%s)",
            (uid, email, hash_pw(d['password']), d['role'], ref_code, referred_by))
    except Exception as e:
        if 'unique' in str(e).lower():
            return jsonify({'error':'conflict','message':'Email already registered'}), 409
        raise

    if d['role'] == 'creator':
        db_exec("INSERT INTO creator_profiles(user_id,legal_first_name,legal_last_name) VALUES(%s,'','')", (uid,))

    for acct_type in ('creator_pending','creator_available','creator_paid'):
        db_exec("INSERT INTO ledger_accounts(account_type,entity_id,entity_type,currency) VALUES(%s,%s,'user','NGN') ON CONFLICT DO NOTHING",
            (acct_type, uid))
      token = gen_token(48); token_hash = hash_token(token)
    db_exec("INSERT INTO email_verifications(user_id,token_hash,token_type,expires_at) VALUES(%s,%s,'email_verification',NOW()+INTERVAL '24 hours')",
        (uid, token_hash))

    if referred_by:
        db_exec("INSERT INTO referrals(referrer_user_id,referred_user_id,referral_code) VALUES(%s,%s,%s) ON CONFLICT DO NOTHING",
            (referred_by, uid, d.get('referral_code','').upper()))

    audit(uid, 'user.registered', 'user', uid)
    return jsonify({'message':'Account created. Please verify your email.',
        'user_id': uid, 'email': email, 'role': d['role'],
        '_dev_token': token if cfg.DEBUG else None}), 201

@app.route('/api/v1/auth/verify-email', methods=['POST'])
@vj('token')
def verify_email():
    token_hash = hash_token(g.data['token'])
    v = db_one("SELECT id,user_id,expires_at,used_at FROM email_verifications WHERE token_hash=%s AND token_type='email_verification'", (token_hash,))
    if not v: return jsonify({'error':'invalid_token'}), 400
    if v['used_at']: return jsonify({'error':'token_used'}), 400
    if v['expires_at'].replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        return jsonify({'error':'token_expired'}), 400

    db_exec("UPDATE users SET email_verified=true,email_verified_at=NOW(),status=CASE WHEN status='pending_verification' THEN 'active' ELSE status END WHERE id=%s", (v['user_id'],))
    db_exec("UPDATE email_verifications SET used_at=NOW() WHERE id=%s", (v['id'],))

    user = db_one("SELECT id,email,role FROM users WHERE id=%s", (v['user_id'],))
    access = make_access_token(user['id'], user['role'])
    rt, rth = make_refresh_token()
    db_exec("INSERT INTO sessions(user_id,refresh_token_hash,ip_address,expires_at) VALUES(%s,%s,%s,NOW()+INTERVAL '30 days')",
        (user['id'], rth, request.remote_addr))

    return jsonify({'message':'Email verified','access_token':access,'refresh_token':rt,
        'user':{'id':user['id'],'email':user['email'],'role':user['role']}})

@app.route('/api/v1/auth/login', methods=['POST'])
@rate_limit(10, 300, 'login')
@vj('email','password')
def login():
    d = g.data
    email = d['email'].lower().strip()
    user = db_one("SELECT id,email,password_hash,role,status,email_verified,failed_login_attempts,locked_until,two_factor_enabled FROM users WHERE email=%s AND deleted_at IS NULL", (email,))

    if user and user.get('locked_until') and user['locked_until'].replace(tzinfo=timezone.utc) > datetime.now(timezone.utc):
        return jsonify({'error':'account_locked','message':'Account temporarily locked'}), 423

    if not user or not verify_pw(d['password'], user['password_hash']):
        if user:
            attempts = (user.get('failed_login_attempts') or 0) + 1
            locked = datetime.now(timezone.utc) + timedelta(minutes=15) if attempts >= 5 else None
            db_exec("UPDATE users SET failed_login_attempts=%s,locked_until=%s WHERE id=%s", (attempts, locked, user['id']))
        return jsonify({'error':'invalid_credentials','message':'Invalid email or password'}), 401

    if user['status'] == 'suspended': return jsonify({'error':'account_suspended'}), 403
    if user['status'] == 'banned': return jsonify({'error':'account_banned'}), 403

    db_exec("UPDATE users SET failed_login_attempts=0,locked_until=NULL,last_login_at=NOW(),last_login_ip=%s WHERE id=%s",
        (request.remote_addr, user['id']))

    access = make_access_token(user['id'], user['role'])
    rt, rth = make_refresh_token()
    db_exec("INSERT INTO sessions(user_id,refresh_token_hash,ip_address,expires_at) VALUES(%s,%s,%s,NOW()+INTERVAL '30 days')",
        (user['id'], rth, request.remote_addr))
    audit(user['id'], 'user.logged_in')

    return jsonify({'access_token':access,'refresh_token':rt,'token_type':'Bearer',
        'expires_in':cfg.JWT_ACCESS_MINS*60,
        'user':{'id':user['id'],'email':user['email'],'role':user['role'],'email_verified':user['email_verified']}})

@app.route('/api/v1/auth/refresh', methods=['POST'])
@vj('refresh_token')
def refresh_token():
    token_hash = hash_token(g.data['refresh_token'])
    session = db_one("""SELECT s.id,s.user_id,s.expires_at,s.is_revoked,u.role,u.status
        FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.refresh_token_hash=%s AND u.deleted_at IS NULL""", (token_hash,))
    if not session or session['is_revoked']: return jsonify({'error':'invalid_token'}), 401
    if session['expires_at'].replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        return jsonify({'error':'token_expired'}), 401
    if session['status'] in ('suspended','banned'): return jsonify({'error':'account_inactive'}), 403

    db_exec("UPDATE sessions SET is_revoked=true,revoked_at=NOW(),revoke_reason='rotated' WHERE id=%s", (session['id'],))
    rt, rth = make_refresh_token()
    db_exec("INSERT INTO sessions(user_id,refresh_token_hash,ip_address,expires_at) VALUES(%s,%s,%s,NOW()+INTERVAL '30 days')",
        (session['user_id'], rth, request.remote_addr))
    return jsonify({'access_token':make_access_token(session['user_id'],session['role']),'refresh_token':rt,'token_type':'Bearer'})

@app.route('/api/v1/auth/logout', methods=['POST'])
@require_auth
def logout():
    d = request.get_json(silent=True) or {}
    if d.get('refresh_token'):
        db_exec("UPDATE sessions SET is_revoked=true,revoked_at=NOW() WHERE refresh_token_hash=%s", (hash_token(d['refresh_token']),))
    audit(g._user['id'], 'user.logged_out')
    return jsonify({'message':'Logged out'})

@app.route('/api/v1/auth/me')
@require_auth
def me():
    u = g._user
    if u['role'] == 'creator':
        p = db_one("""SELECT cp.*,u.email,u.phone,u.email_verified,u.phone_verified,u.status,u.referral_code,u.created_at as registered_at
            FROM creator_profiles cp JOIN users u ON u.id=cp.user_id WHERE cp.user_id=%s""", (u['id'],))
        if p: return jsonify({'user':dict(p),'role':'creator'})
    full = db_one("SELECT id,email,phone,role,status,email_verified,phone_verified,created_at FROM users WHERE id=%s", (u['id'],))
    return jsonify({'user':dict(full),'role':u['role']})

@app.route('/api/v1/auth/forgot-password', methods=['POST'])
@rate_limit(5, 3600, 'forgot')
@vj('email')
def forgot_password():
    email = g.data['email'].lower().strip()
    user = db_one("SELECT id FROM users WHERE email=%s AND deleted_at IS NULL", (email,))
    if user:
        token = gen_token(48)
        db_exec("INSERT INTO email_verifications(user_id,token_hash,token_type,expires_at) VALUES(%s,%s,'password_reset',NOW()+INTERVAL '1 hour')",
            (user['id'], hash_token(token)))
        if cfg.DEBUG: logger.info(f"Password reset token for {email}: {token}")
    return jsonify({'message':'If registered, check your email for reset instructions.',
        '_dev_token': token if cfg.DEBUG and user else None})

@app.route('/api/v1/auth/reset-password', methods=['POST'])
@vj('token','password')
def reset_password():
    d = g.data
    if len(d['password']) < 8: return jsonify({'error':'validation_error','message':'Password too short'}), 422
    v = db_one("SELECT id,user_id,expires_at,used_at FROM email_verifications WHERE token_hash=%s AND token_type='password_reset'",
        (hash_token(d['token']),))
    if not v or v['used_at']: return jsonify({'error':'invalid_token'}), 400
    if v['expires_at'].replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        return jsonify({'error':'token_expired'}), 400
    db_exec("UPDATE users SET password_hash=%s,failed_login_attempts=0,locked_until=NULL WHERE id=%s", (hash_pw(d['password']), v['user_id']))
    db_exec("UPDATE email_verifications SET used_at=NOW() WHERE id=%s", (v['id'],))
    db_exec("UPDATE sessions SET is_revoked=true,revoke_reason='password_reset' WHERE user_id=%s", (v['user_id'],))
    return jsonify({'message':'Password reset. Please log in with your new password.'})

# ─── USERS / CREATOR PROFILE ──────────────────────────────────
@app.route('/api/v1/users/creator/profile', methods=['GET'])
@require_auth
@require_role('creator')
def get_creator_profile():
    p = db_one("""SELECT cp.*,u.email,u.phone,u.email_verified,u.phone_verified,u.status,u.risk_level,u.referral_code,u.created_at as registered_at
        FROM creator_profiles cp JOIN users u ON u.id=cp.user_id WHERE cp.user_id=%s""", (g._user['id'],))
    if not p: return jsonify({'error':'not_found'}), 404
    return jsonify({'profile':dict(p)})

@app.route('/api/v1/users/creator/profile', methods=['PUT'])
@require_auth
@require_role('creator')
def update_creator_profile():
    d = request.get_json(silent=True) or {}
    allowed = ['display_name','username','bio','country_code','state','city','languages','content_niches','portfolio_links']
    if 'username' in d and d['username']:
        un = d['username'].lower().strip()
        if not re.match(r'^[a-z0-9_]{3,30}$', un):
            return jsonify({'error':'validation_error','message':'Username: 3-30 chars, letters/numbers/underscore'}), 422
        ex = db_one("SELECT user_id FROM creator_profiles WHERE username=%s AND user_id!=%s", (un, g._user['id']))
        if ex: return jsonify({'error':'conflict','message':'Username taken'}), 409
        d['username'] = un
    updates = {k: json.dumps(v) if isinstance(v,(list,dict)) else v for k,v in d.items() if k in allowed and v is not None}
    if not updates: return jsonify({'error':'validation_error','message':'No valid fields'}), 422
    cols = ','.join(f"{k}=%s" for k in updates)
    db_exec(f"UPDATE creator_profiles SET {cols},updated_at=NOW() WHERE user_id=%s", list(updates.values())+[g._user['id']])
    p = db_one("SELECT * FROM creator_profiles WHERE user_id=%s", (g._user['id'],))
    return jsonify({'profile':dict(p),'message':'Profile updated'})

@app.route('/api/v1/users/creator/onboarding', methods=['GET'])
@require_auth
@require_role('creator')
def onboarding_status():
    p = db_one("""SELECT cp.*,u.email_verified,u.phone_verified FROM creator_profiles cp
        JOIN users u ON u.id=cp.user_id WHERE cp.user_id=%s""", (g._user['id'],))
    if not p: return jsonify({'error':'not_found'}), 404
    payout = db_one("SELECT id FROM payout_accounts WHERE user_id=%s AND status='verified'", (g._user['id'],))
    steps = {
        1: bool(p.get('email_verified')), 2: bool(p.get('phone_verified')),
        3: bool(p.get('legal_first_name') and p.get('legal_last_name')),
        4: bool(p.get('country_code')), 5: bool(p.get('date_of_birth')),
        6: bool(p.get('username') and p.get('bio')),
        7: bool(p.get('content_niches') and len(p.get('content_niches') or []) > 0),
        8: bool(p.get('social_platforms') and len(p.get('social_platforms') or []) > 0),
        9: True, 10: p.get('identity_verification_status') in ('verified','pending'),
        11: bool(payout), 12: True
    }
    return jsonify({'current_step': p.get('onboarding_step',1), 'completed': p.get('onboarding_completed',False), 'steps': steps})

@app.route('/api/v1/users/phone/send-otp', methods=['POST'])
@require_auth
@vj('phone')
def send_otp():
    import random
    phone = g.data['phone'].strip()
    if phone.startswith('0') and len(phone)==11: phone = '+234'+phone[1:]
    otp = ''.join([str(random.randint(0,9)) for _ in range(6)])
    db_exec("INSERT INTO phone_verifications(user_id,phone,otp_hash,expires_at) VALUES(%s,%s,%s,NOW()+INTERVAL '10 minutes')",
        (g._user['id'], phone, hash_token(otp)))
    if cfg.DEBUG: logger.info(f"OTP for {phone}: {otp}")
    return jsonify({'message':'OTP sent','_dev_otp': otp if cfg.DEBUG else None})

@app.route('/api/v1/users/phone/verify-otp', methods=['POST'])
@require_auth
@vj('phone','otp')
def verify_otp():
    d = g.data
    phone = d['phone'].strip()
    if phone.startswith('0') and len(phone)==11: phone = '+234'+phone[1:]
    v = db_one("SELECT id,expires_at,verified_at FROM phone_verifications WHERE user_id=%s AND phone=%s AND otp_hash=%s ORDER BY created_at DESC LIMIT 1",
        (g._user['id'], phone, hash_token(d['otp'])))
    if not v: return jsonify({'error':'invalid_otp'}), 400
    if v.get('verified_at'): return jsonify({'error':'already_used'}), 400
    if v['expires_at'].replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        return jsonify({'error':'otp_expired'}), 400
    db_exec("UPDATE phone_verifications SET verified_at=NOW() WHERE id=%s", (v['id'],))
    db_exec("UPDATE users SET phone=%s,phone_verified=true,phone_verified_at=NOW() WHERE id=%s", (phone, g._user['id']))
    return jsonify({'message':'Phone verified'})

@app.route('/api/v1/users/change-password', methods=['POST'])
@require_auth
@vj('current_password','new_password')
def change_password():
    d = g.data
    user = db_one("SELECT password_hash FROM users WHERE id=%s", (g._user['id'],))
    if not verify_pw(d['current_password'], user['password_hash']):
        return jsonify({'error':'invalid_password','message':'Current password incorrect'}), 400
    if len(d['new_password']) < 8: return jsonify({'error':'validation_error','message':'Password too short'}), 422
    db_exec("UPDATE users SET password_hash=%s WHERE id=%s", (hash_pw(d['new_password']), g._user['id']))
    audit(g._user['id'], 'user.password_changed')
    return jsonify({'message':'Password changed'})

@app.route('/api/v1/users/creators/<username>')
def public_creator(username):
    p = db_one("""SELECT cp.username,cp.display_name,cp.bio,cp.profile_image_url,cp.country_code,
        cp.content_niches,cp.social_platforms,cp.total_campaigns,cp.approved_submissions,cp.quality_score,u.created_at as member_since
        FROM creator_profiles cp JOIN users u ON u.id=cp.user_id WHERE cp.username=%s AND u.status='active'""", (username.lower(),))
    if not p: return jsonify({'error':'not_found'}), 404
    return jsonify({'creator':dict(p)})

# ─── SOCIAL ACCOUNTS ──────────────────────────────────────────
@app.route('/api/v1/social/accounts', methods=['GET'])
@require_auth
def list_social():
    accounts = db_fetch("SELECT id,platform,username,display_name,profile_url,follower_count,connection_status,ownership_verified,last_synced_at FROM social_accounts WHERE user_id=%s ORDER BY created_at DESC", (g._user['id'],))
    return jsonify({'social_accounts':[dict(a) for a in accounts]})

@app.route('/api/v1/social/accounts', methods=['POST'])
@require_auth
@vj('platform','platform_user_id','username')
def connect_social():
    d = g.data
    if d['platform'] not in ('tiktok','instagram','youtube','twitter','facebook'):
        return jsonify({'error':'validation_error','message':'Invalid platform'}), 422
    if db_one("SELECT id FROM social_accounts WHERE user_id=%s AND platform=%s", (g._user['id'], d['platform'])):
        return jsonify({'error':'conflict','message':'Already connected'}), 409
    aid = str(uuid.uuid4())
    try:
        db_exec("INSERT INTO social_accounts(id,user_id,platform,platform_user_id,username,display_name,follower_count,connection_status,ownership_verified) VALUES(%s,%s,%s,%s,%s,%s,%s,'connected',false)",
            (aid, g._user['id'], d['platform'], d['platform_user_id'], d['username'], d.get('display_name',d['username']), int(d.get('follower_count',0))))
    except Exception as e:
        if 'unique' in str(e).lower(): return jsonify({'error':'conflict','message':'Account already connected to another user'}), 409
        raise
    return jsonify({'account_id':aid,'platform':d['platform'],'message':'Connected. Verification pending.'}), 201

@app.route('/api/v1/social/accounts/<account_id>', methods=['DELETE'])
@require_auth
def disconnect_social(account_id):
    if not db_one("SELECT id FROM social_accounts WHERE id=%s AND user_id=%s", (account_id, g._user['id'])):
        return jsonify({'error':'not_found'}), 404
    db_exec("UPDATE social_accounts SET connection_status='disconnected',access_token_encrypted=NULL,refresh_token_encrypted=NULL WHERE id=%s", (account_id,))
    return jsonify({'message':'Disconnected'})

# ─── CAMPAIGNS ────────────────────────────────────────────────
@app.route('/api/v1/campaigns')
def list_campaigns():
    page = max(1, int(request.args.get('page',1)))
    per = min(50, int(request.args.get('per_page',20)))
    offset = (page-1)*per
    where = ["c.status='active'","c.deleted_at IS NULL"]
    params = []
    if request.args.get('type'): where.append("c.campaign_type=%s"); params.append(request.args['type'])
    if request.args.get('platform'): where.append("%s=ANY(c.platforms)"); params.append(request.args['platform'])
    if request.args.get('search'):
        where.append("(c.name ILIKE %s OR c.description ILIKE %s)")
        params.extend([f"%{request.args['search']}%"]*2)
    w = ' AND '.join(where)
    total = db_one(f"SELECT COUNT(*) as n FROM campaigns c WHERE {w}", params)['n']
    camps = db_fetch(f"""SELECT c.id,c.name,c.campaign_type,c.compensation_type,c.platforms,
        c.rate_per_unit_kobo,c.fixed_fee_kobo,c.creator_payout_pool_kobo,c.reserved_earnings_kobo,
        c.end_date,c.image_url,c.invitation_only,c.application_required,c.min_followers,c.currency,
        o.name as brand_name,o.logo_url as brand_logo
        FROM campaigns c JOIN organizations o ON o.id=c.organization_id
        WHERE {w} ORDER BY c.created_at DESC LIMIT %s OFFSET %s""", params+[per,offset])
    result = []
    for c in camps:
        r = dict(c)
        pool = r.get('creator_payout_pool_kobo') or 0
        reserved = r.get('reserved_earnings_kobo') or 0
        r['remaining_budget_kobo'] = max(0, pool-reserved)
        result.append(r)
    import math
    return jsonify({'campaigns':result,'pagination':{'page':page,'per_page':per,'total':total,'pages':math.ceil(total/per)}})

@app.route('/api/v1/campaigns/<cid>')
def get_campaign(cid):
    c = db_one("""SELECT c.*,o.name as brand_name,o.logo_url as brand_logo,o.industry,
        cr.required_hashtags,cr.required_mentions,cr.required_links,cr.required_disclosure,cr.call_to_action,cr.talking_points
        FROM campaigns c JOIN organizations o ON o.id=c.organization_id
        LEFT JOIN campaign_requirements cr ON cr.campaign_id=c.id
        WHERE c.id=%s AND c.deleted_at IS NULL""", (cid,))
    if not c: return jsonify({'error':'not_found'}), 404
    u = current_user()
    if c['status'] not in ('active','completed','budget_exhausted'):
      if not u or u['role'] not in ('super_admin','moderator','finance_admin','support_agent'):
            return jsonify({'error':'not_found'}), 404
    assets = db_fetch("SELECT id,asset_type,file_name,file_url,description FROM campaign_assets WHERE campaign_id=%s", (cid,))
    r = dict(c)
    r['assets'] = [dict(a) for a in assets]
    pool = r.get('creator_payout_pool_kobo') or 0
    reserved = r.get('reserved_earnings_kobo') or 0
    r['remaining_budget_kobo'] = max(0, pool-reserved)
    if u and u['role']=='creator':
        part = db_one("SELECT id FROM campaign_participants WHERE campaign_id=%s AND creator_user_id=%s", (cid, u['id']))
        app_ = db_one("SELECT id,status FROM campaign_applications WHERE campaign_id=%s AND creator_user_id=%s", (cid, u['id']))
        r['user_status'] = {'is_participant':bool(part),'application':dict(app_) if app_ else None}
    return jsonify({'campaign':r})

@app.route('/api/v1/campaigns', methods=['POST'])
@require_auth
@require_role('brand','super_admin')
@vj('name','campaign_type','organization_id')
def create_campaign():
    d = g.data
    org_id = d['organization_id']
    if g._user['role'] != 'super_admin':
        if not db_one("SELECT id FROM organization_members WHERE organization_id=%s AND user_id=%s AND is_active=true", (org_id, g._user['id'])):
            return jsonify({'error':'forbidden'}), 403
    valid_types = ['clipping','ugc','logo','music_sound','promotional','meme','affiliate','fixed_fee','custom']
    if d['campaign_type'] not in valid_types: return jsonify({'error':'validation_error','message':'Invalid type'}), 422
    comp_type = d.get('compensation_type','pay_per_view')
    cid = str(uuid.uuid4())
    slug = re.sub(r'[^a-z0-9]+','-',d['name'].lower())+'-'+cid[:8]
    total = int(d.get('total_budget_kobo',0))
    fee = int(total * cfg.PLATFORM_FEE_PCT / 100)
    pool = total - fee
    db_exec("""INSERT INTO campaigns(id,organization_id,created_by,name,slug,description,objective,campaign_type,status,
        compensation_type,currency,total_budget_kobo,creator_payout_pool_kobo,platform_fee_kobo,
        rate_per_unit_kobo,fixed_fee_kobo,min_followers,max_followers,requires_verification,
        invitation_only,application_required,start_date,end_date,submission_deadline,
        max_submissions_per_creator,content_retention_days,performance_measurement_days,clearing_period_days)
        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,'draft',%s,'NGN',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (cid,org_id,g._user['id'],d['name'],slug,d.get('description'),d.get('objective'),d['campaign_type'],
         comp_type,total,pool,fee,
         int(d.get('rate_per_unit_kobo',0)),int(d.get('fixed_fee_kobo',0)),
         int(d.get('min_followers',0)),int(d.get('max_followers',0)) or None,
         bool(d.get('requires_verification')),bool(d.get('invitation_only')),bool(d.get('application_required')),
         d.get('start_date'),d.get('end_date'),d.get('submission_deadline'),
         int(d.get('max_submissions_per_creator',1)),
         int(d.get('content_retention_days',30)),
         int(d.get('performance_measurement_days',7)),
         int(d.get('clearing_period_days',14))))
    db_exec("INSERT INTO campaign_status_history(campaign_id,to_status,changed_by,reason) VALUES(%s,'draft',%s,'Created')", (cid, g._user['id']))
    audit(g._user['id'], 'campaign.created', 'campaign', cid)
    camp = db_one("SELECT * FROM campaigns WHERE id=%s", (cid,))
    return jsonify({'campaign':dict(camp),'message':'Campaign draft created'}), 201

@app.route('/api/v1/campaigns/<cid>/join', methods=['POST'])
@require_auth
@require_role('creator')
def join_campaign(cid):
    d = request.get_json(silent=True) or {}
    if not d.get('accepted_terms'): return jsonify({'error':'validation_error','message':'Must accept terms'}), 422
    c = db_one("SELECT * FROM campaigns WHERE id=%s AND deleted_at IS NULL", (cid,))
    if not c: return jsonify({'error':'not_found'}), 404
    if c['status'] != 'active': return jsonify({'error':'conflict','message':'Campaign not active'}), 409
    if c['invitation_only'] or c['application_required']:
        return jsonify({'error':'conflict','message':'Requires invitation or application'}), 409
    if db_one("SELECT id FROM campaign_participants WHERE campaign_id=%s AND creator_user_id=%s", (cid, g._user['id'])):
        return jsonify({'error':'conflict','message':'Already joined'}), 409
    pid = str(uuid.uuid4())
    db_exec("INSERT INTO campaign_participants(id,campaign_id,creator_user_id) VALUES(%s,%s,%s)", (pid, cid, g._user['id']))
    import hashlib as hl
    terms_hash = hl.sha256(f"Campaign {cid} v{c.get('terms_version',1)}".encode()).hexdigest()
    db_exec("INSERT INTO campaign_agreements(campaign_id,creator_user_id,terms_version,terms_content_hash,ip_address) VALUES(%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
        (cid, g._user['id'], c.get('terms_version',1), terms_hash, request.remote_addr))
    return jsonify({'message':'Joined campaign','participant_id':pid})

@app.route('/api/v1/campaigns/<cid>/apply', methods=['POST'])
@require_auth
@require_role('creator')
def apply_campaign(cid):
    d = request.get_json(silent=True) or {}
    c = db_one("SELECT id,status,application_required FROM campaigns WHERE id=%s AND deleted_at IS NULL", (cid,))
    if not c: return jsonify({'error':'not_found'}), 404
    if c['status'] != 'active': return jsonify({'error':'conflict','message':'Not accepting applications'}), 409
    if db_one("SELECT id FROM campaign_applications WHERE campaign_id=%s AND creator_user_id=%s", (cid, g._user['id'])):
        return jsonify({'error':'conflict','message':'Already applied'}), 409
    aid = str(uuid.uuid4())
    db_exec("INSERT INTO campaign_applications(id,campaign_id,creator_user_id,status,application_message,proposed_concept) VALUES(%s,%s,%s,'submitted',%s,%s)",
        (aid, cid, g._user['id'], d.get('application_message'), d.get('proposed_concept')))
    return jsonify({'application_id':aid,'status':'submitted'}), 201

@app.route('/api/v1/campaigns/<cid>/approve', methods=['POST'])
@require_auth
@require_staff
def approve_campaign(cid):
    c = db_one("SELECT status FROM campaigns WHERE id=%s", (cid,))
    if not c: return jsonify({'error':'not_found'}), 404
    if c['status'] != 'pending_review': return jsonify({'error':'conflict','message':'Not pending review'}), 409
    db_exec("UPDATE campaigns SET approved_by=%s,approved_at=NOW(),status='awaiting_funding' WHERE id=%s", (g._user['id'], cid))
    db_exec("INSERT INTO campaign_status_history(campaign_id,from_status,to_status,changed_by) VALUES(%s,'pending_review','awaiting_funding',%s)", (cid, g._user['id']))
    audit(g._user['id'], 'campaign.approve', 'campaign', cid)
    return jsonify({'message':'Campaign approved','status':'awaiting_funding'})

@app.route('/api/v1/campaigns/<cid>/status', methods=['PUT'])
@require_auth
@require_staff
@vj('status')
def change_campaign_status(cid):
    new_status = g.data['status']
    c = db_one("SELECT status FROM campaigns WHERE id=%s", (cid,))
    if not c: return jsonify({'error':'not_found'}), 404
    VALID = {'draft':['pending_review','cancelled'],'pending_review':['approved','changes_requested','cancelled'],
        'changes_requested':['pending_review','cancelled'],'approved':['awaiting_funding','cancelled'],
        'awaiting_funding':['scheduled','active','cancelled'],'scheduled':['active','paused','cancelled'],
        'active':['paused','budget_exhausted','completed','cancelled'],'paused':['active','completed','cancelled'],
        'budget_exhausted':['completed','cancelled'],'completed':['archived'],'cancelled':['archived']}
    if new_status not in VALID.get(c['status'], []):
        return jsonify({'error':'conflict','message':f'Cannot go from {c["status"]} to {new_status}'}), 409
    db_exec("UPDATE campaigns SET status=%s WHERE id=%s", (new_status, cid))
    db_exec("INSERT INTO campaign_status_history(campaign_id,from_status,to_status,changed_by,reason) VALUES(%s,%s,%s,%s,%s)",
        (cid, c['status'], new_status, g._user['id'], g.data.get('reason')))
    audit(g._user['id'], f'campaign.status_change', 'campaign', cid)
    return jsonify({'message':f'Status changed to {new_status}','status':new_status})

@app.route('/api/v1/campaigns/creator/my-campaigns')
@require_auth
@require_role('creator')
def creator_campaigns():
    camps = db_fetch("""SELECT c.id,c.name,c.campaign_type,c.status,c.compensation_type,
        c.rate_per_unit_kobo,c.fixed_fee_kobo,c.currency,c.end_date,c.image_url,
        cp.submission_count,cp.total_earnings_kobo,cp.joined_at,o.name as brand_name
        FROM campaign_participants cp JOIN campaigns c ON c.id=cp.campaign_id
        JOIN organizations o ON o.id=c.organization_id
        WHERE cp.creator_user_id=%s AND cp.is_active=true ORDER BY cp.joined_at DESC""", (g._user['id'],))
    return jsonify({'campaigns':[dict(c) for c in camps]})

@app.route('/api/v1/campaigns/brand/my-campaigns')
@require_auth
@require_role('brand','super_admin')
def brand_campaigns():
    orgs = db_fetch("SELECT organization_id FROM organization_members WHERE user_id=%s AND is_active=true", (g._user['id'],))
    if not orgs: return jsonify({'campaigns':[]})
    oids = [o['organization_id'] for o in orgs]
    placeholders = ','.join(['%s']*len(oids))
    camps = db_fetch(f"""SELECT c.id,c.name,c.campaign_type,c.status,c.compensation_type,
        c.total_budget_kobo,c.funded_amount_kobo,c.reserved_earnings_kobo,c.paid_earnings_kobo,
        c.start_date,c.end_date,c.created_at,o.name as brand_name
        FROM campaigns c JOIN organizations o ON o.id=c.organization_id
        WHERE c.organization_id IN ({placeholders}) AND c.deleted_at IS NULL
        ORDER BY c.created_at DESC""", oids)
    return jsonify({'campaigns':[dict(c) for c in camps]})

# ─── SUBMISSIONS ──────────────────────────────────────────────
SUPPORTED_DOMAINS = {'tiktok':['tiktok.com','vm.tiktok.com'],'instagram':['instagram.com','www.instagram.com'],
    'youtube':['youtube.com','youtu.be','www.youtube.com'],'twitter':['twitter.com','x.com'],'facebook':['facebook.com','fb.watch']}

def detect_platform(url):
    from urllib.parse import urlparse
    try:
        domain = urlparse(url).netloc.lower().lstrip('www.')
        for plat, domains in SUPPORTED_DOMAINS.items():
            if any(domain.endswith(d.lstrip('www.')) for d in domains): return plat
    except: pass
    return None

@app.route('/api/v1/submissions', methods=['POST'])
@require_auth
@require_role('creator')
@vj('campaign_id','social_account_id','post_url')
def create_submission():
    d = g.data
    cid = d['campaign_id']; said = d['social_account_id']; url = d['post_url'].strip()
    if not db_one("SELECT id FROM campaign_participants WHERE campaign_id=%s AND creator_user_id=%s AND is_active=true", (cid, g._user['id'])):
        return jsonify({'error':'forbidden','message':'Not joined this campaign'}), 403
    camp = db_one("SELECT * FROM campaigns WHERE id=%s AND deleted_at IS NULL", (cid,))
    if not camp: return jsonify({'error':'not_found'}), 404
    if camp['status'] != 'active': return jsonify({'error':'conflict','message':'Campaign not active'}), 409
    sa = db_one("SELECT * FROM social_accounts WHERE id=%s AND user_id=%s", (said, g._user['id']))
    if not sa: return jsonify({'error':'not_found','message':'Social account not found'}), 404
    plat = detect_platform(url)
    if not plat: return jsonify({'error':'validation_error','message':'Unsupported URL'}), 422
    if plat != sa['platform']: return jsonify({'error':'validation_error','message':f'URL is {plat} but account is {sa["platform"]}'}), 422
    cnt = db_one("SELECT COUNT(*) as n FROM submissions WHERE campaign_id=%s AND creator_user_id=%s AND status NOT IN ('rejected','disqualified','removed')", (cid, g._user['id']))
    if (cnt['n'] or 0) >= (camp.get('max_submissions_per_creator') or 1):
        return jsonify({'error':'limit_exceeded','message':'Max submissions reached for this campaign'}), 409
    if db_one("SELECT id FROM submissions WHERE post_url=%s AND status NOT IN ('rejected','disqualified','removed')", (url,)):
        return jsonify({'error':'duplicate','message':'Post already submitted'}), 409
    if not d.get('creator_declaration'): return jsonify({'error':'validation_error','message':'Must confirm declaration'}), 422
    sid = str(uuid.uuid4())
    try:
        db_exec("INSERT INTO submissions(id,campaign_id,creator_user_id,social_account_id,platform,post_url,caption,status,creator_declaration) VALUES(%s,%s,%s,%s,%s,%s,%s,'manual_review',true)",
            (sid, cid, g._user['id'], said, plat, url, d.get('caption')))
    except Exception as e:
        if 'unique' in str(e).lower(): return jsonify({'error':'duplicate','message':'Duplicate submission'}), 409
        raise
    db_exec("UPDATE campaign_participants SET submission_count=submission_count+1 WHERE campaign_id=%s AND creator_user_id=%s", (cid, g._user['id']))
    audit(g._user['id'], 'submission.created', 'submission', sid)
    sub = db_one("SELECT * FROM submissions WHERE id=%s", (sid,))
    return jsonify({'submission':dict(sub),'message':'Submitted for review'}), 201

@app.route('/api/v1/submissions/<sid>')
@require_auth
def get_submission(sid):
    sub = db_one("""SELECT s.*,sa.platform as acct_platform,sa.username as acct_username,
        cp.display_name as creator_display_name,c.name as campaign_name,c.organization_id
        FROM submissions s JOIN social_accounts sa ON sa.id=s.social_account_id
        LEFT JOIN creator_profiles cp ON cp.user_id=s.creator_user_id
        JOIN campaigns c ON c.id=s.campaign_id WHERE s.id=%s""", (sid,))
    if not sub: return jsonify({'error':'not_found'}), 404
    u = g._user
    if u['role']=='creator' and sub['creator_user_id']!=u['id']: return jsonify({'error':'forbidden'}), 403
    metrics = db_fetch("SELECT * FROM submission_metrics WHERE submission_id=%s ORDER BY snapshot_at DESC LIMIT 5", (sid,))
    r = dict(sub); r['metrics'] = [dict(m) for m in metrics]
    return jsonify({'submission':r})

@app.route('/api/v1/submissions/campaign/<cid>')
@require_auth
@require_role('creator')
def creator_submissions(cid):
    subs = db_fetch("""SELECT s.*,e.status as earning_status,e.net_amount_kobo,e.eligible_views
        FROM submissions s LEFT JOIN earnings e ON e.submission_id=s.id
        WHERE s.campaign_id=%s AND s.creator_user_id=%s ORDER BY s.submitted_at DESC""", (cid, g._user['id']))
    return jsonify({'submissions':[dict(s) for s in subs]})

@app.route('/api/v1/submissions/<sid>/appeal', methods=['POST'])
@require_auth
@require_role('creator')
@vj('explanation')
def appeal_submission(sid):
    sub = db_one("SELECT * FROM submissions WHERE id=%s AND creator_user_id=%s", (sid, g._user['id']))
    if not sub: return jsonify({'error':'not_found'}), 404
    if sub['status'] not in ('rejected',): return jsonify({'error':'conflict','message':'Only rejected submissions can be appealed'}), 409
    review = db_one("SELECT id FROM submission_reviews WHERE submission_id=%s ORDER BY created_at DESC LIMIT 1", (sid,))
    if not review: return jsonify({'error':'not_found','message':'No review found'}), 404
    if db_one("SELECT id FROM submission_appeals WHERE submission_id=%s AND creator_user_id=%s", (sid, g._user['id'])):
        return jsonify({'error':'conflict','message':'Already appealed'}), 409
    aid = str(uuid.uuid4())
    db_exec("INSERT INTO submission_appeals(id,submission_id,creator_user_id,original_review_id,explanation,status) VALUES(%s,%s,%s,%s,%s,'submitted')",
        (aid, sid, g._user['id'], review['id'], g.data['explanation']))
    db_exec("UPDATE submissions SET status='appealed' WHERE id=%s", (sid,))
    return jsonify({'appeal_id':aid,'status':'submitted','message':'Appeal submitted'}), 201

# ─── EARNINGS & WALLET ────────────────────────────────────────
@app.route('/api/v1/earnings/wallet')
@require_auth
@require_role('creator')
def wallet():
    uid = g._user['id']
    accts = db_fetch("SELECT account_type,balance_kobo FROM ledger_accounts WHERE entity_id=%s AND entity_type='user'", (uid,))
    bal = {a['account_type']: (a['balance_kobo'] or 0) for a in accts}
    est = db_one("SELECT COALESCE(SUM(net_amount_kobo),0) as t FROM earnings WHERE creator_user_id=%s AND status='estimated'", (uid,))
    pend = db_one("SELECT COALESCE(SUM(net_amount_kobo),0) as t FROM earnings WHERE creator_user_id=%s AND status='pending'", (uid,))
    paid = db_one("SELECT COALESCE(SUM(amount_kobo),0) as t FROM withdrawals WHERE user_id=%s AND status='successful'", (uid,))
    return jsonify({'wallet':{'currency':'NGN','divisor':100,'estimated_kobo':est['t'] or 0,'pending_kobo':pend['t'] or 0,
        'available_kobo':bal.get('creator_available',0),'frozen_kobo':0,'total_paid_kobo':paid['t'] or 0}})

@app.route('/api/v1/earnings/history')
@require_auth
@require_role('creator')
def earnings_history():
    page = max(1, int(request.args.get('page',1))); per = min(50,int(request.args.get('per_page',20)))
    offset = (page-1)*per; uid = g._user['id']
    rows = db_fetch("""SELECT e.id,e.status,e.compensation_type,e.raw_views,e.eligible_views,
        e.gross_amount_kobo,e.net_amount_kobo,e.currency,e.estimated_at,e.cleared_at,e.available_at,
        c.name as campaign_name,c.campaign_type,s.post_url,s.platform
        FROM earnings e JOIN campaigns c ON c.id=e.campaign_id JOIN submissions s ON s.id=e.submission_id
        WHERE e.creator_user_id=%s ORDER BY e.created_at DESC LIMIT %s OFFSET %s""", (uid, per, offset))
    total = db_one("SELECT COUNT(*) as n FROM earnings WHERE creator_user_id=%s", (uid,))
    import math
    return jsonify({'earnings':[dict(r) for r in rows],'pagination':{'page':page,'per_page':per,'total':total['n'],'pages':math.ceil((total['n'] or 1)/per)}})

# ─── PAYOUTS ──────────────────────────────────────────────────
BANKS = {'044':'Access Bank','023':'Citibank','050':'Ecobank','070':'Fidelity Bank','011':'First Bank',
    '214':'First City Monument Bank','058':'GTBank','030':'Heritage Bank','082':'Keystone Bank',
    '076':'Polaris Bank','221':'Stanbic IBTC','232':'Sterling Bank','032':'Union Bank',
    '033':'UBA','215':'Unity Bank','035':'Wema Bank','057':'Zenith Bank',
    '305':'Kuda Bank','309':'Opay','306':'PalmPay','307':'Moniepoint'}

@app.route('/api/v1/payouts/banks')
def list_banks():
    return jsonify({'banks':sorted([{'code':k,'name':v} for k,v in BANKS.items()], key=lambda x:x['name'])})

@app.route('/api/v1/payouts/bank-accounts')
@require_auth
@require_role('creator')
def get_bank_accounts():
    accts = db_fetch("SELECT id,bank_code,bank_name,account_number_masked,account_name,account_verified,status,is_primary,withdrawal_hold_until,created_at FROM payout_accounts WHERE user_id=%s ORDER BY is_primary DESC,created_at DESC", (g._user['id'],))
    return jsonify({'bank_accounts':[dict(a) for a in accts]})

@app.route('/api/v1/payouts/bank-accounts', methods=['POST'])
@require_auth
@require_role('creator')
@vj('bank_code','account_number','account_name')
def add_bank_account():
    d = g.data
    bank_code = d['bank_code'].strip()
    acct_num = re.sub(r'\D','',d['account_number'])
    if len(acct_num) != 10: return jsonify({'error':'validation_error','message':'Account number must be 10 digits'}), 422
    if bank_code not in BANKS: return jsonify({'error':'validation_error','message':'Invalid bank code'}), 422
    masked = '****'+acct_num[-4:]
    if db_one("SELECT id FROM payout_accounts WHERE user_id=%s AND bank_code=%s AND account_number_masked=%s", (g._user['id'], bank_code, masked)):
        return jsonify({'error':'conflict','message':'Account already registered'}), 409
    aid = str(uuid.uuid4())
    hold = datetime.now(timezone.utc) + timedelta(hours=48)
    db_exec("INSERT INTO payout_accounts(id,user_id,country_code,payout_method,bank_code,bank_name,account_number_masked,account_name,account_verified,status,is_primary,withdrawal_hold_until) VALUES(%s,%s,'NG','bank_transfer',%s,%s,%s,%s,false,'pending_verification',true,%s)",
        (aid, g._user['id'], bank_code, BANKS[bank_code], masked, d['account_name'].strip(), hold))
    audit(g._user['id'], 'payout_account.added', 'payout_account', aid)
    return jsonify({'account_id':aid,'bank_name':BANKS[bank_code],'account_number_masked':masked,
        'status':'pending_verification','withdrawal_hold_until':hold.isoformat(),
        'message':f'Bank added. Withdrawals on hold for 48 hours for security.'}), 201

@app.route('/api/v1/payouts/bank-accounts/<acid>/verify', methods=['POST'])
@require_auth
@require_role('creator')
def verify_bank(acid):
    if not db_one("SELECT id FROM payout_accounts WHERE id=%s AND user_id=%s", (acid, g._user['id'])):
        return jsonify({'error':'not_found'}), 404
    db_exec("UPDATE payout_accounts SET status='verified',account_verified=true,account_verified_at=NOW() WHERE id=%s", (acid,))
    return jsonify({'message':'Bank account verified','verified':True})

@app.route('/api/v1/payouts/withdraw', methods=['POST'])
@require_auth
@require_role('creator')
@vj('amount_kobo','payout_account_id')
def request_withdrawal():
    d = g.data; uid = g._user['id']
    amount = int(d['amount_kobo'])
    if amount < cfg.MIN_WITHDRAWAL: return jsonify({'error':'below_minimum','message':f'Minimum: ₦{cfg.MIN_WITHDRAWAL//100:,}'}), 422
    if amount > cfg.MAX_WITHDRAWAL: return jsonify({'error':'above_maximum','message':f'Maximum: ₦{cfg.MAX_WITHDRAWAL//100:,}'}), 422
    pa = db_one("SELECT * FROM payout_accounts WHERE id=%s AND user_id=%s AND status='verified'", (d['payout_account_id'], uid))
    if not pa: return jsonify({'error':'not_found','message':'Verified bank account not found'}), 404
    if pa.get('withdrawal_hold_until') and pa['withdrawal_hold_until'].replace(tzinfo=timezone.utc) > datetime.now(timezone.utc):
        return jsonify({'error':'withdrawal_hold','message':f'Withdrawals on hold until {pa["withdrawal_hold_until"].isoformat()}'}), 409
    la = db_one("SELECT id,balance_kobo FROM ledger_accounts WHERE account_type='creator_available' AND entity_id=%s AND entity_type='user'", (uid,))
    avail = la['balance_kobo'] if la else 0
    if avail < amount: return jsonify({'error':'insufficient_funds','message':f'Available: ₦{(avail or 0)//100:,}'}), 422
    if db_one("SELECT id FROM withdrawals WHERE user_id=%s AND status IN ('requested','under_review','approved','submitted','processing')", (uid,)):
        return jsonify({'error':'conflict','message':'Pending withdrawal exists. Wait for it to complete.'}), 409
    wid = str(uuid.uuid4())
    # Debit ledger
    new_bal = avail - amount
    db_exec("UPDATE ledger_accounts SET balance_kobo=%s WHERE id=%s", (new_bal, la['id']))
    db_exec("INSERT INTO ledger_entries(ledger_account_id,entry_type,amount_kobo,balance_after_kobo,reference_type,reference_id,description) VALUES(%s,'debit',%s,%s,'withdrawal',%s,'Withdrawal request')",
        (la['id'], amount, new_bal, wid))
    db_exec("INSERT INTO withdrawals(id,user_id,payout_account_id,ledger_account_id,amount_kobo,currency,status,payout_provider,country_code) VALUES(%s,%s,%s,%s,%s,'NGN','requested','paystack','NG')",
        (wid, uid, d['payout_account_id'], la['id'], amount))
    db_exec("INSERT INTO notifications(user_id,type,title,message) VALUES(%s,'withdrawal_submitted','Withdrawal Requested','Your withdrawal is being processed.')", (uid,))
    audit(uid, 'withdrawal.requested', 'withdrawal', wid)
    return jsonify({'withdrawal_id':wid,'amount_kobo':amount,'status':'requested','message':'Withdrawal submitted. Processing within 1-2 business days.'}), 201

@app.route('/api/v1/payouts/withdrawals')
@require_auth
@require_role('creator')
def get_withdrawals():
    page = max(1,int(request.args.get('page',1))); per = min(50,int(request.args.get('per_page',20)))
    offset = (page-1)*per; uid = g._user['id']
    rows = db_fetch("""SELECT w.id,w.amount_kobo,w.currency,w.status,w.created_at,w.completed_at,w.failure_reason,
        pa.bank_name,pa.account_number_masked,pa.account_name
        FROM withdrawals w JOIN payout_accounts pa ON pa.id=w.payout_account_id
        WHERE w.user_id=%s ORDER BY w.created_at DESC LIMIT %s OFFSET %s""", (uid, per, offset))
    total = db_one("SELECT COUNT(*) as n FROM withdrawals WHERE user_id=%s", (uid,))
    import math
    return jsonify({'withdrawals':[dict(r) for r in rows],'pagination':{'page':page,'per_page':per,'total':total['n'],'pages':math.ceil((total['n'] or 1)/per)}})

@app.route('/api/v1/payouts/admin/withdrawals')
@require_auth
@require_staff
def admin_withdrawals():
    status = request.args.get('status','requested'); page=max(1,int(request.args.get('page',1))); per=min(100,int(request.args.get('per_page',50))); offset=(page-1)*per
    if status=='all':
        rows = db_fetch("""SELECT w.*,u.email as creator_email,cp.display_name as creator_name,pa.bank_name,pa.account_number_masked,pa.account_name
            FROM withdrawals w JOIN users u ON u.id=w.user_id LEFT JOIN creator_profiles cp ON cp.user_id=w.user_id
            JOIN payout_accounts pa ON pa.id=w.payout_account_id ORDER BY w.created_at ASC LIMIT %s OFFSET %s""", [per,offset])
        total = db_one("SELECT COUNT(*) as n FROM withdrawals")
    else:
        rows = db_fetch("""SELECT w.*,u.email as creator_email,cp.display_name as creator_name,pa.bank_name,pa.account_number_masked,pa.account_name
            FROM withdrawals w JOIN users u ON u.id=w.user_id LEFT JOIN creator_profiles cp ON cp.user_id=w.user_id
            JOIN payout_accounts pa ON pa.id=w.payout_account_id WHERE w.status=%s ORDER BY w.created_at ASC LIMIT %s OFFSET %s""", [status,per,offset])
        total = db_one("SELECT COUNT(*) as n FROM withdrawals WHERE status=%s", (status,))
    import math
    return jsonify({'withdrawals':[dict(r) for r in rows],'pagination':{'page':page,'per_page':per,'total':total['n'],'pages':math.ceil((total['n'] or 1)/per)}})

@app.route('/api/v1/payouts/admin/withdrawals/<wid>/process', methods=['POST'])
@require_auth
@require_staff
@vj('action')
def process_withdrawal(wid):
    action = g.data['action']; uid = g._user['id']
    wd = db_one("SELECT * FROM withdrawals WHERE id=%s", (wid,))
    if not wd: return jsonify({'error':'not_found'}), 404
    if action == 'approve':
        db_exec("UPDATE withdrawals SET status='approved',reviewed_by=%s,reviewed_at=NOW() WHERE id=%s", (uid, wid))
    elif action == 'reject':
        reason = g.data.get('reason','Rejected')
        la = db_one("SELECT id,balance_kobo FROM ledger_accounts WHERE account_type='creator_available' AND entity_id=%s AND entity_type='user'", (wd['user_id'],))
        if la:
            new_b = (la['balance_kobo'] or 0) + wd['amount_kobo']
            db_exec("UPDATE ledger_accounts SET balance_kobo=%s WHERE id=%s", (new_b, la['id']))
        db_exec("UPDATE withdrawals SET status='cancelled',failure_reason=%s,reviewed_by=%s,reviewed_at=NOW() WHERE id=%s", (reason, uid, wid))
        db_exec("INSERT INTO notifications(user_id,type,title,message) VALUES(%s,'withdrawal_failed','Withdrawal Declined',%s)", (wd['user_id'], f'Your withdrawal was declined. Reason: {reason}'))
    elif action == 'mark_paid':
        db_exec("UPDATE withdrawals SET status='successful',completed_at=NOW(),provider_transfer_code=%s WHERE id=%s",
            (g.data.get('provider_reference',f'MANUAL_{wid[:8]}'), wid))
        la = db_one("SELECT id,balance_kobo FROM ledger_accounts WHERE account_type='creator_paid' AND entity_id=%s AND entity_type='user'", (wd['user_id'],))
        if la:
            new_b = (la['balance_kobo'] or 0) + wd['amount_kobo']
            db_exec("UPDATE ledger_accounts SET balance_kobo=%s WHERE id=%s", (new_b, la['id']))
        db_exec("INSERT INTO notifications(user_id,type,title,message) VALUES(%s,'withdrawal_paid','Withdrawal Successful','Your withdrawal has been sent to your bank account.')", (wd['user_id'],))
    elif action == 'mark_failed':
        reason = g.data.get('reason','Transfer failed')
        la = db_one("SELECT id,balance_kobo FROM ledger_accounts WHERE account_type='creator_available' AND entity_id=%s AND entity_type='user'", (wd['user_id'],))
        if la:
            new_b = (la['balance_kobo'] or 0) + wd['amount_kobo']
            db_exec("UPDATE ledger_accounts SET balance_kobo=%s WHERE id=%s", (new_b, la['id']))
        db_exec("UPDATE withdrawals SET status='failed',failure_reason=%s WHERE id=%s", (reason, wid))
        db_exec("INSERT INTO notifications(user_id,type,title,message) VALUES(%s,'withdrawal_failed','Withdrawal Failed','Transfer failed. Funds returned to your wallet.')", (wd['user_id'],))
    else:
        return jsonify({'error':'validation_error','message':'Invalid action'}), 422
    audit(uid, f'withdrawal.{action}', 'withdrawal', wid)
    return jsonify({'message':f'Withdrawal {action} completed'})

# ─── MODERATION ───────────────────────────────────────────────
REJECTION_CATS = ['broken_or_private_link','wrong_social_account','wrong_platform','duplicate_submission',
    'missing_hashtag','missing_mention','missing_disclosure','missing_link','incorrect_logo_placement',
    'incorrect_audio','incorrect_duration','low_quality_content','unoriginal_content','copyright_concern',
    'prohibited_content','published_outside_campaign_dates','fake_engagement_suspected',
    'paid_traffic_suspected','creator_ineligible','content_removed','other']

@app.route('/api/v1/moderation/queue')
@require_auth
@require_staff
def moderation_queue():
    status = request.args.get('status','manual_review'); page=max(1,int(request.args.get('page',1))); per=min(50,int(request.args.get('per_page',20))); offset=(page-1)*per
    where = ["s.status=%s"]; params=[status]
    if request.args.get('campaign_id'): where.append("s.campaign_id=%s"); params.append(request.args['campaign_id'])
    w=' AND '.join(where)
    subs = db_fetch(f"""SELECT s.id,s.post_url,s.platform,s.status,s.submitted_at,s.automated_risk_score,
        s.hashtags_present,s.mentions_present,s.disclosure_present,s.url_valid,
        c.name as campaign_name,c.campaign_type,cp.display_name as creator_name,cp.username,
        u.email as creator_email,u.risk_level
        FROM submissions s JOIN campaigns c ON c.id=s.campaign_id JOIN users u ON u.id=s.creator_user_id
        LEFT JOIN creator_profiles cp ON cp.user_id=s.creator_user_id
        WHERE {w} ORDER BY s.submitted_at ASC LIMIT %s OFFSET %s""", params+[per,offset])
    total = db_one(f"SELECT COUNT(*) as n FROM submissions s WHERE {w}", params)
    import math
    return jsonify({'submissions':[dict(s) for s in subs],'pagination':{'page':page,'per_page':per,'total':total['n'],'pages':math.ceil((total['n'] or 1)/per)}})

@app.route('/api/v1/moderation/submissions/<sid>/review', methods=['POST'])
@require_auth
@require_staff
@vj('action')
def review_submission(sid):
    d = g.data; action = d['action']; uid = g._user['id']
    if action not in ('approve','reject','correction_requested','escalate'):
        return jsonify({'error':'validation_error','message':'Invalid action'}), 422
    sub = db_one("SELECT * FROM submissions WHERE id=%s", (sid,))
    if not sub: return jsonify({'error':'not_found'}), 404
    if sub['status'] not in ('manual_review','automated_review','changes_requested','appealed'):
        return jsonify({'error':'conflict','message':f'Cannot review submission in {sub["status"]} status'}), 409
    if action=='reject' and not d.get('rejection_category'):
        return jsonify({'error':'validation_error','message':'Rejection category required'}), 422
    status_map = {'approve':'approved','reject':'rejected','correction_requested':'changes_requested','escalate':'manual_review'}
    new_status = status_map[action]
    appeal_deadline = datetime.now(timezone.utc)+timedelta(days=7) if action=='reject' else None
    db_exec("""UPDATE submissions SET status=%s,reviewed_by=%s,reviewed_at=NOW(),
        rejection_reason_category=%s,rejection_reason=%s,correction_permitted=%s,
        appeal_deadline=%s,internal_moderator_notes=%s WHERE id=%s""",
        (new_status, uid, d.get('rejection_category'), d.get('creator_facing_reason'),
         d.get('correction_permitted',False), appeal_deadline, d.get('internal_notes'), sid))
    db_exec("""INSERT INTO submission_reviews(submission_id,reviewed_by,action,rejection_category,creator_facing_reason,internal_notes,correction_permitted,appeal_deadline,evidence)
        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (sid, uid, action, d.get('rejection_category'), d.get('creator_facing_reason'),
         d.get('internal_notes'), d.get('correction_permitted',False), appeal_deadline,
         json.dumps(d.get('evidence',[]))))
    if action=='approve':
        # Create initial earnings record
        try:
            camp = db_one("SELECT * FROM campaigns WHERE id=%s", (sub['campaign_id'],))
            if camp:
                eid = str(uuid.uuid4())
                db_exec("""INSERT INTO earnings(id,campaign_id,submission_id,creator_user_id,status,compensation_type,
                    gross_amount_kobo,net_amount_kobo,currency,country_code,pending_at)
                    VALUES(%s,%s,%s,%s,'pending',%s,0,0,'NGN','NG',NOW())""",
                    (eid, sub['campaign_id'], sid, sub['creator_user_id'], camp.get('compensation_type','pay_per_view')))
                db_exec("UPDATE submissions SET earnings_id=%s WHERE id=%s", (eid, sid))
        except Exception as e: logger.warning(f"Earnings creation error: {e}")
    notif_map = {'approve':('submission_approved','Submission Approved!','Your post was approved.'),
        'reject':('submission_rejected','Submission Rejected',d.get('creator_facing_reason','See dashboard.')),
        'correction_requested':('correction_requested','Correction Required','A correction is needed.')}
    if action in notif_map:
        ntype, ntitle, nmsg = notif_map[action]
        db_exec("INSERT INTO notifications(user_id,type,title,message,reference_type,reference_id) VALUES(%s,%s,%s,%s,'submission',%s)",
            (sub['creator_user_id'], ntype, ntitle, nmsg, sid))
    audit(uid, f'submission.{action}', 'submission', sid)
    return jsonify({'message':f'Submission {action}d','status':new_status})

@app.route('/api/v1/moderation/appeals')
@require_auth
@require_staff
def list_appeals():
    page=max(1,int(request.args.get('page',1))); per=min(50,int(request.args.get('per_page',20))); offset=(page-1)*per
    rows = db_fetch("""SELECT sa.*,s.post_url,s.platform,s.status as submission_status,
        c.name as campaign_name,cp.display_name as creator_name,u.email as creator_email
        FROM submission_appeals sa JOIN submissions s ON s.id=sa.submission_id
        JOIN campaigns c ON c.id=s.campaign_id JOIN users u ON u.id=sa.creator_user_id
        LEFT JOIN creator_profiles cp ON cp.user_id=sa.creator_user_id
        WHERE sa.status IN ('submitted','under_review') ORDER BY sa.created_at ASC LIMIT %s OFFSET %s""", [per,offset])
    return jsonify({'appeals':[dict(r) for r in rows]})

@app.route('/api/v1/moderation/appeals/<aid>/decide', methods=['POST'])
@require_auth
@require_staff
@vj('decision')
def decide_appeal(aid):
    d = g.data; decision = d['decision']
    if decision not in ('approved','rejected'): return jsonify({'error':'validation_error'}), 422
    appeal = db_one("SELECT * FROM submission_appeals WHERE id=%s", (aid,))
    if not appeal: return jsonify({'error':'not_found'}), 404
    orig = db_one("SELECT reviewed_by FROM submission_reviews WHERE id=%s", (appeal['original_review_id'],))
    if orig and orig['reviewed_by'] == g._user['id']:
        return jsonify({'error':'conflict','message':'Original moderator cannot decide appeal'}), 409
    db_exec("UPDATE submission_appeals SET status=%s,decision=%s,decision_reason=%s,decided_by=%s,decided_at=NOW() WHERE id=%s",
        (decision, decision, d.get('reason',''), g._user['id'], aid))
    new_sub_status = 'manual_review' if decision=='approved' else 'appeal_rejected'
    db_exec("UPDATE submissions SET status=%s WHERE id=%s", (new_sub_status, appeal['submission_id']))
    db_exec("INSERT INTO notifications(user_id,type,title,message,reference_type,reference_id) VALUES(%s,'appeal_decision','Appeal Decision',%s,'submission',%s)",
        (appeal['creator_user_id'], f'Your appeal was {decision}. {d.get("reason","")}', appeal['submission_id']))
    return jsonify({'message':f'Appeal {decision}','decision':decision})

@app.route('/api/v1/moderation/rejection-categories')
def rejection_categories():
    return jsonify({'categories':REJECTION_CATS})

# ─── NOTIFICATIONS ────────────────────────────────────────────
@app.route('/api/v1/notifications')
@require_auth
def get_notifications():
    page=max(1,int(request.args.get('page',1))); per=min(50,int(request.args.get('per_page',20))); offset=(page-1)*per
    uid = g._user['id']
    where = "WHERE n.user_id=%s"; params=[uid]
    if request.args.get('unread')=='true': where += " AND n.read=false"
    rows = db_fetch(f"SELECT * FROM notifications {where} ORDER BY created_at DESC LIMIT %s OFFSET %s", params+[per,offset])
    unread = db_one("SELECT COUNT(*) as n FROM notifications WHERE user_id=%s AND read=false", (uid,))
    return jsonify({'notifications':[dict(r) for r in rows],'unread_count':unread['n'] or 0})

@app.route('/api/v1/notifications/mark-read', methods=['POST'])
@require_auth
def mark_read():
    d = request.get_json(silent=True) or {}; uid = g._user['id']
    ids = d.get('ids',[])
    if ids:
        db_exec(f"UPDATE notifications SET read=true,read_at=NOW() WHERE id=ANY(%s) AND user_id=%s", (ids, uid))
    else:
        db_exec("UPDATE notifications SET read=true,read_at=NOW() WHERE user_id=%s AND read=false", (uid,))
    return jsonify({'message':'Marked as read'})

# ─── SUPPORT ──────────────────────────────────────────────────
@app.route('/api/v1/support/tickets')
@require_auth
def get_tickets():
    u = g._user
    if u['role'] in ('super_admin','moderator','finance_admin','support_agent'):
        rows = db_fetch("SELECT st.*,u.email as user_email FROM support_tickets st JOIN users u ON u.id=st.user_id ORDER BY st.created_at DESC LIMIT 100")
    else:
        rows = db_fetch("SELECT * FROM support_tickets WHERE user_id=%s ORDER BY created_at DESC", (u['id'],))
    return jsonify({'tickets':[dict(r) for r in rows]})

@app.route('/api/v1/support/tickets', methods=['POST'])
@require_auth
@vj('category','subject','message')
def create_ticket():
    d = g.data; uid = g._user['id']; tid = str(uuid.uuid4())
    db_exec("INSERT INTO support_tickets(id,user_id,category,subject,status,priority,related_campaign_id,related_submission_id) VALUES(%s,%s,%s,%s,'open',%s,%s,%s)",
        (tid, uid, d['category'], d['subject'], d.get('priority','normal'), d.get('campaign_id'), d.get('submission_id')))
    db_exec("INSERT INTO support_messages(ticket_id,sender_id,message) VALUES(%s,%s,%s)", (tid, uid, d['message']))
    ticket = db_one("SELECT * FROM support_tickets WHERE id=%s", (tid,))
    return jsonify({'ticket':dict(ticket),'message':'Ticket created'}), 201

@app.route('/api/v1/support/tickets/<tid>/reply', methods=['POST'])
@require_auth
@vj('message')
def reply_ticket(tid):
    d = g.data; u = g._user
    ticket = db_one("SELECT * FROM support_tickets WHERE id=%s", (tid,))
    if not ticket: return jsonify({'error':'not_found'}), 404
    if ticket['user_id'] != u['id'] and u['role'] not in ('super_admin','support_agent','moderator'):
        return jsonify({'error':'forbidden'}), 403
    is_internal = d.get('internal',False) and u['role'] in ('super_admin','support_agent','moderator')
    db_exec("INSERT INTO support_messages(ticket_id,sender_id,message,is_internal) VALUES(%s,%s,%s,%s)", (tid, u['id'], d['message'], is_internal))
    new_status = 'waiting_user' if u['role'] in ('support_agent','super_admin') else 'waiting_support'
    db_exec("UPDATE support_tickets SET status=%s WHERE id=%s", (new_status, tid))
    return jsonify({'message':'Reply sent'})

# ─── PAYMENTS ─────────────────────────────────────────────────
@app.route('/api/v1/payments/campaign/<cid>/fund', methods=['POST'])
@require_auth
@require_role('brand','super_admin')
@vj('amount_kobo')
def fund_campaign(cid):
    d = g.data; amount = int(d['amount_kobo'])
    camp = db_one("SELECT * FROM campaigns WHERE id=%s AND deleted_at IS NULL", (cid,))
    if not camp: return jsonify({'error':'not_found'}), 404
    if g._user['role'] != 'super_admin':
        if not db_one("SELECT id FROM organization_members WHERE organization_id=%s AND user_id=%s AND is_active=true AND role IN ('owner','admin','finance')", (camp['organization_id'], g._user['id'])):
            return jsonify({'error':'forbidden'}), 403
    if camp['status'] not in ('approved','awaiting_funding'):
        return jsonify({'error':'conflict','message':f'Cannot fund campaign in {camp["status"]} status'}), 409
    fee = int(amount * cfg.PLATFORM_FEE_PCT / 100)
    pool = amount - fee
    txn_id = str(uuid.uuid4())
    ref = f"CLIPPER_{txn_id[:16].replace('-','').upper()}"
    db_exec("INSERT INTO campaign_funding_transactions(id,campaign_id,organization_id,amount_kobo,currency,payment_provider,country_code,platform_fee_kobo,creator_pool_kobo,status,provider_reference) VALUES(%s,%s,%s,%s,'NGN','paystack','NG',%s,%s,'initiated',%s)",
        (txn_id, cid, camp['organization_id'], amount, fee, pool, ref))
    auth_url = f"{request.host_url}api/v1/payments/dev-simulate/{txn_id}" if cfg.DEBUG else f"https://checkout.paystack.com/{ref}"
    return jsonify({'transaction_id':txn_id,'provider_reference':ref,'amount_kobo':amount,
        'platform_fee_kobo':fee,'creator_pool_kobo':pool,'authorization_url':auth_url,'message':'Payment initialized'}), 201

@app.route('/api/v1/payments/dev-simulate/<txn_id>')
def dev_simulate(txn_id):
    if not cfg.DEBUG: return jsonify({'error':'not_found'}), 404
    txn = db_one("SELECT * FROM campaign_funding_transactions WHERE id=%s", (txn_id,))
    if not txn: return jsonify({'error':'not_found'}), 404
      if txn['status'] != 'initiated': return jsonify({'message':f'Already {txn["status"]}','status':txn['status']})
    db_exec("UPDATE campaign_funding_transactions SET status='successful' WHERE id=%s", (txn_id,))
    db_exec("UPDATE campaigns SET funded_amount_kobo=funded_amount_kobo+%s,creator_payout_pool_kobo=creator_payout_pool_kobo+%s,platform_fee_kobo=platform_fee_kobo+%s,status=CASE WHEN status='awaiting_funding' THEN 'active' ELSE status END WHERE id=%s",
        (txn['amount_kobo'], txn['creator_pool_kobo'], txn['platform_fee_kobo'], txn['campaign_id']))
    return jsonify({'message':'Payment simulated (dev mode)','transaction_id':txn_id,'status':'successful'})

@app.route('/api/v1/webhooks/paystack', methods=['POST'])
def paystack_webhook():
    payload = request.get_data()
    sig = request.headers.get('X-Paystack-Signature','')
    if cfg.PAYSTACK_SECRET:
        computed = hmac.new(cfg.PAYSTACK_SECRET.encode(), payload, hashlib.sha512).hexdigest()
        if not hmac.compare_digest(computed, sig):
            return jsonify({'error':'invalid_signature'}), 400
    try: data = json.loads(payload)
    except: return jsonify({'error':'invalid_json'}), 400
    event = data.get('event','')
    pid = data.get('data',{}).get('id','') or str(uuid.uuid4())
    ikey = f"paystack_{event}_{pid}"
    ex = db_one("SELECT id,processed FROM provider_webhooks WHERE idempotency_key=%s", (ikey,))
    if ex and ex['processed']: return jsonify({'message':'already_processed'}), 200
    wid = str(uuid.uuid4())
    db_exec("INSERT INTO provider_webhooks(id,provider,event_type,provider_event_id,payload,signature_valid,idempotency_key) VALUES(%s,'paystack',%s,%s,%s,true,%s) ON CONFLICT(idempotency_key) DO NOTHING",
        (wid, event, str(pid), json.dumps(data), ikey))
    if event == 'charge.success':
        ref = data.get('data',{}).get('reference','')
        txn = db_one("SELECT id FROM campaign_funding_transactions WHERE provider_reference=%s", (ref,))
        if txn:
            db_exec("UPDATE campaign_funding_transactions SET status='successful' WHERE id=%s AND status='initiated'", (txn['id'],))
    elif event in ('transfer.success','transfer.failed','transfer.reversed'):
        tc = data.get('data',{}).get('transfer_code','')
        wd = db_one("SELECT * FROM withdrawals WHERE provider_transfer_code=%s", (tc,))
        if wd:
            if event == 'transfer.success':
                db_exec("UPDATE withdrawals SET status='successful',completed_at=NOW() WHERE id=%s", (wd['id'],))
            else:
                db_exec("UPDATE withdrawals SET status='failed',failure_reason=%s WHERE id=%s",
                    (data.get('data',{}).get('reason','Transfer failed'), wd['id']))
    db_exec("UPDATE provider_webhooks SET processed=true,processed_at=NOW() WHERE idempotency_key=%s", (ikey,))
    return jsonify({'message':'ok'}), 200

# ─── ORGANIZATIONS ────────────────────────────────────────────
@app.route('/api/v1/organizations', methods=['POST'])
@require_auth
@require_role('brand','super_admin')
@vj('name')
def create_org():
    d = g.data; uid = g._user['id']
    slug = re.sub(r'[^a-z0-9]+','-',d['name'].lower())+'-'+str(uuid.uuid4())[:8]
    oid = str(uuid.uuid4())
    db_exec("INSERT INTO organizations(id,name,slug,website,industry,country_code,status,created_by) VALUES(%s,%s,%s,%s,%s,%s,'active',%s)",
        (oid, d['name'], slug, d.get('website'), d.get('industry'), d.get('country_code','NG'), uid))
    db_exec("INSERT INTO organization_members(organization_id,user_id,role,is_active,invitation_accepted_at) VALUES(%s,%s,'owner',true,NOW())", (oid, uid))
    org = db_one("SELECT * FROM organizations WHERE id=%s", (oid,))
    return jsonify({'organization':dict(org),'message':'Organization created'}), 201

@app.route('/api/v1/organizations/<oid>/members')
@require_auth
def org_members(oid):
    if g._user['role'] != 'super_admin':
        if not db_one("SELECT id FROM organization_members WHERE organization_id=%s AND user_id=%s AND is_active=true", (oid, g._user['id'])):
            return jsonify({'error':'forbidden'}), 403
    members = db_fetch("""SELECT om.id,om.role,om.created_at,u.email,u.status
        FROM organization_members om JOIN users u ON u.id=om.user_id
        WHERE om.organization_id=%s AND om.is_active=true""", (oid,))
    return jsonify({'members':[dict(m) for m in members]})

# ─── ADMIN ────────────────────────────────────────────────────
@app.route('/api/v1/admin/overview')
@require_auth
@require_staff
def admin_overview():
    u = db_one("""SELECT COUNT(*) FILTER(WHERE role='creator') as total_creators,
        COUNT(*) FILTER(WHERE role='creator' AND status='active') as active_creators,
        COUNT(*) FILTER(WHERE role='brand') as total_brands,
        COUNT(*) FILTER(WHERE created_at>NOW()-INTERVAL '30 days') as new_users_30d
        FROM users WHERE deleted_at IS NULL""")
    c = db_one("""SELECT COUNT(*) FILTER(WHERE status='active') as active_campaigns,
        COUNT(*) FILTER(WHERE status='pending_review') as pending_review,
        COALESCE(SUM(total_budget_kobo),0) as total_funded_kobo,
        COALESCE(SUM(paid_earnings_kobo),0) as total_paid_kobo FROM campaigns WHERE deleted_at IS NULL""")
    s = db_one("""SELECT COUNT(*) as total_submissions,COUNT(*) FILTER(WHERE status='approved') as approved,
        COUNT(*) FILTER(WHERE status='rejected') as rejected,
        COUNT(*) FILTER(WHERE status IN ('manual_review','automated_review')) as pending_review FROM submissions""")
    f = db_one("""SELECT COALESCE(SUM(amount_kobo) FILTER(WHERE status='requested'),0) as pending_withdrawal_kobo,
        COALESCE(SUM(amount_kobo) FILTER(WHERE status='successful'),0) as paid_out_kobo FROM withdrawals""")
    fr = db_one("SELECT COUNT(*) FILTER(WHERE resolved=false) as open_flags,COUNT(*) FILTER(WHERE severity='high' AND resolved=false) as high_severity FROM fraud_signals")
    su = db_one("SELECT COUNT(*) FILTER(WHERE status='open') as open_tickets FROM support_tickets")
    return jsonify({'overview':{'users':dict(u),'campaigns':dict(c),'submissions':dict(s),'financial':dict(f),'fraud':dict(fr),'support':dict(su)},'generated_at':datetime.now(timezone.utc).isoformat()})

@app.route('/api/v1/admin/users')
@require_auth
@require_staff
def admin_users():
    page=max(1,int(request.args.get('page',1))); per=min(100,int(request.args.get('per_page',50))); offset=(page-1)*per
    where=["u.deleted_at IS NULL"]; params=[]
    if request.args.get('role'): where.append("u.role=%s"); params.append(request.args['role'])
    if request.args.get('status'): where.append("u.status=%s"); params.append(request.args['status'])
    if request.args.get('search'):
        where.append("(u.email ILIKE %s OR cp.username ILIKE %s)"); s=f"%{request.args['search']}%"; params+=[s,s]
    w=' AND '.join(where)
    rows = db_fetch(f"""SELECT u.id,u.email,u.role,u.status,u.email_verified,u.phone_verified,u.risk_level,u.created_at,u.last_login_at,cp.display_name,cp.username,cp.identity_verification_status
        FROM users u LEFT JOIN creator_profiles cp ON cp.user_id=u.id WHERE {w} ORDER BY u.created_at DESC LIMIT %s OFFSET %s""", params+[per,offset])
    total = db_one(f"SELECT COUNT(*) as n FROM users u LEFT JOIN creator_profiles cp ON cp.user_id=u.id WHERE {w}", params)
    import math
    return jsonify({'users':[dict(r) for r in rows],'pagination':{'page':page,'per_page':per,'total':total['n'],'pages':math.ceil((total['n'] or 1)/per)}})

@app.route('/api/v1/admin/users/<uid>')
@require_auth
@require_staff
def admin_get_user(uid):
    u = db_one("SELECT u.*,cp.display_name,cp.username,cp.quality_score,cp.total_campaigns,cp.approved_submissions,cp.total_earnings_kobo,cp.identity_verification_status FROM users u LEFT JOIN creator_profiles cp ON cp.user_id=u.id WHERE u.id=%s", (uid,))
    if not u: return jsonify({'error':'not_found'}), 404
    subs = db_fetch("SELECT id,campaign_id,status,submitted_at FROM submissions WHERE creator_user_id=%s ORDER BY submitted_at DESC LIMIT 5", (uid,))
    wds = db_fetch("SELECT id,amount_kobo,status,created_at FROM withdrawals WHERE user_id=%s ORDER BY created_at DESC LIMIT 5", (uid,))
    signals = db_fetch("SELECT signal_type,severity,description,created_at FROM fraud_signals WHERE user_id=%s ORDER BY created_at DESC LIMIT 10", (uid,))
    r=dict(u); r['recent_submissions']=[dict(s) for s in subs]; r['recent_withdrawals']=[dict(w) for w in wds]; r['fraud_signals']=[dict(f) for f in signals]
    return jsonify({'user':r})

@app.route('/api/v1/admin/users/<uid>/action', methods=['POST'])
@require_auth
@require_role('super_admin')
@vj('action')
def admin_user_action(uid):
    action = g.data['action']
    u = db_one("SELECT id,status,role FROM users WHERE id=%s AND deleted_at IS NULL", (uid,))
    if not u: return jsonify({'error':'not_found'}), 404
    if action == 'suspend':
        db_exec("UPDATE users SET status='suspended' WHERE id=%s", (uid,))
        db_exec("UPDATE sessions SET is_revoked=true,revoked_at=NOW() WHERE user_id=%s AND is_revoked=false", (uid,))
    elif action == 'unsuspend': db_exec("UPDATE users SET status='active' WHERE id=%s", (uid,))
    elif action == 'ban':
        db_exec("UPDATE users SET status='banned' WHERE id=%s", (uid,))
        db_exec("UPDATE sessions SET is_revoked=true,revoked_at=NOW() WHERE user_id=%s AND is_revoked=false", (uid,))
    else: return jsonify({'error':'validation_error','message':'Invalid action'}), 422
    audit(g._user['id'], f'admin.user_{action}', 'user', uid)
    return jsonify({'message':f'User {action}ed','user_id':uid})

@app.route('/api/v1/admin/campaigns')
@require_auth
@require_staff
def admin_campaigns():
    page=max(1,int(request.args.get('page',1))); per=min(100,int(request.args.get('per_page',50))); offset=(page-1)*per
    where=["c.deleted_at IS NULL"]; params=[]
    if request.args.get('status'): where.append("c.status=%s"); params.append(request.args['status'])
    if request.args.get('search'):
        where.append("(c.name ILIKE %s OR o.name ILIKE %s)"); s=f"%{request.args['search']}%"; params+=[s,s]
    w=' AND '.join(where)
    rows = db_fetch(f"""SELECT c.id,c.name,c.campaign_type,c.status,c.compensation_type,c.total_budget_kobo,c.funded_amount_kobo,c.paid_earnings_kobo,c.reserved_earnings_kobo,c.created_at,c.start_date,c.end_date,o.name as brand_name
        FROM campaigns c JOIN organizations o ON o.id=c.organization_id WHERE {w} ORDER BY c.created_at DESC LIMIT %s OFFSET %s""", params+[per,offset])
    total = db_one(f"SELECT COUNT(*) as n FROM campaigns c JOIN organizations o ON o.id=c.organization_id WHERE {w}", params)
    import math
    return jsonify({'campaigns':[dict(r) for r in rows],'pagination':{'page':page,'per_page':per,'total':total['n'],'pages':math.ceil((total['n'] or 1)/per)}})

@app.route('/api/v1/admin/submissions')
@require_auth
@require_staff
def admin_submissions():
    page=max(1,int(request.args.get('page',1))); per=min(100,int(request.args.get('per_page',50))); offset=(page-1)*per
    where=[]; params=[]
    if request.args.get('status'): where.append("s.status=%s"); params.append(request.args['status'])
    if request.args.get('campaign_id'): where.append("s.campaign_id=%s"); params.append(request.args['campaign_id'])
    w=('WHERE '+' AND '.join(where)) if where else ''
    rows = db_fetch(f"""SELECT s.id,s.post_url,s.platform,s.status,s.submitted_at,s.automated_risk_score,
        c.name as campaign_name,cp.display_name as creator_name,u.email as creator_email
        FROM submissions s JOIN campaigns c ON c.id=s.campaign_id JOIN users u ON u.id=s.creator_user_id
        LEFT JOIN creator_profiles cp ON cp.user_id=s.creator_user_id {w} ORDER BY s.submitted_at DESC LIMIT %s OFFSET %s""", params+[per,offset])
    total = db_one(f"SELECT COUNT(*) as n FROM submissions s {w}", params)
    import math
    return jsonify({'submissions':[dict(r) for r in rows],'pagination':{'page':page,'per_page':per,'total':total['n'],'pages':math.ceil((total['n'] or 1)/per)}})

@app.route('/api/v1/admin/fraud-signals')
@require_auth
@require_staff
def admin_fraud():
    rows = db_fetch("""SELECT fs.*,u.email as user_email,s.post_url FROM fraud_signals fs
        LEFT JOIN users u ON u.id=fs.user_id LEFT JOIN submissions s ON s.id=fs.submission_id
        WHERE fs.resolved=false ORDER BY CASE fs.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,fs.created_at DESC LIMIT 100""")
    return jsonify({'fraud_signals':[dict(r) for r in rows]})

@app.route('/api/v1/admin/settings')
@require_auth
@require_role('super_admin')
def get_settings():
    rows = db_fetch("SELECT key,value,value_type,category,description,is_public FROM platform_settings ORDER BY category,key")
    return jsonify({'settings':[dict(r) for r in rows]})

@app.route('/api/v1/admin/settings', methods=['PUT'])
@require_auth
@require_role('super_admin')
@vj('key','value')
def update_setting():
    d = g.data
    db_exec("UPDATE platform_settings SET value=%s,updated_by=%s WHERE key=%s", (str(d['value']), g._user['id'], d['key']))
    audit(g._user['id'], 'admin.setting_updated')
    return jsonify({'message':'Setting updated'})

@app.route('/api/v1/admin/feature-flags')
@require_auth
@require_role('super_admin')
def get_flags():
    rows = db_fetch("SELECT * FROM feature_flags ORDER BY key")
    return jsonify({'feature_flags':[dict(r) for r in rows]})

@app.route('/api/v1/admin/feature-flags/<key>', methods=['PUT'])
@require_auth
@require_role('super_admin')
@vj('enabled')
def toggle_flag(key):
    db_exec("UPDATE feature_flags SET enabled=%s WHERE key=%s", (bool(g.data['enabled']), key))
    audit(g._user['id'], 'admin.flag_updated')
    return jsonify({'message':f'Flag {key} {"enabled" if g.data["enabled"] else "disabled"}'})

@app.route('/api/v1/admin/audit-logs')
@require_auth
@require_role('super_admin')
def audit_logs():
    page=max(1,int(request.args.get('page',1))); per=min(100,int(request.args.get('per_page',50))); offset=(page-1)*per
    where=[]; params=[]
    if request.args.get('user_id'): where.append("al.user_id=%s"); params.append(request.args['user_id'])
    if request.args.get('action'): where.append("al.action ILIKE %s"); params.append(f"%{request.args['action']}%")
    w=('WHERE '+' AND '.join(where)) if where else ''
    rows = db_fetch(f"SELECT al.*,u.email as user_email FROM audit_logs al LEFT JOIN users u ON u.id=al.user_id {w} ORDER BY al.created_at DESC LIMIT %s OFFSET %s", params+[per,offset])
    total = db_one(f"SELECT COUNT(*) as n FROM audit_logs al {w}", params)
    import math
    return jsonify({'logs':[dict(r) for r in rows],'pagination':{'page':page,'per_page':per,'total':total['n'],'pages':math.ceil((total['n'] or 1)/per)}})

@app.route('/api/v1/admin/organizations')
@require_auth
@require_staff
def admin_orgs():
    rows = db_fetch("""SELECT o.*,u.email as owner_email,COUNT(DISTINCT om.user_id) as member_count,COUNT(DISTINCT c.id) as campaign_count
        FROM organizations o LEFT JOIN users u ON u.id=o.created_by
        LEFT JOIN organization_members om ON om.organization_id=o.id AND om.is_active=true
        LEFT JOIN campaigns c ON c.organization_id=o.id AND c.deleted_at IS NULL
        WHERE o.deleted_at IS NULL GROUP BY o.id,u.email ORDER BY o.created_at DESC LIMIT 100""")
    return jsonify({'organizations':[dict(r) for r in rows]})

@app.route('/api/v1/admin/financial/wallets')
@require_auth
@require_staff
def admin_wallets():
    ws = db_one("""SELECT
        COALESCE(SUM(CASE WHEN la.account_type='creator_available' THEN la.balance_kobo ELSE 0 END),0) as total_available,
        COALESCE(SUM(CASE WHEN la.account_type='creator_pending' THEN la.balance_kobo ELSE 0 END),0) as total_pending,
        COALESCE(SUM(CASE WHEN la.account_type='creator_paid' THEN la.balance_kobo ELSE 0 END),0) as total_paid,
        COUNT(DISTINCT la.entity_id) FILTER(WHERE la.balance_kobo>0) as total_creators_with_balance
        FROM ledger_accounts la WHERE la.account_type IN ('creator_available','creator_pending','creator_paid') AND la.entity_type='user'""")
    pe = db_one("SELECT COALESCE(SUM(net_amount_kobo),0) as t FROM earnings WHERE status IN ('estimated','pending')")
    return jsonify({'wallet_summary':dict(ws),'pending_earnings_kobo':pe['t'] or 0})

# ─── FILES ────────────────────────────────────────────────────
@app.route('/api/v1/files/upload', methods=['POST'])
@require_auth
def upload_file():
    if 'file' not in request.files: return jsonify({'error':'validation_error','message':'No file'}), 422
    f = request.files['file']
    if not f.filename: return jsonify({'error':'validation_error','message':'Empty filename'}), 422
    allowed = {'image/jpeg','image/png','image/gif','image/webp','video/mp4','application/pdf','audio/mpeg'}
    if f.content_type not in allowed: return jsonify({'error':'validation_error','message':'File type not allowed'}), 422
    f.seek(0,2); size=f.tell(); f.seek(0)
    if size > 100*1024*1024: return jsonify({'error':'validation_error','message':'File too large (max 100MB)'}), 422
    ext = f.filename.rsplit('.',1)[-1].lower() if '.' in f.filename else 'bin'
    uid = g._user['id']
    key = f"{uid}/{uuid.uuid4().hex}.{ext}"
    path = os.path.join(cfg.UPLOAD_PATH, key)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    f.save(path)
    file_url = f"{request.host_url}api/v1/files/{key}"
    fid = str(uuid.uuid4())
    db_exec("INSERT INTO file_uploads(id,uploaded_by,reference_type,reference_id,file_name,file_key,file_url,file_size,mime_type,storage_provider) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,'local')",
        (fid, uid, request.form.get('reference_type'), request.form.get('reference_id'), f.filename, key, file_url, size, f.content_type))
    return jsonify({'file_id':fid,'file_url':file_url,'file_key':key,'file_size':size}), 201

@app.route('/api/v1/files/<path:key>')
def serve_file(key):
    path = os.path.join(cfg.UPLOAD_PATH, key)
    if not os.path.exists(path): return jsonify({'error':'not_found'}), 404
    return send_from_directory(os.path.dirname(path), os.path.basename(path))

# ─── DATABASE MIGRATION ───────────────────────────────────────
def run_migrations():
    """Run database schema on startup if not already applied."""
    try:
        existing = db_one("SELECT COUNT(*) as n FROM information_schema.tables WHERE table_schema='public' AND table_name='users'")
        if existing and existing['n'] > 0:
            logger.info("Database schema already exists — skipping migration")
            return
        logger.info("Running database migrations...")
        sql_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
        if os.path.exists(sql_path):
            with open(sql_path) as f: schema = f.read()
            conn = get_db()
            conn.autocommit = False
            try:
                cur = conn.cursor(); cur.execute(schema); conn.commit()
                logger.info("Migration complete")
            except Exception as e:
                conn.rollback(); logger.error(f"Migration failed: {e}")
            finally:
                conn.autocommit = True
    except Exception as e:
        logger.warning(f"Migration check failed: {e}")

# ─── STARTUP ──────────────────────────────────────────────────
if __name__ == '__main__':
    if cfg.DATABASE_URL:
        run_migrations()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=cfg.DEBUG)
