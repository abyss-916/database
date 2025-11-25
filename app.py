from flask import Flask, request, jsonify, send_from_directory, session, redirect
from db import get_conn, init_db, execute, query_all, get_config
import os
import secrets
import hashlib
import datetime
import re

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(16))
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False

def _require_csrf():
    if request.method in ('POST', 'PUT', 'DELETE'):
        token = request.headers.get('X-CSRF-Token') or ''
        if not session.get('csrf_token') or token != session.get('csrf_token'):
            return jsonify({'error': 'csrf'}), 403
    return None

def _require_login(role=None):
    uid = session.get('user_id')
    r = session.get('role')
    if not uid:
        return jsonify({'error': 'unauthorized'}), 401
    if role and r != role:
        return jsonify({'error': 'forbidden'}), 403
    return None

def _hash_password(pw, salt=None):
    s = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac('sha256', pw.encode('utf-8'), s, 120000)
    return dk, s

@app.before_request
def _csrf_hook():
    if request.path in ('/csrf-token', '/health'):
        return None
    return _require_csrf()

@app.get('/')
def index():
    return send_from_directory('templates', 'landing.html')

@app.get('/csrf-token')
def csrf_token():
    t = session.get('csrf_token')
    if not t:
        t = secrets.token_hex(16)
        session['csrf_token'] = t
    return jsonify({'token': t})

@app.get('/login')
def login_page():
    return send_from_directory('templates', 'login.html')

@app.get('/register')
def register_page():
    return send_from_directory('templates', 'register.html')

@app.post('/register')
def register():
    data = request.get_json(force=True)
    username = data.get('username')
    password = data.get('password')
    name = data.get('name')
    identity_no = data.get('identity_no')
    city = data.get('city')
    street = data.get('street')
    if not username or not password or not name or not identity_no or not city or not street:
        return jsonify({'ok': False, 'error': 'invalid'}), 400
    if username == 'administrator':
        return jsonify({'ok': False, 'error': 'forbidden'}), 403
    if not re.fullmatch(r'[A-Za-z0-9]{4,12}', username or ''):
        return jsonify({'ok': False, 'error': 'bad_username'}), 400
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute('SELECT 1 FROM app_user WHERE username=%s', (username,))
        if cur.fetchone():
            return jsonify({'ok': False, 'error': 'exists'}), 409
        dk, s = _hash_password(password)
        cur.execute('INSERT INTO app_user(username, role, password_hash, password_salt) VALUES(%s,%s,%s,%s) RETURNING id', (username, 'user', dk, s))
        uid = cur.fetchone()[0]
        cur.execute('INSERT INTO customer(name, identity_no, city, street) VALUES(%s,%s,%s,%s) RETURNING id', (name, identity_no, city, street))
        cid = cur.fetchone()[0]
        cur.execute('INSERT INTO user_customer(user_id, customer_id) VALUES(%s,%s)', (uid, cid))
        cur.execute('INSERT INTO activity_log(user_id, action, meta) VALUES(%s,%s,%s)', (uid, 'register', None))
        conn.commit()
        return jsonify({'ok': True})
    except Exception as e:
        conn.rollback()
        return jsonify({'ok': False, 'error': str(e)}), 400
    finally:
        cur.close()
        conn.close()

@app.post('/login')
def login():
    data = request.get_json(force=True)
    username = data.get('username')
    password = data.get('password')
    conn = get_conn()
    cur = conn.cursor()
    try:
        if username == 'administrator':
            cur.execute('SELECT id, password_hash, password_salt, failed_attempts, locked_until FROM admin_user WHERE username=%s', (username,))
            row = cur.fetchone()
            if not row:
                ph, ps = _hash_password('123456')
                cur.execute('INSERT INTO admin_user(username, password_hash, password_salt) VALUES(%s,%s,%s) RETURNING id, password_hash, password_salt, failed_attempts, locked_until', (username, ph, ps))
                conn.commit()
                row = cur.fetchone()
            uid, ph, ps, fa, lu = row
            if lu and lu > datetime.datetime.utcnow():
                return jsonify({'ok': False, 'error': 'locked'}), 403
            dk, _ = _hash_password(password, ps)
            if isinstance(ph, memoryview):
                ph = ph.tobytes()
            elif isinstance(ph, (bytes, bytearray)):
                ph = bytes(ph)
            if dk != ph:
                nfa = (fa or 0) + 1
                until = None
                if nfa >= 5:
                    until = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
                cur.execute('UPDATE admin_user SET failed_attempts=%s, locked_until=%s WHERE id=%s', (nfa, until, uid))
                conn.commit()
                return jsonify({'ok': False, 'error': 'invalid'}), 401
            cur.execute('UPDATE admin_user SET failed_attempts=0, locked_until=NULL, last_login_at=NOW() WHERE id=%s', (uid,))
            conn.commit()
            session['user_id'] = uid
            session['role'] = 'admin'
            session['csrf_token'] = secrets.token_hex(16)
            cur.execute('INSERT INTO admin_activity_log(user_id, action, meta) VALUES(%s,%s,%s)', (uid, 'login', None))
            conn.commit()
            return jsonify({'ok': True, 'redirect': '/admin'})
        else:
            cur.execute('SELECT id, role, password_hash, password_salt, failed_attempts, locked_until FROM app_user WHERE username=%s', (username,))
            row = cur.fetchone()
            if not row:
                return jsonify({'ok': False, 'error': 'invalid'}), 401
            uid, role, ph, ps, fa, lu = row
            if lu and lu > datetime.datetime.utcnow():
                return jsonify({'ok': False, 'error': 'locked'}), 403
            dk, _ = _hash_password(password, ps)
            if isinstance(ph, memoryview):
                ph = ph.tobytes()
            elif isinstance(ph, (bytes, bytearray)):
                ph = bytes(ph)
            if dk != ph:
                nfa = (fa or 0) + 1
                until = None
                if nfa >= 5:
                    until = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
                cur.execute('UPDATE app_user SET failed_attempts=%s, locked_until=%s WHERE id=%s', (nfa, until, uid))
                conn.commit()
                return jsonify({'ok': False, 'error': 'invalid'}), 401
            cur.execute('UPDATE app_user SET failed_attempts=0, locked_until=NULL, last_login_at=NOW() WHERE id=%s', (uid,))
            conn.commit()
            session['user_id'] = uid
            session['role'] = role
            session['csrf_token'] = secrets.token_hex(16)
            cur.execute('INSERT INTO activity_log(user_id, action, meta) VALUES(%s,%s,%s)', (uid, 'login', None))
            conn.commit()
            dest = '/admin' if role == 'admin' else '/user'
            return jsonify({'ok': True, 'redirect': dest})
    except Exception:
        return jsonify({'ok': False, 'error': 'server'}), 500
    finally:
        cur.close()
        conn.close()

@app.post('/logout')
def logout():
    uid = session.get('user_id')
    role = session.get('role')
    if uid:
        conn = get_conn()
        cur = conn.cursor()
        try:
            if role == 'admin':
                cur.execute('INSERT INTO admin_activity_log(user_id, action, meta) VALUES(%s,%s,%s)', (uid, 'logout', None))
            else:
                cur.execute('INSERT INTO activity_log(user_id, action, meta) VALUES(%s,%s,%s)', (uid, 'logout', None))
            conn.commit()
        finally:
            cur.close()
            conn.close()
    session.clear()
    return jsonify({'ok': True})

@app.get('/admin')
def admin_page():
    if _require_login('admin'):
        return _require_login('admin')
    return send_from_directory('templates', 'admin.html')

@app.get('/user')
def user_page():
    if _require_login('user'):
        return _require_login('user')
    return send_from_directory('templates', 'user.html')

@app.get('/me')
def me():
    if _require_login():
        return _require_login()
    uid = session.get('user_id')
    role = session.get('role')
    if role == 'admin':
        rows = query_all('SELECT id, username, created_at, last_login_at FROM admin_user WHERE id=%s', (uid,))
        if rows:
            r = dict(rows[0])
            r['role'] = 'admin'
            return jsonify(r)
        return jsonify({})
    else:
        rows = query_all('SELECT id, username, role, created_at, last_login_at FROM app_user WHERE id=%s', (uid,))
        return jsonify(rows[0] if rows else {})

@app.get('/health')
def health():
    try:
        conn = get_conn()
        conn.close()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.get('/db-config')
def db_config():
    cfg = get_config()
    return jsonify({"host": cfg["host"], "port": cfg["port"], "database": cfg["database"], "user": cfg["user"], "has_password": bool(cfg["password"])})

@app.post('/init-db')
def initdb():
    try:
        init_db()
        conn = get_conn()
        cur = conn.cursor()
        ph, ps = _hash_password('123456')
        cur.execute('INSERT INTO admin_user(username, password_hash, password_salt) VALUES(%s,%s,%s) ON CONFLICT (username) DO NOTHING', ('administrator', ph, ps))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.get('/branches')
def list_branches():
    if _require_login('admin'):
        return _require_login('admin')
    rows = query_all('SELECT id, union_no, name, city FROM branch ORDER BY id')
    return jsonify(rows)

@app.post('/branches')
def create_branch():
    if _require_login('admin'):
        return _require_login('admin')
    data = request.get_json(force=True)
    union_no = data.get('union_no')
    name = data.get('name')
    city = data.get('city')
    if not union_no or not name or not city:
        return jsonify({'ok': False, 'error': 'invalid'}), 400
    execute('INSERT INTO branch(union_no, name, city) VALUES(%s,%s,%s)', (union_no, name, city))
    return jsonify({"ok": True})

@app.post('/branches/update')
def update_branch():
    if _require_login('admin'):
        return _require_login('admin')
    data = request.get_json(force=True)
    bid = data.get('id')
    name = data.get('name')
    city = data.get('city')
    execute('UPDATE branch SET name=%s, city=%s WHERE id=%s', (name, city, bid))
    return jsonify({'ok': True})

@app.post('/branches/delete')
def delete_branch():
    if _require_login('admin'):
        return _require_login('admin')
    data = request.get_json(force=True)
    bid = data.get('id')
    execute('DELETE FROM branch WHERE id=%s', (bid,))
    return jsonify({'ok': True})

@app.get('/employees')
def list_employees():
    if _require_login('admin'):
        return _require_login('admin')
    rows = query_all('SELECT id, name, phone, hire_date, manager_id FROM employee ORDER BY id')
    return jsonify(rows)

@app.post('/employees')
def create_employee():
    if _require_login('admin'):
        return _require_login('admin')
    data = request.get_json(force=True)
    name = data.get('name')
    phone = data.get('phone')
    hire_date = data.get('hire_date')
    manager_id = data.get('manager_id')
    if not name or not hire_date:
        return jsonify({'ok': False, 'error': 'invalid'}), 400
    execute('INSERT INTO employee(name, phone, hire_date, manager_id) VALUES(%s,%s,%s,%s)', (name, phone, hire_date, manager_id))
    return jsonify({"ok": True})

@app.post('/dependents')
def create_dependent():
    if _require_login('admin'):
        return _require_login('admin')
    data = request.get_json(force=True)
    employee_id = data.get('employee_id')
    name = data.get('name')
    relationship = data.get('relationship')
    execute('INSERT INTO dependent(employee_id, name, relationship) VALUES(%s,%s,%s)', (employee_id, name, relationship))
    return jsonify({"ok": True})

@app.get('/customers')
def list_customers():
    if _require_login('admin'):
        return _require_login('admin')
    rows = query_all('SELECT id, name, identity_no, city, street, assistant_employee_id FROM customer ORDER BY id')
    return jsonify(rows)

@app.post('/customers')
def create_customer():
    if _require_login('admin'):
        return _require_login('admin')
    data = request.get_json(force=True)
    name = data.get('name')
    identity_no = data.get('identity_no')
    city = data.get('city')
    street = data.get('street')
    assistant_employee_id = data.get('assistant_employee_id')
    if not name or not identity_no or not city or not street:
        return jsonify({'ok': False, 'error': 'invalid'}), 400
    execute('INSERT INTO customer(name, identity_no, city, street, assistant_employee_id) VALUES(%s,%s,%s,%s,%s)', (name, identity_no, city, street, assistant_employee_id))
    return jsonify({"ok": True})

@app.get('/accounts')
def list_accounts():
    if _require_login('admin'):
        return _require_login('admin')
    rows = query_all('SELECT a.id, a.account_no, a.created_at, a.balance, a.type, s.interest_rate, c.overdraft_limit FROM account a LEFT JOIN savings_account s ON s.account_id = a.id LEFT JOIN checking_account c ON c.account_id = a.id ORDER BY a.id')
    return jsonify(rows)

@app.post('/accounts')
def create_account():
    if _require_login('admin'):
        return _require_login('admin')
    data = request.get_json(force=True)
    account_no = data.get('account_no')
    balance = data.get('balance', 0)
    type_ = data.get('type')
    customer_id = data.get('customer_id')
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('INSERT INTO account(account_no, balance, type) VALUES(%s,%s,%s) RETURNING id', (account_no, balance, type_))
    account_id = cur.fetchone()[0]
    if type_ == 'savings':
        interest_rate = data.get('interest_rate')
        cur.execute('INSERT INTO savings_account(account_id, interest_rate) VALUES(%s,%s)', (account_id, interest_rate))
    elif type_ == 'checking':
        overdraft_limit = data.get('overdraft_limit')
        cur.execute('INSERT INTO checking_account(account_id, overdraft_limit) VALUES(%s,%s)', (account_id, overdraft_limit))
    if customer_id:
        cur.execute('INSERT INTO account_customer(account_id, customer_id) VALUES(%s,%s) ON CONFLICT DO NOTHING', (account_id, customer_id))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"ok": True, "account_id": account_id})

@app.post('/account_owners')
def add_account_owner():
    if _require_login('admin'):
        return _require_login('admin')
    data = request.get_json(force=True)
    account_id = data.get('account_id')
    customer_id = data.get('customer_id')
    execute('INSERT INTO account_customer(account_id, customer_id) VALUES(%s,%s) ON CONFLICT DO NOTHING', (account_id, customer_id))
    return jsonify({"ok": True})

@app.post('/account_access')
def update_access():
    if _require_login('admin'):
        return _require_login('admin')
    data = request.get_json(force=True)
    account_id = data.get('account_id')
    customer_id = data.get('customer_id')
    date = data.get('date')
    execute('INSERT INTO account_customer(account_id, customer_id, last_access_date) VALUES(%s,%s,%s) ON CONFLICT (account_id, customer_id) DO UPDATE SET last_access_date = EXCLUDED.last_access_date', (account_id, customer_id, date))
    return jsonify({"ok": True})

@app.get('/loans')
def list_loans():
    if _require_login('admin'):
        return _require_login('admin')
    rows = query_all('SELECT id, loan_no, amount, branch_id FROM loan ORDER BY id')
    return jsonify(rows)

@app.post('/loans')
def create_loan():
    if _require_login('admin'):
        return _require_login('admin')
    data = request.get_json(force=True)
    loan_no = data.get('loan_no')
    amount = data.get('amount')
    branch_id = data.get('branch_id')
    customer_ids = data.get('customer_ids') or []
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('INSERT INTO loan(loan_no, amount, branch_id) VALUES(%s,%s,%s) RETURNING id', (loan_no, amount, branch_id))
    loan_id = cur.fetchone()[0]
    for cid in customer_ids:
        cur.execute('INSERT INTO loan_customer(loan_id, customer_id) VALUES(%s,%s) ON CONFLICT DO NOTHING', (loan_id, cid))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"ok": True, "loan_id": loan_id})

@app.get('/repayments')
def list_repayments():
    if _require_login('admin'):
        return _require_login('admin')
    rows = query_all('SELECT id, loan_id, batch_no, paid_at, amount, savings_account_id FROM repayment ORDER BY id')
    return jsonify(rows)

@app.post('/repayments')
def create_repayment():
    if _require_login('admin'):
        return _require_login('admin')
    data = request.get_json(force=True)
    loan_id = data.get('loan_id')
    batch_no = data.get('batch_no')
    paid_at = data.get('paid_at')
    amount = data.get('amount')
    savings_account_id = data.get('savings_account_id')
    execute('INSERT INTO repayment(loan_id, batch_no, paid_at, amount, savings_account_id) VALUES(%s,%s,%s,%s,%s)', (loan_id, batch_no, paid_at, amount, savings_account_id))
    return jsonify({"ok": True})

@app.get('/admin/query/customers')
def admin_query_customers():
    if _require_login('admin'):
        return _require_login('admin')
    name = request.args.get('name')
    city = request.args.get('city')
    idno = request.args.get('idno')
    page = int(request.args.get('page', '1'))
    size = int(request.args.get('size', '10'))
    where = []
    params = []
    if name:
        where.append('name ILIKE %s')
        params.append('%' + name + '%')
    if city:
        where.append('city ILIKE %s')
        params.append('%' + city + '%')
    if idno:
        where.append('identity_no ILIKE %s')
        params.append('%' + idno + '%')
    sql = 'SELECT id, name, identity_no, city, street FROM customer'
    if where:
        sql += ' WHERE ' + ' AND '.join(where)
    sql += ' ORDER BY id LIMIT %s OFFSET %s'
    params.extend([size, (page - 1) * size])
    rows = query_all(sql, tuple(params))
    return jsonify(rows)

@app.get('/admin/export/customers')
def admin_export_customers():
    if _require_login('admin'):
        return _require_login('admin')
    name = request.args.get('name')
    city = request.args.get('city')
    idno = request.args.get('idno')
    where = []
    params = []
    if name:
        where.append('name ILIKE %s')
        params.append('%' + name + '%')
    if city:
        where.append('city ILIKE %s')
        params.append('%' + city + '%')
    if idno:
        where.append('identity_no ILIKE %s')
        params.append('%' + idno + '%')
    sql = 'SELECT id, name, identity_no, city, street FROM customer'
    if where:
        sql += ' WHERE ' + ' AND '.join(where)
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(sql, tuple(params))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    lines = ['id,name,identity_no,city,street']
    for r in rows:
        lines.append(','.join([str(r[0]), r[1], r[2], r[3], r[4]]))
    return '\n'.join(lines), 200, {'Content-Type': 'text/csv'}

_sensitive_codes = {}

@app.post('/admin/sensitive/start')
def sensitive_start():
    if _require_login('admin'):
        return _require_login('admin')
    code = secrets.token_hex(3)
    _sensitive_codes[session.get('user_id')] = {'code': code, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=5)}
    return jsonify({'ok': True, 'code': code})

@app.post('/admin/batch/delete')
def admin_batch_delete():
    if _require_login('admin'):
        return _require_login('admin')
    data = request.get_json(force=True)
    table = data.get('table')
    ids = data.get('ids') or []
    code = data.get('code')
    info = _sensitive_codes.get(session.get('user_id'))
    if not info or info['code'] != code or info['exp'] < datetime.datetime.utcnow():
        return jsonify({'ok': False, 'error': 'verify'}), 403
    if table not in ('branch','employee','customer','account','loan','repayment'):
        return jsonify({'ok': False, 'error': 'invalid_table'}), 400
    conn = get_conn()
    cur = conn.cursor()
    try:
        for i in ids:
            cur.execute(f'DELETE FROM {table} WHERE id=%s', (i,))
        conn.commit()
        return jsonify({'ok': True})
    except Exception as e:
        conn.rollback()
        return jsonify({'ok': False, 'error': str(e)}), 400
    finally:
        cur.close()
        conn.close()

@app.get('/user/history')
def user_history():
    if _require_login('user'):
        return _require_login('user')
    uid = session.get('user_id')
    rows = query_all('SELECT action, created_at FROM activity_log WHERE user_id=%s ORDER BY id DESC LIMIT 50', (uid,))
    return jsonify(rows)

@app.post('/user/change-password')
def user_change_password():
    if _require_login('user'):
        return _require_login('user')
    data = request.get_json(force=True)
    old = data.get('old_password')
    new = data.get('new_password')
    uid = session.get('user_id')
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('SELECT password_hash, password_salt FROM app_user WHERE id=%s', (uid,))
    row = cur.fetchone()
    if not row:
        return jsonify({'ok': False}), 400
    ph, ps = row
    dk, _ = _hash_password(old, ps)
    if dk != ph:
        return jsonify({'ok': False, 'error': 'invalid'}), 403
    ndk, ns = _hash_password(new)
    cur.execute('UPDATE app_user SET password_hash=%s, password_salt=%s WHERE id=%s', (ndk, ns, uid))
    conn.commit()
    cur.execute('INSERT INTO activity_log(user_id, action, meta) VALUES(%s,%s,%s)', (uid, 'change_password', None))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'ok': True})

if __name__ == '__main__':
    use_waitress = os.getenv('USE_WAITRESS', '1') == '1'
    if use_waitress:
        try:
            from waitress import serve
            serve(app, host='127.0.0.1', port=5000)
        except Exception:
            app.run(host='127.0.0.1', port=5000, use_reloader=False)
    else:
        app.run(host='127.0.0.1', port=5000, use_reloader=False)
