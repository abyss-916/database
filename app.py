from flask import Flask, request, jsonify, send_from_directory, session, redirect
from db import get_conn, init_db, execute, query_all, get_config, begin_transaction, execute_with_conn, map_db_error, is_db_error
import os
import secrets
import hashlib
import datetime
import re
import json
import psycopg2
import threading
import time

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

def _mask_phone(p):
    if not p:
        return ''
    s = str(p)
    if len(s) < 7:
        return s
    return s[:3] + '****' + s[-4:]

def _mask_id(s):
    if not s:
        return ''
    t = str(s)
    if len(t) <= 8:
        return t
    return t[:3] + '*' * (len(t) - 7) + t[-4:]

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
    if not re.fullmatch(r'[A-Za-z0-9]{1,12}', username or ''):
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
        if is_db_error(e):
            s, c, m = map_db_error(e)
            return jsonify({'ok': False, 'error': m, 'code': c}), s
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
def admin_index():
    if _require_login('admin'):
        return _require_login('admin')
    return send_from_directory('templates', 'admin.html')

@app.get('/admin/query/branch')
def admin_query_branch_page():
    if _require_login('admin'):
        return _require_login('admin')
    return send_from_directory('templates', 'query_branch.html')

@app.get('/admin/query/customer')
def admin_query_customer_page():
    if _require_login('admin'):
        return _require_login('admin')
    return send_from_directory('templates', 'query_customer.html')

@app.get('/admin/query/account')
def admin_query_account_page():
    if _require_login('admin'):
        return _require_login('admin')
    return send_from_directory('templates', 'query_account.html')

@app.get('/admin/query/employee')
def admin_query_employee_page():
    if _require_login('admin'):
        return _require_login('admin')
    return send_from_directory('templates', 'query_employee.html')

@app.get('/admin/query/loan')
def admin_query_loan_page():
    if _require_login('admin'):
        return _require_login('admin')
    return send_from_directory('templates', 'query_loan.html')

@app.get('/admin/api/query/branch')
def admin_api_query_branch():
    if _require_login('admin'):
        return _require_login('admin')
    union_no = request.args.get('union_no')
    fuzzy = request.args.get('fuzzy') == '1'
    if not union_no:
        return jsonify({'ok': False, 'error': '缺少联行号'}), 400
    if fuzzy:
        rows = query_all('SELECT id, union_no, name, city FROM branch WHERE union_no ILIKE %s ORDER BY id', ('%' + union_no + '%',))
        result = [{
            'id': r['id'],
            'union_no': r['union_no'],
            'name': r['name'],
            'city': r['city'],
            'address': None,
            'phone': None,
            'manager': None,
            'established_date': None
        } for r in rows]
        return jsonify(result)
    rows = query_all('SELECT id, union_no, name, city FROM branch WHERE union_no=%s', (union_no,))
    if not rows:
        return jsonify({'ok': False, 'error': '未找到支行'}), 404
    r = rows[0]
    return jsonify({
        'id': r['id'],
        'union_no': r['union_no'],
        'name': r['name'],
        'city': r['city'],
        'address': None,
        'phone': None,
        'manager': None,
        'established_date': None
    })

@app.get('/admin/api/query/customer')
def admin_api_query_customer():
    if _require_login('admin'):
        return _require_login('admin')
    cid = request.args.get('id')
    fuzzy = request.args.get('fuzzy') == '1'
    if not cid:
        return jsonify({'ok': False, 'error': '缺少客户ID'}), 400
    if fuzzy:
        rows = query_all('SELECT id, name, identity_no, city, street, assistant_employee_id FROM customer WHERE CAST(id AS TEXT) ILIKE %s ORDER BY id', ('%' + cid + '%',))
        return jsonify([{
            'id': r['id'],
            'name': r['name'],
            'phone': None,
            'address': r['city'] + ' ' + r['street'],
            'identity_no': _mask_id(r['identity_no']),
            'assistant_employee_id': r['assistant_employee_id']
        } for r in rows])
    try:
        cid_i = int(cid)
    except Exception:
        return jsonify({'ok': False, 'error': '客户ID格式错误'}), 400
    rows = query_all('SELECT id, name, identity_no, city, street, assistant_employee_id FROM customer WHERE id=%s', (cid_i,))
    if not rows:
        return jsonify({'ok': False, 'error': '未找到客户'}), 404
    r = rows[0]
    return jsonify({
        'id': r['id'],
        'name': r['name'],
        'phone': None,
        'address': r['city'] + ' ' + r['street'],
        'identity_no': _mask_id(r['identity_no']),
        'assistant_employee_id': r['assistant_employee_id']
    })

@app.get('/admin/api/query/account')
def admin_api_query_account():
    if _require_login('admin'):
        return _require_login('admin')
    account_no = request.args.get('account_no')
    fuzzy = request.args.get('fuzzy') == '1'
    if not account_no:
        return jsonify({'ok': False, 'error': '缺少账户号'}), 400
    if fuzzy:
        rows = query_all('SELECT id, account_no, created_at, type FROM account WHERE account_no ILIKE %s ORDER BY id', ('%' + account_no + '%',))
        result = []
        for a in rows:
            owners = query_all('SELECT customer_id FROM account_customer WHERE account_id=%s', (a['id'],))
            last = query_all('SELECT MAX(last_access_date) AS last_access_date FROM account_customer WHERE account_id=%s', (a['id'],))
            result.append({
                'id': a['id'],
                'account_no': a['account_no'],
                'created_at': a['created_at'],
                'last_access_date': (last[0]['last_access_date'] if last and last[0] else None),
                'type': a['type'],
                'owners': [o['customer_id'] for o in owners]
            })
        return jsonify(result)
    rows = query_all('SELECT id, account_no, created_at, type FROM account WHERE account_no=%s', (account_no,))
    if not rows:
        return jsonify({'ok': False, 'error': '未找到账户'}), 404
    a = rows[0]
    owners = query_all('SELECT customer_id FROM account_customer WHERE account_id=%s', (a['id'],))
    last = query_all('SELECT MAX(last_access_date) AS last_access_date FROM account_customer WHERE account_id=%s', (a['id'],))
    return jsonify({
        'id': a['id'],
        'account_no': a['account_no'],
        'created_at': a['created_at'],
        'last_access_date': (last[0]['last_access_date'] if last and last[0] else None),
        'type': a['type'],
        'owners': [o['customer_id'] for o in owners]
    })

@app.get('/admin/api/query/employee')
def admin_api_query_employee():
    if _require_login('admin'):
        return _require_login('admin')
    eid = request.args.get('id')
    fuzzy = request.args.get('fuzzy') == '1'
    if not eid:
        return jsonify({'ok': False, 'error': '缺少员工ID'}), 400
    if fuzzy:
        rows = query_all('SELECT id, name, phone, hire_date, manager_id FROM employee WHERE CAST(id AS TEXT) ILIKE %s ORDER BY id', ('%' + eid + '%',))
        return jsonify([{
            'id': r['id'],
            'name': r['name'],
            'phone': _mask_phone(r['phone'] or ''),
            'hire_date': r['hire_date'],
            'manager_id': r['manager_id']
        } for r in rows])
    try:
        eid_i = int(eid)
    except Exception:
        return jsonify({'ok': False, 'error': '员工ID格式错误'}), 400
    rows = query_all('SELECT id, name, phone, hire_date, manager_id FROM employee WHERE id=%s', (eid_i,))
    if not rows:
        return jsonify({'ok': False, 'error': '未找到员工'}), 404
    r = rows[0]
    return jsonify({
        'id': r['id'],
        'name': r['name'],
        'phone': _mask_phone(r['phone'] or ''),
        'hire_date': r['hire_date'],
        'manager_id': r['manager_id']
    })

@app.get('/admin/api/query/loan')
def admin_api_query_loan():
    if _require_login('admin'):
        return _require_login('admin')
    loan_no = request.args.get('loan_no')
    fuzzy = request.args.get('fuzzy') == '1'
    if not loan_no:
        return jsonify({'ok': False, 'error': '缺少贷款号'}), 400
    if fuzzy:
        loans = query_all('SELECT id, loan_no, amount, branch_id FROM loan WHERE loan_no ILIKE %s ORDER BY id', ('%' + loan_no + '%',))
        result = []
        for l in loans:
            b = query_all('SELECT union_no FROM branch WHERE id=%s', (l['branch_id'],))
            owners = query_all('SELECT customer_id FROM loan_customer WHERE loan_id=%s', (l['id'],))
            repaid = query_all('SELECT COALESCE(SUM(amount),0) AS total FROM repayment WHERE loan_id=%s', (l['id'],))
            paid = float(repaid[0]['total']) if repaid and repaid[0] else 0.0
            remain = float(l['amount']) - paid
            result.append({
                'id': l['id'],
                'loan_no': l['loan_no'],
                'amount': float(l['amount']),
                'branch_union_no': (b[0]['union_no'] if b else None),
                'customers': [o['customer_id'] for o in owners],
                'paid_amount': paid,
                'remaining_amount': remain
            })
        return jsonify(result)
    rows = query_all('SELECT id, loan_no, amount, branch_id FROM loan WHERE loan_no=%s', (loan_no,))
    if not rows:
        return jsonify({'ok': False, 'error': '未找到贷款'}), 404
    l = rows[0]
    b = query_all('SELECT union_no FROM branch WHERE id=%s', (l['branch_id'],))
    owners = query_all('SELECT customer_id FROM loan_customer WHERE loan_id=%s', (l['id'],))
    repaid = query_all('SELECT COALESCE(SUM(amount),0) AS total FROM repayment WHERE loan_id=%s', (l['id'],))
    paid = float(repaid[0]['total']) if repaid and repaid[0] else 0.0
    remain = float(l['amount']) - paid
    return jsonify({
        'id': l['id'],
        'loan_no': l['loan_no'],
        'amount': float(l['amount']),
        'branch_union_no': (b[0]['union_no'] if b else None),
        'customers': [o['customer_id'] for o in owners],
        'paid_amount': paid,
        'remaining_amount': remain
    })

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
        if is_db_error(e):
            s, c, m = map_db_error(e)
            return jsonify({'ok': False, 'error': m, 'code': c}), s
        return jsonify({"ok": False, "error": '系统繁忙，请稍后再试'}), 500

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
        
        # 初始化新增的表结构
        # 添加业务单表
        cur.execute('''
        CREATE TABLE IF NOT EXISTS business (
          id BIGSERIAL PRIMARY KEY,
          business_type VARCHAR(32) NOT NULL,
          customer_id BIGINT NOT NULL REFERENCES customer(id),
          status VARCHAR(32) NOT NULL DEFAULT 'INIT',
          created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
          operator_id BIGINT REFERENCES employee(id),
          remark TEXT
        )
        ''')
        
        # 添加转账表
        cur.execute('''
        CREATE TABLE IF NOT EXISTS transfer (
          id BIGSERIAL PRIMARY KEY,
          from_account_id BIGINT NOT NULL REFERENCES account(id),
          to_account_id BIGINT NOT NULL REFERENCES account(id),
          amount NUMERIC(18,2) NOT NULL CHECK (amount > 0),
          status VARCHAR(32) NOT NULL DEFAULT 'SUCCESS',
          created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
          completed_at TIMESTAMP
        )
        ''')
        
        # 添加交易流水表
        cur.execute('''
        CREATE TABLE IF NOT EXISTS transaction (
          id BIGSERIAL PRIMARY KEY,
          account_id BIGINT NOT NULL REFERENCES account(id),
          business_id BIGINT REFERENCES business(id),
          transfer_id BIGINT REFERENCES transfer(id),
          txn_type VARCHAR(32) NOT NULL,
          amount NUMERIC(18,2) NOT NULL,
          balance_after NUMERIC(18,2) NOT NULL,
          created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
          remark TEXT
        )
        ''')
        
        # 创建索引
        cur.execute('CREATE INDEX IF NOT EXISTS idx_transaction_account_created ON transaction(account_id, created_at)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_transfer_from_account ON transfer(from_account_id)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_transfer_to_account ON transfer(to_account_id)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_business_customer_status ON business(customer_id, status)')
        
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"ok": True})
    except Exception as e:
        if is_db_error(e):
            s, c, m = map_db_error(e)
            return jsonify({'ok': False, 'error': m, 'code': c}), s
        return jsonify({"ok": False, "error": '系统繁忙，请稍后再试'}), 500

@app.post('/migrate-db')
def migrate_db():
    """数据库迁移接口，添加缺失的字段"""
    if _require_login('admin'):
        return _require_login('admin')
    
    try:
        conn = get_conn()
        cur = conn.cursor()
        
        # 检查并添加account表的closed_at字段
        cur.execute("""
            DO $$
            BEGIN
              IF NOT EXISTS (
                SELECT 1 
                FROM information_schema.columns 
                WHERE table_name = 'account' AND column_name = 'closed_at'
              ) THEN
                ALTER TABLE account ADD COLUMN closed_at TIMESTAMP;
              END IF;
            END$$;
        """)
        
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({"ok": True, "message": "数据库迁移完成"})
    except Exception as e:
        if is_db_error(e):
            s, c, m = map_db_error(e)
            return jsonify({'ok': False, 'error': m, 'code': c}), s
        return jsonify({"ok": False, "error": '系统繁忙，请稍后再试'}), 500

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
        return jsonify({'ok': False, 'error': '参数不完整'}), 400
    union_no = str(union_no).strip()
    name = str(name).strip()
    city = str(city).strip()
    if not union_no or not name or not city:
        return jsonify({'ok': False, 'error': '参数不完整'}), 400
    
    try:
        if query_all('SELECT 1 FROM branch WHERE union_no=%s LIMIT 1', (union_no,)):
            return jsonify({'ok': False, 'error': '联行号已存在'}), 400
        if query_all('SELECT 1 FROM branch WHERE name=%s LIMIT 1', (name,)):
            return jsonify({'ok': False, 'error': '分行名称已存在'}), 400
        execute('INSERT INTO branch(union_no, name, city) VALUES(%s,%s,%s)', (union_no, name, city))
        return jsonify({"ok": True, "message": "分行添加成功"})
    except Exception as e:
        if is_db_error(e):
            s, c, m = map_db_error(e)
            return jsonify({'ok': False, 'error': m, 'code': c}), s
        return jsonify({'ok': False, 'error': '添加分行失败'}), 500

@app.post('/branches/update')
def update_branch():
    if _require_login('admin'):
        return _require_login('admin')
    data = request.get_json(force=True)
    bid = data.get('id')
    name = data.get('name')
    city = data.get('city')
    name = str(name).strip() if name is not None else ''
    city = str(city).strip() if city is not None else ''
    if not name or not city:
        return jsonify({'ok': False, 'error': '参数不完整'}), 400
    
    try:
        if query_all('SELECT 1 FROM branch WHERE name=%s AND id<>%s LIMIT 1', (name, bid)):
            return jsonify({'ok': False, 'error': '分行名称已存在'}), 400
        execute('UPDATE branch SET name=%s, city=%s WHERE id=%s', (name, city, bid))
        return jsonify({'ok': True, "message": "分行信息更新成功"})
    except Exception as e:
        if is_db_error(e):
            s, c, m = map_db_error(e)
            return jsonify({'ok': False, 'error': m, 'code': c}), s
        return jsonify({'ok': False, "error": "更新分行信息失败"}), 500

@app.post('/branches/delete')
def delete_branch():
    if _require_login('admin'):
        return _require_login('admin')
    data = request.get_json(force=True)
    bid = data.get('id')
    if not bid:
        return jsonify({'ok': False, 'error': 'invalid_params'}), 400
    conn = begin_transaction()
    cur = conn.cursor()
    try:
        cur.execute('SELECT id FROM loan WHERE branch_id=%s', (bid,))
        loan_ids = [row[0] for row in cur.fetchall()]
        for lid in loan_ids:
            cur.execute('DELETE FROM loan_customer WHERE loan_id=%s', (lid,))
            cur.execute('DELETE FROM repayment_schedule WHERE loan_id=%s', (lid,))
            cur.execute('DELETE FROM repayment WHERE loan_id=%s', (lid,))
            cur.execute('DELETE FROM loan WHERE id=%s', (lid,))
        cur.execute('DELETE FROM branch WHERE id=%s', (bid,))
        conn.commit()
        cur.close(); conn.close()
        execute('INSERT INTO admin_activity_log(user_id, action, meta) VALUES(%s,%s,%s)', (session.get('user_id'), 'delete_branch', json.dumps({'id': bid})))
        return jsonify({'ok': True, "message": "分行删除成功"})
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        try:
            cur.close(); conn.close()
        except Exception:
            pass
        if is_db_error(e):
            s, c, m = map_db_error(e)
            return jsonify({'ok': False, 'error': m, 'code': c}), s
        return jsonify({'ok': False, "error": "删除分行失败"}), 500

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
        return jsonify({'ok': False, 'error': '参数不完整'}), 400
    
    try:
        execute('INSERT INTO employee(name, phone, hire_date, manager_id) VALUES(%s,%s,%s,%s)', (name, phone, hire_date, manager_id))
        return jsonify({"ok": True, "message": "员工添加成功"})
    except Exception as e:
        if is_db_error(e):
            s, c, m = map_db_error(e)
            return jsonify({'ok': False, 'error': m, 'code': c}), s
        return jsonify({"ok": False, "error": "添加员工失败"}), 500

@app.get('/dependents')
def list_dependents():
    if _require_login('admin'):
        return _require_login('admin')
    rows = query_all('SELECT id, employee_id, name, relationship FROM dependent ORDER BY id')
    return jsonify(rows)

@app.post('/dependents')
def create_dependent():
    if _require_login('admin'):
        return _require_login('admin')
    data = request.get_json(force=True)
    employee_id = data.get('employee_id')
    name = data.get('name')
    relationship = data.get('relationship')
    
    try:
        execute('INSERT INTO dependent(employee_id, name, relationship) VALUES(%s,%s,%s)', (employee_id, name, relationship))
        return jsonify({"ok": True, "message": "家属添加成功"})
    except Exception as e:
        if is_db_error(e):
            s, c, m = map_db_error(e)
            return jsonify({'ok': False, 'error': m, 'code': c}), s
        return jsonify({"ok": False, "error": "添加家属失败"}), 500

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
        return jsonify({'ok': False, 'error': '参数不完整'}), 400
    
    conn = None
    cur = None
    try:
        # 创建客户
        execute('INSERT INTO customer(name, identity_no, city, street, assistant_employee_id) VALUES(%s,%s,%s,%s,%s)', (name, identity_no, city, street, assistant_employee_id))
        
        # 获取刚创建的客户ID
        customer = query_all('SELECT id FROM customer WHERE identity_no=%s ORDER BY id DESC LIMIT 1', (identity_no,))
        if customer and customer[0]:
            customer_id = customer[0]['id']
            
            # 为该客户创建用户账号，使用客户姓名作为用户名，默认密码123456
            password = '123456'
            ph, ps = _hash_password(password)
            
            # 使用独立的连接和事务来创建用户账号
            conn = get_conn()
            cur = conn.cursor()
            
            # 创建用户账号
            cur.execute('INSERT INTO app_user(username, password_hash, password_salt, role) VALUES(%s,%s,%s,%s) ON CONFLICT (username) DO NOTHING RETURNING id', 
                       (name, ph, ps, 'user'))
            
            user_id = cur.fetchone()
            if user_id:
                user_id = user_id[0]
                # 创建用户和客户的关联
                cur.execute('INSERT INTO user_customer(user_id, customer_id) VALUES(%s,%s) ON CONFLICT DO NOTHING', 
                           (user_id, customer_id))
            
            conn.commit()
        
        return jsonify({"ok": True, "message": "客户添加成功，已同步创建用户账号"})
    except Exception as e:
        if conn:
            conn.rollback()
        if is_db_error(e):
            s, c, m = map_db_error(e)
            return jsonify({'ok': False, 'error': m, 'code': c}), s
        return jsonify({"ok": False, "error": "添加客户失败"}), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

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
    
    if not account_no or not type_:
        return jsonify({'ok': False, 'error': '参数不完整'}), 400
    
    conn = None
    cur = None
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute('INSERT INTO account(account_no, balance, type) VALUES(%s,%s,%s) RETURNING id', (account_no, balance, type_))
        account_id = cur.fetchone()[0]
        if type_ == 'savings':
            interest_rate = data.get('interest_rate', 0.02)  # 默认利率2%
            cur.execute('INSERT INTO savings_account(account_id, interest_rate) VALUES(%s,%s)', (account_id, interest_rate))
        elif type_ == 'checking':
            overdraft_limit = data.get('overdraft_limit', 0)  # 默认透支额度0
            cur.execute('INSERT INTO checking_account(account_id, overdraft_limit) VALUES(%s,%s)', (account_id, overdraft_limit))
        if customer_id:
            cur.execute('INSERT INTO account_customer(account_id, customer_id) VALUES(%s,%s) ON CONFLICT DO NOTHING', (account_id, customer_id))
        conn.commit()
        return jsonify({"ok": True, "account_id": account_id, "message": "账户创建成功", "account_no": account_no})
    except Exception as e:
        if conn:
            conn.rollback()
        if is_db_error(e):
            s, c, m = map_db_error(e)
            return jsonify({'ok': False, 'error': m, 'code': c}), s
        return jsonify({"ok": False, "error": "创建账户失败"}), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

@app.post('/loans/<int:loan_id>/status')
def update_loan_status(loan_id):
    if _require_login('admin'):
        return _require_login('admin')
    data = request.get_json(force=True)
    status = data.get('status')
    confirm = data.get('confirm')
    remark = data.get('remark', '')
    if status not in ('APPROVED','DISBURSED','SETTLED'):
        return jsonify({'ok': False, 'error': 'invalid_status'}), 400
    if not confirm:
        return jsonify({'ok': False, 'error': 'need_confirm'}), 400
    admin_id = session.get('user_id')
    conn = None
    cur = None
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute('SELECT status FROM loan WHERE id=%s FOR UPDATE', (loan_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({'ok': False, 'error': 'not_found'}), 404
        old = row[0]
        ok = False
        if old == 'PENDING' and status == 'APPROVED':
            ok = True
        elif old == 'APPROVED' and status == 'DISBURSED':
            ok = True
        elif old in ('DISBURSED','APPROVED') and status == 'SETTLED':
            ok = True
        if not ok:
            return jsonify({'ok': False, 'error': 'invalid_transition'}), 400
        if status == 'SETTLED':
            cur.execute('UPDATE loan SET status=%s, settled_at=NOW() WHERE id=%s', (status, loan_id))
        else:
            cur.execute('UPDATE loan SET status=%s WHERE id=%s', (status, loan_id))
        conn.commit()
        execute('INSERT INTO admin_activity_log(user_id, action, meta) VALUES(%s,%s,%s)', (admin_id, 'loan_status_update', json.dumps({'loan_id': loan_id, 'from': old, 'to': status, 'remark': remark})))
        return jsonify({'ok': True})
    except Exception as e:
        if conn:
            conn.rollback()
        if is_db_error(e):
            s, c, m = map_db_error(e)
            return jsonify({'ok': False, 'error': m, 'code': c}), s
        return jsonify({'ok': False, 'error': str(e)}), 400
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

@app.post('/account_owners')
def add_account_owner():
    if _require_login('admin'):
        return _require_login('admin')
    data = request.get_json(force=True)
    account_id = data.get('account_id')
    customer_id = data.get('customer_id')
    
    try:
        execute('INSERT INTO account_customer(account_id, customer_id) VALUES(%s,%s) ON CONFLICT DO NOTHING', (account_id, customer_id))
        return jsonify({"ok": True, "message": "账户所有者添加成功"})
    except Exception as e:
        if is_db_error(e):
            s, c, m = map_db_error(e)
            return jsonify({'ok': False, 'error': m, 'code': c}), s
        return jsonify({"ok": False, "error": "添加账户所有者失败"}), 500

@app.post('/account_access')
def update_access():
    if _require_login('admin'):
        return _require_login('admin')
    data = request.get_json(force=True)
    account_id = data.get('account_id')
    customer_id = data.get('customer_id')
    date = data.get('date')
    
    try:
        execute('INSERT INTO account_customer(account_id, customer_id, last_access_date) VALUES(%s,%s,%s) ON CONFLICT (account_id, customer_id) DO UPDATE SET last_access_date = EXCLUDED.last_access_date', (account_id, customer_id, date))
        return jsonify({"ok": True, "message": "账户访问记录更新成功"})
    except Exception as e:
        if is_db_error(e):
            s, c, m = map_db_error(e)
            return jsonify({'ok': False, 'error': m, 'code': c}), s
        return jsonify({"ok": False, "error": "更新账户访问记录失败"}), 500

@app.post('/admin/branches/delete')
def admin_delete_branch():
    if _require_login('admin'):
        return _require_login('admin')
    data = request.get_json(force=True)
    bid = data.get('id')
    if not bid:
        return jsonify({'ok': False, 'error': 'invalid_params'}), 400
    conn = begin_transaction()
    cur = conn.cursor()
    try:
        cur.execute('SELECT id FROM loan WHERE branch_id=%s', (bid,))
        loan_ids = [row[0] for row in cur.fetchall()]
        for lid in loan_ids:
            cur.execute('DELETE FROM loan_customer WHERE loan_id=%s', (lid,))
            cur.execute('DELETE FROM repayment_schedule WHERE loan_id=%s', (lid,))
            cur.execute('DELETE FROM repayment WHERE loan_id=%s', (lid,))
            cur.execute('DELETE FROM loan WHERE id=%s', (lid,))
        cur.execute('DELETE FROM branch WHERE id=%s', (bid,))
        conn.commit()
        cur.close(); conn.close()
        execute('INSERT INTO admin_activity_log(user_id, action, meta) VALUES(%s,%s,%s)', (session.get('user_id'), 'delete_branch', json.dumps({'id': bid})))
        return jsonify({'ok': True})
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        try:
            cur.close(); conn.close()
        except Exception:
            pass
        if is_db_error(e):
            s, c, m = map_db_error(e)
            return jsonify({'ok': False, 'error': m, 'code': c}), s
        return jsonify({'ok': False, 'error': '删除分行失败'}), 500

@app.post('/admin/employees/delete')
def admin_delete_employee():
    if _require_login('admin'):
        return _require_login('admin')
    data = request.get_json(force=True)
    eid = data.get('id')
    confirm = data.get('confirm')
    code = data.get('code')
    if not eid or not confirm:
        return jsonify({'ok': False, 'error': 'invalid_params'}), 400
    info = _sensitive_codes.get(session.get('user_id'))
    if not info or info['code'] != code or info['exp'] < datetime.datetime.utcnow():
        return jsonify({'ok': False, 'error': 'verify'}), 403
    conn = begin_transaction()
    cur = conn.cursor()
    try:
        cur.execute('DELETE FROM dependent WHERE employee_id=%s', (eid,))
        cur.execute('UPDATE employee SET manager_id=NULL WHERE manager_id=%s', (eid,))
        cur.execute('UPDATE customer SET assistant_employee_id=NULL WHERE assistant_employee_id=%s', (eid,))
        cur.execute('DELETE FROM employee WHERE id=%s', (eid,))
        conn.commit()
        cur.close(); conn.close()
        execute('INSERT INTO admin_activity_log(user_id, action, meta) VALUES(%s,%s,%s)', (session.get('user_id'), 'delete_employee', json.dumps({'id': eid})))
        return jsonify({'ok': True})
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        try:
            cur.close(); conn.close()
        except Exception:
            pass
        if is_db_error(e):
            s, c, m = map_db_error(e)
            return jsonify({'ok': False, 'error': m, 'code': c}), s
        return jsonify({'ok': False, 'error': '删除员工失败'}), 500

@app.post('/admin/dependents/delete')
def admin_delete_dependent():
    if _require_login('admin'):
        return _require_login('admin')
    data = request.get_json(force=True)
    did = data.get('id')
    confirm = data.get('confirm')
    code = data.get('code')
    if not did or not confirm:
        return jsonify({'ok': False, 'error': 'invalid_params'}), 400
    info = _sensitive_codes.get(session.get('user_id'))
    if not info or info['code'] != code or info['exp'] < datetime.datetime.utcnow():
        return jsonify({'ok': False, 'error': 'verify'}), 403
    try:
        execute('DELETE FROM dependent WHERE id=%s', (did,))
        execute('INSERT INTO admin_activity_log(user_id, action, meta) VALUES(%s,%s,%s)', (session.get('user_id'), 'delete_dependent', json.dumps({'id': did})))
        return jsonify({'ok': True})
    except Exception as e:
        if is_db_error(e):
            s, c, m = map_db_error(e)
            return jsonify({'ok': False, 'error': m, 'code': c}), s
        return jsonify({'ok': False, 'error': '删除家属失败'}), 500

@app.post('/admin/customers/delete')
def admin_delete_customer():
    if _require_login('admin'):
        return _require_login('admin')
    data = request.get_json(force=True)
    cid = data.get('id')
    if not cid:
        return jsonify({'ok': False, 'error': 'invalid_params'}), 400
    conn = begin_transaction()
    cur = conn.cursor()
    try:
        cur.execute('SELECT id FROM business WHERE customer_id=%s', (cid,))
        bs_ids = [row[0] for row in cur.fetchall()]
        for bid_ in bs_ids:
            cur.execute('DELETE FROM transaction WHERE business_id=%s', (bid_,))
        cur.execute('DELETE FROM account_customer WHERE customer_id=%s', (cid,))
        cur.execute('DELETE FROM loan_customer WHERE customer_id=%s', (cid,))
        cur.execute('DELETE FROM business WHERE customer_id=%s', (cid,))
        cur.execute('DELETE FROM user_customer WHERE customer_id=%s', (cid,))
        cur.execute('DELETE FROM customer WHERE id=%s', (cid,))
        conn.commit()
        cur.close(); conn.close()
        execute('INSERT INTO admin_activity_log(user_id, action, meta) VALUES(%s,%s,%s)', (session.get('user_id'), 'delete_customer', json.dumps({'id': cid})))
        return jsonify({'ok': True})
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        try:
            cur.close(); conn.close()
        except Exception:
            pass
        if is_db_error(e):
            s, c, m = map_db_error(e)
            return jsonify({'ok': False, 'error': m, 'code': c}), s
        return jsonify({'ok': False, 'error': '删除客户失败'}), 500

@app.post('/admin/accounts/delete')
def admin_delete_account():
    if _require_login('admin'):
        return _require_login('admin')
    data = request.get_json(force=True)
    aid = data.get('id')
    confirm = data.get('confirm')
    code = data.get('code')
    if not aid or not confirm:
        return jsonify({'ok': False, 'error': 'invalid_params'}), 400
    info = _sensitive_codes.get(session.get('user_id'))
    if not info or info['code'] != code or info['exp'] < datetime.datetime.utcnow():
        return jsonify({'ok': False, 'error': 'verify'}), 403
    conn = begin_transaction()
    cur = conn.cursor()
    try:
        cur.execute('DELETE FROM transaction WHERE account_id=%s', (aid,))
        cur.execute('DELETE FROM transfer WHERE from_account_id=%s OR to_account_id=%s', (aid, aid))
        cur.execute('DELETE FROM account WHERE id=%s', (aid,))
        conn.commit()
        cur.close(); conn.close()
        execute('INSERT INTO admin_activity_log(user_id, action, meta) VALUES(%s,%s,%s)', (session.get('user_id'), 'delete_account', json.dumps({'id': aid})))
        return jsonify({'ok': True})
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        try:
            cur.close(); conn.close()
        except Exception:
            pass
        if is_db_error(e):
            s, c, m = map_db_error(e)
            return jsonify({'ok': False, 'error': m, 'code': c}), s
        return jsonify({'ok': False, 'error': '删除账户失败'}), 500

@app.post('/admin/loans/delete')
def admin_delete_loan():
    if _require_login('admin'):
        return _require_login('admin')
    data = request.get_json(force=True)
    lid = data.get('id')
    confirm = data.get('confirm')
    code = data.get('code')
    if not lid or not confirm:
        return jsonify({'ok': False, 'error': 'invalid_params'}), 400
    info = _sensitive_codes.get(session.get('user_id'))
    if not info or info['code'] != code or info['exp'] < datetime.datetime.utcnow():
        return jsonify({'ok': False, 'error': 'verify'}), 403
    conn = begin_transaction()
    cur = conn.cursor()
    try:
        cur.execute('DELETE FROM loan_customer WHERE loan_id=%s', (lid,))
        cur.execute('DELETE FROM repayment_schedule WHERE loan_id=%s', (lid,))
        cur.execute('DELETE FROM repayment WHERE loan_id=%s', (lid,))
        cur.execute('DELETE FROM loan WHERE id=%s', (lid,))
        conn.commit()
        cur.close(); conn.close()
        execute('INSERT INTO admin_activity_log(user_id, action, meta) VALUES(%s,%s,%s)', (session.get('user_id'), 'delete_loan', json.dumps({'id': lid})))
        return jsonify({'ok': True})
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        try:
            cur.close(); conn.close()
        except Exception:
            pass
        if is_db_error(e):
            s, c, m = map_db_error(e)
            return jsonify({'ok': False, 'error': m, 'code': c}), s
        return jsonify({'ok': False, 'error': '删除贷款失败'}), 500

@app.post('/admin/repayments/delete')
def admin_delete_repayment():
    if _require_login('admin'):
        return _require_login('admin')
    data = request.get_json(force=True)
    rid = data.get('id')
    confirm = data.get('confirm')
    code = data.get('code')
    if not rid or not confirm:
        return jsonify({'ok': False, 'error': 'invalid_params'}), 400
    info = _sensitive_codes.get(session.get('user_id'))
    if not info or info['code'] != code or info['exp'] < datetime.datetime.utcnow():
        return jsonify({'ok': False, 'error': 'verify'}), 403
    try:
        execute('DELETE FROM repayment WHERE id=%s', (rid,))
        execute('INSERT INTO admin_activity_log(user_id, action, meta) VALUES(%s,%s,%s)', (session.get('user_id'), 'delete_repayment', json.dumps({'id': rid})))
        return jsonify({'ok': True})
    except Exception as e:
        if is_db_error(e):
            s, c, m = map_db_error(e)
            return jsonify({'ok': False, 'error': m, 'code': c}), s
        return jsonify({'ok': False, 'error': '删除还款记录失败'}), 500

@app.get('/loans')
def list_loans():
    if _require_login('admin'):
        return _require_login('admin')
    rows = query_all('SELECT id, loan_no, amount, branch_id FROM loan ORDER BY id')
    return jsonify(rows)

@app.get('/loans/financials')
def loans_financials():
    if _require_login('admin'):
        return _require_login('admin')
    loans = query_all('SELECT id, loan_no, amount, status, interest_rate, start_date FROM loan ORDER BY id')
    conn = get_conn()
    cur = conn.cursor()
    result = []
    try:
        for l in loans:
            loan_id = l['id']
            days = 0
            if l.get('start_date'):
                days = max((datetime.date.today() - l['start_date']).days, 0)
            rate = float(l.get('interest_rate') or 0)
            principal = float(l['amount'])
            total_interest = round(principal * rate * days / 365.0, 2)
            repaid_rows = query_all('SELECT COALESCE(SUM(amount),0) AS total FROM repayment WHERE loan_id=%s', (loan_id,))
            repaid_total = float(repaid_rows[0]['total']) if repaid_rows and repaid_rows[0] else 0.0
            remaining = round(principal + total_interest - repaid_total, 2)
            if remaining < 0:
                remaining = 0.0
            if remaining <= 0 and l['status'] != 'SETTLED':
                cur.execute('UPDATE loan SET status=%s, settled_at=NOW() WHERE id=%s', ('SETTLED', loan_id))
            result.append({
                'loan_id': loan_id,
                'loan_no': l['loan_no'],
                'principal_amount': round(principal, 2),
                'cumulative_interest': total_interest,
                'remaining_amount': remaining
            })
        conn.commit()
        return jsonify(result)
    finally:
        cur.close(); conn.close()

@app.post('/loans')
def create_loan():
    if _require_login('admin'):
        return _require_login('admin')
    data = request.get_json(force=True)
    loan_no = data.get('loan_no')
    amount = data.get('amount')
    branch_id = data.get('branch_id')
    customer_ids = data.get('customer_ids') or []
    interest_rate = data.get('interest_rate')
    term_months = data.get('term_months')
    repayment_method = data.get('repayment_method')
    
    if not loan_no or not amount or not branch_id or interest_rate is None or not term_months or not repayment_method:
        return jsonify({'ok': False, 'error': '参数不完整'}), 400
    if not isinstance(customer_ids, list) or len(customer_ids) < 1:
        return jsonify({'ok': False, 'error': '贷款必须至少由一位客户拥有'}), 400
    if not query_all('SELECT 1 FROM branch WHERE id=%s LIMIT 1', (branch_id,)):
        return jsonify({'ok': False, 'error': '分行不存在'}), 400
    for cid in customer_ids:
        if not query_all('SELECT 1 FROM customer WHERE id=%s LIMIT 1', (cid,)):
            return jsonify({'ok': False, 'error': f'客户不存在: {cid}'}), 400
    if not isinstance(term_months, int) or term_months <= 0:
        return jsonify({'ok': False, 'error': '期限不合法'}), 400
    if not isinstance(interest_rate, (int, float)) or interest_rate < 0:
        return jsonify({'ok': False, 'error': '利率不合法'}), 400
    if repayment_method not in ('EQUAL_INSTALLMENT','EQUAL_PRINCIPAL'):
        return jsonify({'ok': False, 'error': '还款方式不合法'}), 400
    
    conn = None
    cur = None
    try:
        conn = get_conn()
        cur = conn.cursor()
        start_date = datetime.date.today()
        cur.execute('INSERT INTO loan(loan_no, amount, branch_id, interest_rate, term_months, repayment_method, status, start_date, end_date) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id', (loan_no, amount, branch_id, interest_rate, term_months, repayment_method, 'PENDING', start_date, None))
        loan_id = cur.fetchone()[0]
        for cid in customer_ids:
            cur.execute('INSERT INTO loan_customer(loan_id, customer_id) VALUES(%s,%s) ON CONFLICT DO NOTHING', (loan_id, cid))
        monthly_rate = (interest_rate or 0) / 12.0
        def _add_months(d, m):
            y = d.year + (d.month - 1 + m) // 12
            mo = (d.month - 1 + m) % 12 + 1
            day = min(d.day, [31,29 if (y%4==0 and (y%100!=0 or y%400==0)) else 28,31,30,31,30,31,31,30,31,30,31][mo-1])
            return datetime.date(y, mo, day)
        remaining = float(amount)
        last_due = None
        if repayment_method == 'EQUAL_INSTALLMENT':
            r = monthly_rate
            n = term_months
            pay = 0.0
            if r > 0:
                pay = remaining * r * (1 + r) ** n / ((1 + r) ** n - 1)
            else:
                pay = remaining / n
            pay = round(pay + 1e-8, 2)
            for i in range(1, term_months + 1):
                interest = round(remaining * r, 2)
                principal = pay - interest
                if i == term_months:
                    principal = round(remaining, 2)
                    interest = round(pay - principal, 2) if monthly_rate > 0 else 0.0
                due_date = _add_months(start_date, i)
                cur.execute('INSERT INTO repayment_schedule(loan_id, period_no, due_date, principal_due, interest_due, status) VALUES(%s,%s,%s,%s,%s,%s)', (loan_id, i, due_date, principal, interest, 'DUE'))
                remaining = round(remaining - principal, 2)
                last_due = due_date
        else:
            principal_each = round(remaining / term_months, 2)
            for i in range(1, term_months + 1):
                interest = round(remaining * monthly_rate, 2)
                principal = principal_each if i < term_months else round(remaining, 2)
                due_date = _add_months(start_date, i)
                cur.execute('INSERT INTO repayment_schedule(loan_id, period_no, due_date, principal_due, interest_due, status) VALUES(%s,%s,%s,%s,%s,%s)', (loan_id, i, due_date, principal, interest, 'DUE'))
                remaining = round(remaining - principal, 2)
                last_due = due_date
        if last_due:
            cur.execute('UPDATE loan SET end_date=%s WHERE id=%s', (last_due, loan_id))
        conn.commit()
        return jsonify({"ok": True, "loan_id": loan_id, "message": "贷款创建成功"})
    except Exception as e:
        if conn:
            conn.rollback()
        if is_db_error(e):
            s, c, m = map_db_error(e)
            return jsonify({'ok': False, 'error': m, 'code': c}), s
        return jsonify({"ok": False, "error": "创建贷款失败"}), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

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
    
    if not loan_id or not batch_no or not paid_at or not amount or not savings_account_id:
        return jsonify({'ok': False, 'error': '参数不完整'}), 400
    if not query_all('SELECT 1 FROM loan WHERE id=%s LIMIT 1', (loan_id,)):
        return jsonify({'ok': False, 'error': '贷款不存在'}), 400
    if not query_all('SELECT 1 FROM savings_account WHERE account_id=%s LIMIT 1', (savings_account_id,)):
        return jsonify({'ok': False, 'error': '必须使用储蓄账户还款'}), 400
    
    try:
        execute('INSERT INTO repayment(loan_id, batch_no, paid_at, amount, savings_account_id) VALUES(%s,%s,%s,%s,%s)', (loan_id, batch_no, paid_at, amount, savings_account_id))
        return jsonify({"ok": True, "message": "还款记录添加成功"})
    except Exception as e:
        if is_db_error(e):
            s, c, m = map_db_error(e)
            return jsonify({'ok': False, 'error': m, 'code': c}), s
        return jsonify({'ok': False, 'error': '添加还款记录失败'}), 500

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
            if table == 'branch':
                cur.execute('SELECT id FROM loan WHERE branch_id=%s', (i,))
                loan_ids = [row[0] for row in cur.fetchall()]
                for lid in loan_ids:
                    cur.execute('DELETE FROM loan_customer WHERE loan_id=%s', (lid,))
                    cur.execute('DELETE FROM repayment_schedule WHERE loan_id=%s', (lid,))
                    cur.execute('DELETE FROM repayment WHERE loan_id=%s', (lid,))
                    cur.execute('DELETE FROM loan WHERE id=%s', (lid,))
                cur.execute('DELETE FROM branch WHERE id=%s', (i,))
            elif table == 'customer':
                cur.execute('SELECT id FROM business WHERE customer_id=%s', (i,))
                bs_ids = [row[0] for row in cur.fetchall()]
                for bid_ in bs_ids:
                    cur.execute('DELETE FROM transaction WHERE business_id=%s', (bid_,))
                cur.execute('DELETE FROM account_customer WHERE customer_id=%s', (i,))
                cur.execute('DELETE FROM loan_customer WHERE customer_id=%s', (i,))
                cur.execute('DELETE FROM business WHERE customer_id=%s', (i,))
                cur.execute('DELETE FROM user_customer WHERE customer_id=%s', (i,))
                cur.execute('DELETE FROM customer WHERE id=%s', (i,))
            else:
                cur.execute(f'DELETE FROM {table} WHERE id=%s', (i,))
        conn.commit()
        return jsonify({'ok': True})
    except Exception as e:
        conn.rollback()
        if is_db_error(e):
            s, c, m = map_db_error(e)
            return jsonify({'ok': False, 'error': m, 'code': c}), s
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

@app.post('/user/deposit')
def deposit():
    """存款操作"""
    if _require_login('user'):
        return _require_login('user')
    
    data = request.get_json(force=True)
    account_id = data.get('account_id')
    amount = data.get('amount')
    remark = data.get('remark', '')
    
    if not account_id or not amount or amount <= 0:
        return jsonify({'ok': False, 'error': 'invalid_params'}), 400
    
    # 获取用户关联的客户ID
    uid = session.get('user_id')
    customer_row = query_all('SELECT customer_id FROM user_customer WHERE user_id=%s', (uid,))
    if not customer_row:
        return jsonify({'ok': False, 'error': 'no_customer'}), 400
    
    customer_id = customer_row[0]['customer_id']
    
    # 开始事务
    conn = begin_transaction()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # 检查账户是否属于该客户并锁定账户
        cur.execute("""
            SELECT a.id, a.balance 
            FROM account a
            JOIN account_customer ac ON a.id = ac.account_id
            WHERE a.id = %s AND ac.customer_id = %s
            FOR UPDATE
        """, (account_id, customer_id))
        
        account = cur.fetchone()
        if not account:
            raise Exception("账户不存在或不属于该用户")
        
        old_balance = account['balance']
        new_balance = old_balance + amount
        
        # 更新账户余额
        cur.execute("""
            UPDATE account 
            SET balance = %s 
            WHERE id = %s
        """, (new_balance, account_id))
        
        # 创建业务单
        cur.execute("""
            INSERT INTO business(business_type, customer_id, status, remark) 
            VALUES(%s, %s, %s, %s) RETURNING id
        """, ('DEPOSIT', customer_id, 'COMPLETED', remark))
        
        business_id = cur.fetchone()['id']
        
        # 插入交易流水
        cur.execute("""
            INSERT INTO transaction(account_id, business_id, txn_type, amount, balance_after, remark)
            VALUES(%s, %s, %s, %s, %s, %s)
        """, (account_id, business_id, 'DEPOSIT', amount, new_balance, remark))
        
        conn.commit()
        cur.close()
        conn.close()
        
        # 记录活动日志
        execute('INSERT INTO activity_log(user_id, action, meta) VALUES(%s,%s,%s)', 
                (uid, 'deposit', json.dumps({'account_id': account_id, 'amount': float(amount)})))
        
        return jsonify({'ok': True, 'balance': float(new_balance)})
        
    except Exception as e:
        conn.rollback()
        cur.close()
        conn.close()
        if is_db_error(e):
            s, c, m = map_db_error(e)
            return jsonify({'ok': False, 'error': m, 'code': c}), s
        return jsonify({'ok': False, 'error': str(e)}), 400

@app.post('/user/withdraw')
def withdraw():
    """取款操作"""
    if _require_login('user'):
        return _require_login('user')
    
    data = request.get_json(force=True)
    account_id = data.get('account_id')
    amount = data.get('amount')
    remark = data.get('remark', '')
    
    if not account_id or not amount or amount <= 0:
        return jsonify({'ok': False, 'error': 'invalid_params'}), 400
    
    # 获取用户关联的客户ID
    uid = session.get('user_id')
    customer_row = query_all('SELECT customer_id FROM user_customer WHERE user_id=%s', (uid,))
    if not customer_row:
        return jsonify({'ok': False, 'error': 'no_customer'}), 400
    
    customer_id = customer_row[0]['customer_id']
    
    # 开始事务
    conn = begin_transaction()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # 检查账户是否属于该客户并锁定账户
        cur.execute("""
            SELECT a.id, a.balance 
            FROM account a
            JOIN account_customer ac ON a.id = ac.account_id
            WHERE a.id = %s AND ac.customer_id = %s
            FOR UPDATE
        """, (account_id, customer_id))
        
        account = cur.fetchone()
        if not account:
            raise Exception("账户不存在或不属于该用户")
        
        old_balance = account['balance']
        if old_balance < amount:
            raise Exception("余额不足")
        
        new_balance = old_balance - amount
        
        # 更新账户余额
        cur.execute("""
            UPDATE account 
            SET balance = %s 
            WHERE id = %s
        """, (new_balance, account_id))
        
        # 创建业务单
        cur.execute("""
            INSERT INTO business(business_type, customer_id, status, remark) 
            VALUES(%s, %s, %s, %s) RETURNING id
        """, ('WITHDRAW', customer_id, 'COMPLETED', remark))
        
        business_id = cur.fetchone()['id']
        
        # 插入交易流水
        cur.execute("""
            INSERT INTO transaction(account_id, business_id, txn_type, amount, balance_after, remark)
            VALUES(%s, %s, %s, %s, %s, %s)
        """, (account_id, business_id, 'WITHDRAW', amount, new_balance, remark))
        
        conn.commit()
        cur.close()
        conn.close()
        
        # 记录活动日志
        execute('INSERT INTO activity_log(user_id, action, meta) VALUES(%s,%s,%s)', 
                (uid, 'withdraw', json.dumps({'account_id': account_id, 'amount': float(amount)})))
        
        return jsonify({'ok': True, 'balance': float(new_balance)})
        
    except Exception as e:
        conn.rollback()
        cur.close()
        conn.close()
        if is_db_error(e):
            s, c, m = map_db_error(e)
            return jsonify({'ok': False, 'error': m, 'code': c}), s
        return jsonify({'ok': False, 'error': str(e)}), 400

@app.post('/user/transfer')
def transfer():
    """转账操作"""
    if _require_login('user'):
        return _require_login('user')
    
    data = request.get_json(force=True)
    from_account_id = data.get('from_account_id')
    to_account_id = data.get('to_account_id')
    amount = data.get('amount')
    remark = data.get('remark', '')
    
    # 确保账户ID是整数类型
    try:
        from_account_id = int(from_account_id)
        to_account_id = int(to_account_id)
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'invalid_params'}), 400
    
    if not from_account_id or not to_account_id or not amount or amount <= 0:
        return jsonify({'ok': False, 'error': 'invalid_params'}), 400
    
    if from_account_id == to_account_id:
        return jsonify({'ok': False, 'error': 'same_account'}), 400
    
    # 获取用户关联的客户ID
    uid = session.get('user_id')
    customer_row = query_all('SELECT customer_id FROM user_customer WHERE user_id=%s', (uid,))
    if not customer_row:
        return jsonify({'ok': False, 'error': 'no_customer'}), 400
    
    customer_id = customer_row[0]['customer_id']
    
    # 开始事务
    conn = begin_transaction()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # 检查转出账户是否属于该客户并锁定账户（按ID顺序锁定避免死锁）
        first_lock_id = min(from_account_id, to_account_id)
        second_lock_id = max(from_account_id, to_account_id)
        
        cur.execute("""
            SELECT id, balance FROM account WHERE id IN (%s, %s) ORDER BY id FOR UPDATE
        """, (first_lock_id, second_lock_id))
        
        accounts = {acc['id']: acc for acc in cur.fetchall()}
        
        if from_account_id not in accounts:
            raise Exception("转出账户不存在")
        
        if to_account_id not in accounts:
            raise Exception("转入账户不存在")
        
        from_account = accounts[from_account_id]
        to_account = accounts[to_account_id]
        
        # 再次确认转出账户属于该客户
        cur.execute("""
            SELECT 1 FROM account_customer 
            WHERE account_id = %s AND customer_id = %s
        """, (from_account_id, customer_id))
        
        if not cur.fetchone():
            raise Exception("转出账户不属于该用户")
            
        # 确认转入账户也属于该客户
        cur.execute("""
            SELECT 1 FROM account_customer 
            WHERE account_id = %s AND customer_id = %s
        """, (to_account_id, customer_id))
        
        if not cur.fetchone():
            raise Exception("转入账户不属于该用户")
        
        # 检查余额
        if from_account['balance'] < amount:
            raise Exception("转出账户余额不足")
        
        new_from_balance = from_account['balance'] - amount
        new_to_balance = to_account['balance'] + amount
        
        # 更新转出账户余额
        cur.execute("""
            UPDATE account 
            SET balance = %s 
            WHERE id = %s
        """, (new_from_balance, from_account_id))
        
        # 更新转入账户余额
        cur.execute("""
            UPDATE account 
            SET balance = %s 
            WHERE id = %s
        """, (new_to_balance, to_account_id))
        
        # 创建转账记录
        cur.execute("""
            INSERT INTO transfer(from_account_id, to_account_id, amount, status) 
            VALUES(%s, %s, %s, %s) RETURNING id
        """, (from_account_id, to_account_id, amount, 'SUCCESS'))
        
        transfer_id = cur.fetchone()['id']
        
        # 创建业务单
        cur.execute("""
            INSERT INTO business(business_type, customer_id, status, remark) 
            VALUES(%s, %s, %s, %s) RETURNING id
        """, ('TRANSFER', customer_id, 'COMPLETED', remark))
        
        business_id = cur.fetchone()['id']
        
        # 插入转出交易流水
        cur.execute("""
            INSERT INTO transaction(account_id, business_id, transfer_id, txn_type, amount, balance_after, remark)
            VALUES(%s, %s, %s, %s, %s, %s, %s)
        """, (from_account_id, business_id, transfer_id, 'TRANSFER_OUT', amount, new_from_balance, remark))
        
        # 插入转入交易流水
        cur.execute("""
            INSERT INTO transaction(account_id, business_id, transfer_id, txn_type, amount, balance_after, remark)
            VALUES(%s, %s, %s, %s, %s, %s, %s)
        """, (to_account_id, business_id, transfer_id, 'TRANSFER_IN', amount, new_to_balance, remark))
        
        conn.commit()
        cur.close()
        conn.close()
        
        # 记录活动日志
        execute('INSERT INTO activity_log(user_id, action, meta) VALUES(%s,%s,%s)', 
                (uid, 'transfer', json.dumps({
                    'from_account_id': from_account_id, 
                    'to_account_id': to_account_id, 
                    'amount': float(amount)
                })))
        
        return jsonify({'ok': True, 'from_balance': float(new_from_balance), 'to_balance': float(new_to_balance)})
        
    except Exception as e:
        conn.rollback()
        cur.close()
        conn.close()
        if is_db_error(e):
            s, c, m = map_db_error(e)
            return jsonify({'ok': False, 'error': m, 'code': c}), s
        return jsonify({'ok': False, 'error': str(e)}), 400

@app.post('/user/create-account')
def user_create_account():
    """用户自助创建银行账户"""
    if _require_login('user'):
        return _require_login('user')
    
    data = request.get_json(force=True)
    account_type = data.get('account_type')
    account_no = data.get('account_no')
    
    # 验证参数
    if not account_type or account_type not in ['savings', 'checking']:
        return jsonify({'ok': False, 'error': 'invalid_account_type'}), 400
    
    if not account_no:
        # 如果没有提供账户号，则自动生成
        import uuid
        account_no = 'ACC' + uuid.uuid4().hex[:12].upper()
    
    # 获取用户关联的客户ID
    uid = session.get('user_id')
    customer_row = query_all('SELECT customer_id FROM user_customer WHERE user_id=%s', (uid,))
    if not customer_row:
        return jsonify({'ok': False, 'error': 'no_customer'}), 400
    
    customer_id = customer_row[0]['customer_id']
    
    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor()
        
        # 创建账户
        cur.execute('INSERT INTO account(account_no, type) VALUES(%s,%s) RETURNING id', (account_no, account_type))
        account_id = cur.fetchone()[0]
        
        # 关联账户和客户
        cur.execute('INSERT INTO account_customer(account_id, customer_id) VALUES(%s,%s)', (account_id, customer_id))
        
        # 如果是储蓄账户，创建储蓄账户记录（默认利率0.01）
        if account_type == 'savings':
            cur.execute('INSERT INTO savings_account(account_id, interest_rate) VALUES(%s,%s)', (account_id, 0.01))
        # 如果是支票账户，创建支票账户记录（默认透支额度0）
        elif account_type == 'checking':
            cur.execute('INSERT INTO checking_account(account_id, overdraft_limit) VALUES(%s,%s)', (account_id, 0))
        
        conn.commit()
        cur.close()
        conn.close()
        
        # 记录活动日志
        execute('INSERT INTO activity_log(user_id, action, meta) VALUES(%s,%s,%s)', 
                (uid, 'create_account', json.dumps({'account_id': account_id, 'account_type': account_type})))
        
        return jsonify({'ok': True, 'account_id': account_id, 'account_no': account_no})
        
    except Exception as e:
        if conn:
            try:
                conn.rollback()
                conn.close()
            except:
                pass
        if is_db_error(e):
            s, c, m = map_db_error(e)
            return jsonify({'ok': False, 'error': m, 'code': c}), s
        return jsonify({'ok': False, 'error': str(e)}), 400

@app.post('/user/close-account-request')
def user_close_account_request():
    """用户申请注销账户"""
    if _require_login('user'):
        return _require_login('user')
    
    data = request.get_json(force=True)
    account_id = data.get('account_id')
    reason = data.get('reason', '')
    
    if not account_id:
        return jsonify({'ok': False, 'error': 'missing_account_id'}), 400
    
    # 获取用户关联的客户ID
    uid = session.get('user_id')
    customer_row = query_all('SELECT customer_id FROM user_customer WHERE user_id=%s', (uid,))
    if not customer_row:
        return jsonify({'ok': False, 'error': 'no_customer'}), 400
    
    customer_id = customer_row[0]['customer_id']
    
    # 检查账户是否属于该客户
    account_check = query_all('''
        SELECT a.id, a.balance, a.type 
        FROM account a
        JOIN account_customer ac ON a.id = ac.account_id
        WHERE a.id = %s AND ac.customer_id = %s
    ''', (account_id, customer_id))
    
    if not account_check:
        return jsonify({'ok': False, 'error': 'account_not_found_or_not_owned'}), 400
    
    account = account_check[0]
    
    try:
        if account['balance'] == 0:
            # 余额为0，直接注销
            execute("UPDATE account SET type = 'closed', closed_at = NOW() WHERE id = %s", (account_id,))
            
            # 记录活动日志
            execute('INSERT INTO activity_log(user_id, action, meta) VALUES(%s,%s,%s)', 
                    (uid, 'close_account', json.dumps({'account_id': account_id, 'reason': reason})))
            
            return jsonify({'ok': True, 'message': '账户已成功注销'})
        else:
            # 余额不为0，需要管理员审批
            # 创建注销申请业务单（需要管理员审批）
            execute('''
                INSERT INTO business(business_type, customer_id, status, remark) 
                VALUES(%s, %s, %s, %s) RETURNING id
            ''', ('CLOSE_ACCOUNT', customer_id, 'PENDING', f'申请注销账户 {account_id}，原因: {reason}'))
            
            business_id = query_all('SELECT id FROM business ORDER BY id DESC LIMIT 1')[0]['id']
            
            # 记录活动日志
            execute('INSERT INTO activity_log(user_id, action, meta) VALUES(%s,%s,%s)', 
                    (uid, 'close_account_request', json.dumps({'account_id': account_id, 'business_id': business_id})))
            
            return jsonify({'ok': True, 'message': '账户注销申请已提交，等待管理员审批'})
        
    except Exception as e:
        if is_db_error(e):
            s, c, m = map_db_error(e)
            return jsonify({'ok': False, 'error': m, 'code': c}), s
        return jsonify({'ok': False, 'error': str(e)}), 400

@app.get('/user/accounts')
def list_user_accounts():
    """列出用户的所有账户"""
    if _require_login('user'):
        return _require_login('user')
    
    uid = session.get('user_id')
    customer_row = query_all('SELECT customer_id FROM user_customer WHERE user_id=%s', (uid,))
    if not customer_row:
        return jsonify([])
    
    customer_id = customer_row[0]['customer_id']
    rows = query_all("""
        SELECT a.id, a.account_no, a.balance, a.type, a.created_at,
               sa.interest_rate, ca.overdraft_limit
        FROM account a
        JOIN account_customer ac ON a.id = ac.account_id
        LEFT JOIN savings_account sa ON a.id = sa.account_id
        LEFT JOIN checking_account ca ON a.id = ca.account_id
        WHERE ac.customer_id = %s
        ORDER BY a.id
    """, (customer_id,))
    
    return jsonify(rows)

@app.get('/user/savings-accounts')
def list_user_savings_accounts():
    if _require_login('user'):
        return _require_login('user')
    uid = session.get('user_id')
    customer_row = query_all('SELECT customer_id FROM user_customer WHERE user_id=%s', (uid,))
    if not customer_row:
        return jsonify([])
    customer_id = customer_row[0]['customer_id']
    rows = query_all("""
        SELECT a.id, a.account_no, a.balance
        FROM account a
        JOIN account_customer ac ON a.id = ac.account_id
        WHERE ac.customer_id = %s AND a.type = 'savings' AND (a.closed_at IS NULL)
        ORDER BY a.id
    """, (customer_id,))
    return jsonify(rows)

@app.get('/user/loans/open')
def list_user_open_loans():
    if _require_login('user'):
        return _require_login('user')
    uid = session.get('user_id')
    customer_row = query_all('SELECT customer_id FROM user_customer WHERE user_id=%s', (uid,))
    if not customer_row:
        return jsonify([])
    customer_id = customer_row[0]['customer_id']
    loans = query_all("""
        SELECT l.id, l.loan_no, l.amount, l.status, l.end_date, l.interest_rate, l.start_date
        FROM loan l
        JOIN loan_customer lc ON l.id = lc.loan_id
        WHERE lc.customer_id = %s AND l.status <> 'SETTLED'
        ORDER BY l.id
    """, (customer_id,))
    result = []
    for l in loans:
        days = 0
        if l.get('start_date'):
            days = max((datetime.date.today() - l['start_date']).days, 0)
        rate = float(l.get('interest_rate') or 0)
        principal = float(l['amount'])
        accrued = round(principal * rate * days / 365.0, 2)
        repaid_rows = query_all('SELECT COALESCE(SUM(amount),0) AS total FROM repayment WHERE loan_id=%s', (l['id'],))
        repaid_total = float(repaid_rows[0]['total']) if repaid_rows and repaid_rows[0] else 0.0
        remain = round(principal + accrued - repaid_total, 2)
        if remain < 0:
            remain = 0.0
        result.append({'loan_id': l['id'], 'loan_no': l['loan_no'], 'principal_amount': round(principal,2), 'remaining_amount': remain, 'end_date': l.get('end_date')})
    return jsonify(result)

@app.get('/user/loan/<int:loan_id>/schedule')
def get_user_loan_schedule(loan_id):
    if _require_login('user'):
        return _require_login('user')
    uid = session.get('user_id')
    customer_row = query_all('SELECT customer_id FROM user_customer WHERE user_id=%s', (uid,))
    if not customer_row:
        return jsonify([])
    customer_id = customer_row[0]['customer_id']
    owned = query_all('SELECT 1 FROM loan_customer WHERE loan_id=%s AND customer_id=%s', (loan_id, customer_id))
    if not owned:
        return jsonify([])
    rows = query_all('SELECT period_no, due_date, principal_due, interest_due, status FROM repayment_schedule WHERE loan_id=%s ORDER BY period_no', (loan_id,))
    return jsonify(rows)

@app.get('/user/loan/<int:loan_id>/repayments')
def get_user_loan_repayments(loan_id):
    if _require_login('user'):
        return _require_login('user')
    uid = session.get('user_id')
    customer_row = query_all('SELECT customer_id FROM user_customer WHERE user_id=%s', (uid,))
    if not customer_row:
        return jsonify([])
    customer_id = customer_row[0]['customer_id']
    owned = query_all('SELECT 1 FROM loan_customer WHERE loan_id=%s AND customer_id=%s', (loan_id, customer_id))
    if not owned:
        return jsonify([])
    rows = query_all("""
        SELECT r.paid_at, r.amount, a.account_no
        FROM repayment r
        JOIN savings_account sa ON r.savings_account_id = sa.account_id
        JOIN account a ON sa.account_id = a.id
        WHERE r.loan_id = %s
        ORDER BY r.paid_at DESC
    """, (loan_id,))
    return jsonify(rows)

@app.post('/user/repay')
def user_repay():
    if _require_login('user'):
        return _require_login('user')
    data = request.get_json(force=True)
    loan_id = data.get('loan_id')
    savings_account_id = data.get('savings_account_id')
    amount = data.get('amount')
    confirm = data.get('confirm')
    try:
        loan_id = int(loan_id)
        savings_account_id = int(savings_account_id)
        amount = float(amount)
    except Exception:
        return jsonify({'ok': False, 'error': 'invalid_params'}), 400
    if not loan_id or not savings_account_id or amount <= 0:
        return jsonify({'ok': False, 'error': 'invalid_params'}), 400
    if not confirm:
        return jsonify({'ok': False, 'error': 'need_confirm'}), 400
    uid = session.get('user_id')
    customer_row = query_all('SELECT customer_id FROM user_customer WHERE user_id=%s', (uid,))
    if not customer_row:
        return jsonify({'ok': False, 'error': 'no_customer'}), 400
    customer_id = customer_row[0]['customer_id']
    conn = begin_transaction()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute('SELECT id, type, balance, closed_at FROM account WHERE id=%s FOR UPDATE', (savings_account_id,))
        acc = cur.fetchone()
        if not acc or acc['type'] != 'savings' or acc.get('closed_at'):
            raise Exception('invalid_account')
        cur.execute('SELECT 1 FROM account_customer WHERE account_id=%s AND customer_id=%s', (savings_account_id, customer_id))
        if not cur.fetchone():
            raise Exception('not_owner')
        cur.execute('SELECT 1 FROM savings_account WHERE account_id=%s', (savings_account_id,))
        if not cur.fetchone():
            raise Exception('invalid_account')
        cur.execute('SELECT 1 FROM loan_customer WHERE loan_id=%s AND customer_id=%s', (loan_id, customer_id))
        if not cur.fetchone():
            raise Exception('not_owner')
        cur.execute('SELECT id, amount, status, interest_rate, start_date FROM loan WHERE id=%s FOR UPDATE', (loan_id,))
        loan_row = cur.fetchone()
        if not loan_row:
            raise Exception('loan_not_found')
        if loan_row['status'] == 'SETTLED':
            raise Exception('settled')
        days = 0
        if loan_row.get('start_date'):
            days = max((datetime.date.today() - loan_row['start_date']).days, 0)
        rate = float(loan_row.get('interest_rate') or 0)
        principal = float(loan_row['amount'])
        accrued = round(principal * rate * days / 365.0, 2)
        cur.execute('SELECT COALESCE(SUM(amount),0) FROM repayment WHERE loan_id=%s', (loan_id,))
        repaid_total = float(cur.fetchone()[0] or 0.0)
        outstanding = round(principal + accrued - repaid_total, 2)
        pay = round(float(amount), 2)
        tol = 0.005
        if pay <= 0:
            raise Exception('amount_range')
        if pay > outstanding + tol:
            raise Exception('amount_range')
        if pay > outstanding:
            pay = outstanding
        if float(acc['balance']) < float(pay):
            raise Exception('insufficient')
        new_balance = round(float(acc['balance']) - float(pay), 2)
        cur.execute('UPDATE account SET balance=%s WHERE id=%s', (new_balance, savings_account_id))
        bn = secrets.token_hex(6)
        cur.execute("""
            INSERT INTO business(business_type, customer_id, status, remark)
            VALUES(%s, %s, %s, %s) RETURNING id
        """, ('REPAYMENT', customer_id, 'COMPLETED', ''))
        business_id = cur.fetchone()['id']
        cur.execute("""
            INSERT INTO repayment(loan_id, batch_no, paid_at, amount, savings_account_id)
            VALUES(%s, %s, %s, %s, %s)
        """, (loan_id, bn, datetime.date.today(), pay, savings_account_id))
        cur.execute("""
            INSERT INTO transaction(account_id, business_id, txn_type, amount, balance_after, remark)
            VALUES(%s, %s, %s, %s, %s, %s)
        """, (savings_account_id, business_id, 'REPAYMENT', pay, new_balance, ''))
        new_outstanding = round(outstanding - pay, 2)
        if new_outstanding <= 0:
            cur.execute('UPDATE loan SET status=%s, settled_at=NOW() WHERE id=%s', ('SETTLED', loan_id))
        else:
            try:
                cur.execute('UPDATE loan SET outstanding_balance=%s WHERE id=%s', (new_outstanding, loan_id))
            except Exception:
                pass
        conn.commit()
        cur.close()
        conn.close()
        execute('INSERT INTO activity_log(user_id, action, meta) VALUES(%s,%s,%s)', (uid, 'repayment', json.dumps({'loan_id': loan_id, 'paid_amount': float(pay), 'account_id': savings_account_id})))
        return jsonify({'ok': True, 'balance': new_balance, 'paid_amount': float(pay)})
    except Exception as e:
        try:
            if conn and not conn.closed:
                conn.rollback()
        except Exception:
            pass
        try:
            if cur:
                cur.close()
        except Exception:
            pass
        try:
            if conn:
                conn.close()
        except Exception:
            pass
        if is_db_error(e):
            s, c, m = map_db_error(e)
            return jsonify({'ok': False, 'error': m, 'code': c}), s
        err = str(e)
        msg_map = {
            'invalid_params': '参数不完整或格式不正确',
            'need_confirm': '缺少确认标记',
            'invalid_account': '账户无效或已注销',
            'not_owner': '账户或贷款不属于当前用户',
            'loan_not_found': '贷款不存在',
            'settled': '贷款已结清',
            'amount_range': '还款金额不合法或超过剩余应还额',
            'insufficient': '账户余额不足'
        }
        return jsonify({'ok': False, 'error': err, 'message': msg_map.get(err, err)}), 400

@app.get('/user/transactions')
def list_user_transactions():
    """列出用户的交易记录"""
    if _require_login('user'):
        return _require_login('user')
    
    uid = session.get('user_id')
    customer_row = query_all('SELECT customer_id FROM user_customer WHERE user_id=%s', (uid,))
    if not customer_row:
        return jsonify([])
    
    customer_id = customer_row[0]['customer_id']
    rows = query_all("""
        SELECT t.id, t.txn_type, t.amount, t.balance_after, t.created_at, t.remark,
               a.account_no
        FROM transaction t
        JOIN account a ON t.account_id = a.id
        JOIN account_customer ac ON a.id = ac.account_id
        WHERE ac.customer_id = %s
        ORDER BY t.created_at DESC
        LIMIT 50
    """, (customer_id,))
    
    return jsonify(rows)

@app.get('/admin/closed-accounts')
def admin_get_closed_accounts():
    """获取已关闭账户列表及存活时间信息"""
    if _require_login('admin'):
        return _require_login('admin')
    
    try:
        rows = query_all('''
            SELECT a.id, a.account_no, a.closed_at,
                   EXTRACT(EPOCH FROM (NOW() - a.closed_at))/3600 as survive_hours
            FROM account a
            WHERE a.type = 'closed' AND a.closed_at IS NOT NULL
            ORDER BY a.closed_at DESC
        ''')
        
        # 处理数据格式
        result = []
        for row in rows:
            survive_hours = row['survive_hours']
            status = '待清理' if survive_hours > 24 else '保留中'
            
            result.append({
                'id': row['id'],
                'account_no': row['account_no'],
                'closed_at': row['closed_at'].strftime('%Y-%m-%d %H:%M:%S') if row['closed_at'] else '',
                'survive_time': f'{survive_hours:.2f} 小时',
                'status': status
            })
        
        return jsonify(result if result else [])
    except Exception as e:
        print(f"获取已关闭账户列表失败: {e}")  # 添加日志以便调试
        return jsonify([]), 500

@app.get('/admin/pending-close-accounts')
def admin_get_pending_close_accounts():
    """获取待审批的账户注销申请"""
    if _require_login('admin'):
        return _require_login('admin')
    
    try:
        rows = query_all('''
            SELECT b.id as business_id, b.customer_id, b.remark, b.created_at, c.name as customer_name
            FROM business b
            JOIN customer c ON b.customer_id = c.id
            WHERE b.business_type = 'CLOSE_ACCOUNT' AND b.status = 'PENDING'
            ORDER BY b.created_at DESC
        ''')
        
        return jsonify(rows)
    except Exception as e:
        if is_db_error(e):
            s, c, m = map_db_error(e)
            return jsonify({'ok': False, 'error': m, 'code': c}), s
        return jsonify({'ok': False, 'error': str(e)}), 400

@app.post('/admin/approve-close-account')
def admin_approve_close_account():
    """管理员审批账户注销申请"""
    if _require_login('admin'):
        return _require_login('admin')
    
    data = request.get_json(force=True)
    business_id = data.get('business_id')
    action = data.get('action')  # APPROVE or REJECT
    remark = data.get('remark', '')
    
    if not business_id or action not in ['APPROVE', 'REJECT']:
        return jsonify({'ok': False, 'error': 'invalid_params'}), 400
    
    # 获取管理员ID
    admin_id = session.get('user_id')
    
    try:
        conn = get_conn()
        cur = conn.cursor()
        
        # 获取业务单信息
        cur.execute('''
            SELECT b.id, b.customer_id, b.remark
            FROM business b
            WHERE b.id = %s AND b.business_type = 'CLOSE_ACCOUNT' AND b.status = 'PENDING'
        ''', (business_id,))
        
        business = cur.fetchone()
        if not business:
            raise Exception("未找到待审批的账户注销申请")
        
        if action == 'APPROVE':
            # 提取账户ID（从备注中提取）
            import re
            match = re.search(r'申请注销账户 (\d+)', business[2])
            if not match:
                raise Exception("无法解析账户信息")
            
            account_id = int(match.group(1))
            
            # 检查账户是否存在
            cur.execute('SELECT id FROM account WHERE id = %s', (account_id,))
            account = cur.fetchone()
            if not account:
                raise Exception("账户不存在")
            
            # 更新账户状态为CLOSED并记录关闭时间
            cur.execute("UPDATE account SET type = 'closed', closed_at = NOW() WHERE id = %s", (account_id,))
            
            # 更新业务单状态
            cur.execute('''
                UPDATE business 
                SET status = 'COMPLETED', operator_id = %s, remark = CONCAT(remark, %s)
                WHERE id = %s
            ''', (admin_id, f'; 已批准，管理员ID: {admin_id}' + (f'，备注: {remark}' if remark else ''), business_id))
            
            result_msg = "账户注销申请已批准，账户已注销"
        else:  # REJECT
            # 更新业务单状态
            cur.execute('''
                UPDATE business 
                SET status = 'REJECTED', operator_id = %s, remark = CONCAT(remark, %s)
                WHERE id = %s
            ''', (admin_id, f'; 已拒绝，管理员ID: {admin_id}' + (f'，备注: {remark}' if remark else ''), business_id))
            
            result_msg = "账户注销申请已拒绝"
        
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({'ok': True, 'message': result_msg})
        
    except Exception as e:
        conn.rollback()
        cur.close()
        conn.close()
        if is_db_error(e):
            s, c, m = map_db_error(e)
            return jsonify({'ok': False, 'error': m, 'code': c}), s
        return jsonify({'ok': False, 'error': str(e)}), 400

def cleanup_scheduler():
    """定期执行清理任务的调度器"""
    while True:
        # 每小时执行一次清理任务
        time.sleep(3600)  # 1小时 = 3600秒
        cleanup_expired_data()

if __name__ == '__main__':
    # 启动清理任务调度器线程
    cleanup_thread = threading.Thread(target=cleanup_scheduler, daemon=True)
    cleanup_thread.start()
    
    use_waitress = os.getenv('USE_WAITRESS', '1') == '1'
    if use_waitress:
        try:
            from waitress import serve
            serve(app, host='127.0.0.1', port=5000)
        except Exception:
            app.run(host='127.0.0.1', port=5000, use_reloader=False)
    else:
        app.run(host='127.0.0.1', port=5000, use_reloader=False)

def cleanup_expired_data():
    """
    清理过期数据
    1. 删除超过24小时的已关闭账户
    2. 删除超过30天的用户活动日志
    """
    try:
        # 删除超过24小时的已关闭账户
        execute("""
            DELETE FROM account 
            WHERE type = 'closed' 
            AND closed_at < NOW() - INTERVAL '24 hours'
        """)
        
        # 删除超过30天的用户活动日志
        execute("""
            DELETE FROM activity_log 
            WHERE created_at < NOW() - INTERVAL '30 days'
        """)
        
        # 删除超过30天的管理员活动日志
        execute("""
            DELETE FROM admin_activity_log 
            WHERE created_at < NOW() - INTERVAL '30 days'
        """)
        
        print(f"[{datetime.datetime.now()}] Cleaned up expired data")
    except Exception as e:
        print(f"[{datetime.datetime.now()}] Error cleaning up expired data: {e}")
