from flask import Flask, request, jsonify, send_from_directory
from db import get_conn, init_db, execute, query_all, get_config
import os

app = Flask(__name__)

@app.get('/')
def index():
    return send_from_directory('templates', 'index.html')

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
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.get('/branches')
def list_branches():
    rows = query_all('SELECT id, union_no, name, city FROM branch ORDER BY id')
    return jsonify(rows)

@app.post('/branches')
def create_branch():
    data = request.get_json(force=True)
    union_no = data.get('union_no')
    name = data.get('name')
    city = data.get('city')
    execute('INSERT INTO branch(union_no, name, city) VALUES(%s,%s,%s)', (union_no, name, city))
    return jsonify({"ok": True})

@app.get('/employees')
def list_employees():
    rows = query_all('SELECT id, name, phone, hire_date, manager_id FROM employee ORDER BY id')
    return jsonify(rows)

@app.post('/employees')
def create_employee():
    data = request.get_json(force=True)
    name = data.get('name')
    phone = data.get('phone')
    hire_date = data.get('hire_date')
    manager_id = data.get('manager_id')
    execute('INSERT INTO employee(name, phone, hire_date, manager_id) VALUES(%s,%s,%s,%s)', (name, phone, hire_date, manager_id))
    return jsonify({"ok": True})

@app.post('/dependents')
def create_dependent():
    data = request.get_json(force=True)
    employee_id = data.get('employee_id')
    name = data.get('name')
    relationship = data.get('relationship')
    execute('INSERT INTO dependent(employee_id, name, relationship) VALUES(%s,%s,%s)', (employee_id, name, relationship))
    return jsonify({"ok": True})

@app.get('/customers')
def list_customers():
    rows = query_all('SELECT id, name, identity_no, city, street, assistant_employee_id FROM customer ORDER BY id')
    return jsonify(rows)

@app.post('/customers')
def create_customer():
    data = request.get_json(force=True)
    name = data.get('name')
    identity_no = data.get('identity_no')
    city = data.get('city')
    street = data.get('street')
    assistant_employee_id = data.get('assistant_employee_id')
    execute('INSERT INTO customer(name, identity_no, city, street, assistant_employee_id) VALUES(%s,%s,%s,%s,%s)', (name, identity_no, city, street, assistant_employee_id))
    return jsonify({"ok": True})

@app.get('/accounts')
def list_accounts():
    rows = query_all('SELECT a.id, a.account_no, a.created_at, a.balance, a.type, s.interest_rate, c.overdraft_limit FROM account a LEFT JOIN savings_account s ON s.account_id = a.id LEFT JOIN checking_account c ON c.account_id = a.id ORDER BY a.id')
    return jsonify(rows)

@app.post('/accounts')
def create_account():
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
    data = request.get_json(force=True)
    account_id = data.get('account_id')
    customer_id = data.get('customer_id')
    execute('INSERT INTO account_customer(account_id, customer_id) VALUES(%s,%s) ON CONFLICT DO NOTHING', (account_id, customer_id))
    return jsonify({"ok": True})

@app.post('/account_access')
def update_access():
    data = request.get_json(force=True)
    account_id = data.get('account_id')
    customer_id = data.get('customer_id')
    date = data.get('date')
    execute('INSERT INTO account_customer(account_id, customer_id, last_access_date) VALUES(%s,%s,%s) ON CONFLICT (account_id, customer_id) DO UPDATE SET last_access_date = EXCLUDED.last_access_date', (account_id, customer_id, date))
    return jsonify({"ok": True})

@app.get('/loans')
def list_loans():
    rows = query_all('SELECT id, loan_no, amount, branch_id FROM loan ORDER BY id')
    return jsonify(rows)

@app.post('/loans')
def create_loan():
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
    rows = query_all('SELECT id, loan_id, batch_no, paid_at, amount, savings_account_id FROM repayment ORDER BY id')
    return jsonify(rows)

@app.post('/repayments')
def create_repayment():
    data = request.get_json(force=True)
    loan_id = data.get('loan_id')
    batch_no = data.get('batch_no')
    paid_at = data.get('paid_at')
    amount = data.get('amount')
    savings_account_id = data.get('savings_account_id')
    execute('INSERT INTO repayment(loan_id, batch_no, paid_at, amount, savings_account_id) VALUES(%s,%s,%s,%s,%s)', (loan_id, batch_no, paid_at, amount, savings_account_id))
    return jsonify({"ok": True})

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
