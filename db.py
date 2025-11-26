import os
import json
import psycopg2
import psycopg2.extras

def _load_cfg():
    path = os.path.join(os.path.dirname(__file__), 'config.local.json')
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def get_config():
    cfg = _load_cfg()
    host = cfg.get('host', os.getenv('PGHOST', 'localhost'))
    port = int(cfg.get('port', os.getenv('PGPORT', '5432')))
    dbname = cfg.get('database', os.getenv('PGDATABASE', 'postgres'))
    user = cfg.get('user', os.getenv('PGUSER', 'postgres'))
    password = cfg.get('password', os.getenv('PGPASSWORD', ''))
    return {"host": host, "port": port, "database": dbname, "user": user, "password": password}

def get_conn():
    c = get_config()
    # 显式指定客户端编码为utf8
    conn = psycopg2.connect(
        host=c['host'],
        port=c['port'],
        dbname=c['database'],
        user=c['user'],
        password=c['password'],
        client_encoding='utf8'
    )
    # 设置连接编码
    conn.set_client_encoding('UTF8')
    return conn

def init_db():
    path = os.path.join(os.path.dirname(__file__), 'schema.sql')
    with open(path, 'r', encoding='utf-8') as f:
        sql = f.read()
    conn = get_conn()
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute(sql)
    cur.close()
    conn.close()

def execute(sql, params=None):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(sql, params or ())
    conn.commit()
    cur.close()
    conn.close()

def execute_with_conn(conn, sql, params=None):
    """在给定连接上执行SQL语句"""
    cur = conn.cursor()
    cur.execute(sql, params or ())
    return cur

def query_all(sql, params=None):
    conn = get_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(sql, params or ())
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows

def query_one(sql, params=None):
    """查询单条记录"""
    conn = get_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(sql, params or ())
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row

def begin_transaction():
    """开始一个事务"""
    conn = get_conn()
    conn.autocommit = False
    return conn