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

USER_DB_ERROR_MAP = {
    '23505': {'code': 'E_DB_UNIQUE', 'message': '数据已存在，请更换其他输入'},
    '23503': {'code': 'E_DB_FOREIGN_KEY', 'message': '关联数据不存在，请检查输入'},
    '23502': {'code': 'E_DB_NOT_NULL', 'message': '必填字段不能为空'},
    '22001': {'code': 'E_DB_TRUNCATION', 'message': '数据长度超限，请检查后重试'},
    '22P02': {'code': 'E_DB_TYPE', 'message': '输入格式不正确，请重新填写'},
    '23514': {'code': 'E_DB_CHECK', 'message': '输入不符合要求，请检查后重试'},
    '23P01': {'code': 'E_DB_EXCLUSION', 'message': '输入不符合要求，请检查后重试'}
}

def map_db_error(e):
    c = getattr(e, 'pgcode', None)
    if c in USER_DB_ERROR_MAP:
        m = USER_DB_ERROR_MAP[c]
        return 400, m['code'], m['message']
    if c and c.startswith('23'):
        return 400, 'E_DB_CONSTRAINT', '输入不符合要求，请检查后重试'
    if c and c.startswith('22'):
        if c == '22001':
            return 400, 'E_DB_TRUNCATION', '数据长度超限，请检查后重试'
        return 400, 'E_DB_TYPE', '输入格式不正确，请重新填写'
    if isinstance(e, psycopg2.IntegrityError):
        return 400, 'E_DB_CONSTRAINT', '输入不符合要求，请检查后重试'
    return 500, 'E_DB_UNKNOWN', '系统繁忙，请稍后再试'

def is_db_error(e):
    return isinstance(e, psycopg2.Error)
