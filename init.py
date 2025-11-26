#!/usr/bin/env python3
"""
银行数据库初始化脚本
"""
import traceback
import psycopg2
import psycopg2.extras
import json
import os
from datetime import datetime
import hashlib
import secrets

def _open_conn(cfg):
    """带统一编码设置的连接函数（和 db.py 保持一致）"""
    conn = psycopg2.connect(
        host=cfg["host"],
        port=cfg["port"],
        dbname=cfg["database"],
        user=cfg["user"],
        password=cfg["password"],
        client_encoding="utf8",
    )
    conn.set_client_encoding("UTF8")
    return conn

def get_db_config():
    """获取数据库连接配置"""
    # 加载本地配置文件
    config_path = os.path.join(os.path.dirname(__file__), 'config.local.json')
    config = {}
    if os.path.exists(config_path):
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
    
    # 合并环境变量配置
    host = config.get('host', os.getenv('PGHOST', 'localhost'))
    port = int(config.get('port', os.getenv('PGPORT', '5432')))
    dbname = config.get('database', os.getenv('PGDATABASE', 'postgres'))
    user = config.get('user', os.getenv('PGUSER', 'postgres'))
    password = config.get('password', os.getenv('PGPASSWORD', ''))
    
    return {
        "host": host,
        "port": port,
        "database": dbname,
        "user": user,
        "password": password
    }

def init_database():
    """初始化数据库表结构"""
    print("🏦 银行数据库初始化脚本")
    print("=" * 50)
    
    # 显示数据库配置
    cfg = get_db_config()
    print("📋 数据库配置:")
    print(f"   主机: {cfg['host']}:{cfg['port']}")
    print(f"   数据库: {cfg['database']}")
    print(f"   用户: {cfg['user']}")
    print("")
    
    # 测试数据库连接
    print("🔌 测试数据库连接...")
    try:
        conn = _open_conn(cfg)
        conn.close()
        print("✅ 数据库连接成功")
    except Exception as e:
        #临时测试 
        traceback.print_exc()
        print(f"❌ 数据库连接失败: {e}")
        return False
    
    # 创建数据库表
    print("")
    print("📊 创建数据库表结构...")
    try:
        # 读取SQL文件
        schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
        with open(schema_path, 'r', encoding='utf-8') as f:
            sql_commands = f.read()
        
        # 执行SQL
        conn = _open_conn(cfg)
        conn.autocommit = True
        cur = conn.cursor()
        cur.execute(sql_commands)
        cur.close()
        conn.close()
        print("✅ 数据库表结构创建完成")
        
    except Exception as e:
        print(f"❌ 创建数据库表结构失败: {e}")
        return False
    
    # 验证表结构
    print("")
    print("🔍 验证表结构...")
    try:
        conn = _open_conn(cfg)
        cur = conn.cursor()
        required_tables = [
            'app_user', 'admin_user', 'customer', 'employee', 'branch', 'account',
            'loan', 'savings_account', 'checking_account', 'user_customer'
        ]
        missing_tables = []
        
        for table in required_tables:
            cur.execute("SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = %s)", (table,))
            exists = cur.fetchone()[0]
            if not exists:
                missing_tables.append(table)
        
        cur.close()
        conn.close()
        
        if missing_tables:
            print(f"❌ 缺少表: {', '.join(missing_tables)}")
            return False
        print("✅ 所有关键表验证通过")
        
    except Exception as e:
        print(f"❌ 表结构验证失败: {e}")
        return False
    
    # 创建默认管理员账户
    print("")
    print("👤 创建默认管理员账户...")
    try:
        conn = _open_conn(cfg)
        cur = conn.cursor()
        
        # 检查是否已存在管理员账户
        cur.execute("SELECT COUNT(*) FROM admin_user WHERE username = 'administrator'")
        exists = cur.fetchone()[0]
        
        if exists == 0:
            # 创建管理员账户 (密码: 123456)
            password = '123456'
            salt = secrets.token_bytes(16)
            pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 120000)
            
            cur.execute(
                "INSERT INTO admin_user (username, password_hash, password_salt, created_at) VALUES (%s, %s, %s, %s)",
                ('administrator', pwd_hash, salt, datetime.now())
            )
            conn.commit()
            print("✅ 管理员账户创建成功")
        else:
            print("ℹ️  管理员账户已存在，跳过创建")
        
        cur.close()
        conn.close()
        
    except Exception as e:
        print(f"❌ 管理员账户创建失败: {e}")
        return False
    
    # 最终验证
    print("")
    print("🎯 最终验证...")
    try:
        conn = _open_conn(cfg)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM admin_user")
        count = cur.fetchone()[0]
        cur.close()
        conn.close()
        print(f"✅ 系统初始化完成！管理员账户数量: {count}")
        
    except Exception as e:
        print(f"❌ 最终验证失败: {e}")
        return False
    
    return True

if __name__ == '__main__':
    if init_database():
        print("")
        print("🎉 数据库初始化成功！")
        print("=" * 50)
        print("📋 管理员登录信息:")
        print("   用户名: administrator")
        print("   密码: 123456")
        print("   角色: Admin")
        print("")
        print("💡 您现在可以启动应用并使用管理员账户登录了！")
    else:
        print("")
        print("💥 数据库初始化失败！")
        print("=" * 50)