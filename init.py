#!/usr/bin/env python3
"""
银行数据库初始化脚本
用于初始化银行管理系统的数据库，包括：
1. 创建所有数据库表结构
2. 创建默认管理员账户
3. 验证数据库连接
"""

import os
import sys
import json
import psycopg2
import psycopg2.extras
from datetime import datetime
import hashlib
import secrets

def load_config():
    """加载数据库配置"""
    config_path = os.path.join(os.path.dirname(__file__), 'config.local.json')
    if os.path.exists(config_path):
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def get_db_config():
    """获取数据库连接配置"""
    cfg = load_config()
    host = cfg.get('host', os.getenv('PGHOST', 'localhost'))
    port = int(cfg.get('port', os.getenv('PGPORT', '5432')))
    dbname = cfg.get('database', os.getenv('PGDATABASE', 'postgres'))
    user = cfg.get('user', os.getenv('PGUSER', 'postgres'))
    password = cfg.get('password', os.getenv('PGPASSWORD', ''))
    return {
        "host": host,
        "port": port,
        "database": dbname,
        "user": user,
        "password": password
    }

def hash_password(password, salt=None):
    """密码哈希函数"""
    s = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), s, 120000)
    return dk, s

def test_connection(config):
    """测试数据库连接"""
    try:
        conn = psycopg2.connect(
            host=config['host'],
            port=config['port'],
            dbname=config['database'],
            user=config['user'],
            password=config['password']
        )
        conn.close()
        return True
    except Exception as e:
        print(f"❌ 数据库连接失败: {e}")
        return False

def execute_schema(conn, schema_path):
    """执行SQL模式文件"""
    try:
        with open(schema_path, 'r', encoding='utf-8') as f:
            sql = f.read()
        
        conn.autocommit = True
        cur = conn.cursor()
        cur.execute(sql)
        cur.close()
        return True
    except Exception as e:
        print(f"❌ 执行模式文件失败: {e}")
        return False

def create_admin_user(conn):
    """创建默认管理员用户到admin_user表"""
    try:
        cur = conn.cursor()
        
        # 检查管理员是否已存在（在admin_user表中）
        cur.execute('SELECT 1 FROM admin_user WHERE username = %s', ('administrator',))
        if cur.fetchone():
            print("ℹ️  管理员账户已存在，跳过创建")
            cur.close()
            return True
        
        # 创建管理员密码哈希
        password_hash, password_salt = hash_password('123456')
        
        # 插入管理员用户到admin_user表
        cur.execute('''
            INSERT INTO admin_user (username, password_hash, password_salt, created_at)
            VALUES (%s, %s, %s, %s)
        ''', ('administrator', password_hash, password_salt, datetime.now()))
        
        conn.commit()
        cur.close()
        print("✅ 管理员账户创建成功")
        return True
    except Exception as e:
        conn.rollback()
        print(f"❌ 创建管理员账户失败: {e}")
        return False

def verify_tables(conn):
    """验证关键表是否创建成功"""
    required_tables = [
        'app_user', 'admin_user', 'customer', 'employee', 'branch', 'account',
        'loan', 'savings_account', 'checking_account', 'user_customer'
    ]
    
    try:
        cur = conn.cursor()
        missing_tables = []
        
        for table in required_tables:
            cur.execute('''
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.tables 
                    WHERE table_schema = 'public' AND table_name = %s
                )
            ''', (table,))
            exists = cur.fetchone()[0]
            if not exists:
                missing_tables.append(table)
        
        cur.close()
        
        if missing_tables:
            print(f"❌ 缺少表: {', '.join(missing_tables)}")
            return False
        else:
            print("✅ 所有关键表验证通过")
            return True
    except Exception as e:
        print(f"❌ 验证表结构失败: {e}")
        return False

def main():
    """主初始化函数"""
    print("🏦 银行数据库初始化脚本")
    print("=" * 50)
    
    # 获取数据库配置
    config = get_db_config()
    print(f"📋 数据库配置:")
    print(f"   主机: {config['host']}:{config['port']}")
    print(f"   数据库: {config['database']}")
    print(f"   用户: {config['user']}")
    
    # 测试数据库连接
    print("\n🔌 测试数据库连接...")
    if not test_connection(config):
        return False
    print("✅ 数据库连接成功")
    
    # 连接数据库
    try:
        conn = psycopg2.connect(
            host=config['host'],
            port=config['port'],
            dbname=config['database'],
            user=config['user'],
            password=config['password']
        )
        
        # 执行模式文件
        print("\n📊 创建数据库表结构...")
        schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
        if not execute_schema(conn, schema_path):
            conn.close()
            return False
        print("✅ 数据库表结构创建完成")
        
        # 验证表结构
        print("\n🔍 验证表结构...")
        if not verify_tables(conn):
            conn.close()
            return False
        
        # 创建管理员用户
        print("\n👤 创建默认管理员账户...")
        if not create_admin_user(conn):
            conn.close()
            return False
        
        # 最终验证
        print("\n🎯 最终验证...")
        cur = conn.cursor()
        cur.execute('SELECT COUNT(*) FROM admin_user WHERE username = %s', ('administrator',))
        admin_count = cur.fetchone()[0]
        cur.close()
        
        if admin_count > 0:
            print(f"✅ 系统初始化完成！管理员账户数量: {admin_count}")
            print("\n🎉 数据库初始化成功！")
            print("=" * 50)
            print("📋 管理员登录信息:")
            print("   用户名: administrator")
            print("   密码: 123456")
            print("   角色: Admin")
            print("\n💡 您现在可以启动应用并使用管理员账户登录了！")
        else:
            print("❌ 管理员账户创建失败")
            return False
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ 数据库操作失败: {e}")
        return False

if __name__ == "__main__":
    success = main()
    if not success:
        sys.exit(1)