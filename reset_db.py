#!/usr/bin/env python3
"""
数据库重置脚本 - 删除所有表结构，恢复到最初状态
"""

import psycopg2
import psycopg2.extras
import json
import os

def get_config():
    """读取数据库配置"""
    try:
        with open('config.local.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print("配置文件 config.local.json 不存在，使用默认配置")
        return {
            "host": "localhost",
            "port": 5432,
            "database": "bank",
            "user": "postgres",
            "password": ""
        }

def reset_database():
    """重置数据库 - 删除所有表结构"""
    cfg = get_config()
    
    try:
        # 连接到PostgreSQL
        conn = psycopg2.connect(
            host=cfg["host"],
            port=cfg["port"],
            database=cfg["database"],
            user=cfg["user"],
            password=cfg["password"]
        )
        conn.autocommit = True
        cur = conn.cursor()
        
        print("开始重置数据库...")
        
        # 获取所有表名（排除系统表）
        cur.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_type = 'BASE TABLE'
            ORDER BY table_name;
        """)
        
        tables = cur.fetchall()
        
        if not tables:
            print("数据库中没有找到任何表")
            return
            
        print(f"发现 {len(tables)} 个表需要删除:")
        for table in tables:
            print(f"  - {table[0]}")
        
        # 删除所有外键约束
        print("\n删除外键约束...")
        cur.execute("""
            SELECT conname, conrelid::regclass 
            FROM pg_constraint 
            WHERE contype = 'f' 
            AND connamespace = 'public'::regnamespace;
        """)
        
        foreign_keys = cur.fetchall()
        for fk in foreign_keys:
            fk_name, table_name = fk
            cur.execute(f'ALTER TABLE {table_name} DROP CONSTRAINT IF EXISTS {fk_name} CASCADE;')
            print(f"  删除外键: {fk_name} on {table_name}")
        
        # 删除所有表
        print("\n删除所有表...")
        for table in tables:
            table_name = table[0]
            cur.execute(f'DROP TABLE IF EXISTS {table_name} CASCADE;')
            print(f"  删除表: {table_name}")
        
        # 删除所有枚举类型
        print("\n删除自定义类型...")
        cur.execute("""
            SELECT typname 
            FROM pg_type 
            WHERE typtype = 'e' 
            AND typnamespace = 'public'::regnamespace;
        """)
        
        enums = cur.fetchall()
        for enum in enums:
            enum_name = enum[0]
            cur.execute(f'DROP TYPE IF EXISTS {enum_name} CASCADE;')
            print(f"  删除枚举类型: {enum_name}")
        
        # 删除所有序列
        print("\n删除序列...")
        cur.execute("""
            SELECT relname 
            FROM pg_class 
            WHERE relkind = 'S' 
            AND relnamespace = 'public'::regnamespace;
        """)
        
        sequences = cur.fetchall()
        for seq in sequences:
            seq_name = seq[0]
            cur.execute(f'DROP SEQUENCE IF EXISTS {seq_name} CASCADE;')
            print(f"  删除序列: {seq_name}")
        
        print("\n数据库重置完成！所有表结构已删除")
        
    except psycopg2.Error as e:
        print(f"数据库错误: {e}")
        return False
    except Exception as e:
        print(f"错误: {e}")
        return False
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
    
    return True

def show_current_tables():
    """显示当前数据库中的表"""
    cfg = get_config()
    
    try:
        conn = psycopg2.connect(
            host=cfg["host"],
            port=cfg["port"],
            database=cfg["database"],
            user=cfg["user"],
            password=cfg["password"]
        )
        cur = conn.cursor()
        
        cur.execute("""
            SELECT table_name, 
                   (SELECT COUNT(*) FROM information_schema.columns 
                    WHERE table_name = t.table_name AND table_schema = t.table_schema) as column_count
            FROM information_schema.tables t
            WHERE table_schema = 'public' 
            AND table_type = 'BASE TABLE'
            ORDER BY table_name;
        """)
        
        tables = cur.fetchall()
        
        if tables:
            print(f"\n当前数据库中有 {len(tables)} 个表:")
            print("表名\t\t\t列数")
            print("-" * 40)
            for table in tables:
                table_name, column_count = table
                print(f"{table_name:<20}\t{column_count}")
        else:
            print("\n当前数据库中没有表")
            
    except Exception as e:
        print(f"显示表信息时出错: {e}")
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

if __name__ == '__main__':
    print("=== 数据库重置工具 ===")
    print("\n警告: 此操作将删除数据库中的所有表结构和数据！")
    print("请确保您已经备份了重要数据。")
    
    # 显示当前表
    show_current_tables()
    
    response = input("\n确定要重置数据库吗? 输入 'yes' 确认: ")
    if response.lower() == 'yes':
        if reset_database():
            print("\n数据库重置成功！")
        else:
            print("\n数据库重置失败！")
    else:
        print("操作已取消")