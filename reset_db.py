#!/usr/bin/env python3
"""
数据库重置脚本 - 彻底清除数据库中的所有对象
"""

import psycopg2
import psycopg2.extras
import json
import os
import traceback
import sys

def get_config():
    """读取数据库配置，与db.py保持一致的配置加载方式"""
    try:
        # 使用绝对路径加载配置文件
        path = os.path.join(os.path.dirname(__file__), 'config.local.json')
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
                # 确保返回的配置包含所有必要的键
                return {
                    "host": cfg.get('host', 'localhost'),
                    "port": cfg.get('port', 5432),
                    "database": cfg.get('database', 'postgres'),
                    "user": cfg.get('user', 'postgres'),
                    "password": cfg.get('password', '')
                }
        else:
            print(f"配置文件 {path} 不存在，使用默认配置")
            return {
                "host": "localhost",
                "port": 5432,
                "database": "postgres",
                "user": "postgres",
                "password": ""
            }
    except Exception as e:
        print(f"加载配置文件时出错: {e}")
        return {
            "host": "localhost",
            "port": 5432,
            "database": "postgres",
            "user": "postgres",
            "password": ""
        }

def reset_database():
    """重置数据库 - 彻底清除public schema中的所有对象并重新创建"""
    cfg = get_config()
    
    try:
        print(f"正在连接到数据库: {cfg['database']} @ {cfg['host']}:{cfg['port']}")
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
        
        print("\n开始重置数据库...")
        
        # 方法1: 使用DROP SCHEMA CASCADE + CREATE SCHEMA，这是最彻底的方法
        try:
            print("\n方法1: 使用DROP SCHEMA CASCADE方式重置数据库...")
            
            # 先检查是否有public schema
            cur.execute("SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname = 'public')")
            if cur.fetchone()[0]:
                print("  正在删除public schema及其所有对象...")
                cur.execute("DROP SCHEMA IF EXISTS public CASCADE")
                print("  正在重新创建public schema...")
                cur.execute("CREATE SCHEMA public")
                
                # 确保public schema的权限正确
                print("  正在设置public schema权限...")
                cur.execute("GRANT ALL ON SCHEMA public TO postgres")
                cur.execute("GRANT ALL ON SCHEMA public TO public")
            else:
                print("  public schema不存在，正在创建...")
                cur.execute("CREATE SCHEMA public")
                cur.execute("GRANT ALL ON SCHEMA public TO postgres")
                cur.execute("GRANT ALL ON SCHEMA public TO public")
            
            print("  方法1执行成功!")
            
        except Exception as e:
            print(f"  方法1执行失败: {e}")
            print("\n方法2: 尝试使用传统方式逐步删除所有对象...")
            
            # 方法2: 传统方式 - 逐步删除各种对象
            # 删除所有触发器
            print("  删除所有触发器...")
            cur.execute("""
                SELECT trigger_name, event_object_table 
                FROM information_schema.triggers 
                WHERE trigger_schema = 'public';
            """)
            triggers = cur.fetchall()
            for trigger in triggers:
                trigger_name, table_name = trigger
                cur.execute(f'DROP TRIGGER IF EXISTS {trigger_name} ON {table_name} CASCADE;')
                print(f"    删除触发器: {trigger_name} on {table_name}")
            
            # 删除所有外键约束
            print("\n  删除外键约束...")
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
                print(f"    删除外键: {fk_name} on {table_name}")
            
            # 删除所有其他约束
            print("\n  删除其他约束...")
            cur.execute("""
                SELECT conname, conrelid::regclass 
                FROM pg_constraint 
                WHERE contype IN ('c', 'p', 'u', 't') 
                AND connamespace = 'public'::regnamespace;
            """)
            other_constraints = cur.fetchall()
            for constraint in other_constraints:
                constraint_name, table_name = constraint
                cur.execute(f'ALTER TABLE {table_name} DROP CONSTRAINT IF EXISTS {constraint_name} CASCADE;')
                print(f"    删除约束: {constraint_name} on {table_name}")
            
            # 删除所有视图
            print("\n  删除所有视图...")
            cur.execute("""
                SELECT table_name 
                FROM information_schema.views 
                WHERE table_schema = 'public';
            """)
            views = cur.fetchall()
            for view in views:
                view_name = view[0]
                cur.execute(f'DROP VIEW IF EXISTS {view_name} CASCADE;')
                print(f"    删除视图: {view_name}")
            
            # 删除所有表
            print("\n  删除所有表...")
            cur.execute("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_type = 'BASE TABLE';
            """)
            tables = cur.fetchall()
            for table in tables:
                table_name = table[0]
                cur.execute(f'DROP TABLE IF EXISTS {table_name} CASCADE;')
                print(f"    删除表: {table_name}")
            
            # 删除所有函数和存储过程
            print("\n  删除所有函数和存储过程...")
            cur.execute("""
                SELECT n.nspname, p.proname 
                FROM pg_proc p 
                JOIN pg_namespace n ON p.pronamespace = n.oid 
                WHERE n.nspname = 'public';
            """)
            functions = cur.fetchall()
            for func in functions:
                schema_name, func_name = func
                cur.execute(f'DROP FUNCTION IF EXISTS {schema_name}.{func_name} CASCADE;')
                print(f"    删除函数: {schema_name}.{func_name}")
            
            # 删除所有自定义类型（包括枚举）
            print("\n  删除所有自定义类型...")
            cur.execute("""
                SELECT typname 
                FROM pg_type 
                WHERE typnamespace = 'public'::regnamespace 
                AND typtype IN ('e', 'c', 'd', 'r')
                AND typname NOT IN ('bool', 'bytea', 'char', 'int8', 'int2', 'int4', 'regproc', 'text', 'oid', 'tid', 'xid', 'cid', 'xml', 'json', 'jsonb');
            """)
            types = cur.fetchall()
            for type_row in types:
                type_name = type_row[0]
                cur.execute(f'DROP TYPE IF EXISTS {type_name} CASCADE;')
                print(f"    删除类型: {type_name}")
            
            # 删除所有序列
            print("\n  删除所有序列...")
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
                print(f"    删除序列: {seq_name}")
        
        print("\n数据库重置完成！所有数据库对象已清除")
        
        # 验证数据库是否已清空
        cur.execute("""
            SELECT count(*) 
            FROM information_schema.tables 
            WHERE table_schema = 'public';
        """)
        table_count = cur.fetchone()[0]
        
        print(f"\n验证结果: public schema中剩余 {table_count} 个表")
        
    except psycopg2.Error as e:
        print(f"\n数据库错误: {e}")
        return False
    except Exception as e:
        print(f"\n错误: {e}")
        return False
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
    
    return True

def show_database_objects():
    """显示当前数据库中的所有对象，包括表、视图、函数等"""
    cfg = get_config()
    
    try:
        print(f"\n正在连接数据库获取对象信息: {cfg['database']} @ {cfg['host']}:{cfg['port']}")
        conn = psycopg2.connect(
            host=cfg["host"],
            port=cfg["port"],
            database=cfg["database"],
            user=cfg["user"],
            password=cfg["password"]
        )
        cur = conn.cursor()
        
        # 显示表信息
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
            print(f"\n1. 表 ({len(tables)} 个):")
            print("表名\t\t\t列数")
            print("-" * 40)
            for table in tables:
                table_name, column_count = table
                print(f"{table_name:<20}\t{column_count}")
        else:
            print("\n1. 表: 没有找到表")
        
        # 显示视图信息
        cur.execute("""
            SELECT table_name 
            FROM information_schema.views 
            WHERE table_schema = 'public'
            ORDER BY table_name;
        """)
        
        views = cur.fetchall()
        if views:
            print(f"\n2. 视图 ({len(views)} 个):")
            for view in views:
                print(f"  - {view[0]}")
        else:
            print("\n2. 视图: 没有找到视图")
        
        # 显示自定义类型信息
        cur.execute("""
            SELECT typname 
            FROM pg_type 
            WHERE typnamespace = 'public'::regnamespace 
            AND typtype IN ('e', 'c', 'd', 'r')
            ORDER BY typname;
        """)
        
        types = cur.fetchall()
        if types:
            print(f"\n3. 自定义类型 ({len(types)} 个):")
            for type_row in types:
                print(f"  - {type_row[0]}")
        else:
            print("\n3. 自定义类型: 没有找到自定义类型")
        
        # 显示函数信息
        cur.execute("""
            SELECT n.nspname, p.proname 
            FROM pg_proc p 
            JOIN pg_namespace n ON p.pronamespace = n.oid 
            WHERE n.nspname = 'public'
            ORDER BY p.proname;
        """)
        
        functions = cur.fetchall()
        if functions:
            print(f"\n4. 函数和存储过程 ({len(functions)} 个):")
            for func in functions[:10]:  # 只显示前10个
                schema_name, func_name = func
                print(f"  - {schema_name}.{func_name}")
            if len(functions) > 10:
                print(f"    ... 以及其他 {len(functions) - 10} 个函数")
        else:
            print("\n4. 函数和存储过程: 没有找到函数")
            
    except psycopg2.Error as e:
        print(f"\n数据库连接错误: {e}")
        print(f"错误详情: {str(e).strip()}")
    except Exception as e:
        print(f"\n显示数据库对象信息时出错: {e}")
        print("错误堆栈:")
        traceback.print_exc(file=sys.stdout)
    finally:
        if 'cur' in locals() and cur:
            cur.close()
        if 'conn' in locals() and conn:
            conn.close()

def main():
    """主函数"""
    try:
        print("=== 数据库重置工具 ===")
        print("\n警告: 此操作将删除数据库中的所有对象和数据！")
        print("请确保您已经备份了重要数据。")
        
        # 显示当前数据库对象
        show_database_objects()
        
        # 获取用户确认
        response = input("\n确定要重置数据库吗? 输入 'yes' 确认: ")
        if response.lower() == 'yes':
            print("\n开始执行数据库重置操作...")
            if reset_database():
                print("\n数据库重置成功！")
                # 重置后再次显示数据库状态进行验证
                print("\n=== 重置后的数据库状态 ===")
                show_database_objects()
            else:
                print("\n数据库重置失败！")
                print("请检查错误信息并手动验证数据库状态。")
        else:
            print("操作已取消")
    except KeyboardInterrupt:
        print("\n\n操作被用户中断")
        sys.exit(1)
    except Exception as e:
        print(f"\n程序执行出错: {e}")
        print("错误堆栈:")
        traceback.print_exc(file=sys.stdout)
        sys.exit(1)

if __name__ == '__main__':
    main()