#!/usr/bin/env python3
"""
BGP Tracer 数据库查看器 (增强版)
================================

用于方便地查看BGP Tracer缓存数据库的内容

使用方法:
1. 交互式模式: python3 db_viewer.py
2. 命令行模式: python3 db_viewer.py <command>

可用命令:
  overview  - 数据库概览
  frequency - 假连接频率缓存 (统计分析结果)
  as-pair   - AS对缓存 (新系统，按日期标识状态，推荐使用)
  stats     - 缓存统计信息
  schema    - 主要表结构
  export    - 导出主要表到CSV
  all       - 显示所有信息 (完整概览)

🚫 已删除功能:
  detection - 假连接检测缓存 (路径缓存，已废弃)

新功能特性:
• 🔗 AS对缓存: 按AS对(as1->as2)存储，更高效精确
• 📊 详细统计: 包含日期标识覆盖率、假连接比例等
• 📅 日期标识: 每条记录都有明确的日期，表明该记录在哪一天有效
• 🎯 状态含义: 清楚标识"某一天+某AS对+是否为假连接"的关系
• 📈 性能指标: 缓存效率和存储优化分析
"""

import sqlite3
import json
import pandas as pd
from pathlib import Path
from datetime import datetime

class DatabaseViewer:
    def __init__(self, db_path):
        self.db_path = Path(db_path)
        if not self.db_path.exists():
            raise FileNotFoundError(f"数据库文件不存在: {db_path}")

        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row  # 允许按列名访问

    def show_overview(self):
        """显示数据库概览"""
        print("🔍 BGP Tracer 缓存数据库查看器 (增强版)")
        print("=" * 60)
        print(f"📁 数据库文件: {self.db_path}")
        print(f"📊 文件大小: {self.db_path.stat().st_size:,} bytes")

        # 获取表信息
        cursor = self.conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()

        print(f"📋 数据表数量: {len(tables)}")
        for table_name, in tables:
            cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
            count = cursor.fetchone()[0]
            icon = "🔗" if table_name == "as_pair_cache" else "📈" if table_name == "fake_connection_cache" else "📊"
            desc = {
                "as_pair_cache": "(新系统 - 高效AS对缓存，按日期标识状态)",
                "fake_connection_cache": "(频率分析缓存，存储统计结果)",
                "fake_connection_detection_cache": "(已废弃 - 路径缓存)"
            }.get(table_name, "")
            print(f"   {icon} {table_name}: {count:,} 条记录 {desc}")

        print("\n💡 提示:")
        print("   • 🔗 as_pair_cache: 新的高效缓存系统，按AS对和日期存储状态")
        print("   • 📈 fake_connection_cache: 频率分析缓存，存储统计结果")
        print("   • 🚫 fake_connection_detection_cache: 路径缓存 (已废弃)")
        print("   • 使用 'as-pair' 查看最新的连接状态缓存")


    def show_fake_connection_frequency_cache(self, limit=10):
        """显示假连接频率缓存"""
        print("\n📊 假连接频率缓存 (fake_connection_cache)")
        print("-" * 60)

        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT fake_connection, date_str, frequency_data, created_at
            FROM fake_connection_cache
            ORDER BY updated_at DESC
            LIMIT ?
        """, (limit,))

        rows = cursor.fetchall()
        if not rows:
            print("⚠️  缓存为空")
            return

        for i, row in enumerate(rows, 1):
            print(f"\n📈 记录 {i}:")
            print(f"   假连接: {row['fake_connection']}")
            print(f"   日期: {row['date_str']}")
            print(f"   创建时间: {row['created_at']}")

            try:
                freq_data = json.loads(row['frequency_data'])
                print(f"   出现次数: {freq_data.get('count', 'N/A')}")
                print(f"   总更新数: {freq_data.get('total_updates', 'N/A')}")
                print(f"   频率比例: {freq_data.get('frequency_ratio', 'N/A'):.4f}")
                print(f"   是否可疑: {'是' if freq_data.get('is_suspicious') else '否'}")
            except json.JSONDecodeError as e:
                print(f"   解析错误: {e}")

    def show_as_pair_cache(self, limit=10):
        """显示新的AS对缓存 (按日期标识有效性)"""
        print("\n🔗 AS对缓存 (as_pair_cache) - 按日期标识连接状态")
        print("-" * 70)

        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT as1, as2, date_str, is_fake, timestamp, asrel_hash, created_at
            FROM as_pair_cache
            ORDER BY timestamp DESC, created_at DESC
            LIMIT ?
        """, (limit,))

        rows = cursor.fetchall()
        if not rows:
            print("⚠️  缓存为空")
            return

        print("📅 格式说明: 日期 | AS对 | 连接状态 | 有效期")
        print("-" * 50)

        for i, row in enumerate(rows, 1):
            fake_status = "❌ 假连接" if row['is_fake'] else "✅ 合法连接"
            valid_date = row['timestamp'] or row['date_str']  # 确保有日期

            print(f"\n🔗 记录 {i}:")
            print(f"   📅 {valid_date} | {row['as1']} → {row['as2']} | {fake_status}")
            print(f"   🎯 含义: {valid_date}这一天，该AS对{('是' if row['is_fake'] else '不是')}假连接")
            print(f"   🔐 AS关系哈希: {row['asrel_hash'][:16]}...")
            print(f"   💾 缓存时间: {row['created_at']}")

    def show_cache_statistics(self):
        """显示缓存统计信息"""
        print("\n📈 缓存统计信息")
        print("-" * 40)

        cursor = self.conn.cursor()

        # 各表记录数
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()

        print("📊 各表记录数:")
        for table_name, in tables:
            cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
            count = cursor.fetchone()[0]
            print(f"   • {table_name}: {count:,} 条")

        # AS对缓存的详细统计
        try:
            cursor.execute("""
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN is_fake = 1 THEN 1 ELSE 0 END) as fake_count,
                    COUNT(DISTINCT date_str) as date_count,
                    COUNT(DISTINCT asrel_hash) as hash_count
                FROM as_pair_cache
            """)
            stats = cursor.fetchone()
            if stats and stats[0] > 0:
                print(f"\n🔗 AS对缓存详情:")
                print(f"   • 总记录数: {stats[0]:,}")
                print(f"   • 假连接数: {stats[1]:,}")
                print(f"   • 合法连接数: {stats[0] - stats[1]:,}")
                print(f"   • 覆盖日期数: {stats[2]}")
                print(f"   • 不同关系哈希数: {stats[3]}")

                # 时间戳统计
                cursor.execute("""
                    SELECT COUNT(*) FROM as_pair_cache
                    WHERE timestamp IS NOT NULL AND timestamp != ''
                """)
                timestamp_count = cursor.fetchone()[0]
                print(f"   • 包含日期标识: {timestamp_count:,} ({timestamp_count/stats[0]*100:.1f}%) - 每条记录都有明确的有效日期")

        except sqlite3.OperationalError:
            print("   (as_pair_cache表不存在或为空)")

        # 频率缓存统计
        try:
            cursor.execute("""
                SELECT COUNT(*) FROM fake_connection_cache
            """)
            freq_count = cursor.fetchone()[0]
            if freq_count > 0:
                print(f"\n📈 频率缓存详情:")
                print(f"   • 分析结果记录数: {freq_count:,}")
        except sqlite3.OperationalError:
            pass

    def export_to_csv(self, table_name, output_file):
        """导出表到CSV文件"""
        try:
            df = pd.read_sql_query(f"SELECT * FROM {table_name}", self.conn)
            df.to_csv(output_file, index=False)
            print(f"✅ 已导出 {len(df)} 条记录到 {output_file}")
        except Exception as e:
            print(f"❌ 导出失败: {e}")

    def show_table_schema(self, table_name):
        """显示表结构"""
        print(f"\n📋 表 '{table_name}' 的结构:")
        cursor = self.conn.cursor()
        cursor.execute(f"PRAGMA table_info({table_name})")
        columns = cursor.fetchall()

        for col in columns:
            col_id, col_name, col_type, not_null, default_val, is_pk = col
            nullable = "NOT NULL" if not_null else "NULL"
            pk = "PRIMARY KEY" if is_pk else ""
            print(f"   {col_name} ({col_type}) {nullable} {pk}".strip())

    def interactive_menu(self):
        """交互式菜单"""
        while True:
            print("\n" + "="*60)
            print("🗄️  BGP Tracer 数据库查看器 (精简版)")
            print("="*60)
            print("1. 数据库概览")
            print("2. 查看假连接频率缓存 (统计分析结果)")
            print("3. 查看AS对缓存 (新系统，按日期标识状态)")
            print("4. 显示缓存统计信息")
            print("5. 显示表结构")
            print("6. 导出到CSV")
            print("7. 退出")

            choice = input("\n请选择操作 (1-7): ").strip()

            if choice == "1":
                self.show_overview()
            elif choice == "2":
                limit = input("显示记录数量 (默认10): ").strip()
                limit = int(limit) if limit.isdigit() else 10
                self.show_fake_connection_frequency_cache(limit)
            elif choice == "3":
                limit = input("显示记录数量 (默认10): ").strip()
                limit = int(limit) if limit.isdigit() else 10
                self.show_as_pair_cache(limit)
            elif choice == "4":
                self.show_cache_statistics()
            elif choice == "5":
                tables = ['fake_connection_cache', 'as_pair_cache', 'fake_connection_detection_cache']
                print("可用表名:", ", ".join(tables))
                print("💡 推荐使用: as_pair_cache (新系统)")
                table = input("输入表名: ").strip()
                if table in tables:
                    self.show_table_schema(table)
                else:
                    print("❌ 无效的表名")
            elif choice == "6":
                tables = ['fake_connection_cache', 'as_pair_cache', 'fake_connection_detection_cache']
                print("可用表名:", ", ".join(tables))
                table = input("输入表名: ").strip()
                output_file = input("输出文件路径 (默认: table_name.csv): ").strip()
                if not output_file:
                    output_file = f"{table}.csv"
                self.export_to_csv(table, output_file)
            elif choice == "7":
                print("👋 再见!")
                break
            else:
                print("❌ 无效选择，请重新输入")

    def close(self):
        """关闭数据库连接"""
        if self.conn:
            self.conn.close()

def main():
    db_path = "/data/bgp_tracer/detectors/cache/fake_conn_cache.db"

    try:
        viewer = DatabaseViewer(db_path)

        # 检查命令行参数
        import sys
        if len(sys.argv) > 1:
            command = sys.argv[1]
            if command == "overview":
                viewer.show_overview()
            elif command == "frequency" or command == "freq":
                viewer.show_fake_connection_frequency_cache()
            elif command == "as-pair" or command == "pair":
                viewer.show_as_pair_cache()
            elif command == "stats":
                viewer.show_cache_statistics()
            elif command == "schema":
                viewer.show_table_schema('as_pair_cache')
                viewer.show_table_schema('fake_connection_cache')
            elif command == "export":
                viewer.export_to_csv('as_pair_cache', 'as_pair_cache.csv')
                viewer.export_to_csv('fake_connection_cache', 'frequency_cache.csv')
            elif command == "all":
                viewer.show_overview()
                viewer.show_cache_statistics()
                viewer.show_as_pair_cache(5)
                viewer.show_fake_connection_frequency_cache(5)
            else:
                print("使用方法: python db_viewer.py [overview|frequency|as-pair|stats|schema|export|all]")
                print("  overview  - 数据库概览")
                print("  frequency - 假连接频率缓存 (统计分析结果)")
                print("  as-pair   - AS对缓存 (新系统，按日期标识状态)")
                print("  stats     - 缓存统计信息")
                print("  schema    - 主要表结构")
                print("  export    - 导出主要表到CSV")
                print("  all       - 显示所有信息")
                viewer.interactive_menu()
        else:
            viewer.interactive_menu()

    except Exception as e:
        print(f"❌ 错误: {e}")
    finally:
        if 'viewer' in locals():
            viewer.close()

if __name__ == "__main__":
    main()
