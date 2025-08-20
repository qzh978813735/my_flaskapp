#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""应用启动脚本：先执行数据迁移，然后启动Flask应用"""
import os
import sys
import subprocess
import time

# 添加当前目录到Python路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def run_migration():
    """执行数据迁移"""
    print("开始执行数据迁移...")
    try:
        # 运行数据迁移脚本
        result = subprocess.run(
            [sys.executable, 'migrate_data.py'],
            cwd=os.path.dirname(os.path.abspath(__file__)),
            capture_output=True,
            text=True
        )

        # 打印迁移结果
        print("数据迁移输出:")
        print(result.stdout)
        
        if result.returncode != 0:
            print(f"数据迁移失败: {result.stderr}")
            return False
        
        print("数据迁移成功完成！")
        return True
    except Exception as e:
        print(f"执行数据迁移时发生错误: {e}")
        return False

def start_flask_app():
    """启动Flask应用"""
    print("开始启动Flask应用...")
    try:
        # 启动Flask应用
        process = subprocess.Popen(
            [sys.executable, 'app.py'],
            cwd=os.path.dirname(os.path.abspath(__file__)),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # 等待应用启动
        time.sleep(2)
        print("Flask应用已启动！")
        print("访问地址: http://localhost:5000")
        print("请按Ctrl+C停止应用...")

        # 保持程序运行
        process.wait()
    except KeyboardInterrupt:
        print("正在停止应用...")
        process.terminate()
        print("应用已停止")
    except Exception as e:
        print(f"启动Flask应用时发生错误: {e}")

def main():
    """主函数"""
    # 先执行数据迁移
    if not run_migration():
        print("数据迁移失败，无法启动应用")
        return
    
    # 数据迁移成功后启动应用
    start_flask_app()

if __name__ == '__main__':
    main()