#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""数据迁移脚本：将内存中的示例数据迁移到数据库中"""
import os
import sys
import uuid
from datetime import datetime

# 添加当前目录到Python路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# 导入数据库工具
from db_utils import db

# 导入应用中的全局变量
from app import test_environments, database_configs, db_connections, execution_plans, execution_logs, email_config, email_recipients, mock_interfaces


def migrate_test_environments():
    """迁移测试环境数据"""
    print("开始迁移测试环境数据...")
    try:
        # 先清空表
        db.execute_query("DELETE FROM TEST_ENVIRONMENT")
        
        # 插入数据
        for env in test_environments:
            # 生成UUID
            env_id = env.get('id', str(uuid.uuid4()))
            
            # 准备数据
            data = {
                'id': env_id,
                'name': env['name'],
                'protocol': env['protocol'],
                'domain': env['domain'],
                'description': env.get('description', ''),
                'status': env['status'],
                'created_at': env['created_at'],
                'updated_at': env['updated_at']
            }
            
            # 插入数据
            db.insert('TEST_ENVIRONMENT', data)
            print(f"已迁移测试环境: {env['name']}")
        
        print("测试环境数据迁移完成！")
    except Exception as e:
        print(f"测试环境数据迁移失败: {e}")


def migrate_database_configs():
    """迁移数据库配置数据"""
    print("开始迁移数据库配置数据...")
    try:
        # 先清空表
        db.execute_query("DELETE FROM DATABASE_CONFIG")
        
        # 插入数据
        for config in database_configs:
            # 生成UUID
            config_id = config.get('id', str(uuid.uuid4()))
            
            # 准备数据
            data = {
                'id': config_id,
                'name': config['name'],
                'type': config['type'],
                'description': config.get('description', ''),
                'status': config['status'],
                'created_at': config['created_at'],
                'updated_at': config['updated_at']
            }
            
            # 插入数据
            db.insert('DATABASE_CONFIG', data)
            print(f"已迁移数据库配置: {config['name']}")
        
        print("数据库配置数据迁移完成！")
    except Exception as e:
        print(f"数据库配置数据迁移失败: {e}")


def migrate_db_connections():
    """迁移数据库连接数据"""
    print("开始迁移数据库连接数据...")
    try:
        # 先清空表
        db.execute_query("DELETE FROM DB_CONNECTION")
        
        # 如果没有数据，跳过
        if not db_connections:
            print("没有数据库连接数据需要迁移")
            return
        
        # 插入数据
        for conn in db_connections:
            # 生成UUID
            conn_id = conn.get('id', str(uuid.uuid4()))
            
            # 准备数据
            data = {
                'id': conn_id,
                'db_id': conn['db_id'],
                'env_id': conn['env_id'],
                'host': conn['host'],
                'port': conn['port'],
                'user': conn['user'],
                'password': conn['password'],
                'db_name': conn['db_name'],
                'created_at': conn['created_at'],
                'updated_at': conn['updated_at']
            }
            
            # 插入数据
            db.insert('DB_CONNECTION', data)
            print(f"已迁移数据库连接: {conn['db_name']} ({conn['host']}:{conn['port']})")
        
        print("数据库连接数据迁移完成！")
    except Exception as e:
        print(f"数据库连接数据迁移失败: {e}")


def migrate_mock_interfaces():
    """迁移MOCK接口数据"""
    print("开始迁移MOCK接口数据...")
    try:
        # 先清空表
        db.execute_query("DELETE FROM MOCK_DATA")
        
        # 如果没有数据，跳过
        if not mock_interfaces:
            print("没有MOCK接口数据需要迁移")
            return
        
        # 插入数据
        for interface_id, interface in mock_interfaces.items():
            # 准备数据
            data = {
                'id': interface_id,
                'name': interface['name'],
                'path': interface['path'],
                'method': interface['method'],
                'response_body': json.dumps(interface['response']),
                'response_status': interface['status_code'],
                'response_headers': json.dumps({}),  # 原数据中没有headers
                'description': interface.get('description', ''),
                'created_by': 'admin',  # 假设是admin创建的
                'is_active': interface['status'] == 'active',
                'created_at': interface['created_at'],
                'updated_at': interface['updated_at']
            }
            
            # 插入数据
            db.insert('MOCK_DATA', data)
            print(f"已迁移MOCK接口: {interface['name']} ({interface['method']} {interface['path']})")
        
        print("MOCK接口数据迁移完成！")
    except Exception as e:
        print(f"MOCK接口数据迁移失败: {e}")


def migrate_email_config():
    """迁移邮件配置数据"""
    print("开始迁移邮件配置数据...")
    try:
        # 先清空表
        db.execute_query("DELETE FROM EMAIL_CONFIG")
        
        # 准备数据
        data = {
            'id': str(uuid.uuid4()),
            'user_id': 'admin_user_id',  # 假设admin用户ID
            'sender_email': email_config['sender_email'],
            'sender_name': 'API测试平台',
            'smtp_server': email_config['smtp_server'],
            'smtp_port': email_config['smtp_port'],
            'smtp_ssl': email_config['use_tls'],
            'smtp_username': email_config['sender_email'],
            'smtp_password': email_config['sender_password'],
            'is_active': bool(email_config['smtp_server'] and email_config['sender_email'] and email_config['sender_password']),
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # 插入数据
        db.insert('EMAIL_CONFIG', data)
        print("已迁移邮件配置数据")
        
        print("邮件配置数据迁移完成！")
    except Exception as e:
        print(f"邮件配置数据迁移失败: {e}")


def migrate_email_recipients():
    """迁移邮件收件人数据"""
    print("开始迁移邮件收件人数据...")
    try:
        # 检查是否存在EMAIL_RECIPIENT表，如果不存在则创建
        try:
            db.execute_query("SELECT 1 FROM EMAIL_RECIPIENT LIMIT 1")
        except:
            print("创建EMAIL_RECIPIENT表...")
            db.execute_query(""
"CREATE TABLE IF NOT EXISTS EMAIL_RECIPIENT (
    id VARCHAR(36) PRIMARY KEY,
    email VARCHAR(100) NOT NULL UNIQUE,
    name VARCHAR(100) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")
        
        # 先清空表
        db.execute_query("DELETE FROM EMAIL_RECIPIENT")
        
        # 如果没有数据，跳过
        if not email_recipients:
            print("没有邮件收件人数据需要迁移")
            return
        
        # 插入数据
        for recipient in email_recipients:
            # 准备数据
            data = {
                'id': recipient['id'],
                'email': recipient['email'],
                'name': recipient['name'],
                'is_active': recipient['is_active'],
                'created_at': recipient['create_time']
            }
            
            # 插入数据
            db.insert('EMAIL_RECIPIENT', data)
            print(f"已迁移邮件收件人: {recipient['name']} ({recipient['email']})")
        
        print("邮件收件人数据迁移完成！")
    except Exception as e:
        print(f"邮件收件人数据迁移失败: {e}")


def migrate_all():
    """迁移所有数据"""
    print("开始数据迁移...")
    
    # 迁移测试环境数据
    migrate_test_environments()
    
    # 迁移数据库配置数据
    migrate_database_configs()
    
    # 迁移数据库连接数据
    migrate_db_connections()
    
    # 迁移MOCK接口数据
    migrate_mock_interfaces()
    
    # 迁移邮件配置数据
    migrate_email_config()
    
    # 迁移邮件收件人数据
    migrate_email_recipients()
    
    print("数据迁移完成！")


if __name__ == '__main__':
    # 执行数据迁移
    migrate_all()