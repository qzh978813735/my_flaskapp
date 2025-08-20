#!/usr/bin/env python
# 初始化所有数据库表结构

import os
from dotenv import load_dotenv
from db_utils import db

# 加载环境变量
load_dotenv()

# 初始化表结构
def init_all_tables():
    print("开始初始化数据库表结构...")

    # 创建ROLE表（如果不存在）
    try:
        db.execute_query("""CREATE TABLE IF NOT EXISTS ROLE (
            id VARCHAR(36) PRIMARY KEY,
            name VARCHAR(50) NOT NULL UNIQUE,
            description TEXT,
            created_at DATETIME NOT NULL
        )""")
        print("ROLE表创建成功或已存在")
    except Exception as e:
        print(f"创建ROLE表失败: {e}")

    # 创建USER表
    try:
        db.execute_query("""CREATE TABLE IF NOT EXISTS USER (
            id VARCHAR(36) PRIMARY KEY,
            username VARCHAR(50) NOT NULL UNIQUE,
            password_hash VARCHAR(100) NOT NULL,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(100) NOT NULL UNIQUE,
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL
        )""")
        print("USER表创建成功或已存在")
    except Exception as e:
        print(f"创建USER表失败: {e}")

    # 创建USER_ROLE表
    try:
        db.execute_query("""CREATE TABLE IF NOT EXISTS USER_ROLE (
            user_id VARCHAR(36) NOT NULL,
            role_id VARCHAR(36) NOT NULL,
            PRIMARY KEY (user_id, role_id),
            FOREIGN KEY (user_id) REFERENCES USER(id) ON DELETE CASCADE,
            FOREIGN KEY (role_id) REFERENCES ROLE(id) ON DELETE CASCADE
        )""")
        print("USER_ROLE表创建成功或已存在")
    except Exception as e:
        print(f"创建USER_ROLE表失败: {e}")

    # 邮件配置 - 发件人配置表
    try:
        db.execute_query("""CREATE TABLE IF NOT EXISTS EMAIL_SENDER_CONFIG (
            id VARCHAR(36) PRIMARY KEY,
            host VARCHAR(100) NOT NULL,
            port INT NOT NULL,
            username VARCHAR(100) NOT NULL,
            password VARCHAR(100) NOT NULL,
            use_ssl BOOLEAN NOT NULL DEFAULT TRUE,
            sender_email VARCHAR(100) NOT NULL,
            sender_name VARCHAR(100),
            is_default BOOLEAN NOT NULL DEFAULT FALSE,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL
        )""")
        print("EMAIL_SENDER_CONFIG表创建成功或已存在")
    except Exception as e:
        print(f"创建EMAIL_SENDER_CONFIG表失败: {e}")

    # 邮件配置 - 收件人表
    try:
        db.execute_query("""CREATE TABLE IF NOT EXISTS EMAIL_RECIPIENT (
            id VARCHAR(36) PRIMARY KEY,
            email VARCHAR(100) NOT NULL,
            name VARCHAR(100),
            type VARCHAR(20) NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL
        )""")
        print("EMAIL_RECIPIENT表创建成功或已存在")
    except Exception as e:
        print(f"创建EMAIL_RECIPIENT表失败: {e}")

    # Mock数据 - 接口配置表
    try:
        db.execute_query("""CREATE TABLE IF NOT EXISTS MOCK_INTERFACE (
            id VARCHAR(36) PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            method VARCHAR(10) NOT NULL,
            route VARCHAR(255) NOT NULL,
            response_code INT NOT NULL DEFAULT 200,
            response_headers TEXT,
            response_body TEXT NOT NULL,
            delay INT NOT NULL DEFAULT 0,
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL
        )""")
        print("MOCK_INTERFACE表创建成功或已存在")
    except Exception as e:
        print(f"创建MOCK_INTERFACE表失败: {e}")

    # 接口测试 - 项目表
    try:
        db.execute_query("""CREATE TABLE IF NOT EXISTS API_TEST_PROJECT (
            id VARCHAR(36) PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            version VARCHAR(20) NOT NULL DEFAULT '1.0',
            description TEXT,
            status VARCHAR(20) NOT NULL DEFAULT 'active',
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            manager_id VARCHAR(36) NOT NULL,
            FOREIGN KEY (manager_id) REFERENCES USER(id)
        )""")
        print("API_TEST_PROJECT表创建成功或已存在")
    except Exception as e:
        print(f"创建API_TEST_PROJECT表失败: {e}")

    # 接口测试 - 用例组表
    try:
        db.execute_query("""CREATE TABLE IF NOT EXISTS API_TEST_GROUP (
            id VARCHAR(36) PRIMARY KEY,
            project_id VARCHAR(36) NOT NULL,
            name VARCHAR(100) NOT NULL,
            priority VARCHAR(10) NOT NULL DEFAULT 'P2',
            description TEXT,
            service VARCHAR(100),
            sprint VARCHAR(50),
            story_id VARCHAR(50),
            test_case_id VARCHAR(50),
            status VARCHAR(20) NOT NULL DEFAULT 'active',
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            FOREIGN KEY (project_id) REFERENCES API_TEST_PROJECT(id) ON DELETE CASCADE
        )""")
        print("API_TEST_GROUP表创建成功或已存在")
    except Exception as e:
        print(f"创建API_TEST_GROUP表失败: {e}")

    # 接口测试 - 测试用例表
    try:
        db.execute_query("""CREATE TABLE IF NOT EXISTS API_TEST_CASE (
            id VARCHAR(36) PRIMARY KEY,
            group_id VARCHAR(36) NOT NULL,
            name VARCHAR(100) NOT NULL,
            method VARCHAR(10) NOT NULL,
            protocol VARCHAR(10) NOT NULL DEFAULT 'HTTP',
            domain VARCHAR(255),
            route VARCHAR(255) NOT NULL,
            service VARCHAR(100),
            sequence INT NOT NULL,
            description TEXT,
            clear_cookies BOOLEAN NOT NULL DEFAULT FALSE,
            status VARCHAR(20) NOT NULL DEFAULT 'active',
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            headers TEXT,
            params TEXT,
            initialization TEXT,
            variables TEXT,
            validations TEXT,
            FOREIGN KEY (group_id) REFERENCES API_TEST_GROUP(id) ON DELETE CASCADE
        )""")
        print("API_TEST_CASE表创建成功或已存在")
    except Exception as e:
        print(f"创建API_TEST_CASE表失败: {e}")

    # 接口测试 - 全局变量表
    try:
        db.execute_query("""CREATE TABLE IF NOT EXISTS API_TEST_GLOBAL_VAR (
            id VARCHAR(36) PRIMARY KEY,
            project_id VARCHAR(36) NOT NULL,
            env_id VARCHAR(36) NOT NULL,
            name VARCHAR(50) NOT NULL,
            value TEXT NOT NULL,
            description TEXT,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            FOREIGN KEY (project_id) REFERENCES API_TEST_PROJECT(id) ON DELETE CASCADE
        )""")
        print("API_TEST_GLOBAL_VAR表创建成功或已存在")
    except Exception as e:
        print(f"创建API_TEST_GLOBAL_VAR表失败: {e}")

    # 接口测试 - 定时任务表
    try:
        db.execute_query("""CREATE TABLE IF NOT EXISTS API_TEST_SCHEDULED_TASK (
            id VARCHAR(36) PRIMARY KEY,
            project_id VARCHAR(36) NOT NULL,
            name VARCHAR(100) NOT NULL,
            group_ids TEXT NOT NULL,
            env_id VARCHAR(36) NOT NULL,
            trigger_type VARCHAR(20) NOT NULL,
            trigger_value TEXT NOT NULL,
            next_execution DATETIME NOT NULL,
            notify_wechat BOOLEAN NOT NULL DEFAULT FALSE,
            notify_dingtalk BOOLEAN NOT NULL DEFAULT FALSE,
            notify_email BOOLEAN NOT NULL DEFAULT FALSE,
            notify_only_failure BOOLEAN NOT NULL DEFAULT TRUE,
            description TEXT,
            status VARCHAR(20) NOT NULL DEFAULT 'active',
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            FOREIGN KEY (project_id) REFERENCES API_TEST_PROJECT(id) ON DELETE CASCADE
        )""")
        print("API_TEST_SCHEDULED_TASK表创建成功或已存在")
    except Exception as e:
        print(f"创建API_TEST_SCHEDULED_TASK表失败: {e}")

    # 执行计划表
    try:
        db.execute_query("""CREATE TABLE IF NOT EXISTS EXECUTION_PLAN (
            id VARCHAR(36) PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            description TEXT,
            cron_expression VARCHAR(50) NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL
        )""")
        print("EXECUTION_PLAN表创建成功或已存在")
    except Exception as e:
        print(f"创建EXECUTION_PLAN表失败: {e}")

    # 执行计划日志表
    try:
        db.execute_query("""CREATE TABLE IF NOT EXISTS EXECUTION_LOG (
            id VARCHAR(36) PRIMARY KEY,
            plan_id VARCHAR(36) NOT NULL,
            status VARCHAR(20) NOT NULL,
            start_time DATETIME NOT NULL,
            end_time DATETIME,
            duration INT,
            message TEXT,
            FOREIGN KEY (plan_id) REFERENCES EXECUTION_PLAN(id) ON DELETE CASCADE
        )""")
        print("EXECUTION_LOG表创建成功或已存在")
    except Exception as e:
        print(f"创建EXECUTION_LOG表失败: {e}")

    print("数据库表结构初始化完成")

if __name__ == '__main__':
    init_all_tables()