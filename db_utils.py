# 数据库操作工具类

import mysql.connector
from db_config import DB_CONFIG
from mysql.connector import Error
import uuid

class DatabaseUtils:
    def __init__(self):
        self.connection = None
        self.cursor = None
        self.connect()

    def connect(self):
        """建立数据库连接"""
        try:
            # 创建连接
            self.connection = mysql.connector.connect(
            host=DB_CONFIG['host'],
            port=DB_CONFIG['port'],
            user=DB_CONFIG['user'],
            password=DB_CONFIG['password'],
            database=DB_CONFIG['database'],
            charset=DB_CONFIG['charset'],
            use_pure=True  # 使用纯Python实现，而不是C扩展
        )

            # 创建游标
            if DB_CONFIG.get('cursorclass') == 'DictCursor':
                self.cursor = self.connection.cursor(dictionary=True)
            else:
                self.cursor = self.connection.cursor()

        except Error as e:
            print(f"数据库连接错误: {e}")
            print(f"连接参数: host={DB_CONFIG['host']}, port={DB_CONFIG['port']}, user={DB_CONFIG['user']}, database={DB_CONFIG['database']}")
            raise

    def execute_query(self, query, params=None):
        """执行SQL查询（无返回结果）"""
        try:
            if not self.connection or not self.connection.is_connected():
                self.connect()
            elif not self.cursor:
                # 连接存在但游标不存在，重新创建游标
                if DB_CONFIG.get('cursorclass') == 'DictCursor':
                    self.cursor = self.connection.cursor(dictionary=True)
                else:
                    self.cursor = self.connection.cursor()
            self.cursor.execute(query, params or ())
            self.connection.commit()
            return True
        except Error as e:
            print(f"执行查询错误: {e}\nQuery: {query}\nParams: {params}")
            self.connection.rollback()
            # 发生错误时，关闭游标以便下次操作时重新创建
            if self.cursor:
                self.cursor.close()
                self.cursor = None
            raise

    def fetch_one(self, query, params=None):
        """执行SQL查询并返回单条结果"""
        try:
            if not self.connection or not self.connection.is_connected():
                self.connect()
            elif not self.cursor:
                # 连接存在但游标不存在，重新创建游标
                if DB_CONFIG.get('cursorclass') == 'DictCursor':
                    self.cursor = self.connection.cursor(dictionary=True)
                else:
                    self.cursor = self.connection.cursor()
            self.cursor.execute(query, params or ())
            return self.cursor.fetchone()
        except Error as e:
            print(f"查询单条记录错误: {e}\nQuery: {query}\nParams: {params}")
            # 发生错误时，关闭游标以便下次操作时重新创建
            if self.cursor:
                self.cursor.close()
                self.cursor = None
            raise

    def fetch_all(self, query, params=None):
        """执行SQL查询并返回所有结果"""
        try:
            if not self.connection or not self.connection.is_connected():
                self.connect()
            elif not self.cursor:
                # 连接存在但游标不存在，重新创建游标
                if DB_CONFIG.get('cursorclass') == 'DictCursor':
                    self.cursor = self.connection.cursor(dictionary=True)
                else:
                    self.cursor = self.connection.cursor()
            self.cursor.execute(query, params or ())
            return self.cursor.fetchall()
        except Error as e:
            print(f"查询多条记录错误: {e}\nQuery: {query}\nParams: {params}")
            # 发生错误时，关闭游标以便下次操作时重新创建
            if self.cursor:
                self.cursor.close()
                self.cursor = None
            raise

    def insert(self, table, data):
        """插入数据到表中"""
        try:
            # 对于USER_ROLE表，不自动添加id字段
            if table != 'USER_ROLE' and 'id' not in data:
                data['id'] = str(uuid.uuid4())
            elif table == 'USER_ROLE' and 'id' not in data:
                # 移除可能存在的id字段（如果有）
                data.pop('id', None)

            # 构建字段和值
            fields = ', '.join(data.keys())
            placeholders = ', '.join(['%s'] * len(data))
            values = tuple(data.values())

            # 构建SQL语句
            query = f"INSERT INTO {table} ({fields}) VALUES ({placeholders})"

            # 执行查询
            self.execute_query(query, values)
            return data.get('id')
        except Error as e:
            print(f"插入数据错误: {e}\nTable: {table}\nData: {data}")
            raise

    def update(self, table, data, condition):
        """更新表中的数据"""
        try:
            # 构建更新字段
            set_clause = ', '.join([f"{k} = %s" for k in data.keys()])
            values = tuple(data.values())

            # 构建条件
            condition_clause = ' AND '.join([f"{k} = %s" for k in condition.keys()])
            condition_values = tuple(condition.values())

            # 合并值
            all_values = values + condition_values

            # 构建SQL语句
            query = f"UPDATE {table} SET {set_clause} WHERE {condition_clause}"

            # 执行查询
            self.execute_query(query, all_values)
            return True
        except Error as e:
            print(f"更新数据错误: {e}\nTable: {table}\nData: {data}\nCondition: {condition}")
            raise

    def delete(self, table, condition):
        """删除表中的数据"""
        try:
            # 构建条件
            condition_clause = ' AND '.join([f"{k} = %s" for k in condition.keys()])
            condition_values = tuple(condition.values())

            # 构建SQL语句
            query = f"DELETE FROM {table} WHERE {condition_clause}"

            # 执行查询
            self.execute_query(query, condition_values)
            return True
        except Error as e:
            print(f"删除数据错误: {e}\nTable: {table}\nCondition: {condition}")
            raise

    def close(self):
        """关闭数据库连接"""
        if self.cursor:
            self.cursor.close()
        if self.connection and self.connection.is_connected():
            self.connection.close()

    def __del__(self):
        """析构函数，确保连接被关闭"""
        self.close()

# 创建数据库工具实例
db = DatabaseUtils()