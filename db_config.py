# 数据库连接配置

import os
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

# 数据库连接配置
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', '3306')),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', 'password'),
    'database': os.getenv('DB_NAME', 'api_test_platform'),
    'charset': 'utf8mb4',
    'cursorclass': 'DictCursor'
}

# 确保所有必需的环境变量都已设置
REQUIRED_ENV_VARS = ['DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME']
MISSING_ENV_VARS = [var for var in REQUIRED_ENV_VARS if not os.getenv(var)]

if MISSING_ENV_VARS:
    raise EnvironmentError(f"缺少必需的环境变量: {', '.join(MISSING_ENV_VARS)}")