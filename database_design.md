# 应用数据库设计图

以下是为应用设计的数据库结构ER图，使用Mermaid语法绘制：

```mermaid
erDiagram
    USER ||--o{ USER_ROLE : "has"
    ROLE ||--o{ USER_ROLE : "assigned to"
    USER ||--o{ API_TEST_PROJECT : "owns"
    USER ||--o{ SCHEDULED_TASK : "created"
    USER ||--o{ MOCK_DATA : "created"
    USER ||--o{ EMAIL_CONFIG : "configured"

    API_TEST_PROJECT ||--o{ TEST_CASE_GROUP : "contains"
    API_TEST_PROJECT ||--o{ SCHEDULED_TASK : "has"
    API_TEST_PROJECT ||--o{ TEST_REPORT : "generates"

    TEST_CASE_GROUP ||--o{ TEST_CASE : "contains"

    TEST_ENVIRONMENT ||--o{ SCHEDULED_TASK : "used in"
    TEST_ENVIRONMENT ||--o{ TEST_REPORT : "executed in"

    DATABASE_CONFIG ||--o{ DB_CONNECTION : "has"
    TEST_ENVIRONMENT ||--o{ DB_CONNECTION : "used in"

    USER {
        string id PK
        string username
        string password_hash
        string email
        string name
        boolean is_active
        datetime created_at
        datetime updated_at
    }

    ROLE {
        string id PK
        string name
        string description
    }

    USER_ROLE {
        string user_id PK, FK
        string role_id PK, FK
        datetime assigned_at
    }

    API_TEST_PROJECT {
        string id PK
        string name
        string description
        string owner_id FK
        boolean is_active
        datetime created_at
        datetime updated_at
    }

    TEST_CASE_GROUP {
        string id PK
        string name
        string description
        string project_id FK
        datetime created_at
        datetime updated_at
    }

    TEST_CASE {
        string id PK
        string name
        string description
        string group_id FK
        string request_url
        string request_method
        json request_headers
        json request_body
        json expected_response
        datetime created_at
        datetime updated_at
    }

    TEST_ENVIRONMENT {
        string id PK
        string name
        string protocol
        string domain
        string description
        string status
        datetime created_at
        datetime updated_at
    }

    SCHEDULED_TASK {
        string id PK
        string name
        string project_id FK
        string env_id FK
        string trigger_type
        string trigger_value
        string next_execution
        boolean notify_wechat
        boolean notify_dingtalk
        boolean notify_email
        boolean notify_only_failure
        string description
        string status
        datetime created_at
        datetime updated_at
    }

    TEST_REPORT {
        string id PK
        string project_id FK
        string env_id FK
        string execution_type
        datetime start_time
        datetime end_time
        integer total_cases
        integer passed_cases
        integer failed_cases
        string status
        json detailed_results
        datetime created_at
    }

    EMAIL_CONFIG {
        string id PK
        string user_id FK
        string sender_email
        string sender_name
        string smtp_server
        integer smtp_port
        boolean smtp_ssl
        string smtp_username
        string smtp_password
        boolean is_active
        datetime created_at
        datetime updated_at
    }

    MOCK_DATA {
        string id PK
        string name
        string path
        string method
        json response_body
        integer response_status
        json response_headers
        string description
        string created_by FK
        boolean is_active
        datetime created_at
        datetime updated_at
    }

    DATABASE_CONFIG {
        string id PK
        string name
        string type
        string description
        string status
        datetime created_at
        datetime updated_at
    }

    DB_CONNECTION {
        string id PK
        string db_id FK
        string env_id FK
        string host
        integer port
        string user
        string password
        string db_name
        datetime created_at
        datetime updated_at
    }
```

## 数据库设计说明

1. **用户与权限管理**
   - `USER`表存储用户基本信息
   - `ROLE`表定义角色
   - `USER_ROLE`表实现用户与角色的多对多关系

2. **API测试管理**
   - `API_TEST_PROJECT`表存储测试项目
   - `TEST_CASE_GROUP`表存储测试用例组
   - `TEST_CASE`表存储具体测试用例

3. **环境与执行**
   - `TEST_ENVIRONMENT`表存储测试环境配置
   - `SCHEDULED_TASK`表存储定时任务
   - `TEST_REPORT`表存储测试报告

4. **其他功能**
   - `EMAIL_CONFIG`表存储邮件配置
   - `MOCK_DATA`表存储MOCK数据
   - `DATABASE_CONFIG`和`DB_CONNECTION`表存储数据库配置和连接信息

这个设计覆盖了应用的核心功能，同时保持了良好的扩展性。您可以根据实际需求进一步调整或简化这个设计。