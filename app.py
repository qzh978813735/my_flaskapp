from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_wtf.csrf import CSRFProtect
from datetime import datetime, timedelta
from functools import wraps
import json
import smtplib
import threading
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask_login import login_required, current_user
import uuid
from functools import wraps

# 导入数据库工具
from db_utils import db
# 导入初始化所有表的函数
from init_all_tables import init_all_tables
import os

# 从环境变量获取是否初始化数据库的配置，默认为False
INIT_DB_ON_START = os.environ.get('INIT_DB_ON_START', 'False').lower() == 'true'

# 只有当配置为True时才初始化数据库
if INIT_DB_ON_START:
    print("正在初始化数据库表结构...")
    init_all_tables()
else:
    print("跳过数据库初始化")

# 初始化Flask应用
app = Flask(__name__)
app.secret_key = 'your-secure-secret-key-1234567890'  # 生产环境请更换为随机字符串

app.config['WTF_CSRF_ENABLED'] = True
csrf = CSRFProtect(app)
# 全局变量初始化（修复NameError）
mock_interfaces = {}  # MOCK接口配置
database_configs = []  # 数据库配置
db_connections = []  # 数据库连接信息
test_environments = []  # 测试环境配置
execution_plans = []  # 执行计划
execution_logs = []  # 执行日志
email_config = {  # 邮件配置默认值
    'smtp_server': '',
    'smtp_port': 587,
    'sender_email': '',
    'sender_password': '',
    'use_tls': True
}
email_recipients = []  # 邮件收件人

# 存储密码重置令牌
password_reset_tokens = {}

# 初始化一些示例数据
test_environments.extend([
    {
        'id': str(uuid.uuid4())[:8],
        'name': '开发环境',
        'protocol': 'http',
        'domain': 'dev.example.com',
        'description': '开发人员使用的环境',
        'status': 'active',
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    },
    {
        'id': str(uuid.uuid4())[:8],
        'name': '测试环境',
        'protocol': 'http',
        'domain': 'test.example.com',
        'description': '测试人员使用的环境',
        'status': 'active',
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    },
    {
        'id': str(uuid.uuid4())[:8],
        'name': '预发布环境',
        'protocol': 'https',
        'domain': 'pre.example.com',
        'description': '上线前的预发布环境',
        'status': 'active',
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    },
    {
        'id': str(uuid.uuid4())[:8],
        'name': '生产环境',
        'protocol': 'https',
        'domain': '${service}.example.com',
        'description': '正式生产环境',
        'status': 'inactive',
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
])

database_configs.extend([
    {
        'id': str(uuid.uuid4())[:8],
        'name': '用户数据库',
        'type': 'MySQL',
        'description': '存储用户信息的数据库',
        'status': 'active',
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    },
    {
        'id': str(uuid.uuid4())[:8],
        'name': '产品数据库',
        'type': 'MongoDB',
        'description': '存储产品信息的数据库',
        'status': 'active',
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
])

# 为简化示例，我们添加一些示例DB连接信息
env_id = test_environments[0]['id']  # 开发环境
db_id = database_configs[0]['id']  # 用户数据库
db_connections.append({
    'id': str(uuid.uuid4())[:8],
    'db_id': db_id,
    'env_id': env_id,
    'host': 'localhost',
    'port': 3306,
    'user': 'root',
    'password': 'password',
    'db_name': 'user_db',
    'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
})

# 添加MongoDB连接信息
env_id = test_environments[1]['id']  # 测试环境
db_id = database_configs[1]['id']  # 产品数据库
db_connections.append({
    'id': str(uuid.uuid4())[:8],
    'db_id': db_id,
    'env_id': env_id,
    'host': 'localhost',
    'port': 27017,
    'user': '',
    'password': '',
    'db_name': 'product_db',
    'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
})

# 登录验证装饰器
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('请先登录系统', 'error')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)

    return decorated_function


# 管理员权限验证
def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            flash('没有足够权限执行此操作', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)

    return decorated_function


# 登录路由
@app.route('/login', methods=['GET', 'POST'])
def login():
    # 在GET请求时清除所有flash消息
    if request.method == 'GET':
        # 清除所有flash消息
        session.pop('_flashes', None)
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not password:
            flash('用户名和密码不能为空', 'error')
            return render_template('login.html')

        try:
            # 从数据库查询用户
            query = "SELECT u.id, u.username, u.password_hash, u.name, u.is_active, r.name as role_name "
            query += "FROM USER u JOIN USER_ROLE ur ON u.id = ur.user_id JOIN ROLE r ON ur.role_id = r.id "
            query += "WHERE u.username = %s"
            user = db.fetch_one(query, (username,))

            if user and user['password_hash'] == password and user['is_active'] == 1:
                session['username'] = user['username']
                session['name'] = user['name']
                session['role'] = user['role_name']
                session['id'] = user['id']  # 保存用户ID到session
                flash(f'欢迎回来，{user["name"]}', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('用户名或密码错误，或账号已被禁用', 'error')
        except Exception as e:
            flash(f'登录失败: {str(e)}', 'error')
            print(f'登录数据库错误: {e}')

    return render_template('login.html')


# 登出路由
@app.route('/logout')
def logout():
    session.clear()
    flash('已成功退出登录', 'success')
    return redirect(url_for('login'))


# 忘记密码路由
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if not email:
            flash('邮箱不能为空', 'error')
            return render_template('forgot_password.html')

        try:
            # 从数据库查询用户
            query = "SELECT id, username, name FROM USER WHERE email = %s AND status = 'active'"
            user = db.fetch_one(query, (email,))

            if not user:
                flash('未找到该邮箱对应的用户', 'error')
                return render_template('forgot_password.html')

            # 生成重置令牌
            token = str(uuid.uuid4())
            expiry = datetime.now() + timedelta(hours=1)  # 1小时后过期

            # 保存重置令牌到数据库
            # 先检查是否存在PASSWORD_RESET表，如果不存在则创建
            try:
                db.execute_query("SELECT 1 FROM PASSWORD_RESET LIMIT 1")
            except:
                db.execute_query("""CREATE TABLE IF NOT EXISTS PASSWORD_RESET (
    token VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    expiry DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES USER(id) ON DELETE CASCADE
)""")

            # 插入令牌
            db.insert('PASSWORD_RESET', {
                'token': token,
                'user_id': user['id'],
                'expiry': expiry.strftime('%Y-%m-%d %H:%M:%S')
            })

            # 构建重置链接
            reset_url = url_for('reset_password', token=token, _external=True)

            # 发送邮件
            # 检查邮件配置
            if not all([email_config['smtp_server'], email_config['sender_email'], email_config['sender_password']]):
                flash('邮件服务器未配置，无法发送重置链接', 'error')
                return render_template('forgot_password.html')

            # 构建邮件
            msg = MIMEMultipart()
            msg['From'] = email_config['sender_email']
            msg['To'] = email
            msg['Subject'] = '密码重置请求 - 自动化测试平台'

            body = f'''
            您收到这封邮件是因为有人请求重置您在自动化测试平台的密码。

            请点击以下链接重置您的密码（链接有效期为1小时）：
            {reset_url}

            如果您没有请求重置密码，请忽略此邮件。
            '''
            msg.attach(MIMEText(body, 'plain'))

            # 发送邮件
            server = smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port'])
            if email_config['use_tls']:
                server.starttls()
            server.login(email_config['sender_email'], email_config['sender_password'])
            text = msg.as_string()
            server.sendmail(email_config['sender_email'], email, text)
            server.quit()

            flash('重置密码链接已发送到您的邮箱，请查收', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            flash(f'处理请求失败: {str(e)}', 'error')
            print(f'忘记密码数据库错误: {e}')
            return render_template('forgot_password.html')

    return render_template('forgot_password.html')


# 重置密码路由
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        # 检查令牌是否有效
        query = "SELECT pr.user_id, pr.expiry, u.username, u.name FROM PASSWORD_RESET pr JOIN USER u ON pr.user_id = u.id WHERE pr.token = %s"
        token_data = db.fetch_one(query, (token,))

        if not token_data:
            return render_template('reset_password.html', invalid_token=True)

        # 检查令牌是否过期
        expiry = datetime.strptime(token_data['expiry'], '%Y-%m-%d %H:%M:%S')
        if datetime.now() > expiry:
            # 删除过期令牌
            db.delete('PASSWORD_RESET', {'token': token})
            return render_template('reset_password.html', invalid_token=True)

        username = token_data['username']

        if request.method == 'POST':
            password = request.form.get('password', '').strip()
            confirm_password = request.form.get('confirm_password', '').strip()

            if not password or not confirm_password:
                flash('密码和确认密码不能为空', 'error')
                return render_template('reset_password.html', token=token)

            if password != confirm_password:
                flash('两次输入的密码不一致', 'error')
                return render_template('reset_password.html', token=token)

            if len(password) < 6:
                flash('密码长度不能少于6位', 'error')
                return render_template('reset_password.html', token=token)

            # 更新密码
            db.update('USER', {'password': password}, {'username': username})

            # 删除已使用的令牌
            db.delete('PASSWORD_RESET', {'token': token})

            flash('密码已成功重置，请使用新密码登录', 'success')
            return redirect(url_for('login'))

        return render_template('reset_password.html', token=token)
    except Exception as e:
        flash(f'处理请求失败: {str(e)}', 'error')
        print(f'重置密码数据库错误: {e}')
        return render_template('reset_password.html', invalid_token=True)


# 仪表盘路由
@app.route('/')
@login_required
def dashboard():
    # 统计数据
    stats = {
        'plan_count': len(execution_plans),
        'interface_count': len(mock_interfaces),
        'env_count': len(test_environments),
        'log_count': len(execution_logs),
        'active_plans': sum(1 for p in execution_plans if p['status'] == 'active'),
        'active_interfaces': sum(1 for i in mock_interfaces.values() if i['status'] == 'active')
    }

    # 最近执行日志
    recent_logs = sorted(execution_logs, key=lambda x: x['time'], reverse=True)[:5]

    return render_template('dashboard.html',
                           username=session['name'],
                           stats=stats,
                           recent_logs=recent_logs)


# 更新用户管理路由，添加邮箱字段
@app.route('/user_management', methods=['GET', 'POST'])
@admin_required
def user_management():
    # 从数据库获取用户数据
    try:
        query = "SELECT u.username, u.name, u.email, IFNULL(r.name, '无角色') as role, u.is_active as status, u.created_at as create_time "
        query += "FROM USER u LEFT JOIN USER_ROLE ur ON u.id = ur.user_id LEFT JOIN ROLE r ON ur.role_id = r.id"
        users_data = db.fetch_all(query)
        # 转换为字典格式以便模板使用
        users = {}
        for user in users_data:
            users[user['username']] = {
                'name': user['name'],
                'email': user['email'],
                'role': user['role'],
                'status': user['status'],
                'create_time': user['create_time']
            }
    except Exception as e:
        flash(f'获取用户数据失败: {str(e)}', 'error')
        users = {}

    if request.method == 'POST':
        action = request.form.get('action', '').strip()

        if action == 'add':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            name = request.form.get('name', '').strip()
            role = request.form.get('role', 'user')
            email = request.form.get('email', '').strip()

            # 验证
            if not username or not password or not name or not email:
                flash('用户名、密码、姓名和邮箱不能为空', 'error')
                return redirect(url_for('user_management'))

            if username in users:
                flash(f'用户名 "{username}" 已存在', 'error')
                return redirect(url_for('user_management'))

            if len(password) < 6:
                flash('密码长度不能少于6位', 'error')
                return redirect(url_for('user_management'))

            if '@' not in email:
                flash('邮箱格式不正确', 'error')
                return redirect(url_for('user_management'))

            # 添加用户到数据库
            try:
                # 插入用户到USER表
                user_id = db.insert('USER', {
                    'username': username,
                    'password_hash': password,
                    'name': name,
                    'email': email,
                    'is_active': 1,
                    'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                })
                
                # 插入用户角色到USER_ROLE表
                role_result = db.fetch_one("SELECT id FROM ROLE WHERE name = %s", (role,))
                if role_result is None:
                    # 如果未找到指定角色，使用默认角色（假设存在'user'角色）
                    role_result = db.fetch_one("SELECT id FROM ROLE WHERE name = 'user'")
                    if role_result is None:
                        flash('角色表中未找到默认角色，请联系管理员', 'error')
                        return redirect(url_for('user_management'))
                role_id = role_result['id']
                db.insert('USER_ROLE', {
                    'user_id': user_id,
                    'role_id': role_id
                })
                
                # 更新内存中的用户列表
                users[username] = {
                    'name': name,
                    'email': email,
                    'role': role,
                    'status': 1,
                    'create_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                flash(f'用户 "{name}" 创建成功', 'success')
            except Exception as e:
                flash(f'添加用户失败: {str(e)}', 'error')
                print(f'添加用户数据库错误: {e}')
            return redirect(url_for('user_management'))

        elif action == 'edit':
            username = request.form.get('username', '').strip()
            name = request.form.get('name', '').strip()
            role = request.form.get('role', 'user')
            status = request.form.get('status', 'inactive')
            email = request.form.get('email', '').strip()

            if not username or not name or not email:
                flash('用户名、姓名和邮箱不能为空', 'error')
                return redirect(url_for('user_management'))

            if username not in users:
                flash('用户不存在', 'error')
                return redirect(url_for('user_management'))

            if '@' not in email:
                flash('邮箱格式不正确', 'error')
                return redirect(url_for('user_management'))

            # 不允许修改管理员自身角色
            if username == session['username'] and role != 'admin':
                flash('不能修改自身角色为非管理员', 'error')
                return redirect(url_for('user_management'))

            # 更新用户到数据库
            try:
                # 更新USER表
                db.update('USER', {
                    'name': name,
                    'email': email,
                    'is_active': 1 if status == 'active' else 0
                }, {'username': username})
                
                # 更新用户角色
                user_id = db.fetch_one("SELECT id FROM USER WHERE username = %s", (username,))['id']
                role_id = db.fetch_one("SELECT id FROM ROLE WHERE name = %s", (role,))['id']
                db.update('USER_ROLE', {'role_id': role_id}, {'user_id': user_id})
                
                # 更新内存中的用户列表
                users[username]['name'] = name
                users[username]['role'] = role
                users[username]['status'] = 1 if status == 'active' else 0
                users[username]['email'] = email
                flash(f'用户 "{name}" 更新成功', 'success')
            except Exception as e:
                flash(f'更新用户失败: {str(e)}', 'error')
                print(f'更新用户数据库错误: {e}')
            return redirect(url_for('user_management'))

        elif action == 'delete':
            username = request.form.get('username', '').strip()

            if not username:
                flash('用户名不能为空', 'error')
                return redirect(url_for('user_management'))

            if username == session['username']:
                flash('不能删除当前登录用户', 'error')
                return redirect(url_for('user_management'))

            try:
                # 从数据库删除用户
                user_id = db.fetch_one("SELECT id FROM USER WHERE username = %s", (username,))['id']
                
                # 删除用户角色关联
                db.delete('USER_ROLE', {'user_id': user_id})
                
                # 删除用户
                db.delete('USER', {'id': user_id})
                
                # 更新内存中的用户列表
                if username in users:
                    del users[username]
                flash('用户已删除', 'success')
            except Exception as e:
                flash(f'删除用户失败: {str(e)}', 'error')
                print(f'删除用户数据库错误: {e}')

            return redirect(url_for('user_management'))

        elif action == 'reset_password':
            username = request.form.get('username', '').strip()
            new_password = request.form.get('new_password', '').strip()

            if not username or not new_password:
                flash('用户名和新密码不能为空', 'error')
                return redirect(url_for('user_management'))

            if username not in users:
                flash('用户不存在', 'error')
                return redirect(url_for('user_management'))

            if len(new_password) < 6:
                flash('密码长度不能少于6位', 'error')
                return redirect(url_for('user_management'))

            try:
                # 更新数据库中的密码
                db.update('USER', {
                    'password_hash': new_password
                }, {'username': username})
                
                # 更新内存中的用户信息
                users[username]['password'] = new_password
                flash(f'用户 "{users[username]["name"]}" 密码已重置', 'success')
            except Exception as e:
                flash(f'重置密码失败: {str(e)}', 'error')
                print(f'重置密码数据库错误: {e}')
            return redirect(url_for('user_management'))

    return render_template('user_management.html',
                           username=session['name'],
                           users=users,
                           current_user_role=session['role'])


# 邮件配置路由


# 邮件发件人配置路由
@app.route('/email_sender_config', methods=['GET', 'POST'])
@login_required
def email_sender_config():
    if request.method == 'POST':
        # 保存发件人配置到数据库
        config_id = request.form.get('config_id', '')
        config_data = {
            'smtp_server': request.form.get('smtp_server', '').strip(),
            'smtp_port': int(request.form.get('smtp_port', 587)),
            'sender_email': request.form.get('sender_email', '').strip(),
            'sender_password': request.form.get('sender_password', '').strip(),
            'use_ssl': request.form.get('use_tls') == 'on',
            'sender_name': request.form.get('sender_name', '').strip(),
            'is_default': request.form.get('is_default') == 'on',
            'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        try:
            if config_id:
                # 更新现有配置
                db.update('EMAIL_CONFIG', config_data, {'id': config_id})
                flash('邮件服务器配置已更新', 'success')
            else:
                # 添加新配置
                config_data['id'] = str(uuid.uuid4())[:8]
                config_data['created_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                db.insert('EMAIL_CONFIG', config_data)
                flash('邮件服务器配置已保存', 'success')
        except Exception as e:
            flash(f'保存配置失败: {str(e)}', 'error')
            print(f'保存邮件配置数据库错误: {e}')

        return redirect(url_for('email_sender_config'))
    else:
        # 从数据库获取配置
        try:
            configs = db.fetch_all('SELECT * FROM EMAIL_CONFIG')
            # 查找默认配置
            default_config = next((c for c in configs if c['is_default']), None) if configs else None
        except Exception as e:
            flash(f'获取配置失败: {str(e)}', 'error')
            print(f'获取邮件配置数据库错误: {e}')
            configs = []
            default_config = None

        return render_template('email_sender_config.html',
                               username=session['name'],
                               configs=configs,
                               default_config=default_config)

# 邮件收件人配置路由
@app.route('/email_recipients_config', methods=['GET', 'POST'])
@login_required
def email_recipients_config():
    if request.method == 'POST':
        # 添加收件人到数据库
        email = request.form.get('email', '').strip()
        name = request.form.get('name', '').strip()
        recipient_type = request.form.get('type', 'to')
        is_active = request.form.get('is_active') == 'on'

        if not email or not name:
            flash('邮箱和姓名不能为空', 'error')
            return redirect(url_for('email_recipients_config'))
        if '@' not in email:
            flash('邮箱格式不正确', 'error')
            return redirect(url_for('email_recipients_config'))

        try:
            # 检查是否已存在
            existing = db.fetch_one('SELECT id FROM EMAIL_RECIPIENT WHERE email = %s', (email,))
            if existing:
                flash(f'邮箱 "{email}" 已存在', 'error')
                return redirect(url_for('email_recipients_config'))

            # 插入新收件人
            recipient_id = str(uuid.uuid4())[:8]
            db.insert('EMAIL_RECIPIENT', {
                'id': recipient_id,
                'email': email,
                'name': name,
                'recipient_type': recipient_type,
                'is_active': is_active,
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })
            flash(f'收件人 "{name}" 添加成功', 'success')
        except Exception as e:
            flash(f'添加收件人失败: {str(e)}', 'error')
            print(f'添加收件人数据库错误: {e}')

        return redirect(url_for('email_recipients_config'))
    else:
        # 从数据库获取收件人列表
        try:
            recipients = db.fetch_all('SELECT * FROM EMAIL_RECIPIENT ORDER BY created_at DESC')
        except Exception as e:
            flash(f'获取收件人列表失败: {str(e)}', 'error')
            print(f'获取收件人数据库错误: {e}')
            recipients = []

        return render_template('email_recipients_config.html',
                               username=session['name'],
                               recipients=recipients)

# 删除收件人路由
@app.route('/delete_recipient/<recipient_id>', methods=['POST'])
@login_required
def delete_recipient(recipient_id):
    try:
        # 从数据库删除收件人
        affected_rows = db.delete('EMAIL_RECIPIENT', {'id': recipient_id})
        if affected_rows > 0:
            return jsonify({'status': 'success', 'message': '收件人已删除'})
        else:
            return jsonify({'status': 'error', 'message': '未找到收件人'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'删除失败: {str(e)}'})

# 邮件配置首页（重定向到发件人配置）
@app.route('/email_config')
@login_required
def email_config():
    # 作为首页，直接跳转到发件人配置页面
    return redirect(url_for('email_sender_config'))
# 测试邮件发送
@app.route('/test_email_send', methods=['POST'])
@login_required
def test_email_send():
    try:
        test_email = request.form.get('test_email', '').strip()
        if not test_email or '@' not in test_email:
            return jsonify({'status': 'error', 'message': '请输入有效的邮箱地址'})

        # 检查邮件配置
        if not all([email_config['smtp_server'], email_config['sender_email'], email_config['sender_password']]):
            return jsonify({'status': 'error', 'message': '请先完成邮件服务器配置'})

        # 构建测试邮件
        msg = MIMEMultipart()
        msg['From'] = email_config['sender_email']
        msg['To'] = test_email
        msg['Subject'] = '测试邮件 - 自动化测试平台'

        body = f'''
        这是一封来自自动化测试平台的测试邮件。

        发送时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        发送用户: {session['name']}

        如果您收到这封邮件，说明邮件配置正常。
        '''
        msg.attach(MIMEText(body, 'plain'))

        # 发送邮件
        server = smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port'])
        if email_config['use_tls']:
            server.starttls()
        server.login(email_config['sender_email'], email_config['sender_password'])
        text = msg.as_string()
        server.sendmail(email_config['sender_email'], test_email, text)
        server.quit()

        return jsonify({'status': 'success', 'message': '测试邮件发送成功'})

    except Exception as e:
        return jsonify({'status': 'error', 'message': f'发送失败: {str(e)}'})


# MOCK数据页面
@app.route('/mock_data')
@login_required
def mock_data():
    return render_template('mock_data.html',
                           username=session['name'])


# MOCK接口配置路由
@app.route('/mock_config', methods=['GET', 'POST'])
@login_required
def mock_config():
    if request.method == 'POST':
        interface_id = request.form.get('id') or str(uuid.uuid4())
        name = request.form.get('name', '').strip()
        path = request.form.get('path', '').strip()
        method = request.form.get('method', 'GET')
        status_code = int(request.form.get('status_code', 200))
        response = request.form.get('response', '').strip()
        description = request.form.get('description', '').strip()
        is_active = request.form.get('status') is not None
        project_id = request.form.get('project_id', '')

        # 验证数据
        if not name:
            flash('接口名称不能为空', 'error')
            return redirect(url_for('mock_config'))

        if not path.startswith('/'):
            flash('接口路径必须以斜杠开头', 'error')
            return redirect(url_for('mock_config'))

        if not (100 <= status_code <= 599):
            flash('状态码必须在100-599之间', 'error')
            return redirect(url_for('mock_config'))

        # 验证响应JSON格式
        parsed_response = {} 
        if response:
            try:
                parsed_response = json.loads(response)
            except json.JSONDecodeError:
                flash('响应数据不是有效的JSON格式', 'error')
                return redirect(url_for('mock_config'))

        try:
            # 验证路径+方法唯一性
            existing = None
            if interface_id:
                existing = db.fetch_one('''
                    SELECT id FROM MOCK_INTERFACE 
                    WHERE path = %s AND method = %s AND id != %s
                ''', (path, method, interface_id))
            else:
                existing = db.fetch_one('''
                    SELECT id FROM MOCK_INTERFACE 
                    WHERE path = %s AND method = %s
                ''', (path, method))

            if existing:
                flash(f'该路径在{method}方法下已存在', 'error')
                return redirect(url_for('mock_config'))

            # 保存接口到数据库
            interface_data = {
                'name': name,
                'path': path,
                'method': method,
                'status_code': status_code,
                'response_content': response,
                'description': description,
                'is_active': is_active,
                'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

            if project_id:
                interface_data['project_id'] = project_id

            if interface_id:
                # 更新现有接口
                db.update('MOCK_INTERFACE', interface_data, {'id': interface_id})
                flash(f'接口「{name}」更新成功', 'success')
            else:
                # 添加新接口
                interface_data['id'] = interface_id
                interface_data['created_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                db.insert('MOCK_INTERFACE', interface_data)
                flash(f'接口「{name}」添加成功', 'success')
        except Exception as e:
            flash(f'保存接口失败: {str(e)}', 'error')
            print(f'保存MOCK接口数据库错误: {e}')

        return redirect(url_for('mock_config'))

    else:
        # 从数据库获取接口列表
        try:
            interfaces = db.fetch_all('SELECT * FROM MOCK_INTERFACE ORDER BY created_at DESC')
            # 转换为字典形式以便模板使用
            mock_interfaces = {interface['id']: interface for interface in interfaces}
        except Exception as e:
            flash(f'获取接口列表失败: {str(e)}', 'error')
            print(f'获取MOCK接口数据库错误: {e}')
            mock_interfaces = {}

        return render_template('mock_config.html',
                               username=session['name'],
                               interfaces=mock_interfaces)


# 删除MOCK接口路由
@app.route('/delete_mock_interface', methods=['POST'])
@login_required
def delete_mock_interface():
    interface_id = request.form.get('id', '').strip()

    try:
        if interface_id:
            affected_rows = db.delete('MOCK_INTERFACE', {'id': interface_id})
            if affected_rows > 0:
                return jsonify({'success': True, 'message': '接口已删除'})
            else:
                return jsonify({'success': False, 'message': '接口不存在'}), 404
        else:
            return jsonify({'success': False, 'message': '接口ID不能为空'}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': f'删除失败: {str(e)}'}), 500


# MOCK接口调用页面
@app.route('/mock_call')
@login_required
def mock_call():
    return render_template('mock_call.html',
                           username=session['name'],
                           interfaces=mock_interfaces)


# MOCK接口实际处理路由
@app.route('/mock/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def mock_handler(path):
    # 构建完整路径
    full_path = f'/{path}'

    # 查找匹配的接口
    for interface in mock_interfaces.values():
        if interface['path'] == full_path and interface['method'] == request.method and interface['status'] == 'active':
            # 记录调用日志
            execution_logs.append({
                'id': str(uuid.uuid4())[:8],
                'type': 'mock_call',
                'name': interface['name'],
                'status': 'success',
                'message': f'MOCK接口调用成功',
                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'details': {
                    'path': full_path,
                    'method': request.method,
                    'status_code': interface['status_code']
                }
            })
            # 返回预设响应
            return jsonify(interface['response']), interface['status_code']

    # 未找到匹配的接口
    execution_logs.append({
        'id': str(uuid.uuid4())[:8],
        'type': 'mock_call',
        'name': f'未找到接口: {full_path}',
        'status': 'error',
        'message': '未找到匹配的MOCK接口',
        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'details': {
            'path': full_path,
            'method': request.method
        }
    })
    return jsonify({
        'error': '未找到MOCK接口',
        'path': full_path,
        'method': request.method
    }), 404


# 接口测试页面
# @app.route('/api_test')
# @login_required
# def api_test():
#     # 获取默认环境
#     default_env = next((e for e in test_environments if e['is_default']), None)
#     return render_template('api_test.html',
#                            username=session['name'],
#                            environments=test_environments,
#                            default_env=default_env)


# 执行计划首页
# 确保路由定义正确
@app.route('/execution_plan')
@login_required
def execution_plan():  # 函数名必须匹配
    return render_template('execution_plan/index.html', username=session['name'])

# 计划执行页面路由
@app.route('/execution_plan/execution')
@login_required
def plan_execution():
    plans_with_status = []
    try:
        # 从数据库获取计划列表
        execution_plans = db.fetch_all('SELECT * FROM EXECUTION_PLAN ORDER BY created_at DESC')
        # 转换tasks字符串为列表
        for plan in execution_plans:
            plan['tasks'] = plan['tasks'].split(',') if plan['tasks'] else []
            plan['day_of_week'] = plan['day_of_week'].split(',') if plan['day_of_week'] else []

            # 查找该计划的最后一次执行记录
            last_execution = db.fetch_one('''
                SELECT * FROM EXECUTION_LOG 
                WHERE plan_id = %s 
                ORDER BY start_time DESC 
                LIMIT 1
            ''', (plan['id'],))

            plans_with_status.append({
                'plan': plan,
                'last_execution': last_execution
            })
    except Exception as e:
        flash(f'获取计划执行状态失败: {str(e)}', 'error')
        print(f'获取计划执行状态数据库错误: {e}')

    return render_template('execution_plan/execution.html',
                           username=session['name'],
                           plans_with_status=plans_with_status)


# 执行计划配置路由
@app.route('/execution_plan/config', methods=['GET', 'POST'])
@login_required
def plan_config():
    if request.method == 'POST':
        action = request.form.get('action', '').strip()

        if action == 'add':
            # 添加新计划
            plan_id = str(uuid.uuid4())[:8]
            name = request.form.get('plan_name', '').strip()
            description = request.form.get('description', '').strip()
            execution_type = request.form.get('execution_type', 'manual')
            frequency = request.form.get('frequency', 'daily')
            execution_time = request.form.get('execution_time', '')
            day_of_week = ','.join(request.form.getlist('day_of_week'))
            day_of_month = request.form.get('day_of_month', '')
            tasks = ','.join(request.form.getlist('tasks[]'))
            is_active = request.form.get('status') == 'on'
            created_by = session['username']
            created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            updated_at = created_at

            # 验证计划名称
            if not name:
                flash('计划名称不能为空', 'error')
                return redirect(url_for('plan_config'))

            # 验证定时任务时间
            if execution_type == 'scheduled' and not execution_time:
                flash('定时任务必须设置执行时间', 'error')
                return redirect(url_for('plan_config'))

            # 验证至少选择一个任务
            if not tasks:
                flash('至少需要选择一个测试任务', 'error')
                return redirect(url_for('plan_config'))

            try:
                # 插入新计划到数据库
                db.insert('EXECUTION_PLAN', {
                    'id': plan_id,
                    'name': name,
                    'description': description,
                    'type': execution_type,
                    'frequency': frequency,
                    'execution_time': execution_time,
                    'day_of_week': day_of_week,
                    'day_of_month': day_of_month,
                    'tasks': tasks,
                    'is_active': is_active,
                    'created_by': created_by,
                    'created_at': created_at,
                    'updated_at': updated_at
                })
                flash(f'执行计划 "{name}" 创建成功', 'success')
            except Exception as e:
                flash(f'创建计划失败: {str(e)}', 'error')
                print(f'创建执行计划数据库错误: {e}')

            return redirect(url_for('plan_config'))

        elif action == 'edit':
            # 编辑计划
            plan_id = request.form.get('plan_id', '').strip()
            if not plan_id:
                flash('计划ID不能为空', 'error')
                return redirect(url_for('plan_config'))

            name = request.form.get('plan_name', '').strip()
            description = request.form.get('description', '').strip()
            execution_type = request.form.get('execution_type', 'manual')
            frequency = request.form.get('frequency', 'daily')
            execution_time = request.form.get('execution_time', '')
            day_of_week = ','.join(request.form.getlist('day_of_week'))
            day_of_month = request.form.get('day_of_month', '')
            tasks = ','.join(request.form.getlist('tasks[]'))
            is_active = request.form.get('status') == 'on'
            updated_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            # 验证计划名称
            if not name:
                flash('计划名称不能为空', 'error')
                return redirect(url_for('plan_config'))

            # 验证定时任务时间
            if execution_type == 'scheduled' and not execution_time:
                flash('定时任务必须设置执行时间', 'error')
                return redirect(url_for('plan_config'))

            # 验证至少选择一个任务
            if not tasks:
                flash('至少需要选择一个测试任务', 'error')
                return redirect(url_for('plan_config'))

            try:
                # 更新计划到数据库
                db.update('EXECUTION_PLAN', {
                    'name': name,
                    'description': description,
                    'type': execution_type,
                    'frequency': frequency,
                    'execution_time': execution_time,
                    'day_of_week': day_of_week,
                    'day_of_month': day_of_month,
                    'tasks': tasks,
                    'is_active': is_active,
                    'updated_at': updated_at
                }, {'id': plan_id})

                # 检查是否有更新成功
                updated_plan = db.fetch_one('SELECT id FROM EXECUTION_PLAN WHERE id = %s', (plan_id,))
                if updated_plan:
                    flash(f'执行计划 "{name}" 更新成功', 'success')
                else:
                    flash('未找到指定的执行计划', 'error')
            except Exception as e:
                flash(f'更新计划失败: {str(e)}', 'error')
                print(f'更新执行计划数据库错误: {e}')

            return redirect(url_for('plan_config'))

        elif action == 'delete':
            # 删除计划
            plan_id = request.form.get('plan_id', '').strip()
            if not plan_id:
                flash('计划ID不能为空', 'error')
                return redirect(url_for('plan_config'))

            try:
                # 从数据库删除计划
                affected_rows = db.delete('EXECUTION_PLAN', {'id': plan_id})
                if affected_rows > 0:
                    flash('执行计划已删除', 'success')
                else:
                    flash('未找到指定的执行计划', 'error')
            except Exception as e:
                flash(f'删除计划失败: {str(e)}', 'error')
                print(f'删除执行计划数据库错误: {e}')

            return redirect(url_for('plan_config'))

    # 模拟测试任务数据
    test_tasks = [
        {'id': 'task1', 'name': 'API基础功能测试'},
        {'id': 'task2', 'name': '支付接口测试'},
        {'id': 'task3', 'name': '用户认证流程测试'},
        {'id': 'task4', 'name': '数据同步测试'}
    ]

    try:
        # 从数据库获取计划列表
        execution_plans = db.fetch_all('SELECT * FROM EXECUTION_PLAN ORDER BY created_at DESC')
        # 转换tasks字符串为列表
        for plan in execution_plans:
            plan['tasks'] = plan['tasks'].split(',') if plan['tasks'] else []
            plan['day_of_week'] = plan['day_of_week'].split(',') if plan['day_of_week'] else []
    except Exception as e:
        flash(f'获取计划列表失败: {str(e)}', 'error')
        print(f'获取执行计划数据库错误: {e}')
        execution_plans = []

    return render_template('execution_plan/config.html',
                           username=session['name'],
                           plans=execution_plans,
                           test_tasks=test_tasks)


# 执行计划日志
@app.route('/execution_plan/logs')
@login_required
def execution_logs_page():
    try:
        # 从数据库获取日志列表
        sorted_logs = db.fetch_all('SELECT * FROM EXECUTION_LOG ORDER BY start_time DESC')
    except Exception as e:
        flash(f'获取执行日志失败: {str(e)}', 'error')
        print(f'获取执行日志数据库错误: {e}')
        sorted_logs = []

    return render_template('execution_plan/logs.html',
                           username=session['name'],
                           logs=sorted_logs)

# 执行日志详情路由
@app.route('/execution_plan/logs/<log_id>')
@login_required
def log_details(log_id):
    try:
        # 从数据库获取日志详情
        log = db.fetch_one('SELECT * FROM EXECUTION_LOG WHERE id = %s', (log_id,))
        if not log:
            return jsonify({'status': 'error', 'message': '未找到日志记录'}), 404
        return jsonify(log)
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'获取日志详情失败: {str(e)}'}), 500





### 接口测试模块

###

### 接口测试模块 - 后端实现 ###

# 权限装饰器 - 仅超级管理员和项目管理员可访问
def project_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_role = session.get('role', 'viewer')
        project_id = kwargs.get('project_id')

        # 超级管理员有所有权限
        if user_role == 'admin':
            return f(*args, **kwargs)

        # 检查是否是项目管理员
        try:
            project = db.fetch_one('SELECT * FROM API_TEST_PROJECT WHERE id = %s', (project_id,))
            if not project or project.get('manager_id') != session.get('username'):
                flash('权限不足：只有超级管理员和项目管理员可以执行此操作', 'error')
                return redirect(url_for('api_test'))
        except Exception as e:
            flash(f'检查项目权限失败: {str(e)}', 'error')
            print(f'检查项目权限数据库错误: {e}')
            return redirect(url_for('api_test'))

        return f(*args, **kwargs)

    return decorated_function

@app.route('/api_test/')
@login_required
def api_test():
    return render_template('api_test.html', username=session['name'])

# 4.1 项目管理
@app.route('/api_test/projects', methods=['GET'])
@login_required
def api_test_projects():
    """项目管理首页"""
    search = request.args.get('search', '').strip()
    try:
        if search:
            # 带搜索条件查询
            filtered_projects = db.fetch_all('''
                SELECT * FROM API_TEST_PROJECT 
                WHERE LOWER(name) LIKE %s 
                ORDER BY created_at DESC
            ''', (f'%{search.lower()}%',))
        else:
            # 查询所有项目
            filtered_projects = db.fetch_all('SELECT * FROM API_TEST_PROJECT ORDER BY created_at DESC')
    except Exception as e:
        flash(f'获取项目列表失败: {str(e)}', 'error')
        print(f'获取项目列表数据库错误: {e}')
        filtered_projects = []

    return render_template('api_test.html',
                           username=session['name'],
                           projects=filtered_projects,
                           user_role=session.get('role'))


@app.route('/api_test/projects', methods=['POST'])
@login_required
def create_project():
    """创建新项目 - 仅管理员可操作"""
    if session.get('role') not in ['admin', 'operator']:
        flash('权限不足：只有管理员可以创建项目', 'error')
        return redirect(url_for('api_test_projects'))

    project_id = str(uuid.uuid4())[:8]
    name = request.form.get('name')
    description = request.form.get('description', '')
    version = request.form.get('version', '1.0.0')
    is_active = True
    created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    updated_at = created_at
    owner_id = session.get('id')

    # 验证必填字段
    if not owner_id:
        flash('请先登录', 'error')
        return redirect(url_for('login'))
    
    if not name:
        flash('项目名称不能为空', 'error')
        return redirect(url_for('api_test_projects'))

    try:
        # 插入新项目到数据库
        db.insert('API_TEST_PROJECT', {
            'id': project_id,
            'name': name,
            'description': description,
            'version': version,
            'is_active': is_active,
            'created_at': created_at,
            'updated_at': updated_at,
            'owner_id': owner_id
        })
        flash(f'项目 "{name}" 创建成功', 'success')
    except Exception as e:
        flash(f'创建项目失败: {str(e)}', 'error')
        print(f'创建项目数据库错误: {e}')

    return redirect(url_for('api_test_projects'))


@app.route('/api_test/projects/<project_id>', methods=['GET'])
@login_required
def get_project(project_id):
    """查看项目详情"""
    try:
        project = db.fetch_one('SELECT * FROM API_TEST_PROJECT WHERE id = %s', (project_id,))
        if not project:
            flash('项目不存在', 'error')
            return redirect(url_for('api_test_projects'))

        # 获取项目下的用例组
        groups = db.fetch_all('''
            SELECT * FROM API_TEST_GROUP 
            WHERE project_id = %s 
            ORDER BY created_at DESC
        ''', (project_id,))
    except Exception as e:
        flash(f'获取项目详情失败: {str(e)}', 'error')
        print(f'获取项目详情数据库错误: {e}')
        return redirect(url_for('api_test_projects'))

    return render_template('api_test/project_detail.html',
                           project=project,
                           groups=groups)


@app.route('/api_test/projects/<project_id>', methods=['PUT'])
@login_required
@project_admin_required
def update_project(project_id):
    """编辑项目"""
    try:
        # 检查项目是否存在
        project = db.fetch_one('SELECT * FROM API_TEST_PROJECT WHERE id = %s', (project_id,))
        if not project:
            return jsonify({'success': False, 'message': '项目不存在'}), 404

        name = request.json.get('name', project['name'])
        version = request.json.get('version', project['version'])
        description = request.json.get('description', project['description'])
        updated_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # 更新项目到数据库
        db.update('API_TEST_PROJECT', {
            'name': name,
            'version': version,
            'description': description,
            'updated_at': updated_at
        }, {'id': project_id})

        return jsonify({'success': True, 'message': '项目更新成功'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'项目更新失败: {str(e)}'}), 500


@app.route('/api_test/projects/<project_id>/status', methods=['PATCH'])
@login_required
@project_admin_required
def toggle_project_status(project_id):
    """启用/禁用项目"""
    try:
        # 检查项目是否存在
        project = db.fetch_one('SELECT * FROM API_TEST_PROJECT WHERE id = %s', (project_id,))
        if not project:
            return jsonify({'success': False, 'message': '项目不存在'}), 404

        new_status = 'inactive' if project['status'] == 'active' else 'active'
        updated_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # 更新项目状态到数据库
        db.update('API_TEST_PROJECT', {
            'status': new_status,
            'updated_at': updated_at
        }, {'id': project_id})

        return jsonify({
            'success': True,
            'message': f'项目已{"禁用" if new_status == "inactive" else "启用"}',
            'status': new_status
        })
    except Exception as e:
        return jsonify({'success': False, 'message': f'项目状态更新失败: {str(e)}'}), 500


@app.route('/api_test/projects/<project_id>', methods=['DELETE'])
@login_required
@project_admin_required
def delete_project(project_id):
    """删除项目"""
    try:
        # 检查项目是否存在
        project = db.fetch_one('SELECT * FROM API_TEST_PROJECT WHERE id = %s', (project_id,))
        if not project:
            return jsonify({'success': False, 'message': '项目不存在'}), 404

        # 开始事务
        db.begin_transaction()

        try:
            # 删除项目下的所有用例组
            db.delete('API_TEST_GROUP', {'project_id': project_id})

            # 删除项目下的所有接口用例
            db.delete('API_TEST_CASE', {'project_id': project_id})

            # 删除项目
            db.delete('API_TEST_PROJECT', {'id': project_id})

            # 提交事务
            db.commit_transaction()

            return jsonify({'success': True, 'message': '项目已删除'})
        except Exception as e:
            # 回滚事务
            db.rollback_transaction()
            return jsonify({'success': False, 'message': f'项目删除失败: {str(e)}'}), 500
    except Exception as e:
        return jsonify({'success': False, 'message': f'检查项目失败: {str(e)}'}), 500


# 4.2 用例组管理
@app.route('/api_test/projects/<project_id>/groups', methods=['POST'])
@login_required
def create_test_group(project_id):
    """创建用例组"""
    try:
        # 检查项目是否存在
        project = db.fetch_one('SELECT * FROM API_TEST_PROJECT WHERE id = %s', (project_id,))
        if not project:
            flash('项目不存在', 'error')
            return redirect(url_for('get_project', project_id=project_id))

        group_id = str(uuid.uuid4())[:8]
        name = request.form.get('name')
        priority = request.form.get('priority', 'P2')
        description = request.form.get('description', '')
        service = request.form.get('service', '')
        sprint = request.form.get('sprint', '')
        story_id = request.form.get('story_id', '')
        test_case_id = request.form.get('test_case_id', '')
        status = 'active'
        created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        updated_at = created_at

        # 验证必填字段
        if not name:
            flash('用例组名称不能为空', 'error')
            return redirect(url_for('get_project', project_id=project_id))

        if priority not in ['P1', 'P2']:
            flash('优先级必须是P1或P2', 'error')
            return redirect(url_for('get_project', project_id=project_id))

        # 插入新用例组到数据库
        db.insert('API_TEST_GROUP', {
            'id': group_id,
            'project_id': project_id,
            'name': name,
            'priority': priority,
            'description': description,
            'service': service,
            'sprint': sprint,
            'story_id': story_id,
            'test_case_id': test_case_id,
            'status': status,
            'created_at': created_at,
            'updated_at': updated_at
        })

        flash(f'用例组 "{name}" 创建成功', 'success')
    except Exception as e:
        flash(f'创建用例组失败: {str(e)}', 'error')
        print(f'创建用例组数据库错误: {e}')

    return redirect(url_for('get_project', project_id=project_id))


@app.route('/api_test/groups/<group_id>/copy', methods=['POST'])
@login_required
def copy_test_group(group_id):
    """复制用例组"""
    try:
        # 检查原始用例组是否存在
        original_group = db.fetch_one('SELECT * FROM API_TEST_GROUP WHERE id = %s', (group_id,))
        if not original_group:
            return jsonify({'success': False, 'message': '用例组不存在'}), 404

        # 开始事务
        db.begin_transaction()

        try:
            # 创建新用例组
            new_group_id = str(uuid.uuid4())[:8]
            new_group_name = f'Copy - {original_group["name"]}'
            created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            updated_at = created_at

            db.insert('API_TEST_GROUP', {
                'id': new_group_id,
                'project_id': original_group['project_id'],
                'name': new_group_name,
                'priority': original_group['priority'],
                'description': original_group['description'],
                'service': original_group['service'],
                'sprint': original_group['sprint'],
                'story_id': original_group['story_id'],
                'test_case_id': original_group['test_case_id'],
                'status': original_group['status'],
                'created_at': created_at,
                'updated_at': updated_at
            })

            # 复制用例组内的接口用例
            original_cases = db.fetch_all('SELECT * FROM API_TEST_CASE WHERE group_id = %s', (group_id,))
            for case in original_cases:
                new_case_id = str(uuid.uuid4())[:8]
                new_case_name = f'Copy - {case["name"]}'

                # 复制case数据，不包括id和group_id
                case_data = {
                    'id': new_case_id,
                    'group_id': new_group_id,
                    'project_id': case['project_id'],
                    'name': new_case_name,
                    'method': case['method'],
                    'protocol': case['protocol'],
                    'domain': case['domain'],
                    'route': case['route'],
                    'service': case['service'],
                    'sequence': case['sequence'],
                    'description': case['description'],
                    'clear_cookies': case['clear_cookies'],
                    'status': case['status'],
                    'created_at': created_at,
                    'updated_at': updated_at,
                    'headers': case['headers'],
                    'params': case['params'],
                    'initialization': case['initialization'],
                    'variables': case['variables'],
                    'validations': case['validations']
                }

                db.insert('API_TEST_CASE', case_data)

            # 提交事务
            db.commit_transaction()

            return jsonify({'success': True, 'message': '用例组复制成功'})
        except Exception as e:
            # 回滚事务
            db.rollback_transaction()
            return jsonify({'success': False, 'message': f'复制用例组失败: {str(e)}'}), 500
    except Exception as e:
        return jsonify({'success': False, 'message': f'检查用例组失败: {str(e)}'}), 500


# 4.3 接口用例管理
@app.route('/api_test/groups/<group_id>/cases', methods=['GET'])
@login_required
def get_test_cases(group_id):
    """获取用例组下的接口用例"""
    try:
        # 检查用例组是否存在
        group = db.fetch_one('SELECT * FROM API_TEST_GROUP WHERE id = %s', (group_id,))
        if not group:
            flash('用例组不存在', 'error')
            return redirect(url_for('api_test_projects'))

        # 获取项目信息
        project = db.fetch_one('SELECT * FROM API_TEST_PROJECT WHERE id = %s', (group['project_id'],))

        # 获取用例组下的接口用例
        cases = db.fetch_all('''
            SELECT * FROM API_TEST_CASE 
            WHERE group_id = %s 
            ORDER BY sequence, created_at
        ''', (group_id,))
    except Exception as e:
        flash(f'获取接口用例失败: {str(e)}', 'error')
        print(f'获取接口用例数据库错误: {e}')
        return redirect(url_for('api_test_projects'))

    return render_template('api_test/test_cases.html',
                           project=project,
                           group=group,
                           cases=cases)


@app.route('/api_test/groups/<group_id>/cases', methods=['POST'])
@login_required
def create_test_case(group_id):
    """创建接口用例"""
    try:
        # 检查用例组是否存在
        group = db.fetch_one('SELECT * FROM API_TEST_GROUP WHERE id = %s', (group_id,))
        if not group:
            return jsonify({'success': False, 'message': '用例组不存在'}), 404

        # 计算新用例的sequence（最大值+1）
        max_sequence_result = db.fetch_one('''
            SELECT MAX(sequence) as max_seq FROM API_TEST_CASE WHERE group_id = %s
        ''', (group_id,))
        max_sequence = max_sequence_result['max_seq'] if max_sequence_result['max_seq'] is not None else 0

        case_id = str(uuid.uuid4())[:8]
        name = request.json.get('name')
        method = request.json.get('method', 'GET')
        protocol = request.json.get('protocol', 'HTTP')
        domain = request.json.get('domain', '')
        route = request.json.get('route', '')
        service = request.json.get('service', '')
        sequence = max_sequence + 1
        description = request.json.get('description', '')
        clear_cookies = request.json.get('clear_cookies', False)
        status = 'active'
        created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        updated_at = created_at
        headers = []
        params = {'type': 'raw', 'content': ''}
        initialization = None
        variables = []
        validations = []

        # 验证必填字段
        if not name or not method or not route:
            return jsonify({'success': False, 'message': '用例名称、请求方法和路由为必填项'}), 400

        # 插入新接口用例到数据库
        db.insert('API_TEST_CASE', {
            'id': case_id,
            'group_id': group_id,
            'project_id': group['project_id'],
            'name': name,
            'method': method,
            'protocol': protocol,
            'domain': domain,
            'route': route,
            'service': service,
            'sequence': sequence,
            'description': description,
            'clear_cookies': clear_cookies,
            'status': status,
            'created_at': created_at,
            'updated_at': updated_at,
            'headers': headers,
            'params': params,
            'initialization': initialization,
            'variables': variables,
            'validations': validations
        })

        return jsonify({
            'success': True,
            'message': '接口用例创建成功',
            'case_id': case_id
        })
    except Exception as e:
        return jsonify({'success': False, 'message': f'创建接口用例失败: {str(e)}'}), 500


# 4.4 接口用例详情编辑
@app.route('/api_test/cases/<case_id>', methods=['GET'])
@login_required
def edit_test_case(case_id):
    """编辑接口用例详情"""
    try:
        # 获取接口用例信息
        case = db.fetch_one('SELECT * FROM API_TEST_CASE WHERE id = %s', (case_id,))
        if not case:
            flash('接口用例不存在', 'error')
            return redirect(url_for('api_test_projects'))

        # 获取用例组信息
        group = db.fetch_one('SELECT * FROM API_TEST_GROUP WHERE id = %s', (case['group_id'],))

        # 获取项目信息
        project = db.fetch_one('SELECT * FROM API_TEST_PROJECT WHERE id = %s', (group['project_id'],))

        # 获取环境配置（实际项目中应从环境配置模块获取）
        environments = [
            {'id': 'env1', 'name': '开发环境', 'domain': 'http://dev.api.com'},
            {'id': 'env2', 'name': '测试环境', 'domain': 'http://test.api.com'}
        ]
    except Exception as e:
        flash(f'获取接口用例详情失败: {str(e)}', 'error')
        print(f'获取接口用例详情数据库错误: {e}')
        return redirect(url_for('api_test_projects'))

    return render_template('api_test/edit_test_case.html',
                           project=project,
                           group=group,
                           case=case,
                           environments=environments)


@app.route('/api_test/cases/<case_id>/params', methods=['PUT'])
@login_required
def update_test_case_params(case_id):
    """更新接口用例请求参数"""
    try:
        # 检查接口用例是否存在
        case = db.fetch_one('SELECT * FROM API_TEST_CASE WHERE id = %s', (case_id,))
        if not case:
            return jsonify({'success': False, 'message': '接口用例不存在'}), 404

        # 获取更新的参数配置
        params = {
            'type': request.json.get('type', 'raw'),
            'content': request.json.get('content', '')
        }
        updated_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # 更新接口用例参数到数据库
        db.update('API_TEST_CASE', {
            'params': params,
            'updated_at': updated_at
        }, 'id = %s', (case_id,))

        return jsonify({'success': True, 'message': '请求参数更新成功'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'更新请求参数失败: {str(e)}'}), 500


# 4.5 全局参数配置
@app.route('/api_test/projects/<project_id>/variables', methods=['GET'])
@login_required
def get_global_variables(project_id):
    """获取项目全局参数"""
    try:
        # 检查项目是否存在
        project = db.fetch_one('SELECT * FROM API_TEST_PROJECT WHERE id = %s', (project_id,))
        if not project:
            flash('项目不存在', 'error')
            return redirect(url_for('api_test_projects'))

        # 获取环境列表（实际项目中应从环境配置模块获取）
        environments = [
            {'id': 'env1', 'name': '开发环境', 'domain': 'http://dev.api.com'},
            {'id': 'env2', 'name': '测试环境', 'domain': 'http://test.api.com'}
        ]

        # 获取指定环境的变量
        env_id = request.args.get('env_id', environments[0]['id'] if environments else '')
        variables = db.fetch_all('''
            SELECT * FROM API_TEST_VARIABLE WHERE project_id = %s AND env_id = %s
        ''', (project_id, env_id))
    except Exception as e:
        flash(f'获取全局参数失败: {str(e)}', 'error')
        print(f'获取全局参数数据库错误: {e}')
        return redirect(url_for('api_test_projects'))

    return render_template('api_test/global_variables.html',
                           project=project,
                           environments=environments,
                           current_env_id=env_id,
                           variables=variables)


# 4.6 用例执行
@app.route('/api_test/cases/<case_id>/execute', methods=['POST'])
@login_required
def execute_test_case(case_id):
    """执行单个接口用例"""
    try:
        # 检查接口用例是否存在
        case = db.fetch_one('SELECT * FROM API_TEST_CASE WHERE id = %s', (case_id,))
        if not case:
            return jsonify({'success': False, 'message': '接口用例不存在'}), 404

        env_id = request.json.get('env_id')
        # 实际项目中应根据环境获取域名等信息
        env_domain = 'http://test.api.com'

        # 模拟接口执行
        start_time = datetime.now()
        time.sleep(0.5)  # 模拟网络请求耗时
        end_time = datetime.now()

        # 构建请求URL
        domain = case['domain'] if case['domain'] else env_domain
        url = f"{domain}{case['route']}"

        # 模拟执行结果
        result = {
            'case_id': case_id,
            'start_time': start_time.strftime('%Y-%m-%d %H:%M:%S'),
            'end_time': end_time.strftime('%Y-%m-%d %H:%M:%S'),
            'duration': (end_time - start_time).total_seconds() * 1000,
            'request_url': url,
            'request_method': case['method'],
            'request_params': case['params'],
            'response_status': 200,
            'response_body': '{"status": "success", "data": "mock response"}',
            'validation_result': 'passed',
            'status': 'passed'
        }

        # 记录执行结果到数据库
        db.insert('API_TEST_EXECUTION', {
            'id': str(uuid.uuid4())[:8],
            'case_id': case_id,
            'project_id': case['project_id'],
            'env_id': env_id,
            'start_time': start_time.strftime('%Y-%m-%d %H:%M:%S'),
            'end_time': end_time.strftime('%Y-%m-%d %H:%M:%S'),
            'duration': result['duration'],
            'status': result['status'],
            'request_url': url,
            'request_method': case['method'],
            'request_params': case['params'],
            'response_status': result['response_status'],
            'response_body': result['response_body'],
            'validation_result': result['validation_result']
        })

        return jsonify({
            'success': True,
            'message': '用例执行完成',
            'result': result
        })
    except Exception as e:
        return jsonify({'success': False, 'message': f'执行用例失败: {str(e)}'}), 500


# 4.7 定时任务
@app.route('/api_test/projects/<project_id>/tasks', methods=['GET'])
@login_required
def get_scheduled_tasks(project_id):
    """获取项目定时任务"""
    try:
        # 检查项目是否存在
        project = db.fetch_one('SELECT * FROM API_TEST_PROJECT WHERE id = %s', (project_id,))
        if not project:
            flash('项目不存在', 'error')
            return redirect(url_for('api_test_projects'))

        # 获取项目定时任务
        tasks = db.fetch_all('''
            SELECT * FROM API_TEST_SCHEDULED_TASK WHERE project_id = %s
        ''', (project_id,))

        # 获取项目用例组
        groups = db.fetch_all('''
            SELECT * FROM API_TEST_GROUP WHERE project_id = %s
        ''', (project_id,))
    except Exception as e:
        flash(f'获取定时任务失败: {str(e)}', 'error')
        print(f'获取定时任务数据库错误: {e}')
        return redirect(url_for('api_test_projects'))

    return render_template('api_test/scheduled_tasks.html',
                           project=project,
                           tasks=tasks,
                           groups=groups)


@app.route('/api_test/projects/<project_id>/tasks', methods=['POST'])
@login_required
def create_scheduled_task(project_id):
    """创建定时任务"""
    try:
        # 检查项目是否存在
        project = db.fetch_one('SELECT * FROM API_TEST_PROJECT WHERE id = %s', (project_id,))
        if not project:
            return jsonify({'success': False, 'message': '项目不存在'}), 404

        trigger_type = request.json.get('trigger_type', 'specific_time')
        trigger_value = request.json.get('trigger_value')

        # 计算下次执行时间
        if trigger_type == 'specific_time':
            next_execution = trigger_value
        else:  # interval
            next_execution = (datetime.now() + timedelta(seconds=int(trigger_value))).strftime('%Y-%m-%d %H:%M:%S')

        task_id = str(uuid.uuid4())[:8]
        name = request.json.get('name')
        group_ids = request.json.get('group_ids', [])
        # 将group_ids列表转换为逗号分隔的字符串
        group_ids_str = ','.join(map(str, group_ids)) if group_ids else ''
        env_id = request.json.get('env_id')
        notify_wechat = request.json.get('notify_wechat', False)
        notify_dingtalk = request.json.get('notify_dingtalk', False)
        notify_email = request.json.get('notify_email', False)
        notify_only_failure = request.json.get('notify_only_failure', True)
        description = request.json.get('description', '')

        # 验证必填字段
        if not name or not group_ids or not env_id or not trigger_value:
            return jsonify({'success': False, 'message': '任务名称、用例组、测试环境和触发条件为必填项'}), 400

        # 插入定时任务到数据库
        db.insert('API_TEST_SCHEDULED_TASK', {
            'id': task_id,
            'project_id': project_id,
            'name': name,
            'group_ids': group_ids_str,
            'env_id': env_id,
            'trigger_type': trigger_type,
            'trigger_value': trigger_value,
            'next_execution': next_execution,
            'notify_wechat': notify_wechat,
            'notify_dingtalk': notify_dingtalk,
            'notify_email': notify_email,
            'notify_only_failure': notify_only_failure,
            'description': description,
            'status': 'active',
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })

        return jsonify({
            'success': True,
            'message': '定时任务创建成功',
            'task_id': task_id
        })
    except Exception as e:
        return jsonify({'success': False, 'message': f'创建定时任务失败: {str(e)}'}), 500


# 4.8 测试报告
@app.route('/api_test/projects/<project_id>/reports', methods=['GET'])
@login_required
def get_test_reports(project_id):
    """获取测试报告"""
    try:
        # 检查项目是否存在
        project = db.fetch_one('SELECT * FROM API_TEST_PROJECT WHERE id = %s', (project_id,))
        if not project:
            flash('项目不存在', 'error')
            return redirect(url_for('api_test_projects'))

        report_type = request.args.get('type', 'manual')
        # 从数据库获取测试报告
        reports = db.fetch_all('''
            SELECT * FROM API_TEST_REPORT WHERE project_id = %s AND type = %s
            ORDER BY created_at DESC
        ''', (project_id, report_type))
    except Exception as e:
        flash(f'获取测试报告失败: {str(e)}', 'error')
        print(f'获取测试报告数据库错误: {e}')
        return redirect(url_for('api_test_projects'))

    return render_template('api_test/test_reports.html',
                           project=project,
                           reports=reports,
                           report_type=report_type)




# 删除DB连接信息
@app.route('/environment_config/database/connection/delete', methods=['POST'])
@login_required
@admin_required
def delete_db_connection():
    conn_id = request.json.get('id')

    if not conn_id:
        return jsonify({'success': False, 'message': '连接ID为必填项'}), 400

    # 删除连接信息
    global db_connections
    original_count = len(db_connections)
    db_connections = [conn for conn in db_connections if conn['id'] != conn_id]

    if len(db_connections) < original_count:
        return jsonify({'success': True, 'message': '连接信息已删除成功'})
    else:
        return jsonify({'success': False, 'message': '未找到指定的连接信息'}), 404


# 环境配置主页
@app.route('/environment_config', methods=['GET']) 
@login_required
@admin_required
def environment_config_home():
    """环境配置主页"""
    return render_template('environment_config.html')


# 环境变量替换工具函数
@app.route('/api/environment/variable/replace', methods=['POST'])
@login_required
def replace_environment_variables():
    env_id = request.json.get('env_id')
    service_name = request.json.get('service_name')

    if not env_id or not service_name:
        return jsonify({'success': False, 'message': '环境ID和服务名为必填项'}), 400

    # 获取环境配置
    environment = next((env for env in test_environments if env['id'] == env_id), None)
    if not environment:
        return jsonify({'success': False, 'message': '未找到指定的环境'}), 404

    # 替换${service}变量
    domain = environment['domain'].replace('${service}', service_name)
    full_url = f"{environment['protocol']}://{domain}"

    return jsonify({
        'success': True,
        'domain': domain,
        'full_url': full_url
    })


# 启动应用
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
