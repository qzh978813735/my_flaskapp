from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import os
import uuid,time
from datetime import datetime
import hashlib  # 用于密码加密
# 现有代码中使用全局变量存储数据（如test_environments、database_configs等）
# 在多线程环境下存在风险，临时添加线程锁避免竞态条件
import threading
from flask import Flask
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # 必须设置密钥
csrf = CSRFProtect(app)  # 启用CSRF保护



# 在全局变量定义处添加锁
data_lock = threading.Lock()

# 初始化Flask应用
app = Flask(__name__)

# 扩展数据模型 - 执行计划
execution_plans = []  # 存储所有执行计划
execution_logs = []  # 存储执行日志
database_configs = []
# 设置会话密钥，用于加密会话数据
app.secret_key = os.environ.get('SECRET_KEY', 'dev_key_for_testing_only')

# 测试环境
test_environments = []

# 设置会话的过期时间，30分钟
# app.permanent_session_lifetime = timedelta(minutes=30)
# 确保会话cookie在浏览器关闭时过期
app.config.update(
    SESSION_COOKIE_SECURE=False,  # 开发环境
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
    # 不设置PERMANENT_SESSION_LIFETIME，使用默认值
)
# 模拟用户数据库
# 扩展用户模型，增加角色和状态
# 角色：admin(超级管理员), operator(操作员), viewer(查看者)
# 状态：active(激活), disabled(禁用)
users = {
    'admin': {
        'password': hashlib.md5('admin123'.encode()).hexdigest(),  # 简单加密
        'name': '超级管理员',
        'role': 'admin',
        'status': 'active',
        'create_time': '2025-01-01 00:00:00'
    },
    'operator': {
        'password': hashlib.md5('operator123'.encode()).hexdigest(),
        'name': '操作员',
        'role': 'operator',
        'status': 'active',
        'create_time': '2025-01-10 00:00:00'
    },
    'viewer': {
        'password': hashlib.md5('viewer123'.encode()).hexdigest(),
        'name': '查看者',
        'role': 'viewer',
        'status': 'active',
        'create_time': '2025-01-20 00:00:00'
    }
}


# 角色权限定义
role_permissions = {
    'admin': ['user_management', 'email_config', 'mock_data', 'api_test', 'execution_plan', 'permission_management'],
    'operator': ['mock_data', 'api_test', 'execution_plan'],
    'viewer': ['mock_data', 'api_test']
}


# 模拟MOCK接口数据库
# 存储格式: {接口ID: {name, path, method, response, status_code, create_time}}
mock_interfaces = {}

# 新增：邮件配置数据存储
# 发件人配置
sender_config = {
    'smtp_server': '',
    'smtp_port': 587,
    'smtp_username': '',
    'smtp_password': '',
    'sender_email': '',
    'use_ssl': False,
    'use_tls': True,
    'timeout': 30
}

# 收件人配置
recipients = {
    # 存储格式: {id: {name, email, is_active, create_time}}
}

# 登录验证装饰器
def login_required(f):
    def wrapper(*args, **kwargs):
        if 'username' not in session:
            flash('请先登录后再访问该页面', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    wrapper.__name__ = f.__name__
    return wrapper


# 超级管理员权限验证装饰器
def admin_required(f):
    def wrapper(*args, **kwargs):
        if 'username' not in session:
            flash('请先登录后再访问该页面', 'error')
            return redirect(url_for('login'))

        current_user = users.get(session['username'])
        if not current_user or current_user['role'] != 'admin':
            flash('权限不足，只有超级管理员可以访问该页面', 'error')
            return redirect(url_for('user_management'))
        return f(*args, **kwargs)

    wrapper.__name__ = f.__name__
    return wrapper

# 用户管理主页面
@app.route('/user_management')
@login_required
def user_management():
    # 默认显示用户列表（增加/禁用用户页面）
    return redirect(url_for('user_add_or_disable'))


# 1. 用户权限变更页面
@app.route('/user_management/permission_change', methods=['GET', 'POST'])
@login_required
def user_permission_change():
    if request.method == 'POST':
        username = request.form.get('username')
        new_role = request.form.get('role')

        if username in users and username != 'admin':  # 不允许修改超级管理员角色
            users[username]['role'] = new_role
            flash(f'用户 {users[username]["name"]} 的权限已更新为 {new_role}', 'success')
            return redirect(url_for('user_permission_change'))
        elif username == 'admin':
            flash('不允许修改超级管理员的权限', 'error')
        else:
            flash('用户不存在', 'error')

    # 获取当前用户角色，控制是否显示修改权限按钮
    current_user_role = users.get(session['username'], {}).get('role', '')
    return render_template('user_permission_change.html',
                           username=session['name'],
                           users=users,
                           current_user_role=current_user_role)


# 2. 增加/禁用用户页面
@app.route('/user_management/add_or_disable', methods=['GET', 'POST'])
@login_required
def user_add_or_disable():
    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'add':
            # 添加新用户
            username = request.form.get('username')
            if username in users:
                flash('用户名已存在', 'error')
                return redirect(url_for('user_add_or_disable'))

            users[username] = {
                'password': hashlib.md5(request.form.get('password').encode()).hexdigest(),
                'name': request.form.get('name'),
                'role': request.form.get('role'),
                'status': 'active',
                'create_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            flash(f'用户 {request.form.get("name")} 已成功添加', 'success')

        elif action == 'toggle_status':
            # 切换用户状态（启用/禁用）
            username = request.form.get('username')
            if username in users and username != 'admin':  # 不允许禁用超级管理员
                users[username]['status'] = 'active' if users[username]['status'] == 'disabled' else 'disabled'
                status_text = '启用' if users[username]['status'] == 'active' else '禁用'
                flash(f'用户 {users[username]["name"]} 已{status_text}', 'success')
            elif username == 'admin':
                flash('不允许禁用超级管理员', 'error')
            else:
                flash('用户不存在', 'error')

        return redirect(url_for('user_add_or_disable'))

    current_user_role = users.get(session['username'], {}).get('role', '')
    return render_template('user_add_or_disable.html',
                           username=session['name'],
                           users=users,
                           current_user_role=current_user_role)


# 3. 重置用户密码页面
@app.route('/user_management/reset_password', methods=['GET', 'POST'])
@login_required
def user_reset_password():
    if request.method == 'POST':
        username = request.form.get('username')
        new_password = request.form.get('new_password')

        if username in users and username != 'admin':  # 不允许重置超级管理员密码
            users[username]['password'] = hashlib.md5(new_password.encode()).hexdigest()
            flash(f'用户 {users[username]["name"]} 的密码已重置', 'success')
        elif username == 'admin':
            flash('不允许重置超级管理员的密码', 'error')
        else:
            flash('用户不存在', 'error')

        return redirect(url_for('user_reset_password'))

    current_user_role = users.get(session['username'], {}).get('role', '')
    return render_template('user_reset_password.html',
                           username=session['name'],
                           users=users,
                           current_user_role=current_user_role)


# 4. 权限管理页面（仅超级管理员可访问）
@app.route('/user_management/permission_management', methods=['GET', 'POST'])
@admin_required
def permission_management():
    if request.method == 'POST':
        role = request.form.get('role')
        permissions = request.form.getlist('permissions[]')

        if role in role_permissions:
            role_permissions[role] = permissions
            flash(f'{role} 角色的权限已更新', 'success')
        else:
            flash('角色不存在', 'error')

        return redirect(url_for('permission_management'))

    return render_template('permission_management.html',
                           username=session['name'],
                           roles=role_permissions.keys(),
                           role_permissions=role_permissions,
                           all_permissions=['user_management', 'email_config', 'mock_data', 'api_test',
                                            'execution_plan', 'permission_management'])




# 邮件配置主页面路由
@app.route('/email_config')
@login_required
def email_config():
    # 默认显示发件人配置
    return redirect(url_for('email_sender_config'))


# 发件人配置页面路由
@app.route('/email_config/sender', methods=['GET', 'POST'])
@login_required
def email_sender_config():
    global sender_config

    if request.method == 'POST':
        # 保存发件人配置
        sender_config.update({
            'smtp_server': request.form.get('smtp_server', ''),
            'smtp_port': int(request.form.get('smtp_port', 587)),
            'smtp_username': request.form.get('smtp_username', ''),
            'smtp_password': request.form.get('smtp_password', ''),
            'sender_email': request.form.get('sender_email', ''),
            'use_ssl': request.form.get('use_ssl') == 'on',
            'use_tls': request.form.get('use_tls') == 'on',
            'timeout': int(request.form.get('timeout', 30))
        })
        flash('发件人配置已保存', 'success')
        return redirect(url_for('email_sender_config'))

    return render_template('email_sender_config.html',
                           username=session['name'],
                           config=sender_config)


# 收件人配置页面路由
@app.route('/email_config/recipients', methods=['GET', 'POST'])
@login_required
def email_recipients_config():
    global recipients

    if request.method == 'POST':
        # 添加新收件人
        recipient_id = str(uuid.uuid4())
        recipients[recipient_id] = {
            'id': recipient_id,
            'name': request.form.get('name', ''),
            'email': request.form.get('email', ''),
            'is_active': request.form.get('is_active') == 'on',
            'create_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        flash('收件人已添加', 'success')
        return redirect(url_for('email_recipients_config'))

    return render_template('email_recipients_config.html',
                           username=session['name'],
                           recipients=recipients)


# 删除收件人
@app.route('/email_config/recipients/delete/<recipient_id>', methods=['POST'])
@login_required
def delete_recipient(recipient_id):
    global recipients
    if recipient_id in recipients:
        del recipients[recipient_id]
        return jsonify({'status': 'success', 'message': '收件人已删除'})
    return jsonify({'status': 'error', 'message': '收件人不存在'}), 404


# 测试邮件发送
@app.route('/email_config/test_send', methods=['POST'])
@login_required
def test_email_send():
    # 这里只是模拟发送，实际项目中需要添加真实的邮件发送逻辑
    import smtplib
    from email.mime.text import MIMEText

    try:
        # 获取发件人配置
        config = sender_config

        # 创建测试邮件内容
        msg = MIMEText('这是一封测试邮件，用于验证邮件配置是否正确。', 'plain', 'utf-8')
        msg['Subject'] = '邮件配置测试'
        msg['From'] = config['sender_email']
        msg['To'] = request.form.get('test_email', '')

        # 模拟发送过程
        # 实际项目中取消下面的注释并实现真实发送逻辑
        """
        server = smtplib.SMTP(config['smtp_server'], config['smtp_port'], timeout=config['timeout'])
        if config['use_tls']:
            server.starttls()
        server.login(config['smtp_username'], config['smtp_password'])
        server.sendmail(config['sender_email'], [msg['To']], msg.as_string())
        server.quit()
        """

        return jsonify({
            'status': 'success',
            'message': f'测试邮件已成功发送至 {msg["To"]}（模拟发送）'
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'发送失败：{str(e)}'}), 500


# 首页路由
@app.route('/')
def index():
    return redirect(url_for('dashboard') if 'username' in session else url_for('login'))


# 登录页面路由 - 修改登录逻辑，不设置永久会话
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username in users and users[username]['password'] == password:
            session['username'] = username
            session['name'] = users[username]['name']
            # 关键修改：移除session.permanent = True，不设置永久会话
            flash(f'登录成功，欢迎回来，{users[username]["name"]}！', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('登录失败，用户名或密码不正确', 'error')

    return render_template('login.html')

# 仪表盘路由
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=session['name'])


# MOCK数据主页面 - 作为父菜单
# 确保MOCK数据主页面路由正确
# @app.route('/mock_data')
# @login_required
# def mock_data():
#     # 确保模板路径正确
#     return render_template('mock_data.html', username=session['name'])
@app.route('/mock_data')
@login_required
def mock_data():
    # 传递接口数据到概览页面
    return render_template('mock_data.html',
                           username=session['name'],
                           interfaces=mock_interfaces)

# MOCK接口配置页面 - 作为MOCK数据的子功能
@app.route('/mock_data/config')
@login_required
def mock_config():
    # 传递所有已配置的MOCK接口到页面
    return render_template('mock_config.html',
                           username=session['name'],
                           interfaces=mock_interfaces)


# 添加/编辑MOCK接口的处理接口
@app.route('/mock_data/save_interface', methods=['POST'])
@login_required
def save_mock_interface():
    # 获取表单数据
    interface_id = request.form.get('id')  # 编辑时存在，新增时为空
    name = request.form.get('name')
    path = request.form.get('path')
    method = request.form.get('method')
    response = request.form.get('response')
    status_code = int(request.form.get('status_code', 200))

    # 验证路径格式
    if not path.startswith('/'):
        path = '/' + path

    # 检查路径是否已存在（编辑时排除自身）
    path_exists = any(
        i['path'] == path and i['method'] == method and id != interface_id
        for id, i in mock_interfaces.items()
    )

    if path_exists:
        flash(f'已存在相同路径和方法的MOCK接口: {method} {path}', 'error')
        return redirect(url_for('mock_config'))

    # 生成新ID或使用现有ID
    if not interface_id:
        interface_id = str(uuid.uuid4())
        flash('MOCK接口创建成功', 'success')
    else:
        flash('MOCK接口更新成功', 'success')

    # 保存接口配置
    mock_interfaces[interface_id] = {
        'id': interface_id,
        'name': name,
        'path': path,
        'method': method,
        'response': response,
        'status_code': status_code
    }

    return redirect(url_for('mock_config'))


# 删除MOCK接口
@app.route('/mock_data/delete_interface/<interface_id>', methods=['DELETE'])
@login_required
def delete_mock_interface(interface_id):
    if interface_id in mock_interfaces:
        del mock_interfaces[interface_id]
        return jsonify({'status': 'success', 'message': '接口已删除'})
    return jsonify({'status': 'error', 'message': '接口不存在'}), 404


# MOCK接口调用页面 - 作为MOCK数据的子功能
@app.route('/mock_data/call')
@login_required
def mock_call():
    return render_template('mock_call.html',
                           username=session['name'],
                           interfaces=mock_interfaces)


# 实际的MOCK接口端点 - 用于模拟API响应
@app.route('/mock/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def mock_endpoint(path):
    # 构建完整路径
    full_path = '/' + path

    # 查找匹配的MOCK接口
    for interface in mock_interfaces.values():
        if interface['path'] == full_path and interface['method'] == request.method:
            # 返回配置的响应和状态码
            return (
                interface['response'],
                interface['status_code'],
                {'Content-Type': 'application/json'}
            )

    # 未找到匹配的MOCK接口
    return jsonify({
        'error': '未找到匹配的MOCK接口',
        'path': full_path,
        'method': request.method
    }), 404


# 其他菜单路由保持不变
# @app.route('/user_management')
# @login_required
# def user_management():
#     return render_template('user_management.html', username=session['name'], users=users)


# @app.route('/environment_config')
# @login_required
# def environment_config():
#     return render_template('environment_config.html', username=session['name'])
# 环境配置页面
# @app.route('/environment_config')
# @login_required
# def environment_config():
#     # 处理逻辑（如获取环境配置数据等）
#     return render_template('environment_config.html', username=session['name'])
#

# 环境配置主页面
# @app.route('/environment_config')
# @login_required
# def environment_config():
#     # 默认显示数据库配置页面
#     return redirect(url_for('database_config'))

@app.route('/environment_config', methods=['GET', 'POST'])
@login_required
def environment_config():
    # 环境配置的处理逻辑
    return render_template('environment_config/base.html',
                          username=session['name'])  # 添加 username 参数

# 1. 数据库配置页面
@app.route('/environment_config/database', methods=['GET', 'POST'])
@login_required
def database_config():
    global database_configs

    # 处理删除操作
    if request.method == 'GET' and request.args.get('action') == 'delete':
        db_id = request.args.get('db_id')
        database_configs = [db for db in database_configs if db['id'] != db_id]
        flash('数据库配置已删除', 'success')
        return redirect(url_for('database_config'))

    # 处理添加/编辑操作
    if request.method == 'POST':
        db_id = request.form.get('db_id')
        db_data = {
            'name': request.form.get('name'),
            'type': request.form.get('type'),
            'host': request.form.get('host'),
            'port': request.form.get('port'),
            'dbname': request.form.get('dbname'),
            'username': request.form.get('username'),
            'password': request.form.get('password'),
            'charset': request.form.get('charset', 'utf8mb4'),
            'description': request.form.get('description'),
            'status': 'active' if request.form.get('status') else 'inactive',
            'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        if db_id:
            # 编辑现有配置
            for i, db in enumerate(database_configs):
                if db['id'] == db_id:
                    # 保留创建时间和ID
                    db_data['id'] = db_id
                    db_data['created_at'] = db['created_at']
                    database_configs[i] = db_data
                    flash(f'数据库配置 "{db_data["name"]}" 已更新', 'success')
                    break
        else:
            # 添加新配置
            db_data['id'] = str(uuid.uuid4())[:8]
            db_data['created_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            database_configs.append(db_data)
            flash(f'数据库配置 "{db_data["name"]}" 已创建', 'success')

        return redirect(url_for('database_config'))

        # 关键修复：传递 username 参数到模板
    return render_template('environment_config/database_config.html',
                           username=session['name'],  # 确保包含此参数
                           databases=database_configs)


# 2. 测试环境管理页面
@app.route('/environment_config/test_environments', methods=['GET', 'POST'])
@login_required
def test_environment_management():
    global test_environments

    # 处理设置默认环境
    if request.method == 'GET' and request.args.get('action') == 'set_default':
        env_id = request.args.get('env_id')
        # 先取消所有环境的默认状态
        for env in test_environments:
            env['is_default'] = False
        # 设置当前环境为默认
        for env in test_environments:
            if env['id'] == env_id:
                env['is_default'] = True
                flash(f'环境 "{env["name"]}" 已设为默认环境', 'success')
                break
        return redirect(url_for('test_environment_management'))

    # 处理删除操作
    if request.method == 'GET' and request.args.get('action') == 'delete':
        env_id = request.args.get('env_id')
        test_environments = [env for env in test_environments if env['id'] != env_id]
        flash('测试环境已删除', 'success')
        return redirect(url_for('test_environment_management'))

    # 处理添加/编辑操作
    if request.method == 'POST':
        env_id = request.form.get('env_id')
        env_data = {
            'name': request.form.get('name'),
            'code': request.form.get('code'),
            'base_url': request.form.get('base_url'),
            'db_config_id': request.form.get('db_config_id'),
            'owner': request.form.get('owner'),
            'contact': request.form.get('contact'),
            'description': request.form.get('description'),
            'status': 'active' if request.form.get('status') else 'inactive',
            'is_default': request.form.get('is_default') == 'on',
            'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        # 如果设置为默认环境，先取消其他环境的默认状态
        if env_data['is_default']:
            for env in test_environments:
                env['is_default'] = False

        if env_id:
            # 编辑现有环境
            for i, env in enumerate(test_environments):
                if env['id'] == env_id:
                    # 保留创建时间和ID
                    env_data['id'] = env_id
                    env_data['created_at'] = env['created_at']
                    test_environments[i] = env_data
                    flash(f'测试环境 "{env_data["name"]}" 已更新', 'success')
                    break
        else:
            # 添加新环境
            env_data['id'] = str(uuid.uuid4())[:8]
            env_data['created_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            test_environments.append(env_data)
            flash(f'测试环境 "{env_data["name"]}" 已创建', 'success')

        return redirect(url_for('test_environment_management'))

    # 获取数据库配置列表，用于环境关联
    db_configs = database_configs

    # 为每个环境添加关联的数据库配置名称
    environments_with_db = []
    for env in test_environments:
        db_config_name = next((db['name'] for db in db_configs if db['id'] == env['db_config_id']), None)
        environments_with_db.append({**env, 'db_config_name': db_config_name})

    return render_template('environment_config/test_environment_management.html',
                           username=session['name'],
                           environments=environments_with_db,
                           databases=db_configs)


# 测试数据库连接（AJAX接口）
@app.route('/environment_config/test_db_connection/<db_id>', methods=['POST'])
@login_required
def test_db_connection(db_id):
    # 查找数据库配置
    db_config = next((db for db in database_configs if db['id'] == db_id), None)
    if not db_config:
        return jsonify({'status': 'error', 'message': '数据库配置不存在'}), 404

    try:
        # 这里根据数据库类型进行实际连接测试
        # 实际项目中需要根据不同数据库类型编写对应的连接测试代码
        import time
        time.sleep(1)  # 模拟连接耗时

        # 模拟连接成功（实际项目中应替换为真实连接测试）
        success = True
        message = "连接成功" if success else "连接失败"

        return jsonify({
            'status': 'success' if success else 'error',
            'message': message
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'连接失败: {str(e)}'})


# @app.route('/email_config')
# @login_required
# def email_config():
#     return render_template('email_config.html', username=session['name'])


@app.route('/api_test')
@login_required
def api_test():
    return render_template('api_test.html', username=session['name'])


# @app.route('/execution_plan')
# @login_required
# def execution_plan():
#     return render_template('execution_plan.html', username=session['name'])


# 执行计划主页面
@app.route('/execution_plan')
@login_required
def execution_plan():
    # 默认显示计划配置页面
    return redirect(url_for('plan_config'))


# 1. 计划配置页面
# @app.route('/execution_plan/config', methods=['GET', 'POST'])
# @login_required
# def plan_config():
#     global execution_plans
#
#     if request.method == 'POST':
#         action = request.form.get('action')
#
#         if action == 'add':
#             # 添加新计划
#             plan_id = str(uuid.uuid4())[:8]
#             new_plan = {
#                 'id': plan_id,
#                 'name': request.form.get('plan_name'),
#                 'description': request.form.get('description'),
#                 'type': request.form.get('execution_type'),  # manual 或 scheduled
#                 'schedule': {
#                     'frequency': request.form.get('frequency'),  # daily, weekly, monthly
#                     'time': request.form.get('execution_time'),
#                     'day_of_week': request.form.get('day_of_week'),
#                     'day_of_month': request.form.get('day_of_month')
#                 },
#                 'tasks': request.form.getlist('tasks[]'),  # 关联的测试任务
#                 'status': 'active' if request.form.get('status') == 'on' else 'inactive',
#                 'created_by': session['username'],
#                 'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
#                 'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
#             }
#             execution_plans.append(new_plan)
#             flash(f'执行计划 "{new_plan["name"]}" 创建成功', 'success')
#             return redirect(url_for('plan_config'))
#
#         elif action == 'edit':
#             # 编辑计划
#             plan_id = request.form.get('plan_id')
#             for plan in execution_plans:
#                 if plan['id'] == plan_id:
#                     plan['name'] = request.form.get('plan_name')
#                     plan['description'] = request.form.get('description')
#                     plan['type'] = request.form.get('execution_type')
#                     plan['schedule'] = {
#                         'frequency': request.form.get('frequency'),
#                         'time': request.form.get('execution_time'),
#                         'day_of_week': request.form.get('day_of_week'),
#                         'day_of_month': request.form.get('day_of_month')
#                     }
#                     plan['tasks'] = request.form.getlist('tasks[]')
#                     plan['status'] = 'active' if request.form.get('status') == 'on' else 'inactive',
#                     plan['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
#                     flash(f'执行计划 "{plan["name"]}" 更新成功', 'success')
#                     return redirect(url_for('plan_config'))
#             flash('未找到指定的执行计划', 'error')
#             return redirect(url_for('plan_config'))
#
#         elif action == 'delete':
#             # 删除计划
#             # plan_id = request.form.get('plan_id')
#             # global execution_plans
#             # execution_plans = [p for p in execution_plans if p['id'] != plan_id]
#             # flash('执行计划已删除', 'success')
#             # return redirect(url_for('plan_config'))
#             # 删除计划 - 修复全局变量声明顺序
#             plan_id = request.form.get('plan_id')
#
#             execution_plans = [p for p in execution_plans if p['id'] != plan_id]
#             flash('执行计划已删除', 'success')
#             return redirect(url_for('plan_config'))
#
#     # 模拟测试任务数据（实际项目中应从数据库获取）
#     test_tasks = [
#         {'id': 'task1', 'name': 'API基础功能测试'},
#         {'id': 'task2', 'name': '支付接口测试'},
#         {'id': 'task3', 'name': '用户认证流程测试'},
#         {'id': 'task4', 'name': '数据同步测试'}
#     ]
#
#     return render_template('execution_plan/config.html',
#                            username=session['name'],
#                            plans=execution_plans,
#                            test_tasks=test_tasks)


# 2. 计划执行页面

# 1. 计划配置页面
@app.route('/execution_plan/config', methods=['GET', 'POST'])
@login_required
def plan_config():
    global execution_plans
    # 添加线程锁（全局变量线程安全处理）
    import threading
    data_lock = threading.Lock()

    if request.method == 'POST':
        # 添加CSRF验证（需先在app初始化时配置CSRFProtect）
        from flask_wtf.csrf import validate_csrf
        from wtforms import ValidationError
        try:
            validate_csrf(request.form.get('csrf_token'))
        except ValidationError:
            flash('表单验证失败，请刷新页面重试', 'error')
            return redirect(url_for('plan_config'))

        action = request.form.get('action')

        if action == 'add':
            # 输入验证
            plan_name = request.form.get('plan_name')
            execution_type = request.form.get('execution_type')
            tasks = request.form.getlist('tasks[]')

            if not plan_name or len(plan_name) > 50:
                flash('计划名称不能为空且长度不能超过50字符', 'error')
                return redirect(url_for('plan_config'))
            if not execution_type:
                flash('请选择执行类型', 'error')
                return redirect(url_for('plan_config'))
            if not tasks:
                flash('至少需要关联一个测试任务', 'error')
                return redirect(url_for('plan_config'))

            # 添加新计划（加锁保护）
            with data_lock:
                plan_id = str(uuid.uuid4())[:8]
                new_plan = {
                    'id': plan_id,
                    'name': plan_name,
                    'description': request.form.get('description') or '',
                    'type': execution_type,  # manual 或 scheduled
                    'schedule': {
                        'frequency': request.form.get('frequency') or '',
                        'time': request.form.get('execution_time') or '',
                        'day_of_week': request.form.get('day_of_week') or '',
                        'day_of_month': request.form.get('day_of_month') or ''
                    },
                    'tasks': tasks,
                    'status': 'active' if request.form.get('status') == 'on' else 'inactive',
                    'created_by': session['username'],
                    'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                execution_plans.append(new_plan)
            flash(f'执行计划 "{new_plan["name"]}" 创建成功', 'success')
            return redirect(url_for('plan_config'))


        elif action == 'edit':
            # 输入验证
            plan_id = request.form.get('plan_id')
            plan_name = request.form.get('plan_name')
            if not plan_id or not plan_name or len(plan_name) > 50:
                flash('计划ID不存在或名称格式错误', 'error')
                return redirect(url_for('plan_config'))

            # 编辑计划（加锁保护）
            with data_lock:
                for plan in execution_plans:
                    if plan['id'] == plan_id:
                        plan['name'] = plan_name
                        plan['description'] = request.form.get('description') or '',
                        plan['type'] = request.form.get('execution_type') or '',
                        plan['schedule'] = {
                            'frequency': request.form.get('frequency') or '',
                            'time': request.form.get('execution_time') or '',
                            'day_of_week': request.form.get('day_of_week') or '',
                            'day_of_month': request.form.get('day_of_month') or ''
                        },
                        plan['tasks'] = request.form.getlist('tasks[]') or [],
                        plan['status'] = 'active' if request.form.get('status') == 'on' else 'inactive',
                        plan['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        flash(f'执行计划 "{plan["name"]}" 更新成功', 'success')
                        return redirect(url_for('plan_config'))
            flash('未找到指定的执行计划', 'error')
            return redirect(url_for('plan_config'))

        elif action == 'delete':
            # 删除计划（加锁保护）
            plan_id = request.form.get('plan_id')
            if not plan_id:
                flash('计划ID不能为空', 'error')
                return redirect(url_for('plan_config'))

            with data_lock:

                execution_plans = [p for p in execution_plans if p['id'] != plan_id]
            flash('执行计划已删除', 'success')
            return redirect(url_for('plan_config'))

    # 模拟测试任务数据（实际项目中应从数据库获取）
    test_tasks = [
        {'id': 'task1', 'name': 'API基础功能测试'},
        {'id': 'task2', 'name': '支付接口测试'},
        {'id': 'task3', 'name': '用户认证流程测试'},
        {'id': 'task4', 'name': '数据同步测试'}
    ]

    return render_template('execution_plan/config.html',
                           username=session['name'],
                           plans=execution_plans,
                           test_tasks=test_tasks)
@app.route('/execution_plan/execution', methods=['GET', 'POST'])
@login_required
def plan_execution():
    if request.method == 'POST':
        # 手动执行计划
        plan_id = request.form.get('plan_id')
        plan = next((p for p in execution_plans if p['id'] == plan_id), None)

        if not plan:
            flash('未找到指定的执行计划', 'error')
            return redirect(url_for('plan_execution'))

        # 模拟执行过程
        log_id = str(uuid.uuid4())[:10]
        execution_log = {
            'id': log_id,
            'plan_id': plan_id,
            'plan_name': plan['name'],
            'status': 'running',
            'started_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'completed_at': None,
            'result': None,
            'executed_by': session['username'],
            'details': []
        }
        execution_logs.append(execution_log)

        # 模拟执行延迟（实际项目中应使用异步任务）
        time.sleep(2)

        # 更新执行结果
        for log in execution_logs:
            if log['id'] == log_id:
                log['status'] = 'success'  # 实际项目中根据真实执行结果设置
                log['completed_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                log['result'] = '成功'
                log['details'] = [
                    {'task': 'API基础功能测试', 'status': 'success', 'duration': '0.8s'},
                    {'task': '支付接口测试', 'status': 'success', 'duration': '1.2s'}
                ]

        flash(f'执行计划 "{plan["name"]}" 已启动', 'success')
        return redirect(url_for('plan_execution'))

    # 获取所有计划及其最后执行状态
    plans_with_status = []
    for plan in execution_plans:
        # 查找该计划的最后一次执行记录
        last_execution = next((log for log in reversed(execution_logs) if log['plan_id'] == plan['id']), None)

        plans_with_status.append({
            'plan': plan,
            'last_execution': last_execution
        })

    return render_template('execution_plan/execution.html',
                           username=session['name'],
                           plans_with_status=plans_with_status)


# 3. 操作日志页面
@app.route('/execution_plan/logs')
@login_required
def plan_logs():
    # 支持按计划和状态筛选
    plan_id = request.args.get('plan_id', '')
    status = request.args.get('status', '')

    # 筛选日志
    filtered_logs = execution_logs
    if plan_id:
        filtered_logs = [log for log in filtered_logs if log['plan_id'] == plan_id]
    if status:
        filtered_logs = [log for log in filtered_logs if log['status'] == status]

    # 按时间倒序排列
    filtered_logs.sort(key=lambda x: x['started_at'], reverse=True)

    return render_template('execution_plan/logs.html',
                           username=session['name'],
                           logs=filtered_logs,
                           plans=execution_plans,
                           current_plan_id=plan_id,
                           current_status=status)


# 获取计划执行详情（用于AJAX请求）
@app.route('/execution_plan/log_details/<log_id>')
@login_required
def log_details(log_id):
    log = next((log for log in execution_logs if log['id'] == log_id), None)
    if not log:
        return jsonify({'error': '未找到日志记录'}), 404
    return jsonify(log)


# 退出登录
@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('name', None)
    flash('您已成功退出登录', 'success')
    return redirect(url_for('login'))


# 应用入口
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)



