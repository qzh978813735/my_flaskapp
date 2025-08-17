from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_wtf.csrf import CSRFProtect
import uuid
from datetime import datetime
from functools import wraps
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# 初始化Flask应用
app = Flask(__name__)
app.secret_key = 'your-secure-secret-key-1234567890'  # 生产环境请更换为随机字符串

app.config['WTF_CSRF_ENABLED'] = True
csrf = CSRFProtect(app)
# 全局变量初始化（修复NameError）
mock_interfaces = {}  # MOCK接口配置
database_configs = []  # 数据库配置
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
users = {  # 用户数据
    'admin': {
        'password': 'admin123',  # 实际项目需哈希存储
        'name': '管理员',
        'role': 'admin',
        'status': 'active',
        'create_time': '2023-01-01 00:00:00'
    }
}


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
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not password:
            flash('用户名和密码不能为空', 'error')
            return render_template('login.html')

        user = users.get(username)
        if user and user['password'] == password and user['status'] == 'active':
            session['username'] = username
            session['name'] = user['name']
            session['role'] = user['role']
            flash(f'欢迎回来，{user["name"]}', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('用户名或密码错误，或账号已被禁用', 'error')

    return render_template('login.html')


# 登出路由
@app.route('/logout')
def logout():
    session.clear()
    flash('已成功退出登录', 'success')
    return redirect(url_for('login'))


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


# 用户管理路由
@app.route('/user_management', methods=['GET', 'POST'])
@admin_required
def user_management():
    global users

    if request.method == 'POST':
        action = request.form.get('action', '').strip()

        if action == 'add':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            name = request.form.get('name', '').strip()
            role = request.form.get('role', 'user')

            # 验证
            if not username or not password or not name:
                flash('用户名、密码和姓名不能为空', 'error')
                return redirect(url_for('user_management'))

            if username in users:
                flash(f'用户名 "{username}" 已存在', 'error')
                return redirect(url_for('user_management'))

            if len(password) < 6:
                flash('密码长度不能少于6位', 'error')
                return redirect(url_for('user_management'))

            # 添加用户
            users[username] = {
                'password': password,
                'name': name,
                'role': role,
                'status': 'active',
                'create_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            flash(f'用户 "{name}" 创建成功', 'success')
            return redirect(url_for('user_management'))

        elif action == 'edit':
            username = request.form.get('username', '').strip()
            name = request.form.get('name', '').strip()
            role = request.form.get('role', 'user')
            status = request.form.get('status', 'inactive')

            if not username or not name:
                flash('用户名和姓名不能为空', 'error')
                return redirect(url_for('user_management'))

            if username not in users:
                flash('用户不存在', 'error')
                return redirect(url_for('user_management'))

            # 不允许修改管理员自身角色
            if username == session['username'] and role != 'admin':
                flash('不能修改自身角色为非管理员', 'error')
                return redirect(url_for('user_management'))

            # 更新用户
            users[username]['name'] = name
            users[username]['role'] = role
            users[username]['status'] = status
            flash(f'用户 "{name}" 更新成功', 'success')
            return redirect(url_for('user_management'))

        elif action == 'delete':
            username = request.form.get('username', '').strip()

            if not username:
                flash('用户名不能为空', 'error')
                return redirect(url_for('user_management'))

            if username == session['username']:
                flash('不能删除当前登录用户', 'error')
                return redirect(url_for('user_management'))

            if username in users:
                del users[username]
                flash('用户已删除', 'success')
            else:
                flash('用户不存在', 'error')

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

            users[username]['password'] = new_password
            flash(f'用户 "{users[username]["name"]}" 密码已重置', 'success')
            return redirect(url_for('user_management'))

    return render_template('user_management.html',
                           username=session['name'],
                           users=users,
                           current_user_role=session['role'])


# 环境配置首页
@app.route('/environment_config')
@login_required
def environment_config():
    return render_template('environment_config/base.html',
                           username=session['name'])


# 数据库配置路由
@app.route('/environment_config', methods=['GET', 'POST'])
@login_required
def database_config():
    global database_configs

    if request.method == 'POST':
        config_id = request.form.get('config_id', '').strip()
        name = request.form.get('name', '').strip()
        db_type = request.form.get('db_type', '').strip()
        host = request.form.get('host', '').strip()
        port = request.form.get('port', '').strip()
        database = request.form.get('database', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        # 验证
        if not all([name, db_type, host, port, database, username]):
            flash('带*的字段为必填项', 'error')
            return redirect(url_for('database_config'))

        # 检查名称唯一性
        for config in database_configs:
            if config['id'] != config_id and config['name'] == name:
                flash(f'数据库配置名称 "{name}" 已存在', 'error')
                return redirect(url_for('database_config'))

        config_data = {
            'name': name,
            'db_type': db_type,
            'host': host,
            'port': port,
            'database': database,
            'username': username,
            'password': password,
            'description': request.form.get('description', '').strip(),
            'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        if config_id:
            # 编辑现有配置
            for i, config in enumerate(database_configs):
                if config['id'] == config_id:
                    config_data['id'] = config_id
                    config_data['created_at'] = config['created_at']
                    database_configs[i] = config_data
                    flash(f'数据库配置 "{name}" 已更新', 'success')
                    return redirect(url_for('database_config'))
            flash('未找到指定的数据库配置', 'error')
        else:
            # 添加新配置
            config_data['id'] = str(uuid.uuid4())[:8]
            config_data['created_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            database_configs.append(config_data)
            flash(f'数据库配置 "{name}" 已创建', 'success')

        return redirect(url_for('database_config'))

    # 处理删除操作
    if request.method == 'GET' and request.args.get('action') == 'delete':
        config_id = request.args.get('config_id', '').strip()
        if config_id:
            original_length = len(database_configs)
            database_configs = [c for c in database_configs if c['id'] != config_id]
            if len(database_configs) < original_length:
                flash('数据库配置已删除', 'success')
            else:
                flash('未找到指定的数据库配置', 'error')
        return redirect(url_for('database_config'))

    return render_template('environment_config/database_config.html',
                           username=session['name'],
                           databases=database_configs)


# 测试环境管理路由
@app.route('/test_environment_management', methods=['GET', 'POST'])
@login_required
def test_environment_management():
    global test_environments

    # 处理GET请求操作
    if request.method == 'GET':
        action = request.args.get('action', '').strip()
        env_id = request.args.get('env_id', '').strip()

        if action == 'set_default' and env_id:
            # 设置默认环境
            found = False
            for env in test_environments:
                if env['id'] == env_id:
                    # 先取消所有环境的默认状态
                    for e in test_environments:
                        e['is_default'] = False
                    env['is_default'] = True
                    flash(f'环境 "{env["name"]}" 已设为默认环境', 'success')
                    found = True
                    break
            if not found:
                flash('未找到指定的测试环境', 'error')
            return redirect(url_for('test_environment_management'))

        if action == 'delete' and env_id:
            # 删除环境
            original_length = len(test_environments)
            test_environments = [env for env in test_environments if env['id'] != env_id]
            if len(test_environments) < original_length:
                flash('测试环境已删除', 'success')
            else:
                flash('未找到指定的测试环境', 'error')
            return redirect(url_for('test_environment_management'))

    # 处理POST请求（添加/编辑环境）
    if request.method == 'POST':
        env_id = request.form.get('env_id', '').strip()
        name = request.form.get('name', '').strip()
        code = request.form.get('code', '').strip()
        base_url = request.form.get('base_url', '').strip()

        # 验证必填字段
        if not name:
            flash('环境名称不能为空', 'error')
            return redirect(url_for('test_environment_management'))
        if not code:
            flash('环境编码不能为空', 'error')
            return redirect(url_for('test_environment_management'))
        if not base_url:
            flash('基础URL不能为空', 'error')
            return redirect(url_for('test_environment_management'))

        # 验证唯一性
        for env in test_environments:
            if env['id'] != env_id and env['name'] == name:
                flash(f'环境名称 "{name}" 已存在', 'error')
                return redirect(url_for('test_environment_management'))
            if env['id'] != env_id and env['code'] == code:
                flash(f'环境编码 "{code}" 已存在', 'error')
                return redirect(url_for('test_environment_management'))

        # 准备环境数据
        env_data = {
            'name': name,
            'code': code,
            'base_url': base_url,
            'db_config_id': request.form.get('db_config_id', '').strip(),
            'owner': request.form.get('owner', '').strip(),
            'contact': request.form.get('contact', '').strip(),
            'description': request.form.get('description', '').strip(),
            'status': 'active' if request.form.get('status') else 'inactive',
            'is_default': request.form.get('is_default') == 'on',
            'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        # 如果设置为默认环境，取消其他环境的默认状态
        if env_data['is_default']:
            for env in test_environments:
                env['is_default'] = False

        if env_id:
            # 编辑现有环境
            for i, env in enumerate(test_environments):
                if env['id'] == env_id:
                    env_data['id'] = env_id
                    env_data['created_at'] = env['created_at']  # 保留创建时间
                    test_environments[i] = env_data
                    flash(f'测试环境 "{name}" 已更新', 'success')
                    return redirect(url_for('test_environment_management'))
            flash('未找到指定的测试环境', 'error')
        else:
            # 添加新环境
            env_data['id'] = str(uuid.uuid4())[:8]
            env_data['created_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            test_environments.append(env_data)
            flash(f'测试环境 "{name}" 已创建', 'success')

        return redirect(url_for('test_environment_management'))

    # 准备页面数据
    db_configs = database_configs
    environments_with_db = []
    for env in test_environments:
        db_name = next((db['name'] for db in db_configs if db['id'] == env['db_config_id']), None)
        environments_with_db.append({**env, 'db_config_name': db_name})

    return render_template('environment_config/test_environment_management.html',
                           username=session['name'],
                           environments=environments_with_db,
                           databases=db_configs)


# 邮件配置路由


# 邮件发件人配置路由
@app.route('/email_sender_config', methods=['GET', 'POST'])
@login_required
def email_sender_config():
    global email_config
    if request.method == 'POST':
        # 保存发件人配置
        email_config = {
            'smtp_server': request.form.get('smtp_server', '').strip(),
            'smtp_port': int(request.form.get('smtp_port', 587)),
            'sender_email': request.form.get('sender_email', '').strip(),
            'sender_password': request.form.get('sender_password', '').strip(),
            'use_tls': request.form.get('use_tls') == 'on'
        }
        flash('邮件服务器配置已保存', 'success')
        return redirect(url_for('email_sender_config'))
    return render_template('email_sender_config.html',
                           username=session['name'],
                           config=email_config)

# 邮件收件人配置路由
@app.route('/email_recipients_config', methods=['GET', 'POST'])
@login_required
def email_recipients_config():
    global email_recipients
    if request.method == 'POST':
        # 添加收件人
        email = request.form.get('email', '').strip()
        name = request.form.get('name', '').strip()
        if not email or not name:
            flash('邮箱和姓名不能为空', 'error')
            return redirect(url_for('email_recipients_config'))
        if '@' not in email:
            flash('邮箱格式不正确', 'error')
            return redirect(url_for('email_recipients_config'))
        if any(r['email'] == email for r in email_recipients):
            flash(f'邮箱 "{email}" 已存在', 'error')
            return redirect(url_for('email_recipients_config'))
        email_recipients.append({
            'id': str(uuid.uuid4())[:8],
            'email': email,
            'name': name,
            'is_active': request.form.get('is_active') == 'on',
            'create_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        flash(f'收件人 "{name}" 添加成功', 'success')
        return redirect(url_for('email_recipients_config'))
    return render_template('email_recipients_config.html',
                           username=session['name'],
                           recipients=email_recipients)

# 删除收件人路由
@app.route('/delete_recipient/<recipient_id>', methods=['POST'])
@login_required
def delete_recipient(recipient_id):
    global email_recipients
    original_length = len(email_recipients)
    email_recipients = [r for r in email_recipients if r['id'] != recipient_id]
    if len(email_recipients) < original_length:
        return jsonify({'status': 'success', 'message': '收件人已删除'})
    return jsonify({'status': 'error', 'message': '未找到收件人'})

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
    global mock_interfaces

    if request.method == 'POST':
        interface_id = request.form.get('id') or str(uuid.uuid4())
        name = request.form.get('name', '').strip()
        path = request.form.get('path', '').strip()
        method = request.form.get('method', 'GET')
        status_code = int(request.form.get('status_code', 200))
        response = request.form.get('response', '').strip()
        description = request.form.get('description', '').strip()
        status = 'active' if request.form.get('status') else 'inactive'

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

        # 验证路径+方法唯一性
        duplicate = False
        for int_id, int_data in mock_interfaces.items():
            if int_id != interface_id and int_data['path'] == path and int_data['method'] == method:
                duplicate = True
                break
        if duplicate:
            flash(f'该路径在{method}方法下已存在', 'error')
            return redirect(url_for('mock_config'))

        # 验证响应JSON格式
        parsed_response = {}
        if response:
            try:
                parsed_response = json.loads(response)
            except json.JSONDecodeError:
                flash('响应数据不是有效的JSON格式', 'error')
                return redirect(url_for('mock_config'))

        # 保存接口
        mock_interfaces[interface_id] = {
            'id': interface_id,
            'name': name,
            'path': path,
            'method': method,
            'status_code': status_code,
            'response': parsed_response,
            'description': description,
            'status': status,
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        flash(f'接口「{name}」保存成功', 'success')
        return redirect(url_for('mock_config'))

    return render_template('mock_config.html',
                           username=session['name'],
                           interfaces=mock_interfaces)


# 删除MOCK接口路由
@app.route('/delete_mock_interface', methods=['POST'])
@login_required
def delete_mock_interface():
    global mock_interfaces
    interface_id = request.form.get('id', '').strip()

    if interface_id in mock_interfaces:
        del mock_interfaces[interface_id]
        return jsonify({'success': True, 'message': '接口已删除'})
    else:
        return jsonify({'success': False, 'message': '接口不存在'}), 404


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
@app.route('/api_test')
@login_required
def api_test():
    # 获取默认环境
    default_env = next((e for e in test_environments if e['is_default']), None)
    return render_template('api_test.html',
                           username=session['name'],
                           environments=test_environments,
                           default_env=default_env)


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
    # 这里可以添加获取计划执行状态的逻辑
    # 示例数据，实际应根据业务逻辑获取
    plans_with_status = []
    for plan in execution_plans:
        # 查找该计划的最后一次执行记录
        last_execution = next((log for log in execution_logs
                              if log.get('plan_id') == plan['id']), None)
        plans_with_status.append({
            'plan': plan,
            'last_execution': last_execution
        })
    return render_template('execution_plan/execution.html',
                           username=session['name'],
                           plans_with_status=plans_with_status)


# 执行计划配置路由
@app.route('/execution_plan/config', methods=['GET', 'POST'])
@login_required
def plan_config():
    global execution_plans

    if request.method == 'POST':
        action = request.form.get('action', '').strip()

        if action == 'add':
            # 添加新计划
            plan_id = str(uuid.uuid4())[:8]
            new_plan = {
                'id': plan_id,
                'name': request.form.get('plan_name', '').strip(),
                'description': request.form.get('description', '').strip(),
                'type': request.form.get('execution_type', 'manual'),
                'schedule': {
                    'frequency': request.form.get('frequency', 'daily'),
                    'time': request.form.get('execution_time', ''),
                    'day_of_week': request.form.getlist('day_of_week'),
                    'day_of_month': request.form.get('day_of_month', '')
                },
                'tasks': request.form.getlist('tasks[]'),
                'status': 'active' if request.form.get('status') == 'on' else 'inactive',
                'created_by': session['username'],
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

            # 验证计划名称
            if not new_plan['name']:
                flash('计划名称不能为空', 'error')
                return redirect(url_for('plan_config'))

            # 验证定时任务时间
            if new_plan['type'] == 'scheduled' and not new_plan['schedule']['time']:
                flash('定时任务必须设置执行时间', 'error')
                return redirect(url_for('plan_config'))

            # 验证至少选择一个任务
            if not new_plan['tasks']:
                flash('至少需要选择一个测试任务', 'error')
                return redirect(url_for('plan_config'))

            execution_plans.append(new_plan)
            flash(f'执行计划 "{new_plan["name"]}" 创建成功', 'success')
            return redirect(url_for('plan_config'))

        elif action == 'edit':
            # 编辑计划
            plan_id = request.form.get('plan_id', '').strip()
            if not plan_id:
                flash('计划ID不能为空', 'error')
                return redirect(url_for('plan_config'))

            for plan in execution_plans:
                if plan['id'] == plan_id:
                    plan['name'] = request.form.get('plan_name', '').strip()
                    plan['description'] = request.form.get('description', '').strip()
                    plan['type'] = request.form.get('execution_type', 'manual')
                    plan['schedule'] = {
                        'frequency': request.form.get('frequency', 'daily'),
                        'time': request.form.get('execution_time', ''),
                        'day_of_week': request.form.getlist('day_of_week'),
                        'day_of_month': request.form.get('day_of_month', '')
                    }
                    plan['tasks'] = request.form.getlist('tasks[]')
                    plan['status'] = 'active' if request.form.get('status') == 'on' else 'inactive'
                    plan['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                    # 验证计划名称
                    if not plan['name']:
                        flash('计划名称不能为空', 'error')
                        return redirect(url_for('plan_config'))

                    # 验证定时任务时间
                    if plan['type'] == 'scheduled' and not plan['schedule']['time']:
                        flash('定时任务必须设置执行时间', 'error')
                        return redirect(url_for('plan_config'))

                    # 验证至少选择一个任务
                    if not plan['tasks']:
                        flash('至少需要选择一个测试任务', 'error')
                        return redirect(url_for('plan_config'))

                    flash(f'执行计划 "{plan["name"]}" 更新成功', 'success')
                    return redirect(url_for('plan_config'))

            flash('未找到指定的执行计划', 'error')
            return redirect(url_for('plan_config'))

        elif action == 'delete':
            # 删除计划
            plan_id = request.form.get('plan_id', '').strip()
            if not plan_id:
                flash('计划ID不能为空', 'error')
                return redirect(url_for('plan_config'))


            original_count = len(execution_plans)
            execution_plans = [p for p in execution_plans if p['id'] != plan_id]

            if len(execution_plans) < original_count:
                flash('执行计划已删除', 'success')
            else:
                flash('未找到指定的执行计划', 'error')

            return redirect(url_for('plan_config'))

    # 模拟测试任务数据
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


# 执行计划日志
@app.route('/execution_plan/logs')
@login_required
def execution_logs_page():
    # 按时间倒序排列日志
    sorted_logs = sorted(execution_logs, key=lambda x: x['time'], reverse=True)
    return render_template('execution_plan/logs.html',
                           username=session['name'],
                           logs=sorted_logs)


# 启动应用
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
