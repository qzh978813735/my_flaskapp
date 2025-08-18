from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_wtf.csrf import CSRFProtect
import uuid
from datetime import datetime, timedelta
from functools import wraps
import json
import smtplib
import threading
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask_login import login_required, current_user
from datetime import datetime, timedelta
import uuid
import json
import threading
import time
from functools import wraps


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

# 执行日志详情路由
@app.route('/execution_plan/logs/<log_id>')
@login_required
def log_details(log_id):
    # 查找指定ID的日志
    log = next((log for log in execution_logs if log['id'] == log_id), None)
    if not log:
        return jsonify({'status': 'error', 'message': '未找到日志记录'}), 404
    return jsonify(log)





### 接口测试模块

###

### 接口测试模块 - 后端实现 ###

# 数据存储结构（实际项目中应使用数据库）
projects = []
test_case_groups = []
test_cases = []
global_variables = []
scheduled_tasks = []
test_reports = []


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
        project = next((p for p in projects if p['id'] == project_id), None)
        if not project or project.get('manager_id') != session.get('user_id'):
            flash('权限不足：只有超级管理员和项目管理员可以执行此操作', 'error')
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
    filtered_projects = [p for p in projects if search.lower() in p['name'].lower()] if search else projects

    return render_template('api_test/projects.html',
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

    project = {
        'id': str(uuid.uuid4())[:8],
        'name': request.form.get('name'),
        'version': request.form.get('version', '1.0'),
        'description': request.form.get('description', ''),
        'status': 'active',
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'manager_id': session.get('username')
    }

    # 验证必填字段
    if not project['name']:
        flash('项目名称不能为空', 'error')
        return redirect(url_for('api_test_projects'))

    projects.append(project)
    flash(f'项目 "{project["name"]}" 创建成功', 'success')
    return redirect(url_for('api_test_projects'))


@app.route('/api_test/projects/<project_id>', methods=['GET'])
@login_required
def get_project(project_id):
    """查看项目详情"""
    project = next((p for p in projects if p['id'] == project_id), None)
    if not project:
        flash('项目不存在', 'error')
        return redirect(url_for('api_test_projects'))

    # 获取项目下的用例组
    groups = [g for g in test_case_groups if g['project_id'] == project_id]

    return render_template('api_test/project_detail.html',
                           project=project,
                           groups=groups)


@app.route('/api_test/projects/<project_id>', methods=['PUT'])
@login_required
@project_admin_required
def update_project(project_id):
    """编辑项目"""
    project = next((p for p in projects if p['id'] == project_id), None)
    if not project:
        return jsonify({'success': False, 'message': '项目不存在'}), 404

    project['name'] = request.json.get('name', project['name'])
    project['version'] = request.json.get('version', project['version'])
    project['description'] = request.json.get('description', project['description'])
    project['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    return jsonify({'success': True, 'message': '项目更新成功'})


@app.route('/api_test/projects/<project_id>/status', methods=['PATCH'])
@login_required
@project_admin_required
def toggle_project_status(project_id):
    """启用/禁用项目"""
    project = next((p for p in projects if p['id'] == project_id), None)
    if not project:
        return jsonify({'success': False, 'message': '项目不存在'}), 404

    project['status'] = 'inactive' if project['status'] == 'active' else 'active'
    project['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    return jsonify({
        'success': True,
        'message': f'项目已{"禁用" if project["status"] == "inactive" else "启用"}',
        'status': project['status']
    })


@app.route('/api_test/projects/<project_id>', methods=['DELETE'])
@login_required
@project_admin_required
def delete_project(project_id):
    """删除项目"""
    global projects
    project = next((p for p in projects if p['id'] == project_id), None)
    if not project:
        return jsonify({'success': False, 'message': '项目不存在'}), 404

    projects = [p for p in projects if p['id'] != project_id]
    return jsonify({'success': True, 'message': '项目已删除'})


# 4.2 用例组管理
@app.route('/api_test/projects/<project_id>/groups', methods=['POST'])
@login_required
def create_test_group(project_id):
    """创建用例组"""
    project = next((p for p in projects if p['id'] == project_id), None)
    if not project:
        flash('项目不存在', 'error')
        return redirect(url_for('get_project', project_id=project_id))

    group = {
        'id': str(uuid.uuid4())[:8],
        'project_id': project_id,
        'name': request.form.get('name'),
        'priority': request.form.get('priority', 'P2'),
        'description': request.form.get('description', ''),
        'service': request.form.get('service', ''),
        'sprint': request.form.get('sprint', ''),
        'story_id': request.form.get('story_id', ''),
        'test_case_id': request.form.get('test_case_id', ''),
        'status': 'active',
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

    # 验证必填字段
    if not group['name']:
        flash('用例组名称不能为空', 'error')
        return redirect(url_for('get_project', project_id=project_id))

    if group['priority'] not in ['P1', 'P2']:
        flash('优先级必须是P1或P2', 'error')
        return redirect(url_for('get_project', project_id=project_id))

    test_case_groups.append(group)
    flash(f'用例组 "{group["name"]}" 创建成功', 'success')
    return redirect(url_for('get_project', project_id=project_id))


@app.route('/api_test/groups/<group_id>/copy', methods=['POST'])
@login_required
def copy_test_group(group_id):
    """复制用例组"""
    original_group = next((g for g in test_case_groups if g['id'] == group_id), None)
    if not original_group:
        return jsonify({'success': False, 'message': '用例组不存在'}), 404

    # 创建新用例组
    new_group = {
        'id': str(uuid.uuid4())[:8],
        'project_id': original_group['project_id'],
        'name': f'Copy - {original_group["name"]}',
        'priority': original_group['priority'],
        'description': original_group['description'],
        'service': original_group['service'],
        'sprint': original_group['sprint'],
        'story_id': original_group['story_id'],
        'test_case_id': original_group['test_case_id'],
        'status': original_group['status'],
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

    test_case_groups.append(new_group)

    # 复制用例组内的接口用例
    original_cases = [c for c in test_cases if c['group_id'] == group_id]
    for case in original_cases:
        new_case = {**case,
                    'id': str(uuid.uuid4())[:8],
                    'group_id': new_group['id'],
                    'name': f'Copy - {case["name"]}',
                    'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }
        test_cases.append(new_case)

    return jsonify({'success': True, 'message': '用例组复制成功'})


# 4.3 接口用例管理
@app.route('/api_test/groups/<group_id>/cases', methods=['GET'])
@login_required
def get_test_cases(group_id):
    """获取用例组下的接口用例"""
    group = next((g for g in test_case_groups if g['id'] == group_id), None)
    if not group:
        flash('用例组不存在', 'error')
        return redirect(url_for('api_test_projects'))

    project = next((p for p in projects if p['id'] == group['project_id']), None)
    cases = [c for c in test_cases if c['group_id'] == group_id]
    # 按sequence和创建时间排序
    cases.sort(key=lambda x: (x['sequence'], x['created_at']))

    return render_template('api_test/test_cases.html',
                           project=project,
                           group=group,
                           cases=cases)


@app.route('/api_test/groups/<group_id>/cases', methods=['POST'])
@login_required
def create_test_case(group_id):
    """创建接口用例"""
    group = next((g for g in test_case_groups if g['id'] == group_id), None)
    if not group:
        return jsonify({'success': False, 'message': '用例组不存在'}), 404

    # 计算新用例的sequence（最大值+1）
    group_cases = [c for c in test_cases if c['group_id'] == group_id]
    max_sequence = max([c['sequence'] for c in group_cases], default=0)

    case = {
        'id': str(uuid.uuid4())[:8],
        'group_id': group_id,
        'name': request.json.get('name'),
        'method': request.json.get('method', 'GET'),
        'protocol': request.json.get('protocol', 'HTTP'),
        'domain': request.json.get('domain', ''),
        'route': request.json.get('route', ''),
        'service': request.json.get('service', ''),
        'sequence': max_sequence + 1,
        'description': request.json.get('description', ''),
        'clear_cookies': request.json.get('clear_cookies', False),
        'status': 'active',
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        # 其他详细信息将在编辑页面补充
        'headers': [],
        'params': {'type': 'raw', 'content': ''},
        'initialization': None,
        'variables': [],
        'validations': []
    }

    # 验证必填字段
    if not case['name'] or not case['method'] or not case['route']:
        return jsonify({'success': False, 'message': '用例名称、请求方法和路由为必填项'}), 400

    test_cases.append(case)
    return jsonify({
        'success': True,
        'message': '接口用例创建成功',
        'case_id': case['id']
    })


# 4.4 接口用例详情编辑
@app.route('/api_test/cases/<case_id>', methods=['GET'])
@login_required
def edit_test_case(case_id):
    """编辑接口用例详情"""
    case = next((c for c in test_cases if c['id'] == case_id), None)
    if not case:
        flash('接口用例不存在', 'error')
        return redirect(url_for('api_test_projects'))

    group = next((g for g in test_case_groups if g['id'] == case['group_id']), None)
    project = next((p for p in projects if p['id'] == group['project_id']), None)

    # 获取环境配置（实际项目中应从环境配置模块获取）
    environments = [
        {'id': 'env1', 'name': '开发环境', 'domain': 'http://dev.api.com'},
        {'id': 'env2', 'name': '测试环境', 'domain': 'http://test.api.com'}
    ]

    return render_template('api_test/edit_test_case.html',
                           project=project,
                           group=group,
                           case=case,
                           environments=environments)


@app.route('/api_test/cases/<case_id>/params', methods=['PUT'])
@login_required
def update_test_case_params(case_id):
    """更新接口用例请求参数"""
    case = next((c for c in test_cases if c['id'] == case_id), None)
    if not case:
        return jsonify({'success': False, 'message': '接口用例不存在'}), 404

    case['params'] = {
        'type': request.json.get('type', 'raw'),
        'content': request.json.get('content', '')
    }
    case['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    return jsonify({'success': True, 'message': '请求参数更新成功'})


# 4.5 全局参数配置
@app.route('/api_test/projects/<project_id>/variables', methods=['GET'])
@login_required
def get_global_variables(project_id):
    """获取项目全局参数"""
    project = next((p for p in projects if p['id'] == project_id), None)
    if not project:
        flash('项目不存在', 'error')
        return redirect(url_for('api_test_projects'))

    # 获取环境列表
    environments = [
        {'id': 'env1', 'name': '开发环境', 'domain': 'http://dev.api.com'},
        {'id': 'env2', 'name': '测试环境', 'domain': 'http://test.api.com'}
    ]

    # 获取指定环境的变量（如果有）
    env_id = request.args.get('env_id', environments[0]['id'] if environments else '')
    variables = [v for v in global_variables if v['project_id'] == project_id and v['env_id'] == env_id]

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
    case = next((c for c in test_cases if c['id'] == case_id), None)
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

    return jsonify({
        'success': True,
        'message': '用例执行完成',
        'result': result
    })


# 4.7 定时任务
@app.route('/api_test/projects/<project_id>/tasks', methods=['GET'])
@login_required
def get_scheduled_tasks(project_id):
    """获取项目定时任务"""
    project = next((p for p in projects if p['id'] == project_id), None)
    if not project:
        flash('项目不存在', 'error')
        return redirect(url_for('api_test_projects'))

    tasks = [t for t in scheduled_tasks if t['project_id'] == project_id]
    groups = [g for g in test_case_groups if g['project_id'] == project_id]

    return render_template('api_test/scheduled_tasks.html',
                           project=project,
                           tasks=tasks,
                           groups=groups)


@app.route('/api_test/projects/<project_id>/tasks', methods=['POST'])
@login_required
def create_scheduled_task(project_id):
    """创建定时任务"""
    project = next((p for p in projects if p['id'] == project_id), None)
    if not project:
        return jsonify({'success': False, 'message': '项目不存在'}), 404

    trigger_type = request.json.get('trigger_type', 'specific_time')
    trigger_value = request.json.get('trigger_value')

    # 计算下次执行时间
    if trigger_type == 'specific_time':
        next_execution = trigger_value
    else:  # interval
        next_execution = (datetime.now() + timedelta(seconds=int(trigger_value))).strftime('%Y-%m-%d %H:%M:%S')

    task = {
        'id': str(uuid.uuid4())[:8],
        'project_id': project_id,
        'name': request.json.get('name'),
        'group_ids': request.json.get('group_ids', []),
        'env_id': request.json.get('env_id'),
        'trigger_type': trigger_type,
        'trigger_value': trigger_value,
        'next_execution': next_execution,
        'notify_wechat': request.json.get('notify_wechat', False),
        'notify_dingtalk': request.json.get('notify_dingtalk', False),
        'notify_email': request.json.get('notify_email', False),
        'notify_only_failure': request.json.get('notify_only_failure', True),
        'description': request.json.get('description', ''),
        'status': 'active',
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

    # 验证必填字段
    if not task['name'] or not task['group_ids'] or not task['env_id'] or not trigger_value:
        return jsonify({'success': False, 'message': '任务名称、用例组、测试环境和触发条件为必填项'}), 400

    scheduled_tasks.append(task)
    return jsonify({'success': True, 'message': '定时任务创建成功'})


# 4.8 测试报告
@app.route('/api_test/projects/<project_id>/reports', methods=['GET'])
@login_required
def get_test_reports(project_id):
    """获取测试报告"""
    project = next((p for p in projects if p['id'] == project_id), None)
    if not project:
        flash('项目不存在', 'error')
        return redirect(url_for('api_test_projects'))

    report_type = request.args.get('type', 'manual')
    reports = [r for r in test_reports if r['project_id'] == project_id and r['type'] == report_type]

    return render_template('api_test/test_reports.html',
                           project=project,
                           reports=reports,
                           report_type=report_type)

# 环境配置相关路由
# 环境配置首页
@app.route('/environment_config')
@login_required
@admin_required
def environment_config_home():
    # 默认重定向到测试环境管理页面
    print("Redirecting to test_environment_management")  # 添加调试信息
    return redirect(url_for('test_environment_management'))


# 测试环境管理
@app.route('/environment_config/test_environment', methods=['GET', 'POST'])
@login_required
@admin_required
def test_environment_management():
    global test_environments
    print("Accessing test_environment_management route")  # 添加调试信息

    if request.method == 'POST':
        env_id = request.json.get('id')
        name = request.json.get('name')
        protocol = request.json.get('protocol')
        domain = request.json.get('domain')
        description = request.json.get('description')

        # 验证必填字段
        if not name or not protocol or not domain:
            return jsonify({'success': False, 'message': '环境名称、HTTP协议和服务域名为必填项'}), 400

        # 检查名称唯一性
        for env in test_environments:
            if env['id'] != env_id and env['name'] == name:
                return jsonify({'success': False, 'message': f'环境名称 "{name}" 已存在'}), 400

        if env_id:
            # 更新现有环境
            for i, env in enumerate(test_environments):
                if env['id'] == env_id:
                    test_environments[i] = {
                        'id': env_id,
                        'name': name,
                        'protocol': protocol,
                        'domain': domain,
                        'description': description,
                        'status': env['status'],  # 保持原有状态
                        'created_at': env['created_at'],  # 保持创建时间
                        'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }
                    return jsonify({'success': True, 'message': f'环境 "{name}" 更新成功'})
            return jsonify({'success': False, 'message': '未找到指定的测试环境'}), 404
        else:
            # 添加新环境
            new_env = {
                'id': str(uuid.uuid4())[:8],
                'name': name,
                'protocol': protocol,
                'domain': domain,
                'description': description,
                'status': 'active',  # 默认为启用状态
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            test_environments.append(new_env)
            return jsonify({'success': True, 'message': f'环境 "{name}" 创建成功'})

    # GET请求，获取环境列表
    print("Rendering test_environment.html")  # 添加调试信息
    return render_template('environment_config/test_environment.html',
                           username=session['name'],
                           environments=test_environments)


# 切换测试环境状态（启用/禁用）
@app.route('/environment_config/test_environment/toggle_status', methods=['POST'])
@login_required
@admin_required
def toggle_environment_status():
    env_id = request.json.get('id')
    new_status = request.json.get('status')

    if not env_id or not new_status:
        return jsonify({'success': False, 'message': '环境ID和状态为必填项'}), 400

    for i, env in enumerate(test_environments):
        if env['id'] == env_id:
            test_environments[i]['status'] = new_status
            test_environments[i]['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            action = '启用' if new_status == 'active' else '禁用'
            return jsonify({'success': True, 'message': f'环境 "{env["name"]}" 已{action}成功'})

    return jsonify({'success': False, 'message': '未找到指定的测试环境'}), 404


# DB配置管理
@app.route('/environment_config/database', methods=['GET', 'POST'])
@login_required
@admin_required
def database_config_management():
    global database_configs

    if request.method == 'POST':
        db_id = request.json.get('id')
        name = request.json.get('name')
        db_type = request.json.get('type')
        description = request.json.get('description')

        # 验证必填字段
        if not name or not db_type:
            return jsonify({'success': False, 'message': 'DB名称和类型为必填项'}), 400

        # 检查名称唯一性
        for db in database_configs:
            if db['id'] != db_id and db['name'] == name:
                return jsonify({'success': False, 'message': f'DB名称 "{name}" 已存在'}), 400

        if db_id:
            # 更新现有DB配置
            for i, db in enumerate(database_configs):
                if db['id'] == db_id:
                    database_configs[i] = {
                        'id': db_id,
                        'name': name,
                        'type': db_type,
                        'description': description,
                        'status': db['status'],  # 保持原有状态
                        'created_at': db['created_at'],  # 保持创建时间
                        'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }
                    return jsonify({'success': True, 'message': f'DB配置 "{name}" 更新成功'})
            return jsonify({'success': False, 'message': '未找到指定的DB配置'}), 404
        else:
            # 添加新DB配置
            new_db = {
                'id': str(uuid.uuid4())[:8],
                'name': name,
                'type': db_type,
                'description': description,
                'status': 'active',  # 默认为启用状态
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            database_configs.append(new_db)
            return jsonify({'success': True, 'message': f'DB配置 "{name}" 创建成功'})

    # GET请求，获取DB配置列表
    return render_template('environment_config/database_config.html',
                           username=session['name'],
                           db_configs=database_configs)


# 切换DB配置状态（启用/禁用）
@app.route('/environment_config/database/toggle_status', methods=['POST'])
@login_required
@admin_required
def toggle_db_config_status():
    db_id = request.json.get('id')
    new_status = request.json.get('status')

    if not db_id or not new_status:
        return jsonify({'success': False, 'message': 'DB配置ID和状态为必填项'}), 400

    for i, db in enumerate(database_configs):
        if db['id'] == db_id:
            database_configs[i]['status'] = new_status
            database_configs[i]['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            action = '启用' if new_status == 'active' else '禁用'
            return jsonify({'success': True, 'message': f'DB配置 "{db["name"]}" 已{action}成功'})

    return jsonify({'success': False, 'message': '未找到指定的DB配置'}), 404


# DB连接信息管理
@app.route('/environment_config/database/<db_id>/connection', methods=['GET'])
@login_required
@admin_required
def db_connection_info(db_id):
    # 获取DB配置
    db_config = next((db for db in database_configs if db['id'] == db_id), None)
    if not db_config:
        flash('未找到指定的DB配置', 'error')
        return redirect(url_for('database_config_management'))

    # 获取所有测试环境
    environments = test_environments

    # 获取DB连接信息
    connections = [conn for conn in db_connections if conn['db_id'] == db_id]

    return render_template('environment_config/db_connection_info.html',
                           username=session['name'],
                           db_config=db_config,
                           environments=environments,
                           db_connections=connections)


# 更新DB连接信息
@app.route('/environment_config/database/connection/update', methods=['POST'])
@login_required
@admin_required
def update_db_connection():
    db_id = request.json.get('db_id')
    env_id = request.json.get('env_id')
    host = request.json.get('host')
    port = request.json.get('port')
    user = request.json.get('user')
    password = request.json.get('password')
    db_name = request.json.get('db_name')

    # 验证必填字段
    if not db_id or not env_id or not host or not port or not db_name:
        return jsonify({'success': False, 'message': 'DB ID、环境 ID、Host、Port 和 DB Name 为必填项'}), 400

    # 检查DB配置和环境是否存在
    db_config = next((db for db in database_configs if db['id'] == db_id), None)
    environment = next((env for env in test_environments if env['id'] == env_id), None)

    if not db_config:
        return jsonify({'success': False, 'message': '未找到指定的DB配置'}), 404
    if not environment:
        return jsonify({'success': False, 'message': '未找到指定的环境'}), 404

    # 查找现有连接
    connection = next((conn for conn in db_connections if conn['db_id'] == db_id and conn['env_id'] == env_id), None)

    connection_data = {
        'db_id': db_id,
        'env_id': env_id,
        'host': host,
        'port': port,
        'user': user,
        'db_name': db_name,
        'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

    # 如果提供了密码，则更新密码
    if password is not None:
        connection_data['password'] = password

    if connection:
        # 更新现有连接
        for i, conn in enumerate(db_connections):
            if conn['db_id'] == db_id and conn['env_id'] == env_id:
                connection_data['id'] = conn['id']
                connection_data['created_at'] = conn['created_at']
                db_connections[i] = connection_data
                return jsonify({'success': True, 'message': f'{environment["name"]} 的连接信息已更新'})
    else:
        # 添加新连接
        connection_data['id'] = str(uuid.uuid4())[:8]
        connection_data['created_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        db_connections.append(connection_data)
        return jsonify({'success': True, 'message': f'{environment["name"]} 的连接信息已创建'})


# 启动应用
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
