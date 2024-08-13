from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash
from models import db, User
from config import Config
import numpy as np
from datetime import datetime, timedelta
import random
import string
from PIL import Image, ImageDraw, ImageFont
from flask import session, send_file
import io
app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    # 如果用户已登录并且是管理员，直接跳转到管理员仪表盘
    if current_user.is_authenticated and current_user.is_admin:
        return redirect(url_for('admin_dashboard'))

    random_users = []

    if current_user.is_authenticated:
        # 获取相同性别的所有用户（排除当前用户）
        same_gender_users = User.query.filter(
            User.id != current_user.id,
            User.has_found_roommate == False,
            User.is_approved == True,
            User.is_banned == False,
            User.is_admin == False,
            User.gender == current_user.gender
        ).all()

        # 随机选择几个用户来显示（例如 3 个）
        random_users = random.sample(same_gender_users, min(3, len(same_gender_users)))

    return render_template('index.html', random_users=random_users)

@app.route('/captcha')
def captcha():
    # 生成随机验证码
    letters = string.ascii_uppercase + string.digits
    captcha_text = ''.join(random.choice(letters) for _ in range(4))
    session['captcha'] = captcha_text  # 将验证码存储在session中

    # 生成图像
    image = Image.new('RGB', (120, 30), color = (255, 255, 255))
    draw = ImageDraw.Draw(image)

    # 尝试加载字体，使用系统默认字体
    try:
        font = ImageFont.truetype("arial.ttf", 22)
    except IOError:
        # 如果系统没有字体文件，使用默认字体
        font = ImageFont.load_default()

    draw.text((10, 5), captcha_text, font=font, fill=(0, 0, 0))

    # 返回图片
    img_io = io.BytesIO()
    image.save(img_io, 'PNG')
    img_io.seek(0)

    return send_file(img_io, mimetype='image/png')

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('你没有权限执行此操作。')
        return redirect(url_for('index'))

    user_to_delete = User.query.get_or_404(user_id)

    if user_to_delete.is_admin:
        flash('无法删除管理员账号。')
        return redirect(url_for('admin_dashboard'))  # 假设你有一个管理员控制面板

    db.session.delete(user_to_delete)
    db.session.commit()
    flash('用户已成功删除。')
    return redirect(url_for('admin_dashboard'))  # 重定向到管理员控制面板

@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('您没有权限访问此页面。')
        return redirect(url_for('index'))

    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)

@app.route('/admin/ban/<int:user_id>')
@login_required
def ban_user(user_id):
    if not current_user.is_admin:
        flash('您没有权限执行此操作。')
        return redirect(url_for('index'))

    user = User.query.get_or_404(user_id)
    user.is_banned = not user.is_banned  # 切换封禁状态
    db.session.commit()
    flash(f'用户 {user.username} 的封禁状态已更改。')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        flash('您没有权限执行此操作。')
        return redirect(url_for('index'))

    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        user.real_name = request.form['real_name']
        user.username = request.form['username']
        user.gender = request.form['gender']
        user.major = request.form['major']
        user.sleep_time = request.form['sleep_time']
        user.wake_time = request.form['wake_time']
        user.ac_temp = int(request.form['ac_temp'])
        user.cleanliness = int(request.form['cleanliness'])
        user.bunk_preference = request.form['bunk_preference']
        user.study_habits = request.form['study_habits']
        user.weekend_stay = request.form['weekend_stay']
        user.group_life = request.form['group_life']
        user.hobbies = request.form['hobbies']
        user.dietary_restrictions = request.form['dietary_restrictions']
        user.wechat = request.form['wechat']

        # 处理密码更新
        new_password = request.form['password']
        if new_password:  # 如果输入了新密码
            user.password_hash = generate_password_hash(new_password)

        db.session.commit()
        flash(f'用户 {user.username} 的信息已更新。')
        return redirect(url_for('admin_dashboard'))

    return render_template('edit_user.html', user=user)

@app.route('/admin/approve/<int:user_id>')
@login_required
def approve_user(user_id):
    if not current_user.is_admin:
        flash('您没有权限执行此操作。')
        return redirect(url_for('index'))

    user = User.query.get_or_404(user_id)
    user.is_approved = True
    db.session.commit()
    flash(f'用户 {user.username} 已通过审核。')
    return redirect(url_for('admin_dashboard'))

@app.route('/toggle_roommate_status', methods=['POST'])
@login_required
def toggle_roommate_status():
    current_user.has_found_roommate = not current_user.has_found_roommate  # 切换状态
    db.session.commit()

    if current_user.has_found_roommate:
        flash('您已标记为已找到室友。您将不再参与匹配。')
    else:
        flash('已取消“已找到室友”标记，您将重新参与匹配。')

    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        ip_address = request.headers.get('True-Client-IP', request.remote_addr)
        existing_ip_user = User.query.filter_by(ip_address=ip_address).first()

        if existing_ip_user:
            flash('该IP地址已经注册过账号，无法再次注册。')
            return redirect(url_for('register'))

        username = request.form['username']
        wechat = request.form['wechat']

        # 检查是否有相同的用户名或微信号
        existing_user = User.query.filter(
            (User.username == username) |
            (User.wechat == wechat)
        ).first()

        if existing_user:
            flash('用户名或微信号已被使用，请选择其他用户名或微信号。')
            return redirect(url_for('register'))

        real_name = request.form['real_name']
        password = request.form['password']
        major = request.form['major']
        gender = request.form['gender']
        sleep_time = request.form['sleep_time']
        wake_time = request.form['wake_time']
        ac_temp = int(request.form['ac_temp'])
        cleanliness = int(request.form['cleanliness'])
        bunk_preference = request.form['bunk_preference']
        study_habits = request.form['study_habits']
        roommate_preferences = request.form['roommate_preferences']
        weekend_stay = request.form['weekend_stay']
        group_life = request.form['group_life']
        hobbies = request.form['hobbies']
        dietary_restrictions = request.form['dietary_restrictions']

        new_user = User(
            real_name=real_name,
            username=username,
            major=major,
            gender=gender,
            sleep_time=sleep_time,
            wake_time=wake_time,
            ac_temp=ac_temp,
            cleanliness=cleanliness,
            bunk_preference=bunk_preference,
            study_habits=study_habits,
            roommate_preferences=roommate_preferences,
            weekend_stay=weekend_stay,
            group_life=group_life,
            hobbies=hobbies,
            dietary_restrictions=dietary_restrictions,
            wechat=wechat,
            ip_address=ip_address
        )
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()
        flash('注册成功，请登录。')
        return redirect(url_for('login'))

    return render_template('register.html')

    if request.method == 'POST':
        ip_address = request.remote_addr
        existing_user = User.query.filter_by(ip_address=ip_address).first()

        if existing_user:
            flash('该IP地址已经注册过账号，无法再次注册。')
            return redirect(url_for('register'))

        username = request.form['username']
        password = request.form['password']
        major = request.form['major']
        sleep_time = request.form['sleep_time']
        wake_time = request.form['wake_time']
        ac_temp = int(request.form['ac_temp'])
        cleanliness = int(request.form['cleanliness'])
        bunk_preference = request.form['bunk_preference']
        study_habits = request.form['study_habits']
        roommate_preferences = request.form['roommate_preferences']
        weekend_stay = request.form['weekend_stay']
        group_life = request.form['group_life']
        hobbies = request.form['hobbies']
        dietary_restrictions = request.form['dietary_restrictions']
        wechat = request.form['wechat']

        new_user = User(
            username=username,
            major=major,
            sleep_time=sleep_time,
            wake_time=wake_time,
            ac_temp=ac_temp,
            cleanliness=cleanliness,
            bunk_preference=bunk_preference,
            study_habits=study_habits,
            roommate_preferences=roommate_preferences,
            weekend_stay=weekend_stay,
            group_life=group_life,
            hobbies=hobbies,
            dietary_restrictions=dietary_restrictions,
            wechat=wechat,
            ip_address=ip_address  # 保存IP地址
        )
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()
        flash('注册成功，请登录。')
        return redirect(url_for('login'))

    return render_template('register.html')


login_attempts = {}

def clean_login_attempts():
    now = datetime.now()
    for ip, data in list(login_attempts.items()):
        if now >= data['last_attempt'] + timedelta(hours=24):
            del login_attempts[ip]
@app.route('/login', methods=['GET', 'POST'])
def login():
    clean_login_attempts()
    ip_address = request.remote_addr
    now = datetime.now()

    # 检查是否超过24小时的登录限制
    if ip_address in login_attempts:
        attempt_data = login_attempts[ip_address]
        if attempt_data['count'] >= 10 and now < attempt_data['last_attempt'] + timedelta(hours=24):
            flash('您已尝试登录失败次数过多，请24小时后再试。')
            return redirect(url_for('index'))

    if request.method == 'POST':
        # 检查验证码
        captcha_input = request.form['captcha']
        if captcha_input.lower() != session.get('captcha', '').lower():
            flash('验证码错误。')
            return redirect(url_for('login'))

        # 处理登录逻辑
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user is None or not user.check_password(password):
            flash('用户名或密码错误。')

            # 记录登录尝试
            if ip_address not in login_attempts:
                login_attempts[ip_address] = {'count': 1, 'last_attempt': now}
            else:
                login_attempts[ip_address]['count'] += 1
                login_attempts[ip_address]['last_attempt'] = now

            return redirect(url_for('login'))

        if user.is_banned:
            flash('该用户已经被封禁。')
            return redirect(url_for('login'))

        # 登录成功，清除该IP的登录尝试计数
        if ip_address in login_attempts:
            del login_attempts[ip_address]

        login_user(user)
        return redirect(url_for('index'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        now = datetime.now()

        # 检查上次更新时间是否超过 24 小时
        if current_user.last_updated and (now - current_user.last_updated).total_seconds() < 86400:
            flash('您一天只能修改一次信息，请稍后再试。')
            return redirect(url_for('profile'))

        current_user.major = request.form['major']
        current_user.sleep_time = request.form['sleep_time']
        current_user.wake_time = request.form['wake_time']
        current_user.ac_temp = int(request.form['ac_temp'])
        current_user.cleanliness = int(request.form['cleanliness'])
        current_user.bunk_preference = request.form['bunk_preference']
        current_user.study_habits = request.form['study_habits']
        current_user.roommate_preferences = request.form['roommate_preferences']
        current_user.weekend_stay = request.form['weekend_stay']
        current_user.group_life = request.form['group_life']
        current_user.hobbies = request.form['hobbies']
        current_user.dietary_restrictions = request.form['dietary_restrictions']


        # 更新 last_updated 字段
        current_user.last_updated = now

        db.session.commit()
        flash('信息更新成功！')

    return render_template('profile.html', user=current_user)


@app.route('/match')
@login_required
def match():
    if current_user.has_found_roommate:
        flash('您已找到室友，不再参与匹配。')
        return redirect(url_for('index'))
    current_vector = current_user.vectorize()

    # 根据用户性别和是否选择了只匹配本专业的同学来过滤用户
    if request.args.get('same_major_only') == 'yes':
        all_users = User.query.filter(
            User.id != current_user.id,
            User.major == current_user.major,
            User.has_found_roommate == False,
            User.gender == current_user.gender,
            User.is_approved == True,
            User.is_admin == False,
            User.is_banned == False
            # 只匹配 "male" 或 "female"
        ).all()
    else:
        all_users = User.query.filter(
            User.id != current_user.id,
            User.has_found_roommate == False,
            User.is_approved == True,
            User.is_banned == False,
            User.is_admin==False,
            User.gender == current_user.gender  # 只匹配 "male" 或 "female"
        ).all()

    print(f"Current User: {current_user.username}, Vector: {current_vector}")

    def calculate_similarity(user_vector):
        # 使用欧几里得距离计算相似度，距离越小越相似
        distance = np.linalg.norm(current_vector - user_vector)
        return distance

    similarities = []

    for user in all_users:
        try:
            user_vector = user.vectorize()
            similarity_score = calculate_similarity(user_vector)
            print(f"Comparing with {user.username}, Vector: {user_vector}, Similarity Score: {similarity_score}")
            similarities.append((user, similarity_score))
        except Exception as e:
            print(f"Error processing user {user.username}: {e}")
            continue

    # 根据相似度从低到高排序（分数越低，匹配度越高）
    similarities.sort(key=lambda x: x[1])

    # 获取最匹配的3个用户
    matched_users = [user for user, score in similarities[:3]]

    # 检查匹配的用户列表
    print(f"Matched Users: {[user.username for user in matched_users]}")

    if not matched_users:
        flash("未找到合适的匹配室友，可能是由于数据量过少的原因，等一会再来看看吧。")
        return redirect(url_for('index'))

    return render_template('match.html', matched_users=matched_users)

app.config.from_object('config.ProductionConfig')
if __name__ == '__main__':
    app.run(debug=False)
