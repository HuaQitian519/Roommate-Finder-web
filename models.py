from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import numpy as np
db = SQLAlchemy()


class User(UserMixin, db.Model):
    is_admin = db.Column(db.Boolean, default=False)  # 标记用户是否为管理员
    is_approved = db.Column(db.Boolean, default=False)  # 标记用户是否通过审核
    is_banned = db.Column(db.Boolean, default=False)  # 标记用户是否被封禁
    has_found_roommate = db.Column(db.Boolean, default=0)
    gender = db.Column(db.String(10), nullable=False)
    last_updated = db.Column(db.DateTime, nullable=True)
    ip_address = db.Column(db.String(45), nullable=False)
    wechat = db.Column(db.String(50), nullable=True)
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)  # 用户名，用于登录
    real_name = db.Column(db.String(100), nullable=False)  # 真实姓名，用于显示
    password_hash = db.Column(db.String(128), nullable=False)
    major = db.Column(db.String(100), nullable=False)
    sleep_time = db.Column(db.String(5), nullable=False)  # 存储为 HH:MM 格式
    wake_time = db.Column(db.String(5), nullable=False)  # 存储为 HH:MM 格式
    ac_temp = db.Column(db.Integer, nullable=False)
    cleanliness = db.Column(db.Integer, nullable=False)
    bunk_preference = db.Column(db.String(10), nullable=False)
    study_habits = db.Column(db.String(100), nullable=False)
    roommate_preferences = db.Column(db.Text)
    weekend_stay = db.Column(db.String(10), nullable=False)
    group_life = db.Column(db.String(3), nullable=False)
    hobbies = db.Column(db.Text)
    dietary_restrictions = db.Column(db.Text)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def vectorize(self):
        # 将时间转换为分钟数
        sleep_time_value = self.time_to_minutes(self.sleep_time)
        wake_time_value = self.time_to_minutes(self.wake_time)

        # 各特征向量化
        bunk_preference_value = 1 if self.bunk_preference == "upper" else 0
        group_life_value = 1 if self.group_life == "是" else 0

        # 向量化并应用权重
        return np.array([
            sleep_time_value * 0.01,  # 将时间权重降低
            wake_time_value * 0.01,  # 将时间权重降低
            self.ac_temp * 0.1,  # 空调温度权重保持0.1
            self.cleanliness * 1.0,  # 洁癖程度权重保持1
            bunk_preference_value * 0.5,  # 上下铺偏好权重保持1
            group_life_value * 1.0  # 群体生活依赖权重保持1
        ])

    @staticmethod
    def time_to_minutes(time_str):
        """将 HH:MM 格式的时间转换为分钟数"""
        hours, minutes = map(int, time_str.split(':'))
        return hours * 60 + minutes


