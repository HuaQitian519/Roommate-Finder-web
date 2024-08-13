# 使用官方 Python 镜像作为基础镜像
FROM python:3.9-slim

# 设置工作目录
WORKDIR /app

# 复制项目的依赖文件
COPY requirements.txt .

# 安装项目的依赖
RUN pip install --no-cache-dir -r requirements.txt

# 复制项目文件到工作目录
COPY . .

# 设置环境变量
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# 暴露应用端口
EXPOSE 8000

# 使用 Gunicorn 运行应用
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8000", "app:app"]