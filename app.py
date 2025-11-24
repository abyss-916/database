from flask import Flask
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_bootstrap import Bootstrap
import os
from dotenv import load_dotenv

# 从app.db导入延迟初始化的db对象
from app.db import db, init_db

# 加载环境变量
load_dotenv()

# 初始化Flask应用
app = Flask(__name__)

# 配置应用
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 初始化扩展
bootstrap = Bootstrap(app)
# 使用延迟初始化的方式初始化数据库
init_db(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'auth.login'
login_manager.login_message_category = 'info'

# 在这里导入User模型，避免循环导入
@login_manager.user_loader
def load_user(user_id):
    from app.models import User
    return User.query.get(int(user_id))

# 导入路由
from app.routes import auth, dashboard, accounts, loans, employees, customers

# 注册蓝图
app.register_blueprint(auth.bp)
app.register_blueprint(dashboard.bp)
app.register_blueprint(accounts.bp)
app.register_blueprint(loans.bp)
app.register_blueprint(employees.bp)
app.register_blueprint(customers.bp)

if __name__ == '__main__':
    app.run(debug=True)
