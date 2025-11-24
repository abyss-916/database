from flask_sqlalchemy import SQLAlchemy

# 延迟初始化SQLAlchemy对象，不立即绑定到Flask应用
# 这种方式可以避免循环导入问题
db = SQLAlchemy()

# 提供一个初始化函数，在Flask应用创建后调用
def init_db(app):
    """初始化数据库连接"""
    db.init_app(app)