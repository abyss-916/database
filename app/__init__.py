# 应用程序初始化文件

# 从新创建的db.py模块导入db对象
from .db import db

# 导出db对象供其他模块使用
__all__ = ['db']
