from datetime import datetime
from .. import db

class Employee(db.Model):
    __tablename__ = 'employees'
    
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.String(20), unique=True, nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    hire_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # 关系
    branch_id = db.Column(db.Integer, db.ForeignKey('branches.id'), nullable=False)
    manager_id = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=True)
    
    # 自引用关系 - 管理的员工
    managed_employees = db.relationship('Employee', 
                                       backref=db.backref('manager', remote_side=[id]))
    
    # 关联用户
    user = db.relationship('User', backref='employee', uselist=False)
    
    # 家属关系
    dependents = db.relationship('Dependent', backref='employee', lazy='dynamic', cascade='all, delete-orphan')
    
    def is_manager(self):
        return self.managed_employees.count() > 0
    
    def __repr__(self):
        return f'<Employee {self.name} ({self.employee_id})>'

class Dependent(db.Model):
    __tablename__ = 'dependents'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    relationship = db.Column(db.String(50), nullable=False)  # 与员工的关系
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=False)
    
    def __repr__(self):
        return f'<Dependent {self.name} ({self.relationship} of {self.employee_id})>'
