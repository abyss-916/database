from datetime import datetime
from .. import db
from .association_tables import customer_accounts, customer_loans

class Customer(db.Model):
    __tablename__ = 'customers'
    
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.String(20), unique=True, nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    id_card = db.Column(db.String(20), unique=True, nullable=False)  # 证件号
    city = db.Column(db.String(100), nullable=False)  # 居住城市
    street = db.Column(db.String(200), nullable=False)  # 街道
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # 关系
    assistant_id = db.Column(db.Integer, db.ForeignKey('employees.id'))  # 私人助理
    assistant = db.relationship('Employee', backref='customers', foreign_keys=[assistant_id])
    
    # 多对多关系
    accounts = db.relationship('Account', secondary=customer_accounts, 
                              back_populates='owners')
    loans = db.relationship('Loan', secondary=customer_loans, 
                           back_populates='borrowers')
    
    # 关联用户
    user = db.relationship('User', backref='customer', uselist=False)
    
    def __repr__(self):
        return f'<Customer {self.name} ({self.customer_id})>'
