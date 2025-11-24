from .. import db

# 客户与账户的多对多关系表
customer_accounts = db.Table('customer_accounts',
    db.Column('customer_id', db.Integer, db.ForeignKey('customers.id'), primary_key=True),
    db.Column('account_id', db.Integer, db.ForeignKey('accounts.id'), primary_key=True)
)

# 客户与贷款的多对多关系表
customer_loans = db.Table('customer_loans',
    db.Column('customer_id', db.Integer, db.ForeignKey('customers.id'), primary_key=True),
    db.Column('loan_id', db.Integer, db.ForeignKey('loans.id'), primary_key=True)
)