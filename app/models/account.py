from datetime import datetime
from .. import db
from .association_tables import customer_accounts

class Account(db.Model):
    __tablename__ = 'accounts'
    
    id = db.Column(db.Integer, primary_key=True)
    account_number = db.Column(db.String(20), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    balance = db.Column(db.Numeric(15, 2), nullable=False, default=0.00)
    last_access_date = db.Column(db.DateTime, default=datetime.utcnow)
    account_type = db.Column(db.String(20), nullable=False)  # 'savings' 或 'checking'
    
    # 多态标识
    __mapper_args__ = {
        'polymorphic_identity': 'account',
        'polymorphic_on': account_type
    }
    
    # 关系
    owners = db.relationship('Customer', secondary=customer_accounts, 
                           back_populates='accounts')
    transactions = db.relationship('Transaction', backref='account', lazy='dynamic')
    loan_payments = db.relationship('LoanPayment', backref='payment_account', lazy='dynamic')
    
    def update_last_access(self):
        self.last_access_date = datetime.utcnow()
    
    def deposit(self, amount):
        if amount > 0:
            self.balance += amount
            self.update_last_access()
            return True
        return False
    
    def withdraw(self, amount):
        if amount > 0 and amount <= self.balance:
            self.balance -= amount
            self.update_last_access()
            return True
        return False
    
    def __repr__(self):
        return f'<Account {self.account_number} (Balance: {self.balance})>'

class SavingsAccount(Account):
    __tablename__ = 'savings_accounts'
    
    id = db.Column(db.Integer, db.ForeignKey('accounts.id'), primary_key=True)
    interest_rate = db.Column(db.Numeric(5, 4), nullable=False, default=0.0100)  # 利率，如0.01表示1%
    
    # 多态标识
    __mapper_args__ = {
        'polymorphic_identity': 'savings'
    }
    
    def __repr__(self):
        return f'<SavingsAccount {self.account_number} (Rate: {self.interest_rate})>'

class CheckingAccount(Account):
    __tablename__ = 'checking_accounts'
    
    id = db.Column(db.Integer, db.ForeignKey('accounts.id'), primary_key=True)
    overdraft_limit = db.Column(db.Numeric(15, 2), nullable=False, default=0.00)  # 可透支额度
    
    # 多态标识
    __mapper_args__ = {
        'polymorphic_identity': 'checking'
    }
    
    def withdraw(self, amount):
        if amount > 0 and amount <= self.balance + self.overdraft_limit:
            self.balance -= amount
            self.update_last_access()
            return True
        return False
    
    def __repr__(self):
        return f'<CheckingAccount {self.account_number} (Overdraft: {self.overdraft_limit})>'

# 交易记录模型
class Transaction(db.Model):
    __tablename__ = 'transactions'
    
    id = db.Column(db.Integer, primary_key=True)
    transaction_type = db.Column(db.String(20), nullable=False)  # 'deposit', 'withdraw', 'transfer', 'payment'
    amount = db.Column(db.Numeric(15, 2), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.String(200))
    
    # 关系
    account_id = db.Column(db.Integer, db.ForeignKey('accounts.id'), nullable=False)
    
    # 转账相关字段
    source_account_id = db.Column(db.Integer, db.ForeignKey('accounts.id'), nullable=True)
    target_account_id = db.Column(db.Integer, db.ForeignKey('accounts.id'), nullable=True)
    
    # 关系
    from_account = db.relationship('Account', foreign_keys=[source_account_id], backref='outgoing_transactions')
    to_account = db.relationship('Account', foreign_keys=[target_account_id], backref='incoming_transactions')
    
    def __repr__(self):
        return f'<Transaction {self.id}: {self.transaction_type} of {self.amount} on {self.timestamp}>'
