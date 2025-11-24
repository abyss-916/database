from datetime import datetime
from .. import db
from .association_tables import customer_loans

class Loan(db.Model):
    __tablename__ = 'loans'
    
    id = db.Column(db.Integer, primary_key=True)
    loan_number = db.Column(db.String(20), unique=True, nullable=False, index=True)
    amount = db.Column(db.Numeric(15, 2), nullable=False)
    issue_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # 关系
    branch_id = db.Column(db.Integer, db.ForeignKey('branches.id'), nullable=False)
    
    # 多对多关系
    borrowers = db.relationship('Customer', secondary=customer_loans, 
                              back_populates='loans')
    
    # 还款记录
    payments = db.relationship('LoanPayment', backref='loan', lazy='dynamic', cascade='all, delete-orphan')
    
    @property
    def remaining_balance(self):
        total_paid = sum(payment.amount for payment in self.payments)
        return self.amount - total_paid
    
    def __repr__(self):
        return f'<Loan {self.loan_number} (Amount: {self.amount})>'

class LoanPayment(db.Model):
    __tablename__ = 'loan_payments'
    
    id = db.Column(db.Integer, primary_key=True)
    payment_batch = db.Column(db.Integer, nullable=False)  # 还款批次
    payment_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    amount = db.Column(db.Numeric(15, 2), nullable=False)
    
    # 关系
    loan_id = db.Column(db.Integer, db.ForeignKey('loans.id'), nullable=False)
    account_id = db.Column(db.Integer, db.ForeignKey('accounts.id'), nullable=False)  # 用于还款的储蓄账户
    
    def __repr__(self):
        return f'<LoanPayment Batch {self.payment_batch} for Loan {self.loan_id}: {self.amount} on {self.payment_date}>'
