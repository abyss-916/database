from .. import db

class Branch(db.Model):
    __tablename__ = 'branches'
    
    id = db.Column(db.Integer, primary_key=True)
    branch_code = db.Column(db.String(20), unique=True, nullable=False, index=True)  # 联行号
    name = db.Column(db.String(100), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    
    # 关系
    employees = db.relationship('Employee', backref='branch', lazy='dynamic')
    loans = db.relationship('Loan', backref='branch', lazy='dynamic')
    
    def __repr__(self):
        return f'<Branch {self.name} ({self.branch_code})>'
