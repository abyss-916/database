from flask import Blueprint, render_template
from flask_login import login_required, current_user
from app import db
from app.models import Customer, Account, Loan, Transaction, LoanPayment, Employee
from datetime import datetime, timedelta

dashboard = Blueprint('dashboard', __name__, url_prefix='')
# 添加bp属性，以匹配app.py中的引用
bp = dashboard

@dashboard.route('/')
@login_required
def index():
    # 根据用户类型显示不同的仪表板内容
    if current_user.user_type == 'employee':
        # 员工仪表板数据
        # 获取所有客户、账户和贷款的数量
        customer_count = Customer.query.count()
        account_count = Account.query.count()
        loan_count = Loan.query.count()
        
        # 计算总存款余额
        total_balance = db.session.query(db.func.sum(Account.balance)).scalar() or 0
        
        # 计算总贷款金额和已还款金额
        total_loan_amount = db.session.query(db.func.sum(Loan.amount)).scalar() or 0
        total_paid_amount = db.session.query(db.func.sum(LoanPayment.amount)).scalar() or 0
        total_loan_balance = total_loan_amount - total_paid_amount
        
        # 获取最近的活动（最近7天的交易和还款）
        seven_days_ago = datetime.now() - timedelta(days=7)
        
        # 获取最近交易
        recent_transactions = Transaction.query.filter(
            Transaction.timestamp >= seven_days_ago
        ).order_by(Transaction.timestamp.desc()).limit(10).all()
        
        # 获取最近还款
        recent_payments = LoanPayment.query.filter(
            LoanPayment.payment_date >= seven_days_ago
        ).order_by(LoanPayment.payment_date.desc()).limit(10).all()
        
        # 合并活动并排序
        recent_activities = []
        for t in recent_transactions:
            recent_activities.append({
                'type': 'transaction',
                'date': t.timestamp,
                'description': f"交易: {t.from_account.account_number} -> {t.to_account.account_number}",
                'amount': t.amount
            })
        
        for p in recent_payments:
            recent_activities.append({
                'type': 'payment',
                'date': p.payment_date,
                'description': f"还款: 贷款{Loan.query.get(p.loan_id).loan_number if p.loan_id else '未知'}",
                'amount': p.amount
            })
        
        # 按日期排序
        recent_activities.sort(key=lambda x: x['date'], reverse=True)
        
        employee_data = {
            'customer_count': customer_count,
            'account_count': account_count,
            'loan_count': loan_count,
            'total_balance': total_balance,
            'total_loan_amount': total_loan_amount,
            'total_loan_balance': total_loan_balance,
            'recent_activities': recent_activities[:10]  # 只显示最近10条
        }
        
        return render_template('dashboard/index.html', title='仪表板', user_type='employee', data=employee_data)
    else:
        # 客户仪表板数据
        # 获取当前用户对应的客户信息
        customer = Customer.query.filter_by(id=current_user.customer_id).first()
        
        if customer:
            # 获取客户的所有账户
            accounts = customer.accounts
            
            # 获取客户的所有贷款
            loans = customer.loans
            
            # 计算总账户余额
            total_account_balance = sum(account.balance for account in accounts)
            
            # 计算总贷款余额
            total_loan_balance = 0
            for loan in loans:
                total_paid = db.session.query(db.func.sum(LoanPayment.amount)).filter(
                    LoanPayment.loan_id == loan.id
                ).scalar() or 0
                total_loan_balance += loan.amount - total_paid
            
            # 获取所有账户ID
            account_ids = [account.id for account in accounts]
            
            # 获取最近的交易记录（最近30天）
            thirty_days_ago = datetime.now() - timedelta(days=30)
            recent_transactions = Transaction.query.filter(
                ((Transaction.from_account_id.in_(account_ids)) | 
                 (Transaction.to_account_id.in_(account_ids))),
                Transaction.timestamp >= thirty_days_ago
            ).order_by(Transaction.timestamp.desc()).limit(10).all()
            
            customer_data = {
                'customer': customer,
                'accounts': accounts,
                'loans': loans,
                'total_account_balance': total_account_balance,
                'total_loan_balance': total_loan_balance,
                'recent_transactions': recent_transactions
            }
            
            return render_template('dashboard/index.html', title='仪表板', user_type='customer', data=customer_data)
        else:
            # 如果找不到客户记录，显示空数据
            customer_data = {
                'customer': None,
                'accounts': [],
                'loans': [],
                'total_account_balance': 0,
                'total_loan_balance': 0,
                'recent_transactions': []
            }
            return render_template('dashboard/index.html', title='仪表板', user_type='customer', data=customer_data)