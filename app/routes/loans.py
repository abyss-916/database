from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from flask_login import current_user, login_required
from app import db
from app.models import Loan, Branch, Customer, Account, LoanPayment, User
from app.forms import LoanCreateForm, LoanPaymentForm

loans = Blueprint('loans', __name__)
# 添加bp属性，以匹配app.py中的引用
bp = loans

@loans.route('/')
@login_required
def list():
    # 查询所有贷款
    loans = Loan.query.all()
    return render_template('loans/list.html', title='贷款列表', loans=loans)

@loans.route('/<int:loan_id>')
@login_required
def detail(loan_id):
    # 查询贷款详情
    loan = Loan.query.get_or_404(loan_id)
    
    # 检查权限：员工可以查看所有贷款，客户只能查看自己的贷款
    if current_user.user_type == 'customer':
        customer = Customer.query.filter_by(user_id=current_user.id).first()
        if customer not in loan.customers:
            abort(403)
    
    # 获取还款记录
    payments = LoanPayment.query.filter_by(loan_id=loan_id).order_by(LoanPayment.payment_date.desc()).all()
    
    # 计算已还款总额
    total_paid = sum(payment.amount for payment in payments)
    
    return render_template('loans/detail.html', title='贷款详情', loan=loan, 
                          payments=payments, total_paid=total_paid)

@loans.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    # 只有员工可以创建贷款
    if current_user.user_type != 'employee':
        abort(403)
    
    form = LoanCreateForm()
    
    # 填充下拉列表
    form.branch_id.choices = [(branch.id, f"{branch.name} ({branch.branch_code})") 
                             for branch in Branch.query.all()]
    
    # 这里我们将使用一个隐藏字段来处理多选客户，在模板中使用JS来管理
    form.customer_ids.choices = [(customer.id, f"{customer.name} ({customer.customer_id})") 
                                for customer in Customer.query.all()]
    
    if form.validate_on_submit():
        # 创建贷款记录
        loan = Loan(
            loan_number=form.loan_number.data,
            amount=form.amount.data,
            branch_id=form.branch_id.data
        )
        
        # 关联客户
        customer_ids = request.form.getlist('customer_ids')
        for customer_id in customer_ids:
            customer = Customer.query.get(int(customer_id))
            if customer:
                loan.customers.append(customer)
        
        db.session.add(loan)
        db.session.commit()
        
        flash('贷款创建成功', 'success')
        return redirect(url_for('loans.detail', loan_id=loan.id))
    
    return render_template('loans/create.html', title='创建贷款', form=form)

@loans.route('/<int:loan_id>/payment', methods=['GET', 'POST'])
@login_required
def payment(loan_id):
    # 查询贷款详情
    loan = Loan.query.get_or_404(loan_id)
    
    # 检查权限：员工可以为任何贷款还款，客户只能为自己的贷款还款
    if current_user.user_type == 'customer':
        customer = Customer.query.filter_by(user_id=current_user.id).first()
        if customer not in loan.customers:
            abort(403)
    
    form = LoanPaymentForm()
    
    # 填充还款账户下拉列表（只能使用储蓄账户）
    if current_user.user_type == 'employee':
        # 员工可以选择任何储蓄账户
        accounts = Account.query.filter_by(account_type='savings').all()
    else:
        # 客户只能选择自己的储蓄账户
        customer = Customer.query.filter_by(user_id=current_user.id).first()
        accounts = Account.query.join(Customer).filter(
            Account.account_type == 'savings',
            Customer.id == customer.id
        ).all()
    
    form.savings_account_id.choices = [(account.id, f"{account.account_number} (余额: ¥{account.balance})") 
                                      for account in accounts]
    
    if form.validate_on_submit():
        # 获取还款账户
        payment_account = Account.query.get(form.savings_account_id.data)
        
        # 检查账户余额是否足够
        if payment_account.balance < form.payment_amount.data:
            flash('账户余额不足', 'danger')
            return redirect(url_for('loans.payment', loan_id=loan_id))
        
        # 创建还款记录
        payment = LoanPayment(
            loan_id=loan_id,
            amount=form.payment_amount.data,
            description=form.description.data,
            payment_account_id=payment_account.id
        )
        
        # 减少还款账户余额
        payment_account.balance -= form.payment_amount.data
        
        db.session.add(payment)
        db.session.commit()
        
        flash('贷款还款成功', 'success')
        return redirect(url_for('loans.detail', loan_id=loan_id))
    
    # 计算已还款总额
    total_paid = sum(payment.amount for payment in LoanPayment.query.filter_by(loan_id=loan_id).all())
    
    return render_template('loans/payment.html', title='贷款还款', form=form, loan=loan, total_paid=total_paid)
