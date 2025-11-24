from flask import Blueprint, render_template, redirect, url_for, flash, abort, request
from flask_login import login_required, current_user
from datetime import datetime
from app import db
from app.models import Account, SavingsAccount, CheckingAccount, Customer, Transaction
from app.forms import AccountCreateForm, AccountDepositForm, AccountWithdrawForm, AccountTransferForm

accounts = Blueprint('accounts', __name__, url_prefix='/accounts')
# 添加bp属性，以匹配app.py中的引用
bp = accounts

@accounts.route('/')
@login_required
def list():
    if current_user.user_type == 'employee':
        # 员工可以查看所有账户
        accounts = Account.query.all()
    else:  # customer
        # 客户只能查看自己的账户
        customer = Customer.query.filter_by(user_id=current_user.id).first()
        if not customer:
            flash('未找到关联的客户信息', 'danger')
            return redirect(url_for('dashboard.index'))
        accounts = customer.accounts
    
    return render_template('accounts/list.html', accounts=accounts)

@accounts.route('/detail/<int:account_id>')
@login_required
def detail(account_id):
    account = Account.query.get_or_404(account_id)
    
    # 权限检查：员工可以查看所有账户，客户只能查看自己的账户
    if current_user.user_type == 'employee':
        pass  # 员工可以查看所有账户
    else:  # customer
        customer = Customer.query.filter_by(user_id=current_user.id).first()
        if not customer or account not in customer.accounts:
            abort(403)
    
    # 更新最后访问时间
    account.last_access_date = datetime.now()
    db.session.commit()
    
    # 获取交易记录
    transactions = Transaction.query.filter(
        (Transaction.from_account_id == account_id) | (Transaction.to_account_id == account_id)
    ).order_by(Transaction.transaction_date.desc()).limit(20).all()
    
    return render_template('accounts/detail.html', account=account, transactions=transactions)

@accounts.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    # 只有员工可以创建账户
    if current_user.user_type != 'employee':
        abort(403)
    
    form = AccountCreateForm()
    # 填充客户下拉列表
    form.customer_ids.choices = [(c.id, f'{c.name} ({c.customer_id})') for c in Customer.query.all()]
    
    if form.validate_on_submit():
        # 检查账户号码是否已存在
        existing_account = Account.query.filter_by(account_number=form.account_number.data).first()
        if existing_account:
            flash('账户号码已存在，请使用不同的号码', 'danger')
            return redirect(url_for('accounts.create'))
        
        # 创建基础账户
        account = Account(
            account_number=form.account_number.data,
            account_type=form.account_type.data,
            balance=form.initial_balance.data,
            created_at=datetime.now(),
            last_access_date=datetime.now()
        )
        
        # 根据账户类型创建特定类型的账户
        if form.account_type.data == 'savings':
            savings_account = SavingsAccount(
                account=account,
                interest_rate=form.interest_rate.data or 0
            )
            db.session.add(savings_account)
        else:  # checking
            checking_account = CheckingAccount(
                account=account,
                overdraft_limit=form.overdraft_limit.data or 0
            )
            db.session.add(checking_account)
        
        # 关联客户
        selected_customers = Customer.query.filter(Customer.id.in_(form.customer_ids.data)).all()
        account.customers = selected_customers
        
        # 如果有初始余额，创建存款交易记录
        if form.initial_balance.data > 0:
            transaction = Transaction(
                transaction_type='deposit',
                from_account_id=None,
                to_account_id=account.id,
                amount=form.initial_balance.data,
                description=f'账户开户存款',
                transaction_date=datetime.now()
            )
            db.session.add(transaction)
        
        db.session.add(account)
        db.session.commit()
        
        flash('账户创建成功！', 'success')
        return redirect(url_for('accounts.detail', account_id=account.id))
    
    return render_template('accounts/create.html', form=form)

@accounts.route('/deposit/<int:account_id>', methods=['GET', 'POST'])
@login_required
def deposit(account_id):
    account = Account.query.get_or_404(account_id)
    
    # 权限检查：员工可以为任何账户存款，客户只能为自己的账户存款
    if current_user.user_type == 'employee':
        pass  # 员工可以为任何账户存款
    else:  # customer
        customer = Customer.query.filter_by(user_id=current_user.id).first()
        if not customer or account not in customer.accounts:
            abort(403)
    
    form = AccountDepositForm()
    
    if form.validate_on_submit():
        # 更新账户余额
        account.balance += form.amount.data
        account.last_access_date = datetime.now()
        
        # 创建存款交易记录
        transaction = Transaction(
            transaction_type='deposit',
            from_account_id=None,
            to_account_id=account.id,
            amount=form.amount.data,
            description=form.description.data or '存款',
            transaction_date=datetime.now()
        )
        
        db.session.add(transaction)
        db.session.commit()
        
        flash(f'成功存入 {form.amount.data} 元', 'success')
        return redirect(url_for('accounts.detail', account_id=account.id))
    
    return render_template('accounts/deposit.html', form=form, account=account)

@accounts.route('/withdraw/<int:account_id>', methods=['GET', 'POST'])
@login_required
def withdraw(account_id):
    account = Account.query.get_or_404(account_id)
    
    # 权限检查：员工可以为任何账户取款，客户只能为自己的账户取款
    if current_user.user_type == 'employee':
        pass  # 员工可以为任何账户取款
    else:  # customer
        customer = Customer.query.filter_by(user_id=current_user.id).first()
        if not customer or account not in customer.accounts:
            abort(403)
    
    # 检查账户类型，确定可用余额
    available_balance = account.balance
    if account.account_type == 'checking':
        checking_account = CheckingAccount.query.filter_by(account_id=account.id).first()
        if checking_account:
            available_balance += checking_account.overdraft_limit
    
    form = AccountWithdrawForm()
    
    if form.validate_on_submit():
        # 检查余额是否足够
        if form.amount.data > available_balance:
            flash('余额不足', 'danger')
            return redirect(url_for('accounts.withdraw', account_id=account_id))
        
        # 更新账户余额
        account.balance -= form.amount.data
        account.last_access_date = datetime.now()
        
        # 创建取款交易记录
        transaction = Transaction(
            transaction_type='withdraw',
            from_account_id=account.id,
            to_account_id=None,
            amount=form.amount.data,
            description=form.description.data or '取款',
            transaction_date=datetime.now()
        )
        
        db.session.add(transaction)
        db.session.commit()
        
        flash(f'成功取出 {form.amount.data} 元', 'success')
        return redirect(url_for('accounts.detail', account_id=account.id))
    
    return render_template('accounts/withdraw.html', form=form, account=account, available_balance=available_balance)

@accounts.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer():
    # 获取当前用户的账户
    if current_user.user_type == 'employee':
        # 员工可以使用所有账户进行转账
        from_accounts = Account.query.all()
    else:  # customer
        # 客户只能使用自己的账户进行转账
        customer = Customer.query.filter_by(user_id=current_user.id).first()
        if not customer:
            flash('未找到关联的客户信息', 'danger')
            return redirect(url_for('dashboard.index'))
        from_accounts = customer.accounts
    
    form = AccountTransferForm()
    # 填充转出账户下拉列表
    form.from_account_id.choices = [(acc.id, f'{acc.account_number} (余额: {acc.balance})') for acc in from_accounts]
    
    if form.validate_on_submit():
        # 获取转出账户
        from_account = Account.query.get(form.from_account_id.data)
        # 获取转入账户
        to_account = Account.query.filter_by(account_number=form.to_account_number.data).first()
        
        if not to_account:
            flash('未找到目标账户', 'danger')
            return redirect(url_for('accounts.transfer'))
        
        # 检查余额是否足够
        available_balance = from_account.balance
        if from_account.account_type == 'checking':
            checking_account = CheckingAccount.query.filter_by(account_id=from_account.id).first()
            if checking_account:
                available_balance += checking_account.overdraft_limit
        
        if form.amount.data > available_balance:
            flash('余额不足', 'danger')
            return redirect(url_for('accounts.transfer'))
        
        # 更新账户余额
        from_account.balance -= form.amount.data
        to_account.balance += form.amount.data
        from_account.last_access_date = datetime.now()
        to_account.last_access_date = datetime.now()
        
        # 创建转账交易记录
        transaction = Transaction(
            transaction_type='transfer',
            from_account_id=from_account.id,
            to_account_id=to_account.id,
            amount=form.amount.data,
            description=form.description.data or '转账',
            transaction_date=datetime.now()
        )
        
        db.session.add(transaction)
        db.session.commit()
        
        flash(f'转账成功，金额: {form.amount.data} 元', 'success')
        return redirect(url_for('accounts.detail', account_id=from_account.id))
    
    return render_template('accounts/transfer.html', form=form)
