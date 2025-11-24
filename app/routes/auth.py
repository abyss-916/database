from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required
from werkzeug.security import generate_password_hash
from app import db
from app.models import User, Customer, Employee
from app.forms import LoginForm, RegistrationForm

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            next_page = request.args.get('next')
            flash('登录成功！', 'success')
            return redirect(next_page) if next_page else redirect(url_for('dashboard.index'))
        else:
            flash('用户名或密码错误！', 'danger')
    return render_template('auth/login.html', title='登录', form=form)

@bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # 检查用户名是否已存在
        if User.query.filter_by(username=form.username.data).first():
            flash('该用户名已被使用！', 'danger')
            return redirect(url_for('auth.register'))
        
        # 检查邮箱是否已存在
        if User.query.filter_by(email=form.email.data).first():
            flash('该邮箱已被注册！', 'danger')
            return redirect(url_for('auth.register'))
        
        # 创建新用户
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        
        # 根据用户类型创建相应的记录
        if form.user_type.data == 'customer':
            customer = Customer(
                customer_id=f'CUST{user.id:04d}',
                name=form.name.data,
                id_card=form.id_card.data,
                city=form.city.data,
                street=form.street.data
            )
            db.session.add(customer)
            db.session.commit()
            
            # 关联用户和客户
            user.user_type = 'customer'
            user.customer_id = customer.id
        else:
            # 员工注册需要管理员权限，这里只是示例
            flash('员工注册需要管理员权限，请联系管理员！', 'warning')
            db.session.delete(user)
            db.session.commit()
            return redirect(url_for('auth.login'))
        
        db.session.commit()
        flash('注册成功！请登录。', 'success')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', title='注册', form=form)

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('您已成功登出！', 'info')
    return redirect(url_for('auth.login'))
