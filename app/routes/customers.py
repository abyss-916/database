from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user
from app import db
from app.models import Customer, Employee, User
from app.forms import CustomerForm, CustomerEditForm

customers = Blueprint('customers', __name__, url_prefix='/customers')
# 添加bp属性，以匹配app.py中的引用
bp = customers

@customers.route('/list')
@login_required
def list():
    # 只有员工可以查看客户列表
    if current_user.user_type != 'employee':
        flash('您没有权限访问此页面！', 'danger')
        return redirect(url_for('dashboard.index'))
    
    # 获取所有客户
    customers = Customer.query.all()
    employees = Employee.query.all()
    
    return render_template('customers/list.html', customers=customers, employees=employees)

@customers.route('/detail/<int:customer_id>')
@login_required
def detail(customer_id):
    # 查找客户
    customer = Customer.query.get_or_404(customer_id)
    
    # 只有员工或客户本人可以查看详情
    if current_user.user_type == 'employee' or \
       (current_user.user_type == 'customer' and current_user.customer_id == customer_id):
        return render_template('customers/detail.html', customer=customer)
    else:
        abort(403)

@customers.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    # 只有员工可以创建客户
    if current_user.user_type != 'employee':
        abort(403)
    
    form = CustomerForm()
    
    # 获取所有员工作为可选的客户助理
    form.assistant_id.choices = [(str(emp.employee_id), emp.name) for emp in Employee.query.all()]
    form.assistant_id.choices.insert(0, ('', '无'))
    
    if form.validate_on_submit():
        # 检查客户ID是否已存在
        existing_customer = Customer.query.filter_by(customer_id=form.customer_id.data).first()
        if existing_customer:
            flash('客户ID已存在，请使用不同的ID', 'danger')
            return redirect(url_for('customers.create'))
            
        # 检查证件号是否已存在
        existing_id_card = Customer.query.filter_by(id_card=form.id_card.data).first()
        if existing_id_card:
            flash('证件号已被使用，请使用不同的证件号', 'danger')
            return redirect(url_for('customers.create'))
        
        # 创建新客户
        customer = Customer(
            customer_id=form.customer_id.data,
            name=form.name.data,
            id_card=form.id_card.data,
            city=form.city.data,
            street=form.street.data
        )
        
        # 设置客户助理（如果有）
        if form.assistant_id.data:
            assistant = Employee.query.filter_by(employee_id=form.assistant_id.data).first()
            if assistant:
                customer.assistant_id = assistant.id
        
        db.session.add(customer)
        db.session.commit()
        
        flash('客户创建成功！', 'success')
        return redirect(url_for('customers.detail', customer_id=customer.id))
    
    return render_template('customers/create.html', form=form)

@customers.route('/edit/<int:customer_id>', methods=['GET', 'POST'])
@login_required
def edit(customer_id):
    # 只有员工可以编辑客户信息
    if current_user.user_type != 'employee':
        abort(403)
    
    customer = Customer.query.get_or_404(customer_id)
    form = CustomerEditForm()
    
    # 获取所有员工作为可选的客户助理
    form.assistant_id.choices = [(str(emp.employee_id), emp.name) for emp in Employee.query.all()]
    form.assistant_id.choices.insert(0, ('', '无'))
    
    if form.validate_on_submit():
        # 更新客户信息
        customer.name = form.name.data
        customer.city = form.city.data
        customer.street = form.street.data
        
        # 设置客户助理
        if form.assistant_id.data:
            assistant = Employee.query.filter_by(employee_id=form.assistant_id.data).first()
            if assistant:
                customer.assistant_id = assistant.id
        else:
            customer.assistant_id = None
        
        db.session.commit()
        
        flash('客户信息更新成功！', 'success')
        return redirect(url_for('customers.detail', customer_id=customer_id))
    
    # 预填充表单数据
    form.name.data = customer.name
    form.city.data = customer.city
    form.street.data = customer.street
    form.assistant_id.data = str(customer.assistant.employee_id) if customer.assistant else ''
    
    return render_template('customers/edit.html', form=form, customer=customer)
