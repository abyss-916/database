from flask import Blueprint, render_template, redirect, url_for, flash, abort
from flask_login import current_user, login_required
from app import db
from app.models import Employee, Branch, User
from app.forms import EmployeeCreateForm, EmployeeEditForm

# 创建蓝图
employees = Blueprint('employees', __name__)
# 添加bp属性，以匹配app.py中的引用
bp = employees

@employees.route('/')
@login_required
def list():
    # 只有员工可以访问员工管理页面
    if current_user.user_type != 'employee':
        abort(403)
    
    # 获取所有员工
    employees = Employee.query.all()
    return render_template('employees/list.html', title='员工列表', employees=employees)

@employees.route('/<int:employee_id>')
@login_required
def detail(employee_id):
    # 只有员工可以查看员工详情
    if current_user.user_type != 'employee':
        abort(403)
    
    # 获取员工详情
    employee = Employee.query.get_or_404(employee_id)
    return render_template('employees/detail.html', title='员工详情', employee=employee)

@employees.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    # 只有员工可以创建新员工
    if current_user.user_type != 'employee':
        abort(403)
    
    form = EmployeeCreateForm()
    
    # 填充支行下拉列表
    form.branch_id.choices = [(branch.id, f"{branch.name} ({branch.branch_code})") 
                             for branch in Branch.query.all()]
    
    if form.validate_on_submit():
        # 检查员工工号是否已存在
        if Employee.query.filter_by(employee_id=form.employee_id.data).first():
            flash('员工工号已存在', 'danger')
            return redirect(url_for('employees.create'))
        
        # 检查用户名是否已存在
        if User.query.filter_by(username=form.username.data).first():
            flash('用户名已存在', 'danger')
            return redirect(url_for('employees.create'))
        
        # 检查邮箱是否已存在
        if User.query.filter_by(email=form.email.data).first():
            flash('邮箱已存在', 'danger')
            return redirect(url_for('employees.create'))
        
        # 创建用户账户
        user = User(
            username=form.username.data,
            email=form.email.data,
            user_type='employee'
        )
        user.set_password(form.password.data)
        
        # 创建员工记录
        employee = Employee(
            employee_id=form.employee_id.data,
            name=form.name.data,
            position=form.position.data,
            branch_id=form.branch_id.data
        )
        employee.user = user
        
        db.session.add(user)
        db.session.add(employee)
        db.session.commit()
        
        flash('员工创建成功', 'success')
        return redirect(url_for('employees.detail', employee_id=employee.id))
    
    return render_template('employees/create.html', title='创建员工', form=form)

@employees.route('/<int:employee_id>/edit', methods=['GET', 'POST'])
@login_required
def edit(employee_id):
    # 只有员工可以编辑员工信息
    if current_user.user_type != 'employee':
        abort(403)
    
    # 获取员工详情
    employee = Employee.query.get_or_404(employee_id)
    
    form = EmployeeEditForm()
    
    # 填充支行下拉列表
    form.branch_id.choices = [(branch.id, f"{branch.name} ({branch.branch_code})") 
                             for branch in Branch.query.all()]
    
    if form.validate_on_submit():
        # 更新员工信息
        employee.name = form.name.data
        employee.position = form.position.data
        employee.branch_id = form.branch_id.data
        
        # 如果提供了新密码，则更新密码
        if form.new_password.data:
            employee.user.set_password(form.new_password.data)
            flash('密码已更新', 'info')
        
        db.session.commit()
        flash('员工信息已更新', 'success')
        return redirect(url_for('employees.detail', employee_id=employee.id))
    
    # 预填充表单
    form.name.data = employee.name
    form.position.data = employee.position
    form.branch_id.data = employee.branch_id
    
    return render_template('employees/edit.html', title='编辑员工', form=form, employee=employee)