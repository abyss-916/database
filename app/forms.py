from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField, IntegerField, DecimalField, DateField
from wtforms.validators import DataRequired, Length, Email, EqualTo, Regexp, Optional, NumberRange

class LoginForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired(), Length(1, 64)])
    password = PasswordField('密码', validators=[DataRequired()])
    remember_me = BooleanField('记住我')
    submit = SubmitField('登录')

class RegistrationForm(FlaskForm):
    username = StringField('用户名', validators=[
        DataRequired(), 
        Length(3, 64),
        Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0, '用户名只能包含字母、数字、点和下划线')
    ])
    email = StringField('邮箱', validators=[DataRequired(), Length(1, 120), Email()])
    password = PasswordField('密码', validators=[
        DataRequired(), 
        EqualTo('password2', message='两次输入的密码必须一致')
    ])
    password2 = PasswordField('确认密码', validators=[DataRequired()])
    
    # 用户类型
    user_type = SelectField('用户类型', choices=[('customer', '客户'), ('employee', '员工')], 
                          validators=[DataRequired()], default='customer')
    
    # 客户必填信息
    name = StringField('姓名', validators=[DataRequired(), Length(1, 100)])
    id_card = StringField('证件号', validators=[DataRequired(), Length(15, 20)])
    city = StringField('城市', validators=[DataRequired(), Length(1, 100)])
    street = StringField('街道', validators=[DataRequired(), Length(1, 200)])
    
    submit = SubmitField('注册')

class CustomerForm(FlaskForm):
    customer_id = StringField('客户ID', validators=[DataRequired(), Length(1, 20)])
    name = StringField('姓名', validators=[DataRequired(), Length(1, 100)])
    id_card = StringField('证件号', validators=[DataRequired(), Length(15, 20)])
    city = StringField('城市', validators=[DataRequired(), Length(1, 100)])
    street = StringField('街道', validators=[DataRequired(), Length(1, 200)])
    assistant_id = SelectField('客户助理', coerce=str, validators=[Optional()])
    submit = SubmitField('创建')

class CustomerEditForm(FlaskForm):
    name = StringField('姓名', validators=[DataRequired(), Length(1, 100)])
    city = StringField('城市', validators=[DataRequired(), Length(1, 100)])
    street = StringField('街道', validators=[DataRequired(), Length(1, 200)])
    assistant_id = SelectField('客户助理', coerce=str, validators=[Optional()])
    submit = SubmitField('更新')

class AccountCreateForm(FlaskForm):
    account_number = StringField('账户号码', validators=[DataRequired(), Length(1, 20)])
    account_type = SelectField('账户类型', choices=[('savings', '储蓄账户'), ('checking', '支票账户')], 
                              validators=[DataRequired()])
    initial_balance = DecimalField('初始余额', validators=[DataRequired(), NumberRange(min=0)])
    # 储蓄账户特定字段
    interest_rate = DecimalField('利率 (%)', validators=[Optional(), NumberRange(min=0, max=100)])
    # 支票账户特定字段
    overdraft_limit = DecimalField('透支额度', validators=[Optional(), NumberRange(min=0)])
    # 关联客户
    customer_ids = SelectField('关联客户', coerce=int, validators=[DataRequired()], choices=[], render_kw={'multiple': True})
    submit = SubmitField('创建账户')

class AccountDepositForm(FlaskForm):
    amount = DecimalField('存款金额', validators=[DataRequired(), NumberRange(min=0.01)])
    description = StringField('描述', validators=[Optional(), Length(1, 200)])
    submit = SubmitField('存款')

class AccountWithdrawForm(FlaskForm):
    amount = DecimalField('取款金额', validators=[DataRequired(), NumberRange(min=0.01)])
    description = StringField('描述', validators=[Optional(), Length(1, 200)])
    submit = SubmitField('取款')

class AccountTransferForm(FlaskForm):
    from_account_id = SelectField('转出账户', coerce=int, validators=[DataRequired()])
    to_account_number = StringField('转入账户号码', validators=[DataRequired(), Length(1, 20)])
    amount = DecimalField('转账金额', validators=[DataRequired(), NumberRange(min=0.01)])
    description = StringField('描述', validators=[Optional(), Length(1, 200)])
    submit = SubmitField('转账')

class LoanCreateForm(FlaskForm):
    loan_number = StringField('贷款号码', validators=[DataRequired(), Length(1, 20)])
    amount = DecimalField('贷款金额', validators=[DataRequired(), NumberRange(min=0.01)])
    branch_id = SelectField('发放支行', coerce=int, validators=[DataRequired()])
    # 关联客户
    customer_ids = SelectField('关联客户', coerce=int, validators=[DataRequired()], choices=[], render_kw={'multiple': True})
    submit = SubmitField('创建贷款')

class LoanPaymentForm(FlaskForm):
    payment_amount = DecimalField('还款金额', validators=[DataRequired(), NumberRange(min=0.01)])
    savings_account_id = SelectField('还款账户', coerce=int, validators=[DataRequired()])
    description = StringField('描述', validators=[Optional(), Length(1, 200)])
    submit = SubmitField('还款')

class EmployeeCreateForm(FlaskForm):
    employee_id = StringField('员工工号', validators=[DataRequired(), Length(1, 20)])
    name = StringField('员工姓名', validators=[DataRequired(), Length(1, 100)])
    position = StringField('职位', validators=[DataRequired(), Length(1, 100)])
    branch_id = SelectField('所属支行', coerce=int, validators=[DataRequired()])
    # 关联用户账户
    username = StringField('用户名', validators=[DataRequired(), Length(1, 64)])
    email = StringField('邮箱', validators=[DataRequired(), Email(), Length(1, 120)])
    password = PasswordField('密码', validators=[DataRequired(), Length(8, 128)])
    submit = SubmitField('创建员工')

class EmployeeEditForm(FlaskForm):
    name = StringField('员工姓名', validators=[DataRequired(), Length(1, 100)])
    position = StringField('职位', validators=[DataRequired(), Length(1, 100)])
    branch_id = SelectField('所属支行', coerce=int, validators=[DataRequired()])
    # 可选更新密码
    new_password = PasswordField('新密码', validators=[Optional(), Length(8, 128)])
    submit = SubmitField('更新员工信息')
