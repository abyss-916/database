from datetime import datetime
# 使用动态导入方式直接导入根目录的app.py中的app和db对象
import importlib.util
import os
import sys

# 获取根目录app.py的绝对路径
app_py_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'app.py'))

# 创建模块规格
spec = importlib.util.spec_from_file_location('root_app', app_py_path)
# 加载模块
root_app = importlib.util.module_from_spec(spec)
# 将模块添加到sys.modules，避免重复导入
sys.modules['root_app'] = root_app
# 执行模块
spec.loader.exec_module(root_app)

# 从动态导入的模块获取app和db
app = root_app.app
db = root_app.db
from app.models import User, Branch, Customer, Employee, Dependent 
from app.models import Account, SavingsAccount, CheckingAccount, Transaction 
from app.models import Loan, LoanPayment

def init_database():
    with app.app_context():
        # 创建所有表
        db.create_all()
        print("数据库表创建成功！")
        
        # 添加初始数据
        
        # 1. 添加支行
        if Branch.query.count() == 0:
            branches = [
                Branch(branch_code='001', name='北京总行', city='北京'),
                Branch(branch_code='002', name='上海分行', city='上海'),
                Branch(branch_code='003', name='广州分行', city='广州')
            ]
            db.session.add_all(branches)
            db.session.commit()
            print("添加初始支行数据成功！")
        
        # 2. 添加员工（包括管理员）
        if Employee.query.count() == 0:
            # 添加管理员用户
            admin_user = User(username='admin', email='admin@bank.com')
            admin_user.set_password('admin123')
            db.session.add(admin_user)
            db.session.commit()
            
            # 添加管理员员工
            manager = Employee(
                employee_id='EMP001', 
                name='张三', 
                phone='13800138001', 
                hire_date=datetime(2010, 1, 1),
                branch_id=1  # 北京总行
            )
            db.session.add(manager)
            db.session.commit()
            
            # 关联用户和员工
            admin_user.user_type = 'employee'
            admin_user.employee_id = manager.id
            db.session.commit()
            
            # 添加普通员工
            employees = [
                Employee(
                    employee_id='EMP002', 
                    name='李四', 
                    phone='13900139002', 
                    hire_date=datetime(2015, 3, 15),
                    branch_id=1,
                    manager_id=manager.id
                ),
                Employee(
                    employee_id='EMP003', 
                    name='王五', 
                    phone='13700137003', 
                    hire_date=datetime(2018, 6, 10),
                    branch_id=2,
                    manager_id=manager.id
                )
            ]
            db.session.add_all(employees)
            db.session.commit()
            
            # 为员工添加家属
            dependents = [
                Dependent(name='张小明', relationship='子女', employee_id=manager.id),
                Dependent(name='李华', relationship='配偶', employee_id=employees[0].id)
            ]
            db.session.add_all(dependents)
            db.session.commit()
            
            print("添加初始员工数据成功！")
        
        # 3. 添加客户
        if Customer.query.count() == 0:
            # 添加客户用户
            customer_user = User(username='customer1', email='customer1@example.com')
            customer_user.set_password('customer123')
            db.session.add(customer_user)
            db.session.commit()
            
            # 添加客户
            customers = [
                Customer(
                    customer_id='CUST001',
                    name='赵六',
                    id_card='110101199001011234',
                    city='北京',
                    street='朝阳区建国路88号',
                    assistant_id=1  # 张三为客户助理
                )
            ]
            db.session.add_all(customers)
            db.session.commit()
            
            # 关联用户和客户
            customer_user.user_type = 'customer'
            customer_user.customer_id = customers[0].id
            db.session.commit()
            
            print("添加初始客户数据成功！")
        
        # 4. 添加账户
        if Account.query.count() == 0:
            # 获取客户
            customer = Customer.query.first()
            if customer:
                # 创建储蓄账户
                savings = SavingsAccount(
                    account_number='SAV10001',
                    balance=10000.00,
                    interest_rate=0.015
                )
                
                # 创建支票账户
                checking = CheckingAccount(
                    account_number='CHK10001',
                    balance=5000.00,
                    overdraft_limit=2000.00
                )
                
                # 添加到数据库
                db.session.add(savings)
                db.session.add(checking)
                db.session.commit()
                
                # 关联客户和账户
                customer.accounts.append(savings)
                customer.accounts.append(checking)
                db.session.commit()
                
                print("添加初始账户数据成功！")
        
        # 5. 添加贷款
        if Loan.query.count() == 0:
            # 获取客户和支行
            customer = Customer.query.first()
            branch = Branch.query.first()
            if customer and branch:
                # 创建贷款
                loan = Loan(
                    loan_number='LOAN10001',
                    amount=50000.00,
                    branch_id=branch.id
                )
                db.session.add(loan)
                db.session.commit()
                
                # 关联客户和贷款
                customer.loans.append(loan)
                db.session.commit()
                
                print("添加初始贷款数据成功！")
        
        print("数据库初始化完成！")

if __name__ == '__main__':
    init_database()

