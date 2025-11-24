# 导入模型类
from .user import User
from .branch import Branch
from .customer import Customer
from .employee import Employee, Dependent
from .account import Account, SavingsAccount, CheckingAccount, Transaction
from .loan import Loan, LoanPayment

# 在所有模型类导入后再导入关系表（避免循环导入）
from . import association_tables

# 导出关系表对象，使其可以通过models模块访问
__all__ = [
    'User', 'Branch', 'Customer', 'Employee', 'Dependent',
    'Account', 'SavingsAccount', 'CheckingAccount', 'Transaction',
    'Loan', 'LoanPayment',
    'association_tables'
]
