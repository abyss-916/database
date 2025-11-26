DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_type WHERE typname = 'account_type'
  ) THEN
    CREATE TYPE account_type AS ENUM ('savings','checking', 'closed');
  END IF;
END$$;

CREATE TABLE IF NOT EXISTS branch (
  id BIGSERIAL PRIMARY KEY,
  union_no VARCHAR(32) NOT NULL UNIQUE,
  name VARCHAR(128) NOT NULL,
  city VARCHAR(64) NOT NULL
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_class WHERE relname = 'idx_branch_name_unique'
  ) THEN
    CREATE UNIQUE INDEX idx_branch_name_unique ON branch(name);
  END IF;
END$$;

CREATE TABLE IF NOT EXISTS employee (
  id BIGSERIAL PRIMARY KEY,
  name VARCHAR(128) NOT NULL,
  phone VARCHAR(32),
  hire_date DATE NOT NULL,
  manager_id BIGINT REFERENCES employee(id)
);

CREATE TABLE IF NOT EXISTS dependent (
  id BIGSERIAL PRIMARY KEY,
  employee_id BIGINT NOT NULL REFERENCES employee(id) ON DELETE CASCADE,
  name VARCHAR(128) NOT NULL,
  relationship VARCHAR(64) NOT NULL
);

CREATE TABLE IF NOT EXISTS customer (
  id BIGSERIAL PRIMARY KEY,
  name VARCHAR(128) NOT NULL,
  identity_no VARCHAR(64) NOT NULL UNIQUE,
  city VARCHAR(64) NOT NULL,
  street VARCHAR(128) NOT NULL,
  assistant_employee_id BIGINT REFERENCES employee(id)
);

CREATE TABLE IF NOT EXISTS account (
  id BIGSERIAL PRIMARY KEY,
  account_no VARCHAR(64) NOT NULL UNIQUE,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  balance NUMERIC(18,2) NOT NULL DEFAULT 0,
  type account_type NOT NULL
);

CREATE TABLE IF NOT EXISTS account_customer (
  account_id BIGINT NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  customer_id BIGINT NOT NULL REFERENCES customer(id) ON DELETE CASCADE,
  last_access_date DATE,
  PRIMARY KEY (account_id, customer_id)
);

CREATE TABLE IF NOT EXISTS savings_account (
  account_id BIGINT PRIMARY KEY REFERENCES account(id) ON DELETE CASCADE,
  interest_rate NUMERIC(5,4) NOT NULL CHECK (interest_rate >= 0)
);

CREATE TABLE IF NOT EXISTS checking_account (
  account_id BIGINT PRIMARY KEY REFERENCES account(id) ON DELETE CASCADE,
  overdraft_limit NUMERIC(18,2) NOT NULL CHECK (overdraft_limit >= 0)
);

CREATE OR REPLACE FUNCTION enforce_account_type_savings() RETURNS TRIGGER AS $$
BEGIN
  IF (SELECT type FROM account WHERE id = NEW.account_id) <> 'savings' THEN
    RAISE EXCEPTION 'account type mismatch';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'trg_savings_account_type'
  ) THEN
    CREATE TRIGGER trg_savings_account_type BEFORE INSERT OR UPDATE ON savings_account
    FOR EACH ROW EXECUTE FUNCTION enforce_account_type_savings();
  END IF;
END$$;

CREATE OR REPLACE FUNCTION enforce_account_type_checking() RETURNS TRIGGER AS $$
BEGIN
  IF (SELECT type FROM account WHERE id = NEW.account_id) <> 'checking' THEN
    RAISE EXCEPTION 'account type mismatch';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'trg_checking_account_type'
  ) THEN
    CREATE TRIGGER trg_checking_account_type BEFORE INSERT OR UPDATE ON checking_account
    FOR EACH ROW EXECUTE FUNCTION enforce_account_type_checking();
  END IF;
END$$;

-- 添加业务单表
CREATE TABLE IF NOT EXISTS business (
  id BIGSERIAL PRIMARY KEY,
  business_type VARCHAR(32) NOT NULL,
  customer_id BIGINT NOT NULL REFERENCES customer(id),
  status VARCHAR(32) NOT NULL DEFAULT 'INIT',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  operator_id BIGINT REFERENCES employee(id),
  remark TEXT
);

-- 添加转账表
CREATE TABLE IF NOT EXISTS transfer (
  id BIGSERIAL PRIMARY KEY,
  from_account_id BIGINT NOT NULL REFERENCES account(id),
  to_account_id BIGINT NOT NULL REFERENCES account(id),
  amount NUMERIC(18,2) NOT NULL CHECK (amount > 0),
  status VARCHAR(32) NOT NULL DEFAULT 'SUCCESS',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  completed_at TIMESTAMP
);

-- 添加交易流水表
CREATE TABLE IF NOT EXISTS transaction (
  id BIGSERIAL PRIMARY KEY,
  account_id BIGINT NOT NULL REFERENCES account(id),
  business_id BIGINT REFERENCES business(id),
  transfer_id BIGINT REFERENCES transfer(id),
  txn_type VARCHAR(32) NOT NULL,
  amount NUMERIC(18,2) NOT NULL,
  balance_after NUMERIC(18,2) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  remark TEXT
);

-- 创建索引以提高查询性能
CREATE INDEX IF NOT EXISTS idx_transaction_account_created ON transaction(account_id, created_at);
CREATE INDEX IF NOT EXISTS idx_transfer_from_account ON transfer(from_account_id);
CREATE INDEX IF NOT EXISTS idx_transfer_to_account ON transfer(to_account_id);
CREATE INDEX IF NOT EXISTS idx_business_customer_status ON business(customer_id, status);

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
   NEW.updated_at = NOW();
   RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'trg_business_updated_at'
  ) THEN
    CREATE TRIGGER trg_business_updated_at 
    BEFORE UPDATE ON business 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();
  END IF;
END$$;

-- 添加应用用户表
CREATE TABLE IF NOT EXISTS app_user (
  id BIGSERIAL PRIMARY KEY,
  username VARCHAR(64) NOT NULL UNIQUE,
  role VARCHAR(32) NOT NULL DEFAULT 'user',
  password_hash BYTEA NOT NULL,
  password_salt BYTEA NOT NULL,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until TIMESTAMP,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_login_at TIMESTAMP
);

-- 添加管理员用户表
CREATE TABLE IF NOT EXISTS admin_user (
  id BIGSERIAL PRIMARY KEY,
  username VARCHAR(64) NOT NULL UNIQUE,
  password_hash BYTEA NOT NULL,
  password_salt BYTEA NOT NULL,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until TIMESTAMP,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_login_at TIMESTAMP
);

-- 添加用户客户关联表
CREATE TABLE IF NOT EXISTS user_customer (
  user_id BIGINT NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  customer_id BIGINT NOT NULL REFERENCES customer(id) ON DELETE CASCADE,
  PRIMARY KEY (user_id, customer_id)
);

-- 添加贷款表
CREATE TABLE IF NOT EXISTS loan (
  id BIGSERIAL PRIMARY KEY,
  loan_no VARCHAR(64) NOT NULL UNIQUE,
  amount NUMERIC(18,2) NOT NULL,
  branch_id BIGINT NOT NULL REFERENCES branch(id)
);

-- 添加贷款客户关联表
CREATE TABLE IF NOT EXISTS loan_customer (
  loan_id BIGINT NOT NULL REFERENCES loan(id) ON DELETE CASCADE,
  customer_id BIGINT NOT NULL REFERENCES customer(id) ON DELETE CASCADE,
  PRIMARY KEY (loan_id, customer_id)
);

CREATE OR REPLACE FUNCTION check_loan_has_customer() RETURNS TRIGGER AS $$
DECLARE
  lid BIGINT;
  cnt INTEGER;
BEGIN
  IF TG_TABLE_NAME = 'loan' THEN
    lid := NEW.id;
  ELSE
    lid := COALESCE(NEW.loan_id, OLD.loan_id);
  END IF;
  SELECT COUNT(*) INTO cnt FROM loan_customer WHERE loan_id = lid;
  IF cnt < 1 THEN
    RAISE EXCEPTION 'loan must have at least one customer';
  END IF;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'ctrg_loan_has_customer_ins'
  ) THEN
    CREATE CONSTRAINT TRIGGER ctrg_loan_has_customer_ins
    AFTER INSERT ON loan
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    EXECUTE FUNCTION check_loan_has_customer();
  END IF;
END$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'ctrg_loan_has_customer_del'
  ) THEN
    CREATE CONSTRAINT TRIGGER ctrg_loan_has_customer_del
    AFTER DELETE ON loan_customer
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    EXECUTE FUNCTION check_loan_has_customer();
  END IF;
END$$;

-- 添加还款表
CREATE TABLE IF NOT EXISTS repayment (
  id BIGSERIAL PRIMARY KEY,
  loan_id BIGINT NOT NULL REFERENCES loan(id),
  batch_no VARCHAR(64) NOT NULL,
  paid_at DATE NOT NULL,
  amount NUMERIC(18,2) NOT NULL,
  savings_account_id BIGINT NOT NULL REFERENCES savings_account(account_id)
);
CREATE INDEX IF NOT EXISTS idx_repayment_loan_id ON repayment(loan_id);

DO $$
DECLARE c_name text;
BEGIN
  SELECT tc.constraint_name INTO c_name
  FROM information_schema.table_constraints tc
  JOIN information_schema.key_column_usage k
    ON tc.constraint_name = k.constraint_name AND tc.table_name = k.table_name
  WHERE tc.table_name = 'repayment' AND tc.constraint_type = 'FOREIGN KEY' AND k.column_name = 'savings_account_id';
  IF c_name IS NOT NULL THEN
    EXECUTE 'ALTER TABLE repayment DROP CONSTRAINT ' || quote_ident(c_name);
  END IF;
  BEGIN
    ALTER TABLE repayment ADD CONSTRAINT repayment_savings_account_fk FOREIGN KEY (savings_account_id) REFERENCES savings_account(account_id);
  EXCEPTION WHEN duplicate_object THEN
  END;
END$$;

-- 添加活动日志表
CREATE TABLE IF NOT EXISTS activity_log (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES app_user(id),
  action VARCHAR(64) NOT NULL,
  meta JSONB,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 添加管理员活动日志表
CREATE TABLE IF NOT EXISTS admin_activity_log (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES admin_user(id),
  action VARCHAR(64) NOT NULL,
  meta JSONB,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
