DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_type WHERE typname = 'account_type'
  ) THEN
    CREATE TYPE account_type AS ENUM ('savings','checking');
  END IF;
END$$;

CREATE TABLE IF NOT EXISTS branch (
  id BIGSERIAL PRIMARY KEY,
  union_no VARCHAR(32) NOT NULL UNIQUE,
  name VARCHAR(128) NOT NULL,
  city VARCHAR(64) NOT NULL
);

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

CREATE TABLE IF NOT EXISTS loan (
  id BIGSERIAL PRIMARY KEY,
  loan_no VARCHAR(64) NOT NULL UNIQUE,
  amount NUMERIC(18,2) NOT NULL CHECK (amount > 0),
  branch_id BIGINT NOT NULL REFERENCES branch(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS loan_customer (
  loan_id BIGINT NOT NULL REFERENCES loan(id) ON DELETE CASCADE,
  customer_id BIGINT NOT NULL REFERENCES customer(id) ON DELETE CASCADE,
  PRIMARY KEY (loan_id, customer_id)
);

CREATE TABLE IF NOT EXISTS repayment (
  id BIGSERIAL PRIMARY KEY,
  loan_id BIGINT NOT NULL REFERENCES loan(id) ON DELETE CASCADE,
  batch_no INTEGER NOT NULL,
  paid_at DATE NOT NULL,
  amount NUMERIC(18,2) NOT NULL CHECK (amount > 0),
  savings_account_id BIGINT NOT NULL REFERENCES savings_account(account_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_employee_manager ON employee(manager_id);
CREATE INDEX IF NOT EXISTS idx_customer_assistant ON customer(assistant_employee_id);
CREATE INDEX IF NOT EXISTS idx_account_type ON account(type);
CREATE INDEX IF NOT EXISTS idx_account_customer_cust ON account_customer(customer_id);
CREATE INDEX IF NOT EXISTS idx_loan_branch ON loan(branch_id);
CREATE INDEX IF NOT EXISTS idx_loan_customer_cust ON loan_customer(customer_id);
CREATE INDEX IF NOT EXISTS idx_repayment_loan ON repayment(loan_id);
CREATE TYPE user_role AS ENUM ('admin','user');
CREATE TABLE IF NOT EXISTS app_user (
  id BIGSERIAL PRIMARY KEY,
  username VARCHAR(64) NOT NULL UNIQUE,
  role user_role NOT NULL,
  password_hash BYTEA NOT NULL,
  password_salt BYTEA NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_login_at TIMESTAMP,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until TIMESTAMP
);
CREATE TABLE IF NOT EXISTS activity_log (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  action VARCHAR(128) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  meta JSONB
);
CREATE TABLE IF NOT EXISTS user_customer (
  user_id BIGINT PRIMARY KEY REFERENCES app_user(id) ON DELETE CASCADE,
  customer_id BIGINT UNIQUE REFERENCES customer(id) ON DELETE SET NULL
);

-- 创建独立的管理员表
CREATE TABLE IF NOT EXISTS admin_user (
  id BIGSERIAL PRIMARY KEY,
  username VARCHAR(64) NOT NULL UNIQUE,
  password_hash BYTEA NOT NULL,
  password_salt BYTEA NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_login_at TIMESTAMP,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until TIMESTAMP
);
CREATE TABLE IF NOT EXISTS admin_activity_log (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES admin_user(id) ON DELETE CASCADE,
  action VARCHAR(128) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  meta JSONB
);
