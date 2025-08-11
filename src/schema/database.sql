-- CREATE TYPE transaction_type AS ENUM (
--     'transfer',
--     'deposit',
--     'fee',
--     'refund',
--     'invoice_payment'
-- );

-- CREATE TYPE transaction_status AS ENUM (
--     'pending',
--     'completed',
--     'failed',
--     'cancelled'
-- );

CREATE Table IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    fullname VARCHAR(100),
    username VARCHAR(100),
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE Table IF NOT EXISTS wallets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    currency VARCHAR(3) DEFAULT 'USD',
    chargebee_customer_id VARCHAR(64) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE Table IF NOT EXISTS transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    from_wallet_id UUID REFERENCES wallets(id),
    to_wallet_id UUID REFERENCES wallets(id),
    amount DECIMAL(20,2) NOT NULL,
    transaction_type VARCHAR(20) NOT NULL, -- 'transfer', 'deposit', 'fee', 'refund', 'invoice_payment'
    status VARCHAR(20) DEFAULT 'pending', -- 'pending', 'completed', 'failed', 'cancelled'
    chargebee_reference_id VARCHAR,
    chargebee_invoice_id VARCHAR,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE Table IF NOT EXISTS wallet_balances (
    wallet_id UUID PRIMARY KEY REFERENCES wallets(id),
    balance DECIMAL(20,2) NOT NULL DEFAULT 100.00,
    version integer NOT NULL DEFAULT 1,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


CREATE INDEX IF NOT EXISTS idx_id ON users(id);
CREATE INDEX IF NOT EXISTS idx_email ON users(email);

CREATE INDEX IF NOT EXISTS idx_wallets_user_id ON wallets(user_id);
CREATE INDEX IF NOT EXISTS idx_chargebee_customer_id ON wallets(chargebee_customer_id);

CREATE INDEX IF NOT EXISTS idx_transactions_from_wallet ON transactions(from_wallet_id);
CREATE INDEX IF NOT EXISTS idx_transactions_to_wallet ON transactions(to_wallet_id);
CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status);
CREATE INDEX IF NOT EXISTS idx_transactions_type ON transactions(transaction_type);
CREATE INDEX IF NOT EXISTS idx_transactions_created_at ON transactions(created_at);
CREATE INDEX IF NOT EXISTS idx_transactions_chargebee_invoice ON transactions(chargebee_invoice_id);
CREATE INDEX IF NOT EXISTS idx_transactions_reference ON transactions(chargebee_reference_id);

CREATE INDEX IF NOT EXISTS idx_wallet_balances_wallet_id ON wallet_balances(wallet_id);