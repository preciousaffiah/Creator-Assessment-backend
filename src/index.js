import dotenv from "dotenv";
dotenv.config();

import chargebee from 'chargebee';
import express from 'express';
import { Pool } from 'pg';
import Redis from 'redis';
import cors from 'cors';
import fs from 'fs';
import jwt from 'jsonwebtoken';

import { authenticateToken } from './authMiddleware.js'

const app = express();

//Database setup
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 20,
});

//Redis setup
const redis = Redis.createClient({
  username: process.env.REDIS_USERNAME,
  password: process.env.REDIS_PASSWORD,
  socket: {
    host: process.env.REDIS_HOST,
    port: Number(process.env.REDIS_PORT),
    tls: true
  }
});


redis.on('error', err => console.error('Redis Client Error', err));

(async () => {
  await redis.connect();
  console.log("Connected to Redis");
})();


// Chargebee setup
chargebee.configure({
  site: process.env.CHARGEBEE_SITE,
  api_key: process.env.CHARGEBEE_API_KEY
});


app.use(express.json());

app.use(cors({
  origin: "*", // Allow all origins
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

// POST - Create new user with Chargebee customer and wallet
app.post('/auth/create', async (req, res) => {
  const { fullname, email, password, username } = req.body;

  // Input field validation
  if (!fullname || !email || !password || !username) {
    return res.status(400).json({
      success: false,
      message: 'Missing required fields: fullname, email, password',
      code: 'VALIDATION_ERROR'
    });
  }

  // Email validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({
      success: false,
      message: 'Invalid email format',
      code: 'INVALID_EMAIL'
    });
  }

  const client = await pool.connect();

  try {
    // Start database transaction
    await client.query('BEGIN');

    // Check if email already exists
    const existingEmail = await client.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );

    if (existingEmail.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(409).json({
        success: false,
        message: 'User with this email already exists',
        code: 'USER_EXISTS'
      });
    }

    // Check if username already exists
    const existingUsername = await client.query(
      'SELECT id FROM users WHERE username = $1',
      [username]
    );

    if (existingUsername.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(409).json({
        success: false,
        message: 'This username is already taken',
        code: 'USER_EXISTS'
      });
    }

    console.log('Creating Chargebee customer...');

    // Create customer in Chargebee
    let chargebeeCustomer;
    try {
      const customerResult = await new Promise((resolve, reject) => {
        chargebee.customer.create({
          email: email,
          first_name: fullname.split(' ')[0] || fullname,
          last_name: fullname.split(' ').slice(1).join(' ') || '',
          auto_collection: 'on',
          // card: {
          //   number: process.env.CARD_NUMBER,
          //   expiry_month: process.env.EXPIRY_MONTH,
          //   expiry_year: process.env.EXPIRY_YEAR,
          //   cvv: process.env.CVV,
          // },
        }).request(function (error, result) {
          if (error) {
            reject(error);
          } else {
            resolve(result);
          }
        });
      });

      chargebeeCustomer = customerResult.customer;
      console.log('Chargebee customer created:', chargebeeCustomer.id);

    } catch (chargebeeError) {
      await client.query('ROLLBACK');
      console.error('Chargebee customer creation failed:', chargebeeError);

      return res.status(500).json({
        success: false,
        message: 'Failed to create payment profile',
        code: 'CHARGEBEE_ERROR',
        details: chargebeeError.message
      });
    }

    // TODO: Hash password using bcrypt
    // const hashedPassword = await bcrypt.hash(password, 10);

    console.log('Creating user in database...');

    // Create user in database
    const userResult = await client.query(`
          INSERT INTO users (fullname, email, password, username)
          VALUES ($1, $2, $3, $4)
          RETURNING id, fullname, email, username, created_at
      `, [fullname, email, username, password]); // Use hashedPassword in production

    const user = userResult.rows[0];
    console.log('User created:', user.id);



    // Create wallet for the user
    console.log('Creating wallet...');
    const walletResult = await client.query(`
          INSERT INTO wallets (user_id, currency, chargebee_customer_id)
          VALUES ($1, $2, $3)
          RETURNING id, user_id, currency, chargebee_customer_id, created_at
      `, [user.id, 'USD', chargebeeCustomer.id]);

    const wallet = walletResult.rows[0];
    console.log('Wallet created:', wallet.id);

    // Generate JWT token
    const userData = {
      id: user.id,
      fullname: user.fullname,
      email: user.email,
      username: user.username,
      created_at: user.created_at,
      wallet_id: wallet.wallet_id,
      currency: wallet.currency,
      balance: parseFloat(walletBalance.balance) || 0.00,
      chargebee_customer_id: chargebeeCustomer.id
    };
    const token = jwt.sign({ user: userData }, process.env.JWT_SECRET || "", {
      expiresIn: "300d",
    });


    // Create wallet balance record
    console.log('Creating wallet balance...');
    const balanceResult = await client.query(`
          INSERT INTO wallet_balances (wallet_id, balance, version)
          VALUES ($1, $2, $3)
          RETURNING wallet_id, balance, version, updated_at
      `, [wallet.id, 100.00, 1]);

    const walletBalance = balanceResult.rows[0];
    console.log('Wallet balance created');

    // Commit transaction
    await client.query('COMMIT');

    // Clear any cached balance for this wallet
    const cacheKey = `wallet_balance:${wallet.id}`;
    try {
      await redis.del(cacheKey);
    } catch (cacheError) {
      console.warn('Failed to clear cache:', cacheError);
    }

    // Return success response
    res.status(201).json({
      success: true,
      message: 'User created successfully',
      data: {
        token,
        userData
      },
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    // Rollback transaction on any error
    await client.query('ROLLBACK');
    console.error('User creation error-', error);

    res.status(500).json({
      success: false,
      message: 'Failed to create user',
      code: 'USER_CREATION_ERROR',
      details: error.message
    });

  } finally {
    client.release();
  }
});

// POST - User login
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;

  // Input validation
  if (!email || !password) {
    return res.status(400).json({
      success: false,
      message: 'Missing required fields: email, password',
      code: 'VALIDATION_ERROR'
    });
  }

  // Email format validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({
      success: false,
      message: 'Invalid email format',
      code: 'INVALID_EMAIL'
    });
  }

  const client = await pool.connect();

  try {
    console.log('Attempting login for:', email);

    // Find user by email with wallet information
    const userResult = await client.query(`
      SELECT 
        u.id,
        u.fullname,
        u.email,
        u.username,
        u.password,
        u.created_at,
        w.id as wallet_id,
        w.currency,
        w.chargebee_customer_id,
        wb.balance
      FROM users u
      LEFT JOIN wallets w ON u.id = w.user_id
      LEFT JOIN wallet_balances wb ON w.id = wb.wallet_id
      WHERE u.email = $1
    `, [email]);

    if (userResult.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password',
        code: 'INVALID_CREDENTIALS'
      });
    }

    const user = userResult.rows[0];

    // TODO: Use bcrypt for password comparison in production
    // const isPasswordValid = await bcrypt.compare(password, user.password);
    const isPasswordValid = password === user.password; // Temporary plain text comparison

    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password',
        code: 'INVALID_CREDENTIALS'
      });
    }

    console.log('Login successful for user:', user.id);

    // Generate JWT token
    const userData = {
      id: user.id,
      fullname: user.fullname,
      username: user.username,
      email: user.email,
      created_at: user.created_at,
      wallet_id: user.wallet_id,
      currency: user.currency,
      balance: user.balance ? parseFloat(user.balance) : 0.00,
      chargebee_customer_id: user.chargebee_customer_id
    };
    const token = jwt.sign({ user: userData }, process.env.JWT_SECRET || "", {
      expiresIn: "300d",
    });

    // Update cache with current balance
    if (user.wallet_id && user.balance !== null) {
      const cacheKey = `wallet_balance:${user.wallet_id}`;
      try {
        await redis.setEx(cacheKey, 30, user.balance.toString());
      } catch (cacheError) {
        console.warn('Failed to cache balance:', cacheError);
      }
    }

    // Return success response (excluding password)
    res.status(200).json({
      success: true,
      message: 'Login successful',
      data: {
        token,
        userData
      },
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('Login error:', error);

    res.status(500).json({
      success: false,
      message: 'Login failed due to internal error',
      code: 'LOGIN_ERROR',
      details: error.message
    });

  } finally {
    client.release();
  }
});


// GET - retrieve the latest balance
app.get('/wallet/balance', authenticateToken, async (req, res) => {
  const walletId = req.user.wallet_id;
  const cacheKey = `wallet_balance:${walletId}`;

  try {
    //Check Redis cache first for performance
    const cachedBalance = await redis.get(cacheKey);

    if (cachedBalance) {
      return res.json({
        success: true,
        data: {
          wallet_id: walletId,
          balance: parseFloat(cachedBalance),
          cached: true,
          timestamp: new Date().toISOString()
        }
      });
    }

    // Check DB
    const client = await pool.connect();

    try {
      // Validate wallet exists and get balance
      const balanceResult = await client.query(`
        SELECT 
          wb.balance,
          wb.version,
          wb.updated_at
        FROM wallet_balances wb
        JOIN wallets w ON wb.wallet_id = w.id
        WHERE wb.wallet_id = $1
      `, [walletId]);

      if (balanceResult.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: 'Wallet not found',
          code: 'WALLET_NOT_FOUND'
        });
      }

      const { balance, version, updated_at, } = balanceResult.rows[0];

      //Cache balance for 30 seconds
      await redis.setEx(cacheKey, 30, balance.toString());

      res.json({
        success: true,
        data: {
          wallet_id: walletId,
          balance: parseFloat(balance),
          version: version,
          last_updated: updated_at,
          cached: false,
          timestamp: new Date().toISOString()
        }
      });

    } finally {
      client.release();
    }

  } catch (error) {
    console.error('Balance retrieval error-', error);

    res.status(500).json({
      success: false,
      message: 'Failed to retrieve balance',
      code: 'BALANCE_RETRIEVAL_ERROR'
    });
  }
});

// GET - retrieve all transactions
app.get('/wallet/transactions', authenticateToken, async (req, res) => {
  const walletId = req.user.wallet_id;
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20)); // Max 100 per page
  const offset = (page - 1) * limit;

  try {
    const client = await pool.connect();

    try {

      const [transactionsResult, countResult] = await Promise.all([
        // Get paginated transactions with mode calculation
        client.query(`
          SELECT
            t.id,
            t.amount,
            t.transaction_type,
            t.status,
            t.description,
            t.created_at,
            t.chargebee_invoice_id,
            t.chargebee_reference_id,
            CASE
              WHEN t.from_wallet_id = $1 THEN 'debit'
              ELSE 'credit'
            END as mode,
            CASE
              WHEN t.from_wallet_id = $1 THEN tw.id
              ELSE fw.id
            END as counterpart_wallet_id,
            CASE
              WHEN t.from_wallet_id = $1 THEN u_to.fullname
              ELSE u_from.fullname
            END as counterpart_user_name
          FROM transactions t
          LEFT JOIN wallets fw ON t.from_wallet_id = fw.id
          LEFT JOIN wallets tw ON t.to_wallet_id = tw.id
          LEFT JOIN users u_from ON fw.user_id = u_from.id
          LEFT JOIN users u_to ON tw.user_id = u_to.id
          WHERE (t.from_wallet_id = $1 OR t.to_wallet_id = $1)
            AND t.status = 'completed'
          ORDER BY t.created_at DESC
          LIMIT $2 OFFSET $3
        `, [walletId, limit, offset]),

        // Get total count for pagination info
        client.query(`
          SELECT COUNT(*) as total
          FROM transactions
          WHERE (from_wallet_id = $1 OR to_wallet_id = $1)
            AND status = 'completed'
        `, [walletId])
      ]);

      const transactions = transactionsResult.rows;
      const totalTransactions = parseInt(countResult.rows[0].total);
      const totalPages = Math.ceil(totalTransactions / limit);

      // Check if requested page exists
      if (page > totalPages && totalTransactions > 0) {
        return res.status(400).json({
          success: false,
          message: `Page ${page} does not exist. Maximum page is ${totalPages}`,
          code: 'INVALID_PAGE'
        });
      }

      res.json({
        success: true,
        data: {
          wallet_id: walletId,
          transactions: transactions.map(tx => ({
            id: tx.id,
            amount: parseFloat(tx.amount),
            type: tx.transaction_type,
            mode: tx.mode,
            status: tx.status,
            description: tx.description,
            counterpart_wallet_id: tx.counterpart_wallet_id, // Fixed: was counterpart_wallet
            counterpart_user_name: tx.counterpart_user_name, // Added: the user name
            chargebee_invoice_id: tx.chargebee_invoice_id,
            chargebee_reference_id: tx.chargebee_reference_id,
            created_at: tx.created_at
          })),
          pagination: {
            current_page: page,
            per_page: limit,
            total_transactions: totalTransactions,
            total_pages: totalPages,
            has_next: page < totalPages,
            has_previous: page > 1
          }
        }
      });

    } finally {
      client.release();
    }

  } catch (error) {
    console.error('Transaction history error-', error);
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve transaction history',
      code: 'TRANSACTION_HISTORY_ERROR'
    });
  }
});

// POST - send money to another account
app.post('/wallet/send', authenticateToken, async (req, res) => {
  const { recipientUsername, amount, description } = req.body;

  const fromWalletId = req.user.wallet_id
  const myUsername = req.user.username

  // INPUT VALIDATION
  if (!recipientUsername || !amount) {
    return res.status(400).json({
      success: false,
      message: 'Missing required fields: recipientUsername, amount',
      code: 'MISSING_REQUIRED_FIELDS'
    });
  }

  if (recipientUsername === myUsername) {
    return res.status(400).json({
      success: false,
      message: 'Cannot send money to the same wallet',
      code: 'SAME_WALLET_TRANSFER'
    });
  }

  const transferAmount = parseFloat(amount);
  if (isNaN(transferAmount) || transferAmount <= 0) {
    return res.status(400).json({
      success: false,
      message: 'Amount must be a positive number',
      code: 'INVALID_AMOUNT'
    });
  }

  if (transferAmount > 1000000) { //Max transfer limit
    return res.status(400).json({
      success: false,
      message: 'Transfer amount exceeds maximum limit',
      code: 'AMOUNT_EXCEEDS_LIMIT'
    });
  }

  const client = await pool.connect();

  try {
    // find the recipient's wallet using their username
    const recipientLookup = await client.query(`
      SELECT 
        u.id as user_id,
        u.fullname,
        u.email,
        u.username,
        w.id as wallet_id
      FROM users u
      LEFT JOIN wallets w ON u.id = w.user_id
      WHERE u.username = $1
    `, [recipientUsername.trim()]);

    if (recipientLookup.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Recipient not found. Please check the username/email.',
        code: 'RECIPIENT_NOT_FOUND'
      });
    }

    const recipient = recipientLookup.rows[0];
    const toWalletId = recipient.wallet_id;

    if (!toWalletId) {
      return res.status(404).json({
        success: false,
        message: 'Recipient does not have a wallet account',
        code: 'RECIPIENT_NO_WALLET'
      });
    }

    // Check if trying to send to self
    if (fromWalletId === toWalletId) {
      return res.status(400).json({
        success: false,
        message: 'Cannot send money to yourself',
        code: 'SAME_WALLET_TRANSFER'
      });
    }


    //Start database transaction with serializable isolation
    await client.query('BEGIN');
    await client.query('SET TRANSACTION ISOLATION LEVEL SERIALIZABLE');

    //Lock wallets in consistent order to prevent deadlocks
    const [firstWallet, secondWallet] = [fromWalletId, toWalletId].sort();

    // Lock both wallets to prevent concurrent modifications
    const lockResult = await client.query(`
      SELECT 
        wb.wallet_id,
        wb.balance,
        wb.version
      FROM wallet_balances wb
      JOIN wallets w ON wb.wallet_id = w.id
      WHERE wb.wallet_id IN ($1, $2)
      ORDER BY wb.wallet_id
      FOR UPDATE NOWAIT
    `, [firstWallet, secondWallet]);

    if (lockResult.rows.length !== 2) {
      await client.query('ROLLBACK');
      return res.status(404).json({
        success: false,
        message: 'One or both wallets not found',
        code: 'WALLET_NOT_FOUND'
      });
    }

    // Find sender and receiver data
    const senderData = lockResult.rows.find(row => row.wallet_id === fromWalletId);
    const receiverData = lockResult.rows.find(row => row.wallet_id === toWalletId);

    //Check sufficient balance
    if (parseFloat(senderData.balance) < transferAmount) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        success: false,
        message: `Insufficient balance.`,
        code: 'INSUFFICIENT_BALANCE',
      });
    }

    // Create transaction record
    const transactionResult = await client.query(`
      INSERT INTO transactions (
        from_wallet_id, to_wallet_id, amount, transaction_type, 
        status, description
      ) VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING id, created_at
    `, [
      fromWalletId,
      toWalletId,
      transferAmount,
      'transfer',
      'completed',
      description || 'Money transfer',
    ]);

    const transactionId = transactionResult.rows[0].id;
    const createdAt = transactionResult.rows[0].created_at;

    // Update both wallet balances with optimistic locking
    const senderUpdateResult = await client.query(`
      UPDATE wallet_balances 
      SET 
        balance = balance - $1,
        version = version + 1,
        updated_at = CURRENT_TIMESTAMP
      WHERE wallet_id = $2 AND version = $3
      RETURNING balance, version
    `, [transferAmount, fromWalletId, senderData.version]);

    const receiverUpdateResult = await client.query(`
      UPDATE wallet_balances 
      SET 
        balance = balance + $1,
        version = version + 1,
        updated_at = CURRENT_TIMESTAMP
      WHERE wallet_id = $2 AND version = $3
      RETURNING balance, version
    `, [transferAmount, toWalletId, receiverData.version]);

    // CONCURRENCY CHECK: Ensure updates succeeded (no concurrent modifications)
    if (senderUpdateResult.rows.length === 0 || receiverUpdateResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(409).json({
        success: false,
        message: 'Concurrent modification detected. Please retry.',
        code: 'CONCURRENT_MODIFICATION'
      });
    }

    // Commit transaction
    await client.query('COMMIT');

    // Invalidate balance cache for both wallets
    await Promise.all([
      redis.del(`wallet_balance:${fromWalletId}`),
      redis.del(`wallet_balance:${toWalletId}`),
    ]);

    // Cache updated balances
    await Promise.all([
      redis.setEx(`wallet_balance:${fromWalletId}`, 30, senderUpdateResult.rows[0].balance.toString()),
      redis.setEx(`wallet_balance:${toWalletId}`, 30, receiverUpdateResult.rows[0].balance.toString())
    ]);

    res.status(201).json({
      success: true,
      data: {
        transaction_id: transactionId,
        from_wallet_id: fromWalletId,
        to_wallet_id: toWalletId,
        amount: transferAmount,
        type: 'transfer',
        description: description || 'Money transfer',
        status: 'completed',
        created_at: createdAt,
        sender_new_balance: parseFloat(senderUpdateResult.rows[0].balance),
        receiver_new_balance: parseFloat(receiverUpdateResult.rows[0].balance)
      }
    });

  } catch (error) {
    // rollback on error
    await client.query('ROLLBACK');

    console.error('Transfer error-', error);

    res.status(500).json({
      success: false,
      message: 'Transfer failed due to internal error',
      code: 'TRANSFER_ERROR'
    });
  } finally {
    client.release();
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error-', error);
  res.status(500).json({
    success: false,
    message: 'Internal server error',
    code: 'INTERNAL_ERROR'
  });
});

const initSchema = async () => {
  const schema = fs.readFileSync('./src/schema/database.sql', 'utf8');
  await pool.query(schema);
};

const PORT = process.env.PORT || 3001;
initSchema().then(() => {
  app.listen(PORT, () => {
    console.log(`Wallet API server running on port ${PORT}`);
  })
}).catch((error) => {
  console.error('Failed to initialize schema:', error);
  process.exit(1);
});

export default app