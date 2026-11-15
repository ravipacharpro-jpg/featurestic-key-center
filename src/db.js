import { neon } from '@neondatabase/serverless';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';

dotenv.config();

const connectionString = process.env.DATABASE_URL || 'postgresql://neondb_owner:npg_ft9EdR7DaPsZ@ep-blue-forest-berzr4o5-pooler.c-9.us-east-2.aws.neon.tech/neondb?sslmode=require&channel_binding=require';

export const sql = neon(connectionString);

export async function initDb() {
  console.log('[FKC-DB] Initializing Neon PostgreSQL Schema & Tables...');

  // Create isolated schema
  await sql`CREATE SCHEMA IF NOT EXISTS fkc`;

  // 1. Users Table (SuperAdmin, Owner, Admin, Reseller)
  await sql`
    CREATE TABLE IF NOT EXISTS fkc.users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(64) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      role VARCHAR(16) NOT NULL, -- 'superadmin', 'owner', 'admin', 'reseller'
      credits INT DEFAULT 0,
      owner_id INT DEFAULT NULL, -- which Owner tenant this user belongs to (NULL for superadmin and owners)
      admin_id INT DEFAULT NULL, -- which Admin this reseller belongs to (NULL for others)
      status VARCHAR(16) DEFAULT 'active', -- 'active', 'blocked'
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;

  // 2. Owner Settings & Pricing
  await sql`
    CREATE TABLE IF NOT EXISTS fkc.owner_settings (
      id SERIAL PRIMARY KEY,
      owner_id INT UNIQUE NOT NULL,
      brand_name VARCHAR(64) DEFAULT 'Featurestic Brand',
      max_loaders INT DEFAULT 5,
      price_1d INT DEFAULT 1,
      price_7d INT DEFAULT 5,
      price_15d INT DEFAULT 10,
      price_30d INT DEFAULT 18,
      price_60d INT DEFAULT 32,
      price_custom_per_day INT DEFAULT 1,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;

  // 3. Loaders Table (Owned by Owner)
  await sql`
    CREATE TABLE IF NOT EXISTS fkc.loaders (
      id SERIAL PRIMARY KEY,
      owner_id INT NOT NULL,
      loader_name VARCHAR(64) NOT NULL,
      slug VARCHAR(32) UNIQUE NOT NULL, -- Short connect endpoint: /c/<slug>
      package_name VARCHAR(128) DEFAULT 'com.pubg.imobile',
      app_version VARCHAR(32) DEFAULT '1.0.0',
      maintenance BOOLEAN DEFAULT FALSE,
      maintenance_msg TEXT DEFAULT 'Service undergoing maintenance.',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;

  // 4. Referral Invite Cards Table
  await sql`
    CREATE TABLE IF NOT EXISTS fkc.referrals (
      id SERIAL PRIMARY KEY,
      code VARCHAR(32) UNIQUE NOT NULL,
      creator_id INT NOT NULL,
      owner_id INT DEFAULT NULL,
      admin_id INT DEFAULT NULL,
      target_role VARCHAR(16) NOT NULL, -- 'owner', 'admin', 'reseller'
      credits_allocated INT DEFAULT 0,
      max_loaders_allowed INT DEFAULT 1,
      used_by_id INT DEFAULT NULL,
      status VARCHAR(16) DEFAULT 'pending', -- 'pending', 'used', 'revoked'
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;

  // 5. License Keys Table
  await sql`
    CREATE TABLE IF NOT EXISTS fkc.license_keys (
      id SERIAL PRIMARY KEY,
      owner_id INT NOT NULL,
      loader_id INT NOT NULL,
      creator_id INT NOT NULL,
      user_key VARCHAR(64) UNIQUE NOT NULL,
      duration_type VARCHAR(16) NOT NULL, -- '1d','7d','15d','30d','60d','custom'
      duration_days INT NOT NULL,
      max_devices INT DEFAULT 1,
      status VARCHAR(16) DEFAULT 'active', -- 'active', 'banned', 'expired'
      first_used_at TIMESTAMP DEFAULT NULL,
      expires_at TIMESTAMP DEFAULT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;

  // 6. Bound Devices Table
  await sql`
    CREATE TABLE IF NOT EXISTS fkc.bound_devices (
      id SERIAL PRIMARY KEY,
      key_id INT NOT NULL,
      device_id VARCHAR(256) NOT NULL,
      model VARCHAR(64) DEFAULT 'Unknown',
      android_version VARCHAR(16) DEFAULT 'Unknown',
      ip_address VARCHAR(64) DEFAULT '',
      first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(key_id, device_id)
    )
  `;

  // 7. Credit Ledger / Transaction Passbook
  await sql`
    CREATE TABLE IF NOT EXISTS fkc.credit_ledger (
      id SERIAL PRIMARY KEY,
      user_id INT NOT NULL,
      actor_id INT NOT NULL,
      action_type VARCHAR(32) NOT NULL, -- 'SIGNUP', 'TOP_UP', 'KEY_GEN', 'TRANSFER'
      amount INT NOT NULL,
      balance_after INT NOT NULL,
      note TEXT DEFAULT '',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;

  // 8. Ensure Initial SuperAdmin Account Exists
  const superUser = process.env.SUPERADMIN_USER || 'admin';
  const superPass = process.env.SUPERADMIN_PASS || 'superadmin2026';
  const existingSuper = (await sql`SELECT id FROM fkc.users WHERE username = ${superUser} AND role = 'superadmin'`)[0];

  if (!existingSuper) {
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(superPass, salt);
    await sql`
      INSERT INTO fkc.users (username, password_hash, role, credits)
      VALUES (${superUser}, ${hash}, 'superadmin', 999999999)
    `;
    console.log(`[FKC-DB] Created default SuperAdmin: ${superUser}`);
  }

  // Migrations for Assigned Loaders
  await sql`ALTER TABLE fkc.users ADD COLUMN IF NOT EXISTS assigned_loaders TEXT DEFAULT '[]'`;
  await sql`ALTER TABLE fkc.referrals ADD COLUMN IF NOT EXISTS assigned_loaders TEXT DEFAULT '[]'`;

  // Create High-Performance B-Tree Indexes for sub-2ms queries
  await sql`CREATE INDEX IF NOT EXISTS idx_fkc_loaders_slug ON fkc.loaders(slug)`;
  await sql`CREATE INDEX IF NOT EXISTS idx_fkc_keys_user_key ON fkc.license_keys(user_key)`;
  await sql`CREATE INDEX IF NOT EXISTS idx_fkc_keys_loader_id ON fkc.license_keys(loader_id)`;
  await sql`CREATE INDEX IF NOT EXISTS idx_fkc_devices_key ON fkc.bound_devices(key_id)`;
  await sql`CREATE INDEX IF NOT EXISTS idx_fkc_referrals_code ON fkc.referrals(code)`;

  console.log('[FKC-DB] Neon Database initialized with zero errors!');
}
