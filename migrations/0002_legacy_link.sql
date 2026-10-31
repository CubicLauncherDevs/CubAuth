-- Links accounts created on the old Supabase backend to Discord at migration time.
ALTER TABLE accounts ADD COLUMN legacy_user_id TEXT;
ALTER TABLE accounts ADD COLUMN discord_email TEXT;
CREATE UNIQUE INDEX accounts_legacy_user ON accounts(legacy_user_id) WHERE legacy_user_id IS NOT NULL;

ALTER TABLE login_tickets ADD COLUMN discord_email TEXT;
ALTER TABLE registrations ADD COLUMN discord_email TEXT;

-- A verified legacy login is kept server-side until the Discord callback completes.
CREATE TABLE legacy_tickets (
  token_hash TEXT PRIMARY KEY,
  legacy_user_id TEXT NOT NULL,
  profile TEXT NOT NULL,
  history TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX legacy_tickets_expiration ON legacy_tickets(expires_at);

-- Abort the entire linking batch if another request consumed the ticket first.
CREATE TABLE legacy_link_guards (
  id TEXT PRIMARY KEY,
  valid INTEGER NOT NULL CHECK (valid = 1)
);
