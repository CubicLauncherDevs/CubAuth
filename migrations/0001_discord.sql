-- New installations only. Existing Supabase accounts are deliberately not imported.
PRAGMA foreign_keys = ON;

CREATE TABLE accounts (
  discord_id TEXT PRIMARY KEY,
  id TEXT NOT NULL UNIQUE,
  disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE profiles (
  id TEXT PRIMARY KEY,
  discord_id TEXT NOT NULL UNIQUE REFERENCES accounts(discord_id) ON DELETE CASCADE,
  name TEXT NOT NULL COLLATE NOCASE UNIQUE CHECK (length(name) BETWEEN 3 AND 16 AND name NOT GLOB '*[^A-Za-z0-9_]*'),
  skin_hash TEXT,
  skin_model TEXT NOT NULL DEFAULT 'default' CHECK (skin_model IN ('default', 'slim'))
);

CREATE TABLE launcher_tokens (
  token_hash TEXT PRIMARY KEY,
  discord_id TEXT NOT NULL REFERENCES accounts(discord_id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);
CREATE INDEX launcher_tokens_expiration ON launcher_tokens(expires_at);

CREATE TABLE sessions (
  token_hash TEXT PRIMARY KEY,
  discord_id TEXT NOT NULL REFERENCES accounts(discord_id) ON DELETE CASCADE,
  profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  client_token TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('web', 'launcher')),
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX sessions_discord ON sessions(discord_id);
CREATE INDEX sessions_expiration ON sessions(expires_at);

CREATE TABLE joins (
  server_id TEXT NOT NULL,
  profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL REFERENCES sessions(token_hash) ON DELETE CASCADE,
  ip TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (server_id, profile_id)
);
CREATE INDEX joins_expiration ON joins(expires_at);

CREATE TABLE rate_limits (
  key TEXT PRIMARY KEY,
  hits INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

-- OAuth state is single-use and stores a hash, never the browser's secret.
CREATE TABLE oauth_states (
  state_hash TEXT PRIMARY KEY,
  challenge TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX oauth_states_expiration ON oauth_states(expires_at);

CREATE TABLE login_tickets (
  token_hash TEXT PRIMARY KEY,
  discord_id TEXT NOT NULL,
  challenge TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE registrations (
  token_hash TEXT PRIMARY KEY,
  discord_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE name_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  previous_name TEXT NOT NULL,
  new_name TEXT NOT NULL,
  changed_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX name_history_profile ON name_history(profile_id, id DESC);
CREATE TRIGGER record_name_change AFTER UPDATE OF name ON profiles
WHEN old.name COLLATE BINARY <> new.name COLLATE BINARY BEGIN
  INSERT INTO name_history(profile_id, previous_name, new_name) VALUES (new.id, old.name, new.name);
END;
