export interface Env {
  PUBLIC_URL: string;
  SERVER_NAME: string;
  SUPABASE_URL: string;
  SUPABASE_ANON_KEY: string;
  SUPABASE_SERVICE_ROLE_KEY: string;
  SIGNING_PRIVATE_KEY: string;
  SIGNING_PUBLIC_KEY: string;
  ALLOW_REGISTRATION: string;
  TOKEN_TTL_SECONDS: string;
  ACCOUNT_URL?: string;
  WEB_ORIGINS?: string;
  ASSETS: Fetcher;
}

export interface Profile {
  id: string;
  user_id: string;
  name: string;
  skin_hash: string | null;
  skin_model: 'default' | 'slim';
}

export interface Session {
  user_id: string;
  client_token: string;
  profile: Profile;
}
