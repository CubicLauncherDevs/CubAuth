-- Run on a dedicated Supabase project. All data access goes through the Worker.
begin;

create schema if not exists cubauth;
revoke all on schema cubauth from public, anon, authenticated;

create table cubauth.profiles (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null unique references auth.users(id) on delete cascade,
  name text not null check (name ~ '^[A-Za-z0-9_]{3,16}$'),
  skin_hash text check (skin_hash ~ '^[0-9a-f]{64}$'),
  skin_model text not null default 'default' check (skin_model in ('default', 'slim'))
);
create unique index profiles_name_unique on cubauth.profiles (lower(name));

create table cubauth.sessions (
  token_hash text primary key check (token_hash ~ '^[0-9a-f]{64}$'),
  user_id uuid not null references auth.users(id) on delete cascade,
  profile_id uuid not null references cubauth.profiles(id) on delete cascade,
  client_token text not null check (length(client_token) between 1 and 1024),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null
);
create index sessions_user on cubauth.sessions(user_id, created_at desc);
create index sessions_expiration on cubauth.sessions(expires_at);

create table cubauth.joins (
  server_id text not null check (length(server_id) between 1 and 128),
  profile_id uuid not null references cubauth.profiles(id) on delete cascade,
  token_hash text not null references cubauth.sessions(token_hash) on delete cascade,
  ip text not null,
  expires_at timestamptz not null,
  primary key (server_id, profile_id)
);
create index joins_expiration on cubauth.joins(expires_at);

create table cubauth.rate_limits (
  key text primary key,
  hits integer not null,
  expires_at timestamptz not null
);

alter table cubauth.profiles enable row level security;
alter table cubauth.sessions enable row level security;
alter table cubauth.joins enable row level security;
alter table cubauth.rate_limits enable row level security;

create function cubauth.create_profile() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  insert into cubauth.profiles(user_id, name) values (new.id, new.raw_user_meta_data->>'username');
  return new;
end;
$$;
create trigger cubauth_new_user after insert on auth.users
for each row execute function cubauth.create_profile();
revoke all on function cubauth.create_profile() from public;

-- A password reset or change also revokes launcher sessions.
create function cubauth.password_changed() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if new.encrypted_password is distinct from old.encrypted_password then
    perform pg_advisory_xact_lock(hashtextextended(new.id::text, 0));
    delete from cubauth.sessions where user_id = new.id;
  end if;
  return new;
end;
$$;
create trigger cubauth_password_changed after update of encrypted_password on auth.users
for each row execute function cubauth.password_changed();
revoke all on function cubauth.password_changed() from public;

create function public.cubauth_login_identity(p_username text) returns jsonb
language sql security definer set search_path = '' as $$
  select jsonb_build_object('email', u.email, 'user_id', u.id)
  from auth.users u join cubauth.profiles p on p.user_id = u.id
  where lower(u.email) = lower(p_username) or lower(p.name) = lower(p_username)
  limit 1;
$$;

create function public.cubauth_rate_limit(p_key text, p_limit integer, p_window integer) returns boolean
language plpgsql security definer set search_path = '' as $$
declare v_hits integer;
begin
  insert into cubauth.rate_limits as r(key, hits, expires_at)
  values (p_key, 1, now() + make_interval(secs => p_window))
  on conflict (key) do update set
    hits = case when r.expires_at <= now() then 1 else least(r.hits + 1, p_limit + 1) end,
    expires_at = case when r.expires_at <= now() then excluded.expires_at else r.expires_at end
  returning hits into v_hits;
  return v_hits <= p_limit;
end;
$$;

create function public.cubauth_issue_session(
  p_user_id uuid, p_hash text, p_client text, p_ttl integer
) returns jsonb language plpgsql security definer set search_path = '' as $$
declare v_profile cubauth.profiles;
begin
  perform pg_advisory_xact_lock(hashtextextended(p_user_id::text, 0));
  select p.* into v_profile from cubauth.profiles p join auth.users u on u.id = p.user_id
    where p.user_id = p_user_id and (u.banned_until is null or u.banned_until <= now());
  if not found then return null; end if;
  delete from cubauth.sessions where user_id = p_user_id and expires_at <= now();
  delete from cubauth.sessions where token_hash in (
    select token_hash from cubauth.sessions where user_id = p_user_id
    order by created_at desc, token_hash offset 9
  );
  insert into cubauth.sessions(token_hash, user_id, profile_id, client_token, expires_at)
    values (p_hash, p_user_id, v_profile.id, p_client, now() + make_interval(secs => least(greatest(p_ttl, 60), 2592000)));
  return jsonb_build_object('user_id', p_user_id, 'client_token', p_client, 'profile', to_jsonb(v_profile));
end;
$$;

create function public.cubauth_session(p_hash text, p_client text default null) returns jsonb
language sql security definer set search_path = '' as $$
  select jsonb_build_object('user_id', s.user_id, 'client_token', s.client_token, 'profile', to_jsonb(p))
  from cubauth.sessions s join cubauth.profiles p on p.id = s.profile_id join auth.users u on u.id = s.user_id
  where s.token_hash = p_hash and s.expires_at > now()
    and (p_client is null or s.client_token = p_client)
    and (u.banned_until is null or u.banned_until <= now());
$$;

create function public.cubauth_refresh(p_hash text, p_new_hash text, p_client text, p_ttl integer) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare v_user uuid; v_session jsonb;
begin
  select user_id into v_user from cubauth.sessions where token_hash = p_hash;
  if not found then return null; end if;
  perform pg_advisory_xact_lock(hashtextextended(v_user::text, 0));
  v_session := public.cubauth_session(p_hash, p_client);
  if v_session is null then return null; end if;
  delete from cubauth.sessions where token_hash = p_hash;
  insert into cubauth.sessions(token_hash, user_id, profile_id, client_token, expires_at)
    values (p_new_hash, v_user, (v_session->'profile'->>'id')::uuid,
      v_session->>'client_token', now() + make_interval(secs => least(greatest(p_ttl, 60), 2592000)));
  return v_session;
end;
$$;

create function public.cubauth_invalidate(p_hash text) returns void
language plpgsql security definer set search_path = '' as $$
declare v_user uuid;
begin
  select user_id into v_user from cubauth.sessions where token_hash = p_hash;
  if found then
    perform pg_advisory_xact_lock(hashtextextended(v_user::text, 0));
    delete from cubauth.sessions where token_hash = p_hash;
  end if;
end;
$$;

create function public.cubauth_signout(p_user_id uuid) returns void
language plpgsql security definer set search_path = '' as $$
begin
  perform pg_advisory_xact_lock(hashtextextended(p_user_id::text, 0));
  delete from cubauth.sessions where user_id = p_user_id;
end;
$$;

create function public.cubauth_join(p_hash text, p_profile uuid, p_server text, p_ip text) returns boolean
language plpgsql security definer set search_path = '' as $$
declare v_user uuid; v_session jsonb;
begin
  select user_id into v_user from cubauth.sessions where token_hash = p_hash;
  if not found then return false; end if;
  perform pg_advisory_xact_lock(hashtextextended(v_user::text, 0));
  v_session := public.cubauth_session(p_hash);
  if v_session is null or (v_session->'profile'->>'id')::uuid <> p_profile then return false; end if;
  insert into cubauth.joins(server_id, profile_id, token_hash, ip, expires_at)
    values (p_server, p_profile, p_hash, p_ip, now() + interval '30 seconds')
    on conflict (server_id, profile_id) do update set token_hash = excluded.token_hash,
      ip = excluded.ip, expires_at = excluded.expires_at;
  return true;
end;
$$;

create function public.cubauth_has_joined(p_name text, p_server text, p_ip text default null) returns jsonb
language sql security definer set search_path = '' as $$
  select to_jsonb(p) from cubauth.joins j
    join cubauth.sessions s on s.token_hash = j.token_hash
    join cubauth.profiles p on p.id = j.profile_id
    join auth.users u on u.id = s.user_id
    where j.server_id = p_server and lower(p.name) = lower(p_name)
      and j.expires_at > now() and s.expires_at > now()
      and (p_ip is null or j.ip::inet = p_ip::inet)
      and (u.banned_until is null or u.banned_until <= now()) limit 1;
$$;

create function public.cubauth_profile(p_id uuid) returns jsonb
language sql security definer set search_path = '' as $$
  select to_jsonb(p) from cubauth.profiles p where p.id = p_id;
$$;

create function public.cubauth_profiles(p_names text[]) returns jsonb
language sql security definer set search_path = '' as $$
  select coalesce(jsonb_agg(jsonb_build_object('id', replace(id::text, '-', ''), 'name', name)), '[]'::jsonb)
  from cubauth.profiles where lower(name) = any(array(select lower(unnest(p_names))));
$$;

create function public.cubauth_set_skin(p_hash text, p_profile uuid, p_skin text, p_model text) returns boolean
language plpgsql security definer set search_path = '' as $$
declare v_user uuid; v_session jsonb;
begin
  select user_id into v_user from cubauth.sessions where token_hash = p_hash;
  if not found then return false; end if;
  perform pg_advisory_xact_lock(hashtextextended(v_user::text, 0));
  v_session := public.cubauth_session(p_hash);
  if v_session is null or (v_session->'profile'->>'id')::uuid <> p_profile then return false; end if;
  update cubauth.profiles set skin_hash = p_skin, skin_model = p_model where id = p_profile;
  return true;
end;
$$;

create function public.cubauth_cleanup() returns void
language plpgsql security definer set search_path = '' as $$
begin
  delete from cubauth.joins where expires_at <= now();
  delete from cubauth.sessions where expires_at <= now();
  delete from cubauth.rate_limits where expires_at <= now();
end;
$$;

-- Only the service key can call these RPCs, including future default PUBLIC grants.
do $$
declare f record;
begin
  for f in select p.oid::regprocedure as signature from pg_proc p
    join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public' and p.proname like 'cubauth\_%' escape '\'
  loop
    execute format('revoke all on function %s from public, anon, authenticated', f.signature);
    execute format('grant execute on function %s to service_role', f.signature);
  end loop;
end;
$$;

-- Public reads; no anon/authenticated write policies. Uploads use the Worker service key.
insert into storage.buckets(id, name, public, file_size_limit, allowed_mime_types)
values ('skins', 'skins', true, 131072, array['image/png']);

commit;
