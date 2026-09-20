-- Apply after 202609200001_cubauth.sql. Existing accounts and UUIDs are preserved.
begin;

alter table cubauth.sessions add column needs_refresh boolean not null default false;

create table cubauth.name_history (
  id uuid primary key default gen_random_uuid(),
  profile_id uuid not null references cubauth.profiles(id) on delete cascade,
  previous_name text not null,
  new_name text not null,
  changed_at timestamptz not null default clock_timestamp()
);
create index name_history_profile on cubauth.name_history(profile_id, changed_at desc);
alter table cubauth.name_history enable row level security;

create or replace function public.cubauth_session(p_hash text, p_client text default null) returns jsonb
language sql security definer set search_path = '' as $$
  select jsonb_build_object('user_id', s.user_id, 'client_token', s.client_token, 'profile', to_jsonb(p))
  from cubauth.sessions s join cubauth.profiles p on p.id = s.profile_id join auth.users u on u.id = s.user_id
  where s.token_hash = p_hash and s.expires_at > now() and not s.needs_refresh
    and (p_client is null or s.client_token = p_client)
    and (u.banned_until is null or u.banned_until <= now());
$$;

-- Renamed profiles temporarily invalidate old sessions: only refresh remains allowed.
create or replace function public.cubauth_refresh(p_hash text, p_new_hash text, p_client text, p_ttl integer) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare v_user uuid; v_session jsonb;
begin
  select user_id into v_user from cubauth.sessions where token_hash = p_hash;
  if not found then return null; end if;
  perform pg_advisory_xact_lock(hashtextextended(v_user::text, 0));
  select jsonb_build_object('user_id', s.user_id, 'client_token', s.client_token, 'profile', to_jsonb(p))
    into v_session from cubauth.sessions s
    join cubauth.profiles p on p.id = s.profile_id join auth.users u on u.id = s.user_id
    where s.token_hash = p_hash and s.expires_at > now()
      and (p_client is null or s.client_token = p_client)
      and (u.banned_until is null or u.banned_until <= now());
  if v_session is null then return null; end if;
  delete from cubauth.sessions where token_hash = p_hash;
  insert into cubauth.sessions(token_hash, user_id, profile_id, client_token, expires_at)
    values (p_new_hash, v_user, (v_session->'profile'->>'id')::uuid,
      v_session->>'client_token', now() + make_interval(secs => least(greatest(p_ttl, 60), 2592000)));
  return v_session;
end;
$$;

create function public.cubauth_account(p_hash text) returns jsonb
language sql security definer set search_path = '' as $$
  select jsonb_build_object(
    'user_id', u.id, 'profile', to_jsonb(p), 'email', u.email,
    'email_confirmed', u.email_confirmed_at is not null,
    'pending_email', nullif(u.new_email, ''), 'created_at', u.created_at,
    'name_history', coalesce((select jsonb_agg(h order by h.changed_at desc) from (
      select previous_name, new_name, changed_at from cubauth.name_history
      where profile_id = p.id order by changed_at desc limit 20
    ) h), '[]'::jsonb),
    'history_total', (select count(*) from cubauth.name_history where profile_id = p.id)
  ) from cubauth.sessions s
    join cubauth.profiles p on p.id = s.profile_id join auth.users u on u.id = s.user_id
    where s.token_hash = p_hash and s.expires_at > now() and not s.needs_refresh
      and (u.banned_until is null or u.banned_until <= now());
$$;

create function public.cubauth_rename_profile(p_hash text, p_name text, p_new_hash text, p_ttl integer) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare v_user uuid; v_session jsonb; v_profile uuid; v_old_name text;
begin
  if p_name !~ '^[A-Za-z0-9_]{3,16}$' then return jsonb_build_object('error', 'InvalidUsername'); end if;
  select user_id into v_user from cubauth.sessions where token_hash = p_hash;
  if not found then return null; end if;
  perform pg_advisory_xact_lock(hashtextextended(v_user::text, 0));
  v_session := public.cubauth_session(p_hash);
  if v_session is null then return null; end if;
  v_profile := (v_session->'profile'->>'id')::uuid;
  v_old_name := v_session->'profile'->>'name';
  if v_old_name <> p_name then
    begin
      update cubauth.profiles set name = p_name where id = v_profile;
    exception when unique_violation then
      return jsonb_build_object('error', 'UsernameTaken');
    end;
    insert into cubauth.name_history(profile_id, previous_name, new_name) values (v_profile, v_old_name, p_name);
    update auth.users set raw_user_meta_data = jsonb_set(coalesce(raw_user_meta_data, '{}'::jsonb), '{username}', to_jsonb(p_name)) where id = v_user;
    delete from cubauth.joins j using cubauth.sessions s where j.token_hash = s.token_hash and s.user_id = v_user;
    update cubauth.sessions set needs_refresh = true where user_id = v_user;
  end if;
  delete from cubauth.sessions where token_hash = p_hash;
  return public.cubauth_issue_session(v_user, p_new_hash, v_session->>'client_token', p_ttl);
end;
$$;

create or replace function public.cubauth_has_joined(p_name text, p_server text, p_ip text default null) returns jsonb
language sql security definer set search_path = '' as $$
  select to_jsonb(p) from cubauth.joins j
    join cubauth.sessions s on s.token_hash = j.token_hash
    join cubauth.profiles p on p.id = j.profile_id
    join auth.users u on u.id = s.user_id
    where j.server_id = p_server and lower(p.name) = lower(p_name)
      and j.expires_at > now() and s.expires_at > now() and not s.needs_refresh
      and (p_ip is null or j.ip::inet = p_ip::inet)
      and (u.banned_until is null or u.banned_until <= now()) limit 1;
$$;

revoke all on function public.cubauth_account(text) from public, anon, authenticated;
revoke all on function public.cubauth_rename_profile(text, text, text, integer) from public, anon, authenticated;
grant execute on function public.cubauth_account(text) to service_role;
grant execute on function public.cubauth_rename_profile(text, text, text, integer) to service_role;

notify pgrst, 'reload schema';
commit;
