-- Jalankan sekali di Supabase SQL Editor untuk mengaktifkan kontrol user di Panel Admin.
-- Fungsi memakai SECURITY DEFINER; anon hanya boleh mengeksekusi, bukan membaca tabel.

create or replace function public.ahg_admin_profile(
  p_token text,
  p_target text,
  p_display text,
  p_color text
) returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_admin boolean;
  v_display text := btrim(coalesce(p_display, ''));
begin
  select exists (
    select 1
    from public.ahg_sessions s
    join public.ahg_users u on u.name = s.name
    where s.token = p_token and u.role = 'admin'
  ) into v_admin;

  if not v_admin then return jsonb_build_object('ok', false, 'err', 'auth'); end if;
  if p_target = 'admin' then return jsonb_build_object('ok', false, 'err', 'protected'); end if;
  if v_display = '' or char_length(v_display) > 40 then
    return jsonb_build_object('ok', false, 'err', 'display');
  end if;
  if coalesce(p_color, '') !~ '^#[0-9a-fA-F]{6}$' then
    return jsonb_build_object('ok', false, 'err', 'color');
  end if;

  update public.ahg_users
  set display = v_display, color = lower(p_color)
  where name = p_target and role <> 'admin';

  if not found then return jsonb_build_object('ok', false, 'err', 'not_found'); end if;
  return jsonb_build_object('ok', true);
end;
$$;

create or replace function public.ahg_admin_kick(
  p_token text,
  p_target text
) returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_admin boolean;
begin
  select exists (
    select 1
    from public.ahg_sessions s
    join public.ahg_users u on u.name = s.name
    where s.token = p_token and u.role = 'admin'
  ) into v_admin;

  if not v_admin then return jsonb_build_object('ok', false, 'err', 'auth'); end if;
  if p_target = 'admin' then return jsonb_build_object('ok', false, 'err', 'protected'); end if;
  if not exists (select 1 from public.ahg_users where name = p_target) then
    return jsonb_build_object('ok', false, 'err', 'not_found');
  end if;

  delete from public.ahg_sessions where name = p_target;
  return jsonb_build_object('ok', true);
end;
$$;

revoke all on function public.ahg_admin_profile(text, text, text, text) from public;
revoke all on function public.ahg_admin_kick(text, text) from public;
grant execute on function public.ahg_admin_profile(text, text, text, text) to anon;
grant execute on function public.ahg_admin_kick(text, text) to anon;

