-- ===== Files library (menu TASK → Files): list / rename / delete + chunked upload up to 100 MB per file, 100 MB total storage (server-enforced). Run this whole block in the Supabase SQL editor (safe to re-run). =====
alter table public.ahg_files add column if not exists ready boolean not null default true;
alter table public.ahg_files add column if not exists chunks int not null default 0;
create table if not exists public.ahg_file_chunks (
  file_id text not null references public.ahg_files(id) on delete cascade, idx int not null, data text not null, primary key (file_id, idx)
);
alter table public.ahg_file_chunks enable row level security;
revoke all on public.ahg_file_chunks from anon, authenticated;

create or replace function public.ahg_file_list(p_token text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare u ahg_users; r jsonb;
begin
  u := ahg_me(p_token);
  if u.name is null then return jsonb_build_object('ok', false, 'err', 'auth'); end if;
  select coalesce(jsonb_agg(jsonb_build_object('id', id, 'name', name, 'mime', mime, 'size', size, 'owner', owner, 'created', (extract(epoch from created) * 1000)::bigint) order by created desc), '[]'::jsonb)
    into r from (select * from ahg_files where ready order by created desc limit 1000) f;
  return jsonb_build_object('ok', true, 'files', r, 'used', (select coalesce(sum(size), 0) from ahg_files), 'limit', 104857600);
end $$;

create or replace function public.ahg_file_rename(p_token text, p_id text, p_name text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare u ahg_users; f ahg_files; nm text;
begin
  u := ahg_me(p_token);
  if u.name is null then return jsonb_build_object('ok', false, 'err', 'auth'); end if;
  nm := trim(coalesce(p_name, ''));
  if nm = '' or length(nm) > 200 then return jsonb_build_object('ok', false, 'err', 'name'); end if;
  select * into f from ahg_files where id = p_id;
  if not found then return jsonb_build_object('ok', false, 'err', 'missing'); end if;
  if f.owner <> u.name and u.role <> 'admin' then return jsonb_build_object('ok', false, 'err', 'forbidden'); end if;
  update ahg_files set name = nm where id = p_id;
  return jsonb_build_object('ok', true, 'name', nm);
end $$;

create or replace function public.ahg_file_delete(p_token text, p_id text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare u ahg_users; f ahg_files;
begin
  u := ahg_me(p_token);
  if u.name is null then return jsonb_build_object('ok', false, 'err', 'auth'); end if;
  select * into f from ahg_files where id = p_id;
  if not found then return jsonb_build_object('ok', false, 'err', 'missing'); end if;
  if f.owner <> u.name and u.role <> 'admin' then return jsonb_build_object('ok', false, 'err', 'forbidden'); end if;
  delete from ahg_files where id = p_id; -- chunks go with it (on delete cascade)
  return jsonb_build_object('ok', true);
end $$;

-- download: small files come back whole; chunked files return {chunks:n} and are fetched with ahg_file_chunk_get
create or replace function public.ahg_file_get(p_token text, p_id text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare u ahg_users; f ahg_files;
begin
  u := ahg_me(p_token);
  if u.name is null then return jsonb_build_object('ok', false, 'err', 'auth'); end if;
  select * into f from ahg_files where id = p_id and ready;
  if not found then return jsonb_build_object('ok', false, 'err', 'missing'); end if;
  return jsonb_build_object('ok', true, 'name', f.name, 'mime', f.mime, 'data', f.data, 'chunks', f.chunks);
end $$;

create or replace function public.ahg_file_chunk_get(p_token text, p_id text, p_idx int)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare u ahg_users; d text;
begin
  u := ahg_me(p_token);
  if u.name is null then return jsonb_build_object('ok', false, 'err', 'auth'); end if;
  select c.data into d from ahg_file_chunks c join ahg_files f on f.id = c.file_id where c.file_id = p_id and c.idx = p_idx and f.ready;
  if d is null then return jsonb_build_object('ok', false, 'err', 'missing'); end if;
  return jsonb_build_object('ok', true, 'data', d);
end $$;

-- chunked upload (max 100 MB, 3 MiB per chunk): begin → chunk_put × n → commit
create or replace function public.ahg_file_begin(p_token text, p_id text, p_name text, p_mime text, p_size bigint, p_chunks int)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare u ahg_users;
begin
  u := ahg_me(p_token);
  if u.name is null then return jsonb_build_object('ok', false, 'err', 'auth'); end if;
  if coalesce(p_id, '') !~ '^[A-Za-z0-9_-]{10,64}$' or length(coalesce(p_name, '')) not between 1 and 200
     or p_size < 1 or p_size > 104857600 or p_chunks <> ceil(p_size / 3145728.0) then
    return jsonb_build_object('ok', false, 'err', 'size'); end if;
  delete from ahg_files where not ready and created < now() - interval '1 day';
  if (select coalesce(sum(size), 0) from ahg_files) + p_size > 104857600 then return jsonb_build_object('ok', false, 'err', 'quota'); end if;
  insert into ahg_files (id, owner, name, mime, size, data, ready, chunks)
  values (p_id, u.name, p_name, left(coalesce(p_mime, ''), 120), p_size, '', false, p_chunks)
  on conflict (id) do nothing;
  if not exists (select 1 from ahg_files where id = p_id and owner = u.name and not ready) then return jsonb_build_object('ok', false, 'err', 'exists'); end if;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.ahg_file_chunk_put(p_token text, p_id text, p_idx int, p_data text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare u ahg_users; f ahg_files;
begin
  u := ahg_me(p_token);
  if u.name is null then return jsonb_build_object('ok', false, 'err', 'auth'); end if;
  select * into f from ahg_files where id = p_id and owner = u.name and not ready;
  if not found then return jsonb_build_object('ok', false, 'err', 'missing'); end if;
  if p_idx < 0 or p_idx >= f.chunks or length(coalesce(p_data, '')) < 1 or length(p_data) > 4300000 then return jsonb_build_object('ok', false, 'err', 'size'); end if;
  insert into ahg_file_chunks (file_id, idx, data) values (p_id, p_idx, p_data)
  on conflict (file_id, idx) do update set data = excluded.data;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.ahg_file_commit(p_token text, p_id text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare u ahg_users; f ahg_files; n int;
begin
  u := ahg_me(p_token);
  if u.name is null then return jsonb_build_object('ok', false, 'err', 'auth'); end if;
  select * into f from ahg_files where id = p_id and owner = u.name and not ready;
  if not found then return jsonb_build_object('ok', false, 'err', 'missing'); end if;
  select count(*) into n from ahg_file_chunks where file_id = p_id;
  if n <> f.chunks then return jsonb_build_object('ok', false, 'err', 'incomplete'); end if;
  update ahg_files set ready = true where id = p_id;
  return jsonb_build_object('ok', true);
end $$;

revoke all on function public.ahg_file_list(text), public.ahg_file_rename(text, text, text), public.ahg_file_delete(text, text),
  public.ahg_file_get(text, text), public.ahg_file_chunk_get(text, text, int), public.ahg_file_begin(text, text, text, text, bigint, int),
  public.ahg_file_chunk_put(text, text, int, text), public.ahg_file_commit(text, text) from public;
grant execute on function public.ahg_file_list(text), public.ahg_file_rename(text, text, text), public.ahg_file_delete(text, text),
  public.ahg_file_get(text, text), public.ahg_file_chunk_get(text, text, int), public.ahg_file_begin(text, text, text, text, bigint, int),
  public.ahg_file_chunk_put(text, text, int, text), public.ahg_file_commit(text, text) to anon, authenticated;

notify pgrst, 'reload schema';

-- small direct upload (also used by chat / task attachments): same 100 MB total quota
create or replace function public.ahg_file_put(p_token text, p_id text, p_name text, p_mime text, p_data text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare u ahg_users;
begin
  u := ahg_me(p_token);
  if u.name is null then return jsonb_build_object('ok', false, 'err', 'auth'); end if;
  if coalesce(p_id, '') !~ '^[A-Za-z0-9_-]{10,64}$' or length(coalesce(p_data, '')) > 15000000 or length(coalesce(p_name, '')) > 200 then
    return jsonb_build_object('ok', false, 'err', 'size'); end if;
  if exists (select 1 from ahg_files where id = p_id) then return jsonb_build_object('ok', true, 'id', p_id); end if;
  if (select coalesce(sum(size), 0) from ahg_files) + length(p_data) * 3 / 4 > 104857600 then return jsonb_build_object('ok', false, 'err', 'quota'); end if;
  insert into ahg_files (id, owner, name, mime, size, data) values (p_id, u.name, p_name, left(coalesce(p_mime, ''), 120), length(p_data) * 3 / 4, p_data)
  on conflict (id) do nothing;
  return jsonb_build_object('ok', true, 'id', p_id);
end $$;
revoke all on function public.ahg_file_put(text, text, text, text, text) from public;
grant execute on function public.ahg_file_put(text, text, text, text, text) to anon, authenticated;
