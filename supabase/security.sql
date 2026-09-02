-- ============================================================================
-- 销售订单登记 —— 数据库访问控制
--
-- 作用：关闭匿名（未登录）访问，只有通过页面密码换到登录令牌的请求才能
--       读写订单数据。执行前请先在 Supabase 后台建好登录账号，见 README。
--
-- 执行方式：Supabase 控制台 → SQL Editor → 新建查询 → 粘贴全文 → Run
-- 可重复执行，不会破坏已有数据。
-- ============================================================================

-- 1. 打开行级安全。开启后，没有匹配策略的请求一律读不到、也写不进数据。
alter table public.orders     enable row level security;
alter table public.order_logs enable row level security;

-- 2. 收回匿名角色的一切权限。
--    这一步是关键：publishable key 对应的就是 anon 角色，
--    它写在前端源码里，谁都拿得到，所以绝不能给它任何权限。
revoke all on public.orders     from anon;
revoke all on public.order_logs from anon;

-- 3. 给登录用户授权。
grant select, insert, update, delete on public.orders     to authenticated;
grant select                        on public.order_logs to authenticated;
grant usage, select on all sequences in schema public to authenticated;

-- 4. 策略：登录用户可以操作全部订单（团队共用一个账号，互相可见）。
drop policy if exists "authenticated can read orders"   on public.orders;
drop policy if exists "authenticated can insert orders" on public.orders;
drop policy if exists "authenticated can update orders" on public.orders;
drop policy if exists "authenticated can delete orders" on public.orders;

create policy "authenticated can read orders"
  on public.orders for select to authenticated using (true);

create policy "authenticated can insert orders"
  on public.orders for insert to authenticated with check (true);

create policy "authenticated can update orders"
  on public.orders for update to authenticated using (true) with check (true);

create policy "authenticated can delete orders"
  on public.orders for delete to authenticated using (true);

-- 5. 操作日志只读。日志由触发器写入，前端不需要、也不应该能改它。
drop policy if exists "authenticated can read logs" on public.order_logs;

create policy "authenticated can read logs"
  on public.order_logs for select to authenticated using (true);

-- ============================================================================
-- 验证：执行完之后可以这样自查
--
--   select tablename, rowsecurity from pg_tables
--    where schemaname = 'public' and tablename in ('orders','order_logs');
--   -- rowsecurity 都应为 true
--
--   select tablename, policyname, roles from pg_policies
--    where schemaname = 'public';
--   -- 应看到上面这 5 条策略，roles 均为 {authenticated}
--
-- 还可以在浏览器无痕窗口直接访问下面这个地址（把 KEY 换成源码里的
-- publishable key），配置正确的话应当返回空数组或 401，而不是订单数据：
--   https://<项目>.supabase.co/rest/v1/orders?select=*&apikey=KEY
-- ============================================================================
