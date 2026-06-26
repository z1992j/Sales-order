# 销售订单登记

电信宽带销售订单登记系统：**Supabase 云数据库 + GitHub Pages 静态前端**，任意访客打开即可登记、查询、共享同一份数据。

## 访问地址

https://z1992j.github.io/Sales-order/

## 功能

| 功能 | 说明 |
|------|------|
| 云端共享 | 所有访客实时共享同一份订单数据 |
| 智能录入 | 粘贴下单文本，自动提取姓名/手机/身份证/地址/运营商/套餐/费用 |
| 地址识别 | 内置全国主要城市映射，根据地址自动识别省市 |
| 订单管理 | 新增 / 编辑 / 删除 / 搜索，底部合计行 |
| 导出 CSV | 一键下载全部订单 |
| 响应式 | 手机 / 电脑均可使用 |

## 架构

```
浏览器 (index.html) ── REST ──> Supabase (PostgreSQL + Row Level Security)
        │
        └── 静态托管在 GitHub Pages
```

- 前端：纯静态 HTML/CSS/JS，无构建步骤
- 数据库：Supabase `orders` 表，开放匿名读 / 写（适合内部小团队）
- 部署：GitHub Actions 自动把 `main` 分支发布到 Pages

## 目录结构

```
.
├── index.html              页面 + 全部前端逻辑（含 Supabase 客户端）
├── orders.json             历史数据快照，已迁移到 Supabase，仅供备份
├── .github/workflows/      GitHub Pages 自动部署
└── README.md
```

## Supabase 表结构

Supabase URL 与 anon key 直接写在 `index.html` 中——anon key 设计上就是可公开的，真正的访问控制由 RLS 策略提供。

```sql
create table orders (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz default now(),
  apply_date date, payback_date date,
  name text not null, phone text not null,
  province text, city text, carrier text, package text, duration text,
  install_fee numeric default 0, package_fee numeric default 0,
  commission numeric default 0, commission_rate numeric default 0,
  id_card text, address text
);

alter table orders enable row level security;
create policy "anyone read"   on orders for select using (true);
create policy "anyone insert" on orders for insert with check (true);
create policy "anyone update" on orders for update using (true);
create policy "anyone delete" on orders for delete using (true);
```

当前策略是"全员可读写"，适合内部信任团队。若需权限控制可改为 Supabase Auth + 基于 `auth.uid()` 的策略。

## 部署

推送到 `main` 分支后，GitHub Actions 自动部署到 Pages（Settings → Pages → Source = GitHub Actions）。
