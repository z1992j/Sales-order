# Sales-order

宽带销售订单登记与查询工具。

## 访问

https://z1992j.github.io/Sales-order/

访问密码：`888888`

## 功能

- 订单录入、编辑、删除、查询
- 密码登录，可选在本设备保持登录
- 一键标记回款，新增时自动提醒重复手机号
- 智能文本解析，自动提取下单信息
- 多用户工作台（通过 URL 参数切换）
- 数据筛选、排序、CSV 导入导出
- 近 12 个月佣金趋势图
- 响应式布局，手机 / 电脑均可使用

## ⚠️ 必读：完成数据库配置，登录才真正有用

这个页面是纯静态的，源码任何人都能看到。**只有页面密码是挡不住人的** ——
懂技术的人可以跳过页面，直接拿源码里的 publishable key 去读写数据库。

真正的防线在数据库那一侧，需要你在 Supabase 后台做两件事。**做完之前，
页面顶部会一直显示橙色提醒。**

### 第 1 步：创建登录账号

1. 打开 Supabase 控制台 → 你的项目 → **Authentication** → **Users**
2. 点 **Add user** → **Create new user**
3. 填写：
   - Email：`team@sales-order.local`
   - Password：`888888`
   - 勾选 **Auto Confirm User**（不勾的话账号需要邮箱验证，无法登录）
4. 保存

邮箱地址必须和 `index.html` 里的 `AUTH_EMAIL` 完全一致。

### 第 2 步：锁死数据库

1. Supabase 控制台 → **SQL Editor** → **New query**
2. 把 [`supabase/security.sql`](supabase/security.sql) 的全部内容粘进去
3. 点 **Run**

这一步会关闭匿名访问，并只放行已登录的请求。脚本可以重复执行，不会动到已有数据。

### 第 3 步：验证

- 刷新页面，重新登录一次，橙色提醒应当消失，数据正常显示。
- 用无痕窗口打开下面这个地址（`KEY` 换成源码里的 publishable key）：
  `https://cgieubqhafwwprwzerty.supabase.co/rest/v1/orders?select=*&apikey=KEY`
  配置成功的话，返回的应该是空数组或 401，而不是订单数据。

如果第 3 步仍然能看到订单，说明 SQL 没执行成功，请回到第 2 步重来。

## 修改密码

密码存在两个地方，必须同时改：

```bash
node tools/hash-password.js 新密码
```

1. 把命令输出的 `PASSWORD_HASH` 那一行替换 `index.html` 中的同名常量。
2. 到 Supabase → Authentication → Users，把 `team@sales-order.local`
   的密码改成同一个新密码。

Supabase 要求密码至少 6 位。建议换成比 `888888` 长一些的密码：源码里
只有哈希值没有明文，但 6 位纯数字用程序很快就能猜完。

## CSV 导入

按**表头名称**匹配列，所以列的顺序无所谓，多几列少几列也没关系，
只要包含「姓名」和「手机号」两列即可。常见的表头别名都能识别，比如
「客户」等同于「姓名」，「联系方式」等同于「手机号」。

最省事的做法：先点「导出 CSV」拿到标准模板，在上面改完再导回来。

重复记录按 **手机号 + 办理日期** 判断，导入时自动跳过。

## 部署

推送 `main` 分支后，GitHub Actions 自动发布到 GitHub Pages。

## 开发

单文件应用，没有构建步骤。本地预览：

```bash
python3 -m http.server 8000
# 浏览器打开 http://localhost:8000
```
