#!/usr/bin/env node
/*
 * 生成页面密码哈希。
 *
 *   node tools/hash-password.js 新密码
 *
 * 把输出的字符串填到 index.html 的 PASSWORD_HASH 常量里，
 * 同时到 Supabase 后台把登录账号的密码改成同一个，两边必须一致。
 */
const crypto = require('crypto');

const SALT = 'sales-order-auth-v1'; // 必须与 index.html 中的 PASSWORD_SALT 相同
const password = process.argv[2];

if (!password) {
  console.error('用法: node tools/hash-password.js <新密码>');
  process.exit(1);
}
if (password.length < 6) {
  console.error('Supabase 要求密码至少 6 位。');
  process.exit(1);
}

const hash = crypto.createHash('sha256').update(SALT + password, 'utf8').digest('base64');
console.log('\nconst PASSWORD_HASH = \'' + hash + '\';\n');
console.log('请把上面这行替换 index.html 中的同名常量，');
console.log('并在 Supabase → Authentication → Users 中把账号密码同步改为：' + password + '\n');
