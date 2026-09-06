require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcryptjs');
const ExcelJS = require('exceljs');
const path = require('path');
const cors = require('cors');
const { createClient } = require('@libsql/client');

// 新增：取得香港時間 YYYY‑MM‑DD HH:mm:ss
// 取得香港時間 YYYY-MM-DD HH:mm:ss（UTC+8，穩定每次取當下時間）
function getHongKongDateTime() {
  const hk = new Date(Date.now() + 8 * 60 * 60 * 1000);
  const p = (n) => String(n).padStart(2, '0');
  return `${hk.getUTCFullYear()}-${p(hk.getUTCMonth() + 1)}-${p(hk.getUTCDate())} ${p(hk.getUTCHours())}:${p(hk.getUTCMinutes())}:${p(hk.getUTCSeconds())}`;
}


// 建立 libsql 資料庫實例
const db = createClient({
url: "file:contact.db"
});
const app = express();
// ========== 下拉選項中文映射表 ==========
const clientTypeMap = {
"hk_company": "香港註冊公司",
"overseas_company": "境外公司",
"individual": "個人 / 自由職業者"
};
const inquiryTypeMap = {
"app-dev": "App 原生雙平台開發（iOS + Android）",
"brand-web": "企業官網 / 品牌展示網站",
"ecommerce": "電商購物網站開發",
"backend-system": "後台管理系統開發",
"landing": "表單型 / 行銷落地頁網站",
"ai-integrate": "AI 功能整合開發",
"refactor": "現有網站/App改版、維護優化",
"ads": "Meta / Google 廣告投流配套",
"quote": "個人作品集網站 報價諮詢、專案評估",
"other": "其他（自行填寫）"
};
// ========== 中間件 ==========
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
// session 完整配置，必須包在 app.use(session({ }))
app.use(session({
secret: 'shenming-2026-random-secret-key-888',
resave: false,
saveUninitialized: false,
store: new SQLiteStore({
db: 'sessions.db',
dir: './',
table: 'sessions'
  }),
cookie: {
httpOnly: true,
maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));
// ========== 初始化數據庫表 ==========
(async function initDB() {
// 客戶諮詢表
await db.execute(`CREATE TABLE IF NOT EXISTS inquiries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    company TEXT,
    name TEXT,
    phone TEXT,
    email TEXT,
    content TEXT,
    client_type TEXT DEFAULT '',
    project_type TEXT DEFAULT '',
    customer_note TEXT DEFAULT '',
    follow_user TEXT DEFAULT '',
    follow_status TEXT DEFAULT '未跟進',
    price TEXT DEFAULT '',
    create_at DATETIME
  )`);
try {
await db.execute(`ALTER TABLE inquiries ADD COLUMN client_type TEXT DEFAULT ''`);
  } catch (e) { /* 欄位已存在忽略 */ }
try {
await db.execute(`ALTER TABLE inquiries ADD COLUMN project_type TEXT DEFAULT ''`);
  } catch (e) { /* 欄位已存在忽略 */ }
// 管理員帳號表
await db.execute(`CREATE TABLE IF NOT EXISTS admin_user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'staff',
    create_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
const hashAdmin = bcrypt.hashSync("admin123", 10);
await db.execute(`INSERT OR REPLACE INTO admin_user(username, password, role) VALUES (?,?,?)`, ["admin", hashAdmin, "admin"]);
console.log("✅已重置管理員：admin / admin123");
const hashStaff = bcrypt.hashSync("123456", 10);
await db.execute(`INSERT OR REPLACE INTO admin_user(username, password, role) VALUES (?,?,?)`, ["staff01", hashStaff, "staff"]);
console.log("✅已重置員工帳號：staff01 / 123456");
})();
// 登入攔截中間件
function checkLogin(req, res, next) {
if (!req.session.isLogin) {
return res.status(401).json({ ok: false, msg: "請先登入後台" });
  }
next();
}
// 權限中間件
function checkRole(requiredRoles) {
return (req, res, next) => {
const userRole = req.session.adminRole;
if (requiredRoles.includes(userRole)) {
next();
    } else {
return res.status(403).json({ ok: false, msg: "權限不足，只有總管理員允許此操作" });
    }
  };
}
// ==================== 接口 ====================
// 登入
app.post("/api/admin-login", async (req, res) => {
const { username, password } = req.body;
const ret = await db.execute("SELECT * FROM admin_user WHERE username = ?", [username]);
const user = ret.rows[0];
if (!user) return res.json({ ok: false, msg: "帳號不存在" });
const passOk = await bcrypt.compare(password, user.password);
if (passOk) {
req.session.isLogin = true;
req.session.adminName = user.username;
req.session.adminRole = user.role;
return res.json({ ok: true, role: user.role });
  } else {
return res.json({ ok: false, msg: "密碼錯誤" });
  }
});
// 登出
app.post("/api/admin-logout", (req, res) => {
req.session.destroy();
res.json({ ok: true });
});
// 取得當前登入用戶
app.get("/api/admin-whoami", checkLogin, (req, res) => {
res.json({
username: req.session.adminName,
role: req.session.adminRole
  });
});
// 修改本人帳號密碼
app.post("/api/change-admin", checkLogin, async (req, res) => {
const { oldPassword, newUsername, newPassword } = req.body;
const nowAdmin = req.session.adminName;
const ret = await db.execute("SELECT * FROM admin_user WHERE username = ?", [nowAdmin]);
const row = ret.rows[0];
if (!row) return res.json({ ok: false, msg: "帳號不存在" });
const oldPassValid = await bcrypt.compare(oldPassword, row.password);
if (!oldPassValid) {
return res.json({ ok: false, msg: "舊密碼不正確" });
  }
const useUsername = newUsername && newUsername.trim() !== "" ? newUsername : row.username;
const newHash = await bcrypt.hash(newPassword, 10);
try {
await db.execute(`UPDATE admin_user SET username = ?, password = ? WHERE id = ?`,
      [useUsername, newHash, row.id]);
req.session.destroy();
res.json({ ok: true, msg: "帳密已更新，請重新登入" });
  } catch (e) {
return res.json({ ok: false, msg: "更新失敗，新帳號已被佔用" });
  }
});
// 取得管理員帳號列表
app.get("/api/admin-user-list", checkLogin, async (req, res) => {
const ret = await db.execute("SELECT username, create_at FROM admin_user ORDER BY id DESC");
res.json(ret.rows);
});
// 建立新管理員
app.post("/api/create-admin-user", checkLogin, checkRole(['admin']), async (req, res) => {
const { username, password } = req.body;
if (!username || !password) return res.json({ ok: false, msg: "帳號密碼不可空白" });
try {
const hash = await bcrypt.hash(password, 10);
await db.execute(`INSERT INTO admin_user(username, password, role) VALUES (?,?,?)`,
      [username, hash, "staff"]);
res.json({ ok: true, msg: "帳號建立完成" });
  } catch (e) {
return res.json({ ok: false, msg: "帳號重複，建立失敗" });
  }
});
// 刪除管理員帳號
app.post("/api/delete-admin-user", checkLogin, checkRole(['admin']), async (req, res) => {
const { username } = req.body;
const loginUsername = req.session.adminName;
if (username === loginUsername) {
return res.json({ ok: false, msg: "禁止刪除當前登入帳號" });
  }
await db.execute(`DELETE FROM admin_user WHERE username = ?`, [username]);
res.json({ ok: true, msg: "刪除成功" });
});
// 重置使用者密碼
app.post("/api/admin-reset-user-pwd", checkLogin, checkRole(['admin']), async (req, res) => {
const { target_username, new_password } = req.body;
if (!target_username || !new_password) {
return res.json({ ok: false, msg: "參數不全" });
  }
const hash = await bcrypt.hash(new_password, 10);
await db.execute(`UPDATE admin_user SET password = ? WHERE username = ?`, [hash, target_username]);
res.json({ ok: true, msg: `帳號 ${target_username} 密碼已重置` });
});
// 客戶表單提交接口
// 客戶表單提交接口
app.post('/api/submit-contact', async (req, res) => {
console.log("👉收到POST，req.body =", req.body);
try {
// 前端傳來的key：clientType（駝峰）、inquiryType
const { company, name, phone, email, inquiryType, clientType, content } = req.body;
await db.execute(`
      INSERT INTO inquiries
      (company, name, phone, email, project_type, client_type, content, create_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `,[
company,
name,
phone,
email,
inquiryType,   // 前端 inquiryType → 資料庫 project_type
clientType,    // 前端 clientType → 資料庫 client_type
content,
getHongKongDateTime()
    ]);
return res.json({ ok: true, msg: "查詢已成功送出！" });
  } catch(err) {
console.error("❌插入資料庫錯誤：", err);
return res.status(500).json({ ok: false, msg: "提交失敗" });
  }
});
// 兼容舊前端路徑 /submit.php
app.post("/submit.php", async (req, res) => {
console.log("📩submit.php 接收到表單：", req.body);
const { company, name, phone, email, content, clientType, inquiryType } = req.body;
try {
await db.execute(`INSERT INTO inquiries(company, name, phone, email, content, client_type, project_type, create_at) VALUES (?,?,?,?,?,?,?,?)`,
      [company, name, phone, email, content, clientType || '', inquiryType || '', getHongKongDateTime()]);
res.json({ ok: true });
  } catch (err) {
console.error('插入錯誤:', err);
return res.json({ ok: false });
  }
});
// 取得諮詢紀錄清單
app.get("/api/inquiry-list", checkLogin, async (req, res) => {
const ret = await db.execute(`SELECT * FROM inquiries ORDER BY id DESC`);
// 做中文映射轉換
const list = ret.rows.map(row => ({
...row,
client_type: clientTypeMap[row.client_type] || row.client_type || "-",
project_type: inquiryTypeMap[row.project_type] || row.project_type || "-"
  }));
res.json(list);
});
// 更新跟進資訊
app.post("/api/update-follow-info", checkLogin, async (req, res) => {
const { id, ...updateFields } = req.body;
if (!id) {
return res.json({ ok: false, msg: "缺少記錄ID" });
  }
if (Object.keys(updateFields).length === 0) {
return res.json({ ok: false, msg: "沒有要更新的內容" });
  }
if (updateFields.customer_note && updateFields.customer_note.length > 1000) {
return res.json({ ok: false, msg: "客戶要求備註不可超過1000字" });
  }
if (updateFields.price && updateFields.price.length > 50) {
return res.json({ ok: false, msg: "初步報價不可超過50字" });
  }
const allowedStatus = ['未跟進', '跟進中', '已跟進'];
if (updateFields.follow_status && !allowedStatus.includes(updateFields.follow_status)) {
return res.json({ ok: false, msg: "跟進狀態僅可選擇：未跟進/跟進中/已跟進" });
  }
const setClauses = [];
const values = [];
for (const [key, value] of Object.entries(updateFields)) {
setClauses.push(`${key} = ?`);
values.push(value);
  }
values.push(id);
const sql = `UPDATE inquiries SET ${setClauses.join(', ')} WHERE id = ?`;
try {
await db.execute(sql, values);
res.json({ ok: true, msg: "更新成功" });
  } catch (err) {
console.error('更新錯誤:', err);
return res.json({ ok: false, msg: "更新失敗" });
  }
});
// Excel匯出
app.get("/api/inquiry-export-csv", checkLogin, async (req, res) => {
try {
const ret = await db.execute(`SELECT * FROM inquiries ORDER BY id DESC`);
const rows = ret.rows;
const workbook = new ExcelJS.Workbook();
const worksheet = workbook.addWorksheet('客戶查詢記錄');
worksheet.columns = [
      { header: 'ID', key: 'id', width: 10 },
      { header: '公司名稱', key: 'company', width: 25 },
      { header: '客戶類型', key: 'client_type', width: 20 },
      { header: '查詢項目', key: 'project_type', width: 35 },
      { header: '負責人', key: 'name', width: 15 },
      { header: '電話', key: 'phone', width: 20 },
      { header: '電郵', key: 'email', width: 25 },
      { header: '查詢內容', key: 'content', width: 40 },
      { header: '客戶要求備註', key: 'customer_note', width: 50 },
      { header: '跟進人', key: 'follow_user', width: 15 },
      { header: '跟進狀態', key: 'follow_status', width: 12 },
      { header: '初步報價', key: 'price', width: 20 },
      { header: '提交時間', key: 'create_at', width: 25 },
    ];
if (rows && rows.length > 0) {
rows.forEach(item => {
worksheet.addRow({
id: item.id,
company: item.company,
client_type: clientTypeMap[item.client_type] || item.client_type || "",
project_type: inquiryTypeMap[item.project_type] || item.project_type || "",
name: item.name,
phone: item.phone,
email: item.email,
content: item.content,
customer_note: item.customer_note || "",
follow_user: item.follow_user || "",
follow_status: item.follow_status || "未跟進",
price: item.price || "",
create_at: item.create_at
        })
      })
    }
worksheet.getRow(1).font = { bold: true, color: { argb: 'FFFFFFFF' } };
worksheet.getRow(1).fill = {
type: 'pattern',
pattern: 'solid',
fgColor: { argb: 'FF4F46E5' }
    };
worksheet.eachRow((row, rowNumber) => {
if (rowNumber > 1) {
const statusCell = row.getCell(11);
if (statusCell.value === '已跟進') {
statusCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF10B981' } };
statusCell.font = { color: { argb: 'FFFFFFFF' }, bold: true };
        } else if (statusCell.value === '跟進中') {
statusCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFF59E0B' } };
statusCell.font = { color: { argb: 'FFFFFFFF' }, bold: true };
        } else if (statusCell.value === '未跟進') {
statusCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFEF4444' } };
statusCell.font = { color: { argb: 'FFFFFFFF' }, bold: true };
        }
      }
    });
const filename = `客戶諮詢紀錄_${new Date().toISOString().slice(0, 10)}.xlsx`;
res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(filename)}"`);
await workbook.xlsx.write(res);
res.end();
  } catch (excelErr) {
console.error("匯出Excel異常：", excelErr);
res.status(500).json({ ok: false, msg: "伺服器生成Excel錯誤" });
  }
});
// 30天統計圖表
app.get("/api/stats-30day", checkLogin, async (req, res) => {
const ret = await db.execute(`SELECT DATE(create_at) as day, COUNT(*) as cnt FROM inquiries GROUP BY DATE(create_at) ORDER BY day ASC`);
const rows = ret.rows;
const labels = [];
const data = [];
for (let i = 29; i >= 0; i--) {
const d = new Date();
d.setDate(d.getDate() - i);
const dateStr = d.toISOString().split('T')[0];
labels.push(dateStr);
const find = rows.find(r => r.day === dateStr);
data.push(find ? find.cnt : 0);
  }
res.json({ labels, data });
});
// 企業來源餅圖
app.get("/api/stats-company", checkLogin, async (req, res) => {
const ret = await db.execute(`
    SELECT company, COUNT(*) as cnt
    FROM inquiries
    WHERE company IS NOT NULL AND company != ''
    GROUP BY company
    ORDER BY cnt DESC
  `);
const raw = ret.rows;
const labels = [];
const data = [];
let otherSum = 0;
raw.forEach((item, idx) => {
if (idx < 6) {
labels.push(item.company);
data.push(item.cnt);
    } else {
otherSum += item.cnt;
    }
  });
if (otherSum > 0) {
labels.push("其他");
data.push(otherSum);
  }
if (labels.length === 0) {
labels.push("暫無數據");
data.push(1);
  }
res.json({ labels, data });
});
// 靜態資源必須放在所有API後面
// 靜態資源必須放在所有API後面
app.use(express.static(path.join(__dirname, 'public')));
app.get(/^\/.*/, (req, res) => {
res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
console.log(`✅後台服務啟動完成，本機: http://127.0.0.1:${PORT}`);
});
