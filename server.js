const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcrypt');
const ExcelJS = require('exceljs');
const path = require('path');
const { createClient } = require('@libsql/client');


const app = express();


// ========== Session 配置 ==========
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


// 中間件
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));


// ========= Turso LibSQL 包裝層，模擬 sqlite3 回調介面，上層業務完全不用改 =========
const tursoClient = createClient({
  url: process.env.TURSO_DATABASE_URL || "libsql://shengming-db-coco123.aws-ap-northeast-1.turso.io",
  authToken: process.env.TURSO_AUTH_TOKEN
});



const db = {
  run: function(sql, params, callback) {
    if(typeof params === 'function'){
      callback = params;
      params = [];
    }
    tursoClient.execute({sql, args:params})
      .then(res=>{
        if(callback) callback(null, { lastID: res.lastInsertRowid, changes: res.rowsAffected });
      })
      .catch(err=>{
        if(callback) callback(err);
      })
  },
  get: function(sql, params, callback) {
    if(typeof params === 'function'){
      callback = params;
      params = [];
    }
    tursoClient.execute({sql, args:params})
      .then(res=>{
        if(callback) callback(null, res.rows[0]);
      })
      .catch(err=>{
        if(callback) callback(err);
      })
  },
  all: function(sql, params, callback) {
    if(typeof params === 'function'){
      callback = params;
      params = [];
    }
    tursoClient.execute({sql, args:params})
      .then(res=>{
        if(callback) callback(null, res.rows);
      })
      .catch(err=>{
        if(callback) callback(err);
      })
  }
};


// 客戶諮詢表【新增初步報價欄位，修復原有結構】
db.run(`CREATE TABLE IF NOT EXISTS inquiries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    company TEXT,
    name TEXT,
    phone TEXT,
    email TEXT,
    content TEXT,
    customer_note TEXT DEFAULT '',
    follow_user TEXT DEFAULT '',
    follow_status TEXT DEFAULT '未跟進',
    price TEXT DEFAULT '',
    create_at DATETIME
)`);


// 管理員帳號表
db.run(`CREATE TABLE IF NOT EXISTS admin_user (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT,
  role TEXT DEFAULT 'staff',
  create_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);


// 初始化預設帳號
db.get("SELECT COUNT(*) as count FROM admin_user", async (err, row) => {
if (row && row.count === 0) {
const hashAdmin = await bcrypt.hash("123456", 10);
    db.run(`INSERT INTO admin_user(username, password, role) VALUES (?,?,?)`, ["admin", hashAdmin, "admin"]);
    console.log("✅ 已建立預設總管理員：admin / 123456 (角色: admin)");


const hashStaff = await bcrypt.hash("123456", 10);
    db.run(`INSERT INTO admin_user(username, password, role) VALUES (?,?,?)`, ["staff", hashStaff, "staff"]);
    console.log("✅ 已建立預設普通員工：staff / 123456 (角色: staff)");
  }
});


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
  db.get("SELECT * FROM admin_user WHERE username = ?", [username], async (err, user) => {
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
});


// 登出
app.post("/api/admin-logout", (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});


// 取得當前登入用戶
app.get("/api/admin-whoami", checkLogin, (req, res) => {
  res.json({
ok: true,
username: req.session.adminName,
role: req.session.adminRole
  });
});


// 修改本人帳號密碼
app.post("/api/change-admin", checkLogin, async (req, res) => {
const { oldPassword, newUsername, newPassword } = req.body;
const nowAdmin = req.session.adminName;


  db.get("SELECT * FROM admin_user WHERE username = ?", [nowAdmin], async (err, row) => {
const oldPassValid = await bcrypt.compare(oldPassword, row.password);
if (!oldPassValid) {
return res.json({ ok: false, msg: "舊密碼不正確" });
    }
const useUsername = newUsername && newUsername.trim() !== "" ? newUsername : row.username;
const newHash = await bcrypt.hash(newPassword, 10);
    db.run(`UPDATE admin_user SET username = ?, password = ? WHERE id = ?`,
      [useUsername, newHash, row.id],
      (e) => {
if (e) return res.json({ ok: false, msg: "更新失敗，新帳號已被佔用" });
        req.session.destroy();
        res.json({ ok: true, msg: "帳密已更新，請重新登入" });
      });
  });
});


// 取得管理員帳號列表
app.get("/api/admin-user-list", checkLogin, checkRole(['admin']), (req, res) => {
  db.all("SELECT username, create_at FROM admin_user ORDER BY id DESC", [], (err, rows) => {
if (err) return res.json({ ok: false, msg: err.message });
    res.json(rows);
  })
});


// 建立新管理員
app.post("/api/create-admin-user", checkLogin, checkRole(['admin']), async (req, res) => {
const { username, password } = req.body;
if (!username || !password) return res.json({ ok: false, msg: "帳號密碼不可空白" });
  bcrypt.hash(password, 10, (err, hash) => {
    db.run(`INSERT INTO admin_user(username, password, role) VALUES (?,?,?)`,
      [username, hash, "staff"],
      (e) => {
if (e) return res.json({ ok: false, msg: "帳號重複，建立失敗" });
        res.json({ ok: true, msg: "帳號建立完成" });
      })
  })
});


// 刪除管理員帳號
app.post("/api/delete-admin-user", checkLogin, checkRole(['admin']), (req, res) => {
const { username } = req.body;
const loginUsername = req.session.adminName;
if (username === loginUsername) {
return res.json({ ok: false, msg: "禁止刪除當前登入帳號" });
  }
  db.run(`DELETE FROM admin_user WHERE username = ?`, [username], (e) => {
if (e) return res.json({ ok: false, msg: "刪除失敗" });
    res.json({ ok: true, msg: "刪除成功" });
  })
});


// 重置使用者密碼
app.post("/api/admin-reset-user-pwd", checkLogin, checkRole(['admin']), async (req, res) => {
const { target_username, new_password } = req.body;
if (!target_username || !new_password) {
return res.json({ ok: false, msg: "參數不全" });
  }
  bcrypt.hash(new_password, 10, (err, hash) => {
    db.run(`UPDATE admin_user SET password = ? WHERE username = ?`, [hash, target_username], (e) => {
if (e) return res.json({ ok: false, msg: "重置密碼失敗" });
      res.json({ ok: true, msg: `帳號 ${target_username} 密碼已重置` });
    })
  })
});


// 客戶表單提交（訪客無需登入）
app.post("/api/submit-inquiry", (req, res) => {
const { company, name, phone, email, content } = req.body;
const localTime = new Date().toLocaleString('zh-HK', {
timeZone:'Asia/Hong_Kong'
});
const sql = `INSERT INTO inquiries(company, name, phone, email, content, create_at) VALUES (?,?,?,?,?,?)`;
  db.run(sql, [company, name, phone, email, content, localTime], function (err) {
if (err) {
    console.error('插入錯誤:',err);
return res.json({ ok: false });
  }
    res.json({ ok: true });
  });
});


// 取得諮詢紀錄清單
app.get("/api/inquiry-list", checkLogin, (req, res) => {
  db.all(`SELECT * FROM inquiries ORDER BY id DESC`, (err, rows) => {
if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});


// ✅ 核心修復：動態更新接口，只更新傳入的字段，其他字段保持不變（解決更新失敗問題）
app.post("/api/update-follow-info", checkLogin, (req, res) => {
const { id, ...updateFields } = req.body;
// 校驗ID
if (!id) {
return res.json({ ok: false, msg: "缺少記錄ID" });
}
// 校驗空更新
if (Object.keys(updateFields).length === 0) {
return res.json({ ok: false, msg: "沒有要更新的內容" });
}
// 字段長度校驗
if (updateFields.customer_note && updateFields.customer_note.length > 1000) {
return res.json({ ok: false, msg: "客戶要求備註不可超過1000字" });
}
if (updateFields.price && updateFields.price.length > 50) {
return res.json({ ok: false, msg: "初步報價不可超過50字" });
}
// 跟進狀態校驗
const allowedStatus = ['未跟進', '跟進中', '已跟進'];
if (updateFields.follow_status && !allowedStatus.includes(updateFields.follow_status)) {
return res.json({ ok: false, msg: "跟進狀態僅可選擇：未跟進/跟進中/已跟進" });
}


// 動態構建SQL，只更新傳入的字段
const setClauses = [];
const values = [];
for (const [key, value] of Object.entries(updateFields)) {
  setClauses.push(`${key} = ?`);
  values.push(value);
}
values.push(id); // WHERE條件的ID


const sql = `UPDATE inquiries SET ${setClauses.join(', ')} WHERE id = ?`;


db.run(sql, values, function (err) {
if (err) {
console.error('更新錯誤:', err);
return res.json({ ok: false, msg: "更新失敗" });
}
res.json({ ok: true, msg: "更新成功" });
  });
});


// Excel匯出（新增初步報價欄位，修復欄位映射問題）
app.get("/api/inquiry-export-csv", checkLogin, checkRole(['admin']), async (req, res) => {
try {
const rows = await new Promise((resolve, reject) => {
db.all(`SELECT * FROM inquiries ORDER BY id DESC`, (err, data) => {
if (err) return reject(err);
resolve(data);
      });
    });
const workbook = new ExcelJS.Workbook();
const worksheet = workbook.addWorksheet('客戶查詢記錄');
worksheet.columns = [
      { header: 'ID', key: 'id', width: 10 },
      { header: '公司名稱', key: 'company', width: 25 },
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
// 手動逐行處理，確保欄位正確映射
if (rows && rows.length > 0) {
rows.forEach(item=>{
worksheet.addRow({
id: item.id,
company: item.company,
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
// 表頭樣式
worksheet.getRow(1).font = { bold: true, color: { argb: 'FFFFFFFF' } };
worksheet.getRow(1).fill = {
type: 'pattern',
pattern: 'solid',
fgColor: { argb: 'FF4F46E5' }
    };
// 狀態顏色標記
worksheet.eachRow((row, rowNumber) => {
if (rowNumber > 1) {
const statusCell = row.getCell(9);
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


const PORT = 3000;


// ========== 圖表統計接口 ==========
app.get("/api/stats-30day", checkLogin, (req, res) => {
db.all(`
    SELECT DATE(create_at) as day, COUNT(*) as cnt
    FROM inquiries
    WHERE create_at >= DATE('now','-29 day')
    GROUP BY DATE(create_at)
    ORDER BY day ASC
  `, (err, rows) => {
if (err) {
console.error(err);
return res.status(500).json({ ok: false, msg: "統計讀取失敗" });
    }
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
res.json({ ok: true, labels, data });
  });
});


app.get("/api/stats-company", checkLogin, (req, res) => {
db.all(`
    SELECT company, COUNT(*) as cnt
    FROM inquiries
    WHERE company IS NOT NULL AND company != ''
    GROUP BY company
    ORDER BY cnt DESC
  `, (err, raw) => {
if (err) {
console.error(err);
return res.status(500).json({ ok: false, msg: "企業統計讀取失敗" });
    }
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
res.json({ ok: true, labels, data });
  });
});


app.listen(PORT, () => {
console.log(`✅後台服務啟動完成，本機: http://127.0.0.1:${PORT}`);

});
