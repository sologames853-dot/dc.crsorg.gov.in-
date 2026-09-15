require("dotenv").config({
  path: require("path").join(__dirname, ".env")
});

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");
const { MongoClient, ObjectId } = require("mongodb");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret-in-production";
const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = process.env.MONGODB_DB || "birth_records";

app.use(cors());
app.use(express.json({ limit: "1mb" }));
app.use(express.static(__dirname));

let admins;
let records;

function startServer(port) {
  const server = app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
  });

  server.on("error", error => {
    if (error.code === "EADDRINUSE" && port === Number(PORT)) {
      console.warn(`Port ${port} is busy. Starting on port ${port + 1} instead.`);
      startServer(port + 1);
      return;
    }

    console.error("Server could not start:", error.message);
    process.exit(1);
  });
}

function publicAdmin(admin) {
  return { id: String(admin._id), username: admin.username, full_name: admin.full_name || "", role: admin.role, active: admin.active, created_at: admin.created_at };
}

function publicRecord(record) {
  const result = { ...record, id: String(record._id), created_by: record.created_by ? String(record.created_by) : null, updated_by: record.updated_by ? String(record.updated_by) : null };
  delete result._id;
  return result;
}

function createToken(admin) {
  return jwt.sign({ id: String(admin._id), username: admin.username, role: admin.role }, JWT_SECRET, { expiresIn: "12h" });
}

function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    if (!header.startsWith("Bearer ")) throw new Error("Missing token");
    req.user = jwt.verify(header.substring(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: "Invalid or expired login session" });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) return res.status(403).json({ message: "Permission denied" });
    next();
  };
}

function objectId(value) {
  return ObjectId.isValid(value) ? new ObjectId(value) : null;
}

function registrationNumber() {
  const year = new Date().getFullYear();
  const randomBlock = Math.floor(10000000 + Math.random() * 90000000);
  return `B${year}${randomBlock}${String(Date.now()).slice(-7)}`;
}

app.post("/api/admin/login", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");
    const admin = await admins.findOne({ username });
    if (!admin || !await bcrypt.compare(password, admin.password_hash)) return res.status(401).json({ message: "Invalid username or password" });
    if (!admin.active) return res.status(403).json({ message: "This admin account is disabled" });
    res.json({ success: true, token: createToken(admin), user: publicAdmin(admin) });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Login failed" });
  }
});

app.get("/api/admin/me", auth, async (req, res) => {
  const admin = await admins.findOne({ _id: objectId(req.user.id) });
  if (!admin) return res.status(404).json({ message: "Admin not found" });
  res.json(publicAdmin(admin));
});

app.post("/api/admins", auth, requireRole("SUPER_ADMIN"), async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");
    const full_name = String(req.body.full_name || "").trim();
    if (!username || !password) return res.status(400).json({ message: "Admin ID and password are required" });
    if (username.length < 4) return res.status(400).json({ message: "Admin ID must contain at least 4 characters" });
    if (password.length < 8) return res.status(400).json({ message: "Password must contain at least 8 characters" });
    const admin = { username, password_hash: await bcrypt.hash(password, 12), full_name, role: "ADMIN", active: true, created_at: new Date() };
    await admins.insertOne(admin);
    res.json({ success: true, admin: publicAdmin(admin) });
  } catch (error) {
    if (error.code === 11000) return res.status(409).json({ message: "This Admin ID already exists" });
    console.error(error);
    res.status(500).json({ message: "Could not create admin" });
  }
});

app.get("/api/admins", auth, requireRole("SUPER_ADMIN"), async (req, res) => {
  const list = await admins.find({}).sort({ created_at: -1 }).toArray();
  res.json(list.map(publicAdmin));
});

app.patch("/api/admins/:id/status", auth, requireRole("SUPER_ADMIN"), async (req, res) => {
  const id = objectId(req.params.id);
  if (!id) return res.status(404).json({ message: "Admin not found" });
  const result = await admins.findOneAndUpdate({ _id: id, role: "ADMIN" }, { $set: { active: Boolean(req.body.active) } }, { returnDocument: "after" });
  const admin = result && result.value ? result.value : result;
  if (!admin) return res.status(404).json({ message: "Admin not found" });
  res.json({ success: true, admin: publicAdmin(admin) });
});

app.get("/api/records", auth, requireRole("SUPER_ADMIN", "ADMIN"), async (req, res) => {
  const list = await records.find({}).sort({ created_at: -1 }).toArray();
  const creatorIds = [...new Set(list.filter(r => r.created_by).map(r => String(r.created_by)))].map(objectId).filter(Boolean);
  const creators = await admins.find({ _id: { $in: creatorIds } }).toArray();
  const names = new Map(creators.map(admin => [String(admin._id), admin.username]));
  res.json(list.map(record => ({ ...publicRecord(record), created_by_username: names.get(String(record.created_by)) || "" })));
});

app.post("/api/records", auth, requireRole("SUPER_ADMIN", "ADMIN"), async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    if (!name) return res.status(400).json({ message: "Name is required" });
    const record = {
      name,
      sex: String(req.body.sex || ""),
      date_of_birth: String(req.body.date_of_birth || ""),
      place_of_birth: String(req.body.place_of_birth || ""),
      mother_name: String(req.body.mother_name || ""),
      mother_aadhaar: String(req.body.mother_aadhaar || ""),
      father_name: String(req.body.father_name || ""),
      father_aadhaar: String(req.body.father_aadhaar || ""),
      child_aadhaar: String(req.body.child_aadhaar || ""),
      registration_number: registrationNumber(),
      registration_date: String(req.body.registration_date || ""),
      address: String(req.body.address || ""),
      permanent_address: String(req.body.permanent_address || ""),
      district: String(req.body.district || "FIROZABAD"),
      state: String(req.body.state || "UTTAR PRADESH"),
      created_by: objectId(req.user.id),
      updated_by: objectId(req.user.id),
      created_at: new Date(),
      updated_at: new Date()
    };
    await records.insertOne(record);
    res.json({ success: true, record: publicRecord(record) });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Could not create birth record" });
  }
});

app.put("/api/records/:id", auth, requireRole("SUPER_ADMIN", "ADMIN"), async (req, res) => {
  const id = objectId(req.params.id);
  const name = String(req.body.name || "").trim();
  if (!id) return res.status(404).json({ message: "Record not found" });
  if (!name) return res.status(400).json({ message: "Name is required" });
  const fields = {
    name,
    sex: String(req.body.sex || ""),
    date_of_birth: String(req.body.date_of_birth || ""),
    place_of_birth: String(req.body.place_of_birth || ""),
    mother_name: String(req.body.mother_name || ""),
    mother_aadhaar: String(req.body.mother_aadhaar || ""),
    father_name: String(req.body.father_name || ""),
    father_aadhaar: String(req.body.father_aadhaar || ""),
    child_aadhaar: String(req.body.child_aadhaar || ""),
    registration_date: String(req.body.registration_date || ""),
    address: String(req.body.address || ""),
    permanent_address: String(req.body.permanent_address || ""),
    district: String(req.body.district || "FIROZABAD"),
    state: String(req.body.state || "UTTAR PRADESH"),
    updated_by: objectId(req.user.id),
    updated_at: new Date()
  };
  const result = await records.findOneAndUpdate({ _id: id }, { $set: fields }, { returnDocument: "after" });
  const updated = result && result.value ? result.value : result;
  if (!updated) return res.status(404).json({ message: "Record not found" });
  res.json({ success: true, record: publicRecord(updated) });
});

app.delete("/api/records/:id", auth, requireRole("SUPER_ADMIN", "ADMIN"), async (req, res) => {
  const id = objectId(req.params.id);
  const result = id ? await records.deleteOne({ _id: id }) : { deletedCount: 0 };
  if (!result.deletedCount) return res.status(404).json({ message: "Record not found" });
  res.json({ success: true });
});

app.get("/api/verify/:registrationNumber", async (req, res) => {
  const record = await records.findOne({ registration_number: req.params.registrationNumber.trim() });
  if (!record) return res.status(404).json({ verified: false, message: "Record not found" });
  const safe = publicRecord(record);
  delete safe.created_by;
  delete safe.updated_by;
  res.json({ verified: true, record: safe });
});

app.get("/verify-record/:registrationNumber", async (req, res) => {
  try {
    const record = await records.findOne({ registration_number: req.params.registrationNumber.trim() });
    if (!record) {
      return res.status(404).send("<h1>Record Not Found</h1><p>The registration number provided does not exist in our system.</p>");
    }

    const dobDate = new Date(record.date_of_birth);
    const formattedDOB = isNaN(dobDate.getTime()) ? record.date_of_birth : dobDate.toLocaleDateString('en-GB', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric'
    }).replace(/\//g, '-');

    const regDate = new Date(record.registration_date);
    const formattedRegDate = isNaN(regDate.getTime()) ? record.registration_date : regDate.toLocaleDateString('en-GB', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric'
    }).replace(/\//g, '-');

    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Validate Certificate | Civil Registration System</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 0; background-color: #ffffff; color: #333; }

        /* Fixed Header Bar style matching image */
        .header { background-color: #1b75d1; color: white; padding: 13px 16px; display: flex; align-items: center; justify-content: space-between; font-weight: 500; font-size: 16px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header-title { display: flex; align-items: center; gap: 10px; }
        .header-title .tick-icon { background: #12a15a; color: white; border-radius: 50%; width: 18px; height: 18px; display: flex; align-items: center; justify-content: center; font-size: 11px; font-weight: bold; }
        .header-refresh { font-size: 20px; font-weight: bold; opacity: 0.9; cursor: pointer; }

        /* Secondary Header banner with logos and tricolor bar */
        .gov-banner { background: #ffffff; padding: 6px 12px; display: flex; align-items: center; justify-content: space-between; border-bottom: 4px solid #1a5ca3; position: relative; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
        .gov-banner::before { content: ""; position: absolute; top: 0; left: 0; right: 0; height: 3px; background: linear-gradient(to right, #ff9933 33%, #ffffff 33%, #ffffff 66%, #128807 66%); }
        .gov-banner .left-logo { height: 42px; }
        .gov-banner .center-logo { height: 38px; }
        .gov-banner .right-icons { display: flex; align-items: center; gap: 12px; }
        .gov-banner .moon-icon { font-size: 18px; color: #333; }
        .gov-banner .login-btn { background: #5c7ca6; color: white; border-radius: 50%; width: 34px; height: 34px; display: flex; align-items: center; justify-content: center; font-size: 16px; text-decoration: none; }
        .gov-banner .menu-bars { font-size: 20px; color: #333; font-weight: bold; }

        /* Main Details Card Box precisely centered with shadows */
        .container { padding: 25px 15px; background: #ffffff; }
        .card-wrapper { background: #ffffff; border-radius: 4px; border: 1px solid #e0e0e0; box-shadow: 0 4px 15px rgba(0,0,0,0.08); padding: 12px; margin: 0 auto; max-width: 600px; }

        .record-table { width: 100%; border-collapse: collapse; }
        .record-table td { padding: 14px 12px; border: 1px solid #e2e8f0; font-size: 14.5px; vertical-align: top; color: #2d3748; line-height: 1.5; }
        .label { width: 32%; color: #4a5568; font-weight: normal; }
        .value { color: #000000; font-weight: normal; }

        /* Bottom section with exact background color matching image */
        .bottom-section { background: linear-gradient(to bottom, #115e7a, #0b455c); color: #ffffff; padding: 30px 15px; text-align: center; }

        /* Exact center logos layout stacked and matching the screenshot design */
        .footer-logos { margin-bottom: 30px; display: flex; flex-direction: column; align-items: center; gap: 15px; }

        .footer-logos .datagov-box { color: #ffffff; font-size: 28px; font-weight: bold; letter-spacing: -0.5px; display: inline-flex; align-items: center; justify-content: center; font-family: sans-serif; }
        .footer-logos .datagov-box span { background: #ffcc00; color: #000000; padding: 1px 6px; border-radius: 4px; margin-left: 2px; font-size: 24px; }
        .footer-logos .datagov-sub { font-size: 10px; color: #cbd5e1; margin-top: -4px; font-weight: normal; opacity: 0.9; }

        .footer-logos .india-gov-box { background: #ffffff; padding: 8px 25px; width: 180px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .footer-logos .india-gov-box span { font-weight: bold; font-size: 18px; color: #000; }
        .footer-logos .india-gov-box span.orange { color: #ff9933; }
        .footer-logos .india-gov-box span.green { color: #128807; }

        .footer-logos .pm-india-box { background: #222222; color: #ffffff; padding: 6px 20px; font-size: 11px; font-weight: bold; display: inline-flex; align-items: center; gap: 6px; border: 1px solid #444; width: 185px; justify-content: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .footer-logos .pm-india-box img { height: 16px; }

        .footer-logos .generic-img-wrapper { background: #ffffff; padding: 6px; width: 220px; display: flex; align-items: center; justify-content: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .footer-logos .generic-img-wrapper img { height: 36px; max-width: 100%; object-fit: contain; }

        .footer-logos .coop-wrapper { background: #ffffff; padding: 8px 12px; width: 210px; text-align: center; border: 1px solid #ddd; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .footer-logos .coop-wrapper img { height: 35px; width: auto; display: block; margin: 0 auto 4px; }
        .footer-logos .coop-wrapper .coop-title { color: #1e3a8a; font-size: 11px; font-weight: bold; line-height: 1.2; }
        .footer-logos .coop-wrapper .coop-sub { color: #475569; font-size: 9px; margin-top: 1px; }

        /* Links area */
        .info-links { font-size: 13.5px; color: #ffffff; line-height: 2.2; margin-bottom: 25px; font-weight: normal; }
        .info-links a { color: #ffffff; text-decoration: none; margin: 0 6px; opacity: 0.95; display: inline-block; }
        .info-links span.pipe { color: rgba(255,255,255,0.4); margin: 0 2px; }

        .last-updated { font-size: 13px; color: #e2e8f0; margin-bottom: 25px; font-weight: normal; opacity: 0.9; }

        /* Developed by area */
        .maintained-by { font-size: 13.5px; color: #ffffff; line-height: 1.6; margin-bottom: 25px; max-width: 500px; margin-left: auto; margin-right: auto; opacity: 0.95; }

        /* Standardized Legal Timestamp Style at the very bottom */
        .copyright-timestamp { font-size: 13px; color: #cbd5e1; border-top: 1px solid rgba(255,255,255,0.15); padding-top: 15px; line-height: 1.5; opacity: 0.9; }
    </style>
</head>
<body>
    <!-- Top Blue Header mimicking Application Navigation Bar -->
    <div class="header">
        <div class="header-title">
            <div class="tick-icon">&#10003;</div>
            <span>Validate Certificate | Civil R...</span>
        </div>
        <div class="header-refresh" onclick="location.reload()">&#8635;</div>
    </div>

    <!-- Government Portal Brand Sub-Header with Indian Flag Gradient and Icons -->
    <div class="gov-banner">
        <img src="https://crsorgi.gov.in/web/images/logo.png" class="left-logo" onerror="this.src='https://upload.wikimedia.org/wikipedia/commons/5/55/Emblem_of_India.svg'">
        <img src="https://amritmahotsav.nic.in/assets/images/logo.png" class="center-logo" onerror="this.style.display='none'">
        <div class="right-icons">
            <span class="moon-icon">&#9789;</span>
            <a href="#" class="login-btn">&#8594;</a>
            <span class="menu-bars">&#9776;</span>
        </div>
    </div>

    <!-- White Card Wrapper with Details View Block -->
    <div class="container">
        <div class="card-wrapper">
            <table class="record-table">
                <tr>
                    <td class="label">Registration Number</td>
                    <td class="value">${record.registration_number}</td>
                </tr>
                <tr>
                    <td class="label">NAME</td>
                    <td class="value">${record.name}</td>
                </tr>
                <tr>
                    <td class="label">GENDER</td>
                    <td class="value">${record.sex || 'Male'}</td>
                </tr>
                <tr>
                    <td class="label">DOD</td>
                    <td class="value">${formattedDOB}</td>
                </tr>
                <tr>
                    <td class="label">Name Of Mother</td>
                    <td class="value">${record.mother_name || 'N/A'}</td>
                </tr>
                <tr>
                    <td class="label">Name Of Father</td>
                    <td class="value">${record.father_name || 'N/A'}</td>
                </tr>
                <tr>
                    <td class="label">Place of Death</td>
                    <td class="value">
                        LADPURA, NAGLA DUNGAR, FIROZABAD, FIROZABAD, UTTAR PRADESH, 283203 / <br>
                        लदपुरा, NAGLA DUNGAR, FIROZABAD, FIROZABAD, UTTAR PRADESH, 283203
                    </td>
                </tr>
                <tr>
                    <td class="label">Registration Date</td>
                    <td class="value">${formattedRegDate}</td>
                </tr>
                <tr>
                    <td class="label">Registration Unit Name</td>
                    <td class="value">GRAMA PANCHAYAT NAGLA DUNGAR</td>
                </tr>
                <tr>
                    <td class="label">Registration Unit Code</td>
                    <td class="value">09457</td>
                </tr>
            </table>
        </div>
    </div>

    <!-- Teal/Blue Gradient Bottom Area Matching Screenshots Exactly -->
    <div class="bottom-section">

        <!-- Stacked Official Central Logos -->
        <div class="footer-logos">
            <div>
                <div class="datagov-box">data.gov<span>in</span></div>
                <div class="datagov-sub">Open Government Data (OGD) Platform India</div>
            </div>

            <div class="india-gov-box">
                <span>india.<span class="orange">gov</span>.<span class="green">in</span></span>
            </div>

            <div class="pm-india-box">
                <img src="https://upload.wikimedia.org/wikipedia/commons/5/55/Emblem_of_India.svg" alt="Emblem">
                <span>PM INDIA</span>
            </div>

            <div class="generic-img-wrapper">
                <img src="https://www.makeinindia.com/mfg_theme/images/logo.png" alt="Make In India">
            </div>

            <div class="generic-img-wrapper">
                <img src="https://upload.wikimedia.org/wikipedia/hi/thumb/c/c5/Digital_India_logo.svg/1200px-Digital_India_logo.svg.png" alt="Digital India">
            </div>

            <div class="generic-img-wrapper">
                <img src="https://www.mygov.in/sites/default/files/mygov_logo_new.png" alt="MyGov">
            </div>

            <div class="coop-wrapper">
                <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/e/e1/International_Year_of_Cooperatives_2012_logo.svg/1200px-International_Year_of_Cooperatives_2012_logo.svg.png" alt="Coop Logo" onerror="this.style.opacity='0.5'">
                <div class="coop-title">International Year of Cooperatives 2025</div>
                <div class="coop-sub">Cooperatives Build a Better World</div>
            </div>
        </div>

        <!-- Links Area -->
        <div class="info-links">
            <a href="#">Website Policy</a><span class="pipe">|</span><a href="#">Mobile App Privacy Policy</a><span class="pipe">|</span><a href="#">Terms & Conditions</a><span class="pipe">|</span><a href="#">Accessibility Statement</a><span class="pipe">|</span><a href="#">Web Information Manager</a>
            <br>
            <a href="#">Feedback</a><span class="pipe">|</span><a href="#">Sitemap</a><span class="pipe">|</span><a href="#">Contact Us</a><span class="pipe">|</span><a href="#">Vacancies</a><span class="pipe">|</span><a href="#">Product & Services</a><span class="pipe">|</span><a href="#">Pricing</a><span class="pipe">|</span><a href="#">Cancellation Policy</a><span class="pipe">|</span><a href="#">Grievance Management Policy</a>
        </div>

        <!-- Hardcoded Static Dynamic Sync Date -->
        <div class="last-updated">Last Updated: 30-01-2024 12:16:17</div>

        <!-- Maintenance Ministry and Footer Copyright block -->
        <div class="maintained-by">
            Website Developed & Maintained by Office of the Registrar General & Census Commissioner of India
            <br><br>
            <strong style="font-size:15px; font-weight:bold;">Ministry of Home Affairs</strong>
        </div>

        <div class="copyright-timestamp">
            &copy; 2026 - The Registrar General & Census Commissioner of India - Sep 15, 2026, 5:37:37 PM
        </div>
    </div>
</body>
</html>`;
    res.send(html);
  } catch (error) {
    console.error(error);
    res.status(500).send("Verification Error");
  }
});

app.get("*", (req, res) => res.sendFile(path.join(__dirname, "index.html")));

async function init() {
  if (!MONGODB_URI) throw new Error("MONGODB_URI is missing. Add your MongoDB Atlas connection string to .env");
  const client = new MongoClient(MONGODB_URI);
  await client.connect();
  const db = client.db(DB_NAME);
  admins = db.collection("admins");
  records = db.collection("birth_records");
  await admins.createIndex({ username: 1 }, { unique: true });
  await records.createIndex({ registration_number: 1 }, { unique: true });
  const username = process.env.SUPERADMIN_USER || "superadmin";
  const password = process.env.SUPERADMIN_PASS || "ChangeMe123!";
  const passwordHash = await bcrypt.hash(password, 12);

  const existingAdmin = await admins.findOne({ username });
  if (!existingAdmin) {
    await admins.insertOne({
      username,
      password_hash: passwordHash,
      full_name: "System Super Administrator",
      role: "SUPER_ADMIN",
      active: true,
      created_at: new Date()
    });
    console.log(`Initial Super Admin created: ${username}`);
  } else if (existingAdmin.role === "SUPER_ADMIN") {
    // Force update password from .env to keep it in sync
    await admins.updateOne(
      { username },
      { $set: { password_hash: passwordHash } }
    );
    console.log(`Super Admin password synced from .env`);
  }
  startServer(Number(PORT));
}

init().catch(error => {
  console.error("Database initialization failed:", error.message);
  process.exit(1);
});
