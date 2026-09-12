
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from http import cookies
import sqlite3, json, os, secrets, hashlib, hmac, datetime, mimetypes

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "gcash.db")
PORT = 8000
SESSIONS = {}

def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = db()
    cur = con.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        mobile TEXT NOT NULL UNIQUE,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS settings(
        user_id INTEGER PRIMARY KEY,
        starting_gcash REAL NOT NULL DEFAULT 0,
        starting_cash REAL NOT NULL DEFAULT 0,
        capital REAL NOT NULL DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS transactions(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        tx_type TEXT NOT NULL,
        amount REAL NOT NULL,
        fee REAL NOT NULL DEFAULT 0,
        reference TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS reset_codes(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        code TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        used INTEGER NOT NULL DEFAULT 0
    )
    """)
    con.commit()
    con.close()

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 120000)
    return dk.hex(), salt

def verify_password(password, expected, salt):
    got, _ = hash_password(password, salt)
    return hmac.compare_digest(got, expected)

def user_by_session(handler):
    raw = handler.headers.get("Cookie", "")
    c = cookies.SimpleCookie()
    c.load(raw)
    sid = c.get("sid")
    if not sid:
        return None
    uid = SESSIONS.get(sid.value)
    if not uid:
        return None
    con = db()
    row = con.execute("SELECT id,name,email,mobile,username FROM users WHERE id=?", (uid,)).fetchone()
    con.close()
    return dict(row) if row else None

def compute_summary(uid):
    con = db()
    s = con.execute("SELECT * FROM settings WHERE user_id=?", (uid,)).fetchone()
    if not s:
        con.execute("INSERT INTO settings(user_id) VALUES(?)", (uid,))
        con.commit()
        s = con.execute("SELECT * FROM settings WHERE user_id=?", (uid,)).fetchone()
    gcash = float(s["starting_gcash"])
    cash = float(s["starting_cash"])
    capital = float(s["capital"])
    fee_income = 0.0
    cashin = cashout = load = scan = 0.0
    txs = con.execute("SELECT * FROM transactions WHERE user_id=? ORDER BY id ASC", (uid,)).fetchall()
    out = []
    for t in txs:
        amount = float(t["amount"])
        fee = float(t["fee"])
        typ = t["tx_type"]
        if typ == "cashin":
            gcash -= amount
            cash += amount + fee
            cashin += amount
        elif typ == "cashout":
            gcash += amount
            cash -= amount
            cash += fee
            cashout += amount
        elif typ in ("load","scan"):
            gcash -= amount
            cash += amount + fee
            if typ == "load": load += amount
            else: scan += amount
        fee_income += fee
        out.append({
            "id": t["id"], "type": typ, "amount": amount, "fee": fee,
            "reference": t["reference"] or "", "created_at": t["created_at"],
            "gcash_after": gcash, "cash_after": cash
        })
    con.close()
    total = gcash + cash
    return {
        "gcash": gcash, "cash": cash, "capital": capital,
        "total_inventory": total, "fee_income": fee_income,
        "profit": total - capital, "cashin": cashin, "cashout": cashout,
        "load": load, "scan": scan, "transactions": out
    }

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args))

    def send_json(self, data, status=200, headers=None):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if headers:
            for k,v in headers.items():
                self.send_header(k,v)
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        try:
            n = int(self.headers.get("Content-Length","0"))
            return json.loads(self.rfile.read(n).decode() or "{}")
        except:
            return {}

    def auth(self):
        u = user_by_session(self)
        if not u:
            self.send_json({"error":"Unauthorized"},401)
            return None
        return u

    def do_GET(self):
        p = urlparse(self.path)
        if p.path == "/api/me":
            u = user_by_session(self)
            return self.send_json({"user":u})
        if p.path == "/api/summary":
            u = self.auth()
            if not u: return
            return self.send_json(compute_summary(u["id"]))
        if p.path == "/api/day":
            u = self.auth()
            if not u: return
            q = parse_qs(p.query)
            day = q.get("date",[""])[0]
            summary = compute_summary(u["id"])
            txs = [t for t in summary["transactions"] if t["created_at"][:10] == day]
            d = {"fee":0,"cashin":0,"cashout":0,"load":0,"scan":0,"count":len(txs),"transactions":txs}
            for t in txs:
                d["fee"] += t["fee"]
                d[t["type"]] += t["amount"]
            return self.send_json(d)

        path = p.path
        if path == "/": path = "/index.html"
        safe = os.path.normpath(path.lstrip("/"))
        f = os.path.join(BASE, safe)
        if not f.startswith(BASE) or not os.path.isfile(f):
            self.send_error(404)
            return
        ctype = mimetypes.guess_type(f)[0] or "application/octet-stream"
        data = open(f,"rb").read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        p = urlparse(self.path)
        data = self.read_json()

        if p.path == "/api/register":
            name = str(data.get("name","")).strip()
            email = str(data.get("email","")).strip().lower()
            mobile = str(data.get("mobile","")).strip()
            username = str(data.get("username","")).strip()
            password = str(data.get("password",""))
            if not all([name,email,mobile,username,password]):
                return self.send_json({"error":"Complete all fields"},400)
            if not email.endswith("@gmail.com"):
                return self.send_json({"error":"Use a valid Gmail address"},400)
            if len(mobile)!=11 or not mobile.isdigit() or not mobile.startswith("09"):
                return self.send_json({"error":"Use 11-digit PH mobile number starting 09"},400)
            if len(password)<4:
                return self.send_json({"error":"Password must be at least 4 characters"},400)
            ph,salt = hash_password(password)
            con = db()
            try:
                cur = con.execute("INSERT INTO users(name,email,mobile,username,password_hash,salt,created_at) VALUES(?,?,?,?,?,?,?)",
                    (name,email,mobile,username,ph,salt,datetime.datetime.now().isoformat(timespec="seconds")))
                uid = cur.lastrowid
                con.execute("INSERT INTO settings(user_id) VALUES(?)",(uid,))
                con.commit()
            except sqlite3.IntegrityError:
                con.close()
                return self.send_json({"error":"Username, Gmail, or mobile already exists"},400)
            con.close()
            sid = secrets.token_urlsafe(24)
            SESSIONS[sid]=uid
            return self.send_json({"ok":True}, headers={"Set-Cookie":f"sid={sid}; Path=/; HttpOnly; SameSite=Lax"})

        if p.path == "/api/login":
            ident = str(data.get("username","")).strip()
            password = str(data.get("password",""))
            con = db()
            row = con.execute("SELECT * FROM users WHERE username=? OR email=? OR mobile=?",(ident,ident.lower(),ident)).fetchone()
            con.close()
            if not row or not verify_password(password,row["password_hash"],row["salt"]):
                return self.send_json({"error":"Invalid login"},400)
            sid = secrets.token_urlsafe(24)
            SESSIONS[sid]=row["id"]
            return self.send_json({"ok":True}, headers={"Set-Cookie":f"sid={sid}; Path=/; HttpOnly; SameSite=Lax"})

        if p.path == "/api/logout":
            raw = self.headers.get("Cookie","")
            c = cookies.SimpleCookie(); c.load(raw)
            sid = c.get("sid")
            if sid: SESSIONS.pop(sid.value,None)
            return self.send_json({"ok":True}, headers={"Set-Cookie":"sid=; Path=/; Max-Age=0"})

        if p.path == "/api/setup":
            u = self.auth()
            if not u: return
            try:
                g=float(data.get("gcash",0)); c=float(data.get("cash",0)); cap=float(data.get("capital",0))
            except:
                return self.send_json({"error":"Invalid values"},400)
            con=db()
            con.execute("""INSERT INTO settings(user_id,starting_gcash,starting_cash,capital)
                VALUES(?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET
                starting_gcash=excluded.starting_gcash, starting_cash=excluded.starting_cash, capital=excluded.capital""",
                (u["id"],g,c,cap))
            con.commit(); con.close()
            return self.send_json({"ok":True})

        if p.path == "/api/transaction":
            u=self.auth()
            if not u:return
            typ=str(data.get("type",""))
            if typ not in ("cashin","cashout","load","scan"):
                return self.send_json({"error":"Invalid type"},400)
            try:
                amt=float(data.get("amount",0)); fee=float(data.get("fee",0))
            except:
                return self.send_json({"error":"Invalid amount"},400)
            if amt<=0 or fee<0:
                return self.send_json({"error":"Invalid amount/fee"},400)
            s=compute_summary(u["id"])
            if typ in ("cashin","load","scan") and s["gcash"] < amt:
                return self.send_json({"error":"Not enough GCash balance"},400)
            if typ=="cashout" and s["cash"] < amt:
                return self.send_json({"error":"Not enough cash on hand"},400)
            con=db()
            con.execute("INSERT INTO transactions(user_id,tx_type,amount,fee,reference,created_at) VALUES(?,?,?,?,?,?)",
                (u["id"],typ,amt,fee,str(data.get("reference","")).strip(),datetime.datetime.now().isoformat(timespec="seconds")))
            con.commit(); con.close()
            return self.send_json({"ok":True})

        if p.path == "/api/delete":
            u=self.auth()
            if not u:return
            tid=int(data.get("id",0))
            con=db(); con.execute("DELETE FROM transactions WHERE id=? AND user_id=?",(tid,u["id"])); con.commit(); con.close()
            return self.send_json({"ok":True})

        if p.path == "/api/request-reset":
            ident=str(data.get("identifier","")).strip()
            con=db()
            row=con.execute("SELECT * FROM users WHERE email=? OR mobile=?",(ident.lower(),ident)).fetchone()
            if not row:
                con.close(); return self.send_json({"error":"Account not found"},400)
            code=str(secrets.randbelow(900000)+100000)
            exp=(datetime.datetime.now()+datetime.timedelta(minutes=10)).isoformat(timespec="seconds")
            con.execute("INSERT INTO reset_codes(user_id,code,expires_at) VALUES(?,?,?)",(row["id"],code,exp))
            con.commit(); con.close()
            # Demo/local mode: return code. Replace with email/SMS provider for production.
            return self.send_json({"ok":True,"demo_code":code,"message":"Local demo code generated"})

        if p.path == "/api/reset-password":
            ident=str(data.get("identifier","")).strip()
            code=str(data.get("code","")).strip()
            password=str(data.get("password",""))
            if len(password)<4:
                return self.send_json({"error":"Password too short"},400)
            con=db()
            row=con.execute("SELECT * FROM users WHERE email=? OR mobile=?",(ident.lower(),ident)).fetchone()
            if not row:
                con.close(); return self.send_json({"error":"Account not found"},400)
            rc=con.execute("""SELECT * FROM reset_codes WHERE user_id=? AND code=? AND used=0
                ORDER BY id DESC LIMIT 1""",(row["id"],code)).fetchone()
            if not rc or rc["expires_at"] < datetime.datetime.now().isoformat(timespec="seconds"):
                con.close(); return self.send_json({"error":"Invalid or expired code"},400)
            ph,salt=hash_password(password)
            con.execute("UPDATE users SET password_hash=?,salt=? WHERE id=?",(ph,salt,row["id"]))
            con.execute("UPDATE reset_codes SET used=1 WHERE id=?",(rc["id"],))
            con.commit(); con.close()
            return self.send_json({"ok":True})

        self.send_error(404)

def main():
    init_db()
    server=ThreadingHTTPServer(("0.0.0.0",PORT),Handler)
    print("="*60)
    print("GCash Multi-Device Server running")
    print(f"On this device: http://127.0.0.1:{PORT}")
    print("For phone/tablet/PC on same Wi-Fi, use this device's LAN IP:")
    print(f"http://<SERVER-IP>:{PORT}")
    print("Press Ctrl+C to stop.")
    print("="*60)
    server.serve_forever()

if __name__=="__main__":
    main()
