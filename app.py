import os
import sqlite3
import hashlib
import csv
from datetime import datetime
from flask import Flask, request, redirect, url_for, render_template_string, send_from_directory, flash, g, Response
from werkzeug.utils import secure_filename
from io import StringIO, BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

# --- Configuration ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
DB_PATH = os.path.join(BASE_DIR, 'evidence.db')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = 'forensics_secret_key'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# --- Database setup ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# --- Table creation ---
def init_db():
    with app.app_context():
        conn = get_db()
        conn.execute('''CREATE TABLE IF NOT EXISTS evidence (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        filename TEXT,
                        file_type TEXT,
                        size INTEGER,
                        md5_hash TEXT,
                        sha256_hash TEXT,
                        uploaded_on TEXT,
                        verified TEXT
                    )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS audit_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        evidence_id INTEGER,
                        action TEXT,
                        timestamp TEXT
                    )''')
        conn.commit()
init_db()

# --- Helper: Hashing ---
def compute_hashes(file_path):
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()

# --- Routes ---
@app.route('/')
def index():
    conn = get_db()
    evidence = conn.execute("SELECT * FROM evidence ORDER BY id DESC").fetchall()
    logs = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 10").fetchall()
    conn.close()

    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Digital Evidence Dashboard</title>
<style>
body {
    font-family: 'Segoe UI', sans-serif;
    background: black;
    color: white;
    margin: 0;
    padding: 0;
    overflow-x: hidden;
}

/* Matrix background */
canvas#matrixCanvas {
    position: fixed;
    top: 0; left: 0;
    z-index: -1;
    width: 100%; height: 100%;
}

/* Container */
.container {
    margin: 60px auto;
    width: 90%;
    background: rgba(255,255,255,0.08);
    border-radius: 15px;
    padding: 25px;
    box-shadow: 0 0 25px rgba(0,255,0,0.3);
}

/* Buttons */
button, a.button {
    text-decoration: none;
    border: none;
    padding: 10px 18px;
    border-radius: 8px;
    font-size: 16px;
    cursor: pointer;
    font-weight: 600;
}
.blue { background:#007bff; color:white; }
.green { background:#28a745; color:white; }
.purple { background:#6f42c1; color:white; }
.red { background:#dc3545; color:white; }
.gray { background:#6c757d; color:white; }
button:hover { opacity:0.9; }

/* Table */
table { width:100%; border-collapse:collapse; margin-top:20px; }
th, td { padding:12px; text-align:center; font-size:15px; }
th { background:#0066cc; color:white; }
tr:nth-child(even) { background:rgba(255,255,255,0.1); }

/* Audit log styling */
.audit {
  margin-top: 25px;
  color: rgba(255,255,255,0.9);
}
body.light-mode .audit {
  color: #111;
}
.audit h3 {
  color: #ffcc00;
  font-size: 1.2rem;
  font-weight: 700;
}

/* Mode toggle */
.mode-toggle {
  float:right;
  display:flex;
  align-items:center;
  gap:8px;
  font-weight:600;
  color:rgba(255,255,255,0.9);
}
body.light-mode .mode-toggle { color:#111; }
.mode-toggle input { transform:scale(1.1); cursor:pointer; }

/* Light mode */
body.light-mode {
    background: #f6f8fa;
    color: #111;
}
body.light-mode .container {
    background: white;
    color: #111;
    box-shadow: 0 0 20px rgba(0,0,0,0.1);
}
body.light-mode th {
    background: #28a745;
}
</style>
</head>

<body>
<canvas id="matrixCanvas"></canvas>
<div class="container">
    <h2>🧾 Digital Evidence Dashboard</h2>
    <div class="mode-toggle">
        <input type="checkbox" id="themeToggle" checked>
        <label for="themeToggle">🌙 Dark / ☀️ Light</label>
    </div>
    <br>
    <a href="{{ url_for('upload') }}" class="button blue">⬆️ Upload Evidence</a>
    <a href="{{ url_for('download_report') }}" class="button green">📥 Download CSV</a>
    <a href="{{ url_for('download_audit') }}" class="button teal">🧾 Download Audit</a>
    <a href="{{ url_for('generate_pdf') }}" class="button purple">📄 Generate PDF</a>

    <table>
        <tr>
            <th>ID</th><th>Filename</th><th>Type</th><th>Size</th>
            <th>MD5</th><th>SHA256</th><th>Uploaded</th><th>Verified</th><th>Actions</th>
        </tr>
        {% for e in evidence %}
        <tr>
            <td>{{ e.id }}</td>
            <td>{{ e.filename }}</td>
            <td>{{ e.file_type }}</td>
            <td>{{ e.size }}</td>
            <td>{{ e.md5_hash[:12] }}...</td>
            <td>{{ e.sha256_hash[:12] }}...</td>
            <td>{{ e.uploaded_on }}</td>
            <td>{{ e.verified }}</td>
            <td>
                <a href="{{ url_for('verify', eid=e.id) }}" class="button blue">✔ Verify</a>
                <a href="{{ url_for('delete_file', eid=e.id) }}" class="button red">🗑 Delete</a>
            </td>
        </tr>
        {% endfor %}
    </table>

    <div class="audit">
        <h3>🧠 Recent Audit Log</h3>
        {% for log in logs %}
            <p>{{ log.timestamp }} — [ID {{ log.evidence_id }}] {{ log.action }}</p>
        {% endfor %}
    </div>
</div>

<script>
// Matrix background
const canvas = document.getElementById('matrixCanvas');
const ctx = canvas.getContext('2d');
canvas.height = window.innerHeight;
canvas.width = window.innerWidth;
const chars = "01";
const fontSize = 14;
const columns = canvas.width / fontSize;
const drops = Array(Math.floor(columns)).fill(1);
function draw() {
  ctx.fillStyle = "rgba(0, 0, 0, 0.05)";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = "#00FF00";
  ctx.font = fontSize + "px monospace";
  drops.forEach((y, i) => {
    const text = chars.charAt(Math.floor(Math.random() * chars.length));
    ctx.fillText(text, i * fontSize, y * fontSize);
    if (y * fontSize > canvas.height && Math.random() > 0.975) drops[i] = 0;
    drops[i]++;
  });
}
setInterval(draw, 33);

// Light/Dark mode
const toggle = document.getElementById('themeToggle');
toggle.addEventListener('change', () => {
  document.body.classList.toggle('light-mode');
});
</script>
</body>
</html>
''', evidence=evidence, logs=logs)

# --- Upload Route ---
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        file = request.files['file']
        if not file:
            flash("No file selected")
            return redirect(url_for('index'))
        filename = secure_filename(file.filename)
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(path)
        size = os.path.getsize(path)
        md5, sha256 = compute_hashes(path)
        file_type = "text/plain" if filename.endswith(".txt") else "unknown"
        uploaded = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = get_db()
        conn.execute("INSERT INTO evidence (filename, file_type, size, md5_hash, sha256_hash, uploaded_on, verified) VALUES (?,?,?,?,?,?,?)",
                     (filename, file_type, size, md5, sha256, uploaded, 'PASS'))
        conn.commit()
        conn.close()
        return redirect(url_for('index'))

    return '''
    <form method="post" enctype="multipart/form-data">
        <input type="file" name="file">
        <input type="submit" value="Upload">
    </form>
    '''

# --- Verify ---
@app.route('/verify/<int:eid>')
def verify(eid):
    conn = get_db()
    conn.execute("INSERT INTO audit_log (evidence_id, action, timestamp) VALUES (?, ?, ?)",
                 (eid, "File Verification: PASS", datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

# --- Delete ---
@app.route('/delete/<int:eid>')
def delete_file(eid):
    conn = get_db()
    conn.execute("DELETE FROM evidence WHERE id=?", (eid,))
    conn.execute("INSERT INTO audit_log (evidence_id, action, timestamp) VALUES (?, ?, ?)",
                 (eid, "File Deleted", datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

# --- CSV Download ---
@app.route('/download_report')
def download_report():
    conn = get_db()
    evidence = conn.execute("SELECT * FROM evidence").fetchall()
    conn.close()
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Filename', 'File Type', 'Size (B)', 'MD5', 'SHA256', 'Uploaded', 'Verified'])
    for e in evidence:
        writer.writerow([e['id'], e['filename'], e['file_type'], e['size'], e['md5_hash'], e['sha256_hash'], e['uploaded_on'], e['verified']])
    response = Response(output.getvalue(), mimetype='text/csv')
    response.headers["Content-Disposition"] = "attachment; filename=forensic_report.csv"
    return response

# --- Audit Download ---
@app.route('/download_audit')
def download_audit():
    conn = get_db()
    logs = conn.execute("SELECT * FROM audit_log").fetchall()
    conn.close()
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Evidence ID', 'Action', 'Timestamp'])
    for log in logs:
        writer.writerow([log['id'], log['evidence_id'], log['action'], log['timestamp']])
    response = Response(output.getvalue(), mimetype='text/csv')
    response.headers["Content-Disposition"] = "attachment; filename=audit_log.csv"
    return response

# --- PDF Report ---
@app.route('/generate_pdf')
def generate_pdf():
    conn = get_db()
    evidence = conn.execute("SELECT * FROM evidence").fetchall()
    conn.close()
    buffer = BytesIO()
    pdf = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = [Paragraph("Digital Evidence Report", styles['Title']), Spacer(1, 12)]
    data = [['ID', 'Filename', 'Type', 'Size (B)', 'MD5', 'SHA256', 'Uploaded', 'Verified']]
    for e in evidence:
        data.append([e['id'], e['filename'], e['file_type'], e['size'], e['md5_hash'][:10], e['sha256_hash'][:10], e['uploaded_on'], e['verified']])
    table = Table(data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0066cc')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('GRID', (0,0), (-1,-1), 0.25, colors.grey)
    ]))
    elements.append(table)
    pdf.build(elements)
    buffer.seek(0)
    return Response(buffer, mimetype='application/pdf',
                    headers={"Content-Disposition": "attachment; filename=forensic_report.pdf"})

if __name__ == '__main__':
    app.run(debug=True)
