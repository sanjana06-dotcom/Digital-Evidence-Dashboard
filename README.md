#  Digital Evidence Dashboard  
**Flask-based Digital Forensics Evidence Management System**

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Visit%20Now-brightgreen?style=for-the-badge)](https://digital-evidence-dashboard.onrender.com)
[![Python](https://img.shields.io/badge/Python-3.13-blue?style=for-the-badge&logo=python)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-Web%20App-black?style=for-the-badge&logo=flask)](https://flask.palletsprojects.com/)
[![Render](https://img.shields.io/badge/Deployed%20on-Render-purple?style=for-the-badge&logo=render)](https://render.com/)

---

##  Overview
**Digital Evidence Dashboard** is a web-based **Forensic Evidence Management System** that allows investigators to securely upload, verify, and document digital files.  
It supports **MD5 & SHA256 hashing**, **audit logging**, and **automated report generation** (CSV and PDF).  
The interface features **dark/light mode** and an **animated “Matrix” 0/1 background** for a modern cyber-forensics look.

---

##  Live Demo  
 **[Click here to open the live app](https://digital-evidence-dashboard.onrender.com)**

---

##  Features
 Upload and automatically calculate **MD5** & **SHA256** hashes  
 **Verify integrity** of uploaded evidence files  
 **Delete** or manage records securely  
 **Audit logging** with timestamps  
 Export reports as:
-  **CSV (Excel)**  
-  **PDF with logo and timestamp**
 Toggle between **Dark  / Light ** themes  
 **Animated 0/1 Matrix background**  
   Fully responsive design (works on PC, tablet, mobile)

---

##  Tech Stack
| Layer | Technology |
|-------|-------------|
| **Frontend** | HTML5, CSS3, JavaScript |
| **Backend** | Flask (Python) |
| **Database** | SQLite3 |
| **Reporting** | ReportLab |
| **Deployment** | Render |
| **Version Control** | Git & GitHub |

---

##  Screenshots

### 🔹 Dashboard View  
![Dashboard Screenshot](https://github.com/sanjana06-dotcom/Digital-Evidence-Dashboard/assets/your_image_id_here)

### 🔹 Matrix Animation Background  
![Matrix Background](https://github.com/sanjana06-dotcom/Digital-Evidence-Dashboard/assets/your_image_id_here)

### 🔹 Dark/Light Theme  
![Theme Toggle](https://github.com/sanjana06-dotcom/Digital-Evidence-Dashboard/assets/your_image_id_here)


---

##  Installation (Local Setup)
If you want to run this locally:
```bash
# Clone this repository
git clone https://github.com/sanjana06-dotcom/Digital-Evidence-Dashboard.git
cd Digital-Evidence-Dashboard

# Create virtual environment
python3 -m venv venv
source venv/bin/activate   # (For Linux/macOS)
venv\Scripts\activate      # (For Windows)

# Install dependencies
pip install -r requirements.txt

# Run the Flask app
python app.py
