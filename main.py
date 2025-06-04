import json
import socket
import sqlite3
import re
from datetime import datetime

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()

# Allow CORS for local development (adjust in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Replace "*" with your frontend domain in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize SQLite DB connection
conn = sqlite3.connect("scans.db", check_same_thread=False)
cursor = conn.cursor()

# Create scans table if not exists
cursor.execute('''
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    ip TEXT NOT NULL,
    open_ports TEXT NOT NULL,
    vulnerabilities TEXT NOT NULL,
    scan_time TEXT NOT NULL
)
''')
conn.commit()

# Pydantic model for scan result validation and serialization
class ScanResult(BaseModel):
    host: str
    ip: str
    open_ports: list[int]
    vulnerabilities: dict[str, list[str]]
    scan_time: str

# Hostname validation using regex
def is_valid_hostname(hostname: str) -> bool:
    if hostname.lower() == "localhost":
        return True
    hostname_regex = re.compile(
        r"^(?=.{1,253}$)([a-zA-Z0-9-]{1,63}\.)*[a-zA-Z0-9-]{1,63}$"
    )
    ip_regex = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    return bool(hostname_regex.match(hostname)) or bool(ip_regex.match(hostname))

@app.get("/", tags=["General"])
async def root():
    return {"message": "Welcome to your Vulnerability Scanner API!"}

@app.get("/health", tags=["General"])
async def health_check():
    return {"status": "ok"}

@app.get("/scan", response_model=ScanResult, tags=["Scan"])
async def scan_host(host: str):
    if not is_valid_hostname(host):
        raise HTTPException(status_code=400, detail="Invalid hostname or IP address")

    # Resolve host to IP address
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        raise HTTPException(status_code=400, detail="Unable to resolve host")

    ports_to_check = [21, 22, 23, 80, 443, 8080]
    open_ports = []

    # Scan each port for openness
    for port in ports_to_check:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            if result == 0:
                open_ports.append(port)

    # Basic simulated vulnerability checks
    vulnerabilities = {}
    for port in open_ports:
        if port == 22:
            vulnerabilities[str(port)] = [
                "SSH - Weak password policies",
                "SSH - Outdated version vulnerability"
            ]
        elif port == 80:
            vulnerabilities[str(port)] = [
                "HTTP - Outdated software",
                "HTTP - Directory listing enabled"
            ]
        else:
            vulnerabilities[str(port)] = ["No known vulnerabilities detected"]

    scan_time = datetime.utcnow().isoformat()

    # Save scan to database with JSON serialized fields
    try:
        cursor.execute('''
            INSERT INTO scans (host, ip, open_ports, vulnerabilities, scan_time)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            host,
            ip,
            json.dumps(open_ports),
            json.dumps(vulnerabilities),
            scan_time
        ))
        conn.commit()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

    return ScanResult(
        host=host,
        ip=ip,
        open_ports=open_ports,
        vulnerabilities=vulnerabilities,
        scan_time=scan_time
    )

@app.get("/scans", tags=["Scan History"])
async def get_all_scans():
    try:
        cursor.execute('SELECT * FROM scans ORDER BY id DESC')
        rows = cursor.fetchall()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

    scans = []
    for row in rows:
        try:
            scans.append({
                "id": row[0],
                "host": row[1],
                "ip": row[2],
                "open_ports": json.loads(row[3]),
                "vulnerabilities": json.loads(row[4]),
                "scan_time": row[5]
            })
        except json.JSONDecodeError:
            # If JSON fails to decode, fallback to empty/default values
            scans.append({
                "id": row[0],
                "host": row[1],
                "ip": row[2],
                "open_ports": [],
                "vulnerabilities": {},
                "scan_time": row[5]
            })

    return scans

# Gracefully close DB connection on shutdown
@app.on_event("shutdown")
def shutdown_event():
    if conn:
        conn.close()
