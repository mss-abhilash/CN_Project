# IoT Secure Home Network — Complete Local Run Guide

Welcome to the **IoT Secure Home Network** project! This guide will walk you through setting up the environment, launching the security gateway, simulating IoT devices, and running security tests (like penetration testing and performance benchmarks).

Follow these steps exactly to get everything running locally on your machine.

---

## 1. Initial Setup Instructions

### Prerequisites
Make sure you have installed on your system:
- **Python 3.10** or higher
- **Git** (optional, for version control)
- A terminal (PowerShell for Windows, Terminal for macOS/Linux)

### Step 1: Open Terminal in the Project Folder
Open your terminal and make sure you are in the project folder:
```bash
cd /path/to/CN_PROJECT
```

### Step 2: Create a Virtual Environment
A virtual environment keeps the project dependencies isolated from your main system.
```bash
# Windows
python -m venv venv
.\venv\Scripts\Activate.ps1

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
```
*(You should now see `(venv)` at the beginning of your terminal prompt).*

### Step 3: Install Dependencies
With the virtual environment active, install all required packages:
```bash
pip install -r requirements.txt
```

---

## 2. Run the Gateway Backend

The heart of the project is the Gateway. It handles authentication, VPN peering, Access Control Lists (ACL), and encrypting/decrypting IoT signals.

### Start the Server
In your terminal (with `venv` active), type:
```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```
**Expected Output:**
```
[OK] Database initialized. VPN manager started.
[ACL] INFO: ACL Engine initialized.
INFO: Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

> **Tip:** Leave this terminal window running! Open a **new** terminal window for the following steps (and remember to activate the `venv` in the new window too!).

---

## 3. Start the IoT Devices

Instead of buying physical hardware, we have Python scripts that simulate real smart devices.

Open a **second terminal** window, activate the `venv`, and run the parallel device test:
```bash
# (Make sure to activate venv first!)
python scripts/test_devices_parallel.py
```
This script will simultaneously launch:
1. A Smart Camera
2. A Temperature Sensor
3. A Smart Lock

**Expected Output:** You will see the devices securely registering to the Gateway backend, receiving their JWT tokens, and successfully outputting encrypted `AES-128 GCM` telemetry.

---

## 4. Test Authentication & VPN

You can test user authentication manually using the interactive API documentation.

1. Open your web browser and go to: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
2. **Register**: Scroll to `POST /register`, click **Try it out**, enter a username, email, and password, and execute.
   - *Save the `totp_secret` it gives you!*
3. **Login Phase 1**: Go to `POST /login`, enter your details. You will get a `phase1_token`. 
4. **Login Phase 2**: Because of Two-Phase Authentication (2FA), Phase 1 is not enough. You must generate a TOTP code.
   - Use a free online tool or Python script to generate a TOTP code from your secret.
   - Go to `POST /verify-otp`, provide the OTP code, and use your `phase1_token` as the Bearer token.
   - You now possess the true `access_token`!

### Creating a VPN Peer
Now that you have your Phase 2 `access_token`, you can go to `POST /vpn/peers` in the docs. Click the green "Authorize" button globally, paste your `access_token`, and execute the VPN endpoint. You will see it generate your `.conf` files in `vpn/configs/` folder.

---

## 5. Simulate Penetration Attacks

To prove the security works, we have a Penetration Testing Suite.

Open a terminal (activate `venv`) and run:
```bash
python attacks/pentest_demo.py
```

This will run 3 powerful attacks against your local system:
1. **Replay Attack** (Trying to use an old token)
2. **Brute-Force Login** (Guessing thousands of passwords)
3. **Packet Sniffing** (Trying to read data without the encryption key)

**What you will see:**
The script demonstrates what an attack looks like **Without Security** (VULNERABLE), and then what it looks like **With Our Security Active** (DEFENDED). You should see the gateway automatically locking out the attacker and rate-limiting them completely!

---

## 6. Measure System Performance

Security often comes at the cost of speed. Want to see exactly how much? We built a benchmark analyzer!

Run:
```bash
python scripts/performance_test.py
```
This will test the processing time of the Gateway for Authentication delays, the speed of making keys for the VPN, and exactly how much slower the network is when AES-128 GCM encryption is enforced.

---

## 🐞 Common Errors & Fixes (Troubleshooting)

**Error 1: `ModuleNotFoundError: No module named 'fastapi'`**
- **Cause:** Your virtual environment isn't activated.
- **Fix:** In Windows, run `.\venv\Scripts\Activate.ps1`. Look for `(venv)` on the prompt.

**Error 2: `[WinError 10048] Only one usage of each socket address is permitted`**
- **Cause:** You tried to start the Gateway, but port 8000 is already in use (you probably left another terminal running it!).
- **Fix:** Find the other terminal window running Uvicorn and stop it with `CTRL + C`.

**Error 3: `HTTP 429 Rate limit exceeded / HTTP 403 Account Locked`**
- **Cause:** You ran tests too fast, or ran the pentest multiple times, and the Gateway ACL banned you!
- **Fix:** The Gateway is working perfectly! To clear your ban, stop the server (`CTRL + C`) and delete the database file (`database/iot_secure.db`), then restart the server.

**Error 4: Cannot run scripts on Windows (`scripts is disabled on this system`)**
- **Cause:** Windows PowerShell prevents running scripts by default.
- **Fix:** Open PowerShell as Administrator and run: `Set-ExecutionPolicy RemoteSigned`, choose "Y" to accept.

---

## 💡 Pro Debug Tips for Developers

1. **Watch the ACL Log**: If a device or test script is failing silently, check the `logs/acl_blocked.log` file. The server engine logs *every single blocked request* precisely by IP Address and rule.
2. **Database resets**: The fastest way to reset testing numbers or lockout timers is just to delete the `database/iot_secure.db` SQLite file. It will automatically recreate entirely empty blocks on restart.
3. **Print Statements are King**: If you want to dive into the cryptography, look inside `gateway/gateway_core.py` and print variables at exactly the `aesgcm.decrypt()` function to view raw byte-dumps.
