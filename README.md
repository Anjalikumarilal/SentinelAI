# 🛡️ SentinelAI – Cyber Threat Intelligence Dashboard

## 📌 Project Overview

SentinelAI is a cybersecurity monitoring dashboard built with Python and Flask. It helps identify suspicious network activity, enrich threat information using Cyber Threat Intelligence (CTI), calculate risk scores, and display security alerts through a web-based dashboard.

## 🎯 Objectives

* Detect suspicious network activities.
* Enrich suspicious IP addresses with threat intelligence.
* Calculate risk scores and classify alert severity.
* Monitor alerts and security incidents.
* Analyze PCAP network capture files.
* Map detected attacks to MITRE ATT&CK techniques.

## ✨ Key Features

* **Threat Detection:** Identifies activities such as port scans, brute-force attempts, suspicious DNS traffic, and network floods.
* **Threat Intelligence:** Enriches IP addresses using mock or real threat intelligence sources.
* **Risk Scoring:** Combines detection, CTI, and behavioral anomaly scores.
* **Security Alerts:** Displays detected threats with severity levels.
* **Incident Management:** Supports incident tracking and investigation.
* **PCAP Analysis:** Analyzes uploaded network capture files.
* **MITRE ATT&CK Mapping:** Connects detected activities to relevant techniques.
* **Authentication:** Provides login and role-based access control.

## 🛠️ Technologies Used

* Python
* Flask
* Supabase
* HTML and CSS
* Scapy
* VirusTotal API (for real CTI enrichment, when configured)

## 📂 Project Structure

```text
SentinelAI/
├── config/
├── cti/
├── detection/
├── ml/
├── risk/
├── routes/
├── static/
├── templates/
├── utils/
├── app.py
├── requirements.txt
├── .env.example
└── README.md
```

## ⚙️ Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/Anjalikumarilal/SentinelAI.git
cd SentinelAI
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

Activate it on Windows:

```bash
venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Create a local `.env` file based on `.env.example`.

Add your own Supabase configuration and Flask secret key. Add a VirusTotal API key if your real CTI configuration requires one.

**Never upload your actual `.env` file or API keys to GitHub.**

### 5. Configure the database

Create and configure the required Supabase tables according to the application's database schema.

### 6. Run the application

```bash
python app.py
```

Open the local URL displayed by Flask in your browser.

## 🔐 Security Notes

* Keep API keys and credentials in environment variables.
* Never commit `.env` files or other secret credentials.
* Use appropriate Supabase Row Level Security policies.
* Restrict administrative actions to authorized users.
* Use synthetic or sanitized PCAP files for testing and demonstrations.

## ⚠️ Disclaimer

SentinelAI is an educational cybersecurity project intended for authorized monitoring, testing, and learning. Use it only on systems and network traffic you are authorized to analyze.

## 👩‍💻 Project

**Name:** SentinelAI
**Category:** Cybersecurity / Threat Intelligence
**Repository:** [GitHub – SentinelAI](https://github.com/Anjalikumarilal/SentinelAI)
