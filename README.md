# GCash Business Tracker

Responsive local web app for tracking a small GCash cash-in/cash-out business across phone, tablet, and PC on the same local network.

## Features

- User registration and login
- Login using username, Gmail, or mobile number
- Password show/hide control
- Local demo forgot-password verification code
- Cash In, Cash Out, Load, and Scan transaction types
- GCash balance, cash on hand, capital, inventory, fee income, and estimated profit
- Daily transaction lookup
- Per-user SQLite data
- Responsive layout for phone, tablet, and PC

## Run locally

Requires Python 3.

```bash
python server.py
```

Open on the server device:

```text
http://127.0.0.1:8000
```

For another device on the same Wi-Fi, use the LAN IP of the device running the server:

```text
http://192.168.x.x:8000
```

## Data and security

The app creates `gcash.db` locally. The database is intentionally excluded from Git so user accounts and transactions are not committed to this repository.

The forgot-password code is currently a **local demo flow** and is shown by the app. Real Gmail/SMS OTP delivery requires an email/SMS provider and production backend configuration.

This project is intended for local/private use. Do not expose the development server directly to the public internet without HTTPS, persistent session storage, rate limiting, CSRF protections, and other production hardening.
