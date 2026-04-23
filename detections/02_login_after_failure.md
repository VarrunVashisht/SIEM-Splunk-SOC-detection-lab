# 🔐 Login After Multiple Failures

## 🎯 Objective

Detect successful login after multiple failed attempts indicating possible compromise.

---

## 📊 Log Source

Splunk synthetic dataset
Index: `practicelog`

---

## 🔎 SPL Query

```spl
index=practicelog 
(event_type=failed_login OR event_type=successful_login)
| stats 
    count(eval(event_type="failed_login")) as failed,
    count(eval(event_type="successful_login")) as success
    by src_ip, user
| where failed > 5 AND success > 0
```

---

## 🧠 Detection Logic

Multiple failed login attempts followed by a successful login.

---

## 🧭 MITRE ATT&CK

* T1110 — Brute Force
* T1078 — Valid Accounts

---

## 🚨 Alert Configuration

* Condition: failed > 5 AND success > 0
* Severity: High

---

## 🕵️ Investigation Steps

* Check IP reputation
* Validate user activity
* Look for post-login anomalies

---

## ❌ False Positives

* User entering wrong password
* Automated retries

---

## 📸 Screenshots

With condition: where failed > 5 AND success > 0
No successful login registered.

<img width="1583" height="650" alt="image" src="https://github.com/user-attachments/assets/3d1cd8f0-f30b-42c1-bdf9-2dec5114898e" />


With condition: where failed > 3 AND success > 0
Successful login registered, but this can be user error also.

<img width="1899" height="637" alt="image" src="https://github.com/user-attachments/assets/0e9c80e9-b9a0-4256-8310-ef91180adab5" />


