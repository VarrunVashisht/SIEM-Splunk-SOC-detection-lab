## 🔓 Use Case 2: Successful Login After Brute Force (Account Compromise)

---

## 🎯 Objective

Detect whether a brute force attack resulted in a **successful login**, indicating account compromise.

---

## 📂 Data Source

* Index: `practicelog`
* Log Type: Linux Authentication Logs (`auth.log`)

---

## 🧠 Investigation Strategy

We are correlating:

* Failed login attempts
  ➡️ Followed by
* Successful login
  ➡️ From same IP
  ➡️ Within short time window

This pattern = **credential compromise**

---

# 🔍 STEP-BY-STEP INVESTIGATION

---

## 🔍 Step 1: Identify Failed Login Events

```spl
index=practicelog "Failed password"
```

### ✅ What

Filter failed authentication attempts.

### 🤔 Why


We start by identifying attacker activity.

---

## 🔍 Step 2: Identify Successful Login Events

```spl
index=practicelog "Accepted password"
```

### ✅ What

Filter successful logins.

### 🤔 Why

We need to see if attacker eventually succeeded.

---

## 🔍 Step 3: Combine Failed + Successful Events

```spl
index=practicelog ("Failed password" OR "Accepted password")
```

### ✅ What

Bring both event types together.

### 🤔 Why

Correlation requires both failure and success data.

---

## 🔍 Step 4: Extract Fields (IP + User)

```spl
index=practicelog ("Failed password" OR "Accepted password")
| rex "for (invalid user )?(?<user>\w+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
```

### ✅ What

Extract structured fields from raw logs.

### 🤔 Why

Splunk needs structured fields for grouping & correlation.

---

## 🔍 Step 5: Label Event Type (Fail vs Success)

```spl
index=practicelog ("Failed password" OR "Accepted password")
| eval status=if(searchmatch("Failed"),"fail","success")
```

### ✅ What

Create a new field `status`.

### 🤔 Why

Helps differentiate attacker behavior sequence.

---

## 🔍 Step 6: Count Failures Before Success

```spl
index=practicelog ("Failed password" OR "Accepted password")
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| eval status=if(searchmatch("Failed"),"fail","success")
| stats count(eval(status="fail")) as failures
count(eval(status="success")) as success
by src_ip
```

### ✅ What

Count failures vs successes per IP.

### 🤔 Why

Attackers show **high failures + eventual success**.

---

<img width="1877" height="884" alt="image" src="https://github.com/user-attachments/assets/b2e14ec4-d838-4527-a77a-adb4f2c4b999" />


## 🔍 Step 7: Detect Suspicious Pattern

```spl
index=practicelog ("Failed password" OR "Accepted password")
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| eval status=if(searchmatch("Failed"),"fail","success")
| stats count(eval(status="fail")) as failures count(eval(status="success")) as success by src_ip
| where failures > 10 AND success > 0
```

### ✅ What

Filter suspicious IPs.

### 🤔 Why

Normal users don’t fail 10+ times then succeed.

---
<img width="1907" height="966" alt="image" src="https://github.com/user-attachments/assets/e4154bb2-bebc-48ed-a285-634e50935d4a" />


## 🔍 Step 8: Sequence Pattern

```spl
index=practicelog ("Failed password" OR "Accepted password")
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| eval status=if(searchmatch("Failed"),"fail","success")
| stats list(status) as sequence by src_ip
```

### ✅ What

Show login sequence.

### 🤔 Why

You visually confirm:
fail → fail → fail → success

👉 This is **attacker behavior**

---

<img width="1892" height="1000" alt="image" src="https://github.com/user-attachments/assets/d47dbc17-c467-4d15-8208-2c69f091f110" />


## 🔍 Step 9: Time-Based Correlation

```spl
index=practicelog ("Failed password" OR "Accepted password")
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| bucket _time span=5m
| stats count by _time, src_ip
```

### ✅ What

Group activity into time windows.

### 🤔 Why

Attack happens within short burst.

---

<img width="1895" height="793" alt="image" src="https://github.com/user-attachments/assets/11f24626-9ec7-4098-bcca-ed1897dc1f27" />

## 🔍 Step 10: Transaction Analysis 
```spl
index=practicelog ("Failed password" OR "Accepted password")
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| transaction src_ip maxspan=5m
```

### ✅ What

Group events into sessions.

🧠 What transaction does
The transaction command groups multiple events into a single event based on a shared field—in this case:
src_ip = all events with the same source IP get grouped together

So instead of seeing individual log lines, you’ll see one combined “transaction” per IP.

### 🤔 Why

Simulates attacker session activity.

---

## 🔍 Step 11: Detect Compromise Sessions

```spl
index=practicelog ("Failed password" OR "Accepted password")
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| transaction src_ip maxspan=5m
| search eventcount > 5
```

### ✅ What

Find sessions with many events.

### 🤔 Why

High activity session = attack window.

---

<img width="1894" height="1008" alt="image" src="https://github.com/user-attachments/assets/69198765-c5a9-4aee-bf9d-2004e3d6b627" />


## 🔍 Step 12: Identify First Successful Login

```spl
index=practicelog "Accepted password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats min(_time) as first_success by src_ip
```

### ✅ What

Find first success time.

### 🤔 Why

Marks **compromise point**

---

## 🔍 Step 13: Raw Event Verification

```spl
index=practicelog ("Failed password" OR "Accepted password")
| rex "for (invalid user )?(?<user>\w+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| table _time src_ip user
```

### ✅ What

View raw events.

### 🤔 Why

Always validate before reporting.

---
<img width="1880" height="878" alt="image" src="https://github.com/user-attachments/assets/877e9229-0c16-4c5a-b51a-90277062d5a1" />

# 📊 Findings

* Identified IP performing multiple failed attempts
* Same IP achieved successful login
* Activity occurred within short time window

---

# 🧠 Correlation Insight 

This is NOT just failed login.

This is:

* High failure count

- Same IP
- Eventual success
- Short time window

👉 = **Confirmed Account Compromise**

---

# ⚠️ Risk Level

🚨 **Critical**

Attacker has valid credentials.

---

# 🛡️ Recommendations

* Immediately reset affected account
* Enable MFA
* Check lateral movement (other systems)
* Block attacker IP
* Monitor login patterns

---

# 🧭 MITRE ATT&CK Mapping

* T1110 → Brute Force
* T1078 → Valid Accounts

---

# 🧠 Analyst Mindset 

Most people:
❌ “There were failed logins”

You:
✔ “Attacker executed brute force → achieved access → compromised account”

👉 That’s **SOC thinking**

---

## Author
Varrun Vashisht
