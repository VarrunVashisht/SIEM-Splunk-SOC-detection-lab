## 🌐 Use Case 4: Web Scanning Detection (Reconnaissance Phase)

---

## 🎯 Objective

Detect **web application scanning activity** where an attacker probes multiple endpoints to discover vulnerabilities.

---

## 📂 Data Source

* Index: `practicelog`
* Sourcetype: `web_logs`

---

## 🧠 Investigation Strategy

Attackers during reconnaissance:

* Access multiple endpoints rapidly
* Target sensitive paths (`/admin`, `/login`, `/phpmyadmin`)
* Generate high number of 404 errors
* Show automated, repetitive behavior

---

# 🔍 STEP-BY-STEP INVESTIGATION

---

## 🔍 Step 1: View Raw Logs

```spl id="y2m3n1"
index=practicelog sourcetype=web_logs
```

### ✅ What

Load raw events.

### 🤔 Why

Understand log format and patterns before analysis.

---

## 🔍 Step 2: Extract Key Fields 

```spl id="b9r4t7"
index=practicelog sourcetype=web_logs
| rex "^(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "\"GET (?<uri>\S+)"
| rex "\" (?<status>\d{3}) (?<bytes>\d+)"
```

### ✅ What

Extract:

* Source IP
* URI
* Status code
* Bytes

### 🤔 Why

We need structured fields to detect scanning behavior.

---

## 🔍 Step 3: Validate Extraction

```spl id="v8k2h3"
index=practicelog sourcetype=web_logs
| rex "^(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "\"GET (?<uri>\S+)"
| rex "\" (?<status>\d{3}) (?<bytes>\d+)"
| table _time src_ip uri status bytes
```

### Why

Always verify parsing before deeper analysis.

---

<img width="1899" height="811" alt="image" src="https://github.com/user-attachments/assets/95187730-c474-4b13-86f5-58b97c1fcdb1" />

## 🔍 Step 4: Identify High Request Volume per IP

```spl id="n4c7q1"
index=practicelog sourcetype=web_logs
| rex "^(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as request_count by src_ip
| sort -request_count
```

### ✅ What

Count total requests per IP.

<img width="1896" height="985" alt="image" src="https://github.com/user-attachments/assets/17ed982d-aa1a-4702-b2e9-d51fed35e34c" />


### 🤔 Why

Scanners generate unusually high traffic.

---

## 🔍 Step 5: Detect Multiple Endpoint Access

```spl id="x7z1l5"
index=practicelog sourcetype=web_logs
| rex "^(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "\"GET (?<uri>\S+)"
| stats dc(uri) as unique_paths values(uri) as paths by src_ip
| sort -unique_paths
```

### ✅ What

Count distinct URIs accessed.

### 🤔 Why

Scanning = trying many different endpoints.

---
<img width="1884" height="958" alt="image" src="https://github.com/user-attachments/assets/39ca5d1a-2abd-4316-8347-c783cb9223f9" />


## 🔍 Step 6: Detect Sensitive Path Probing

```spl id="k2p8w9"
index=practicelog sourcetype=web_logs
| rex "^(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "\"GET (?<uri>\S+)"
| search uri IN ("/admin","/login","/phpmyadmin","/etc/passwd")
| stats count by src_ip uri
```

### 🤔 Why

Attackers specifically probe known vulnerable paths.

---

<img width="1911" height="719" alt="image" src="https://github.com/user-attachments/assets/8cb22a79-8423-4aac-838c-9b658647aa67" />


## 🔍 Step 7: High 404 Error Detection

```spl id="u9d3f6"
index=practicelog sourcetype=web_logs
| rex "^(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "\" (?<status>\d{3})"
| search status=404
| stats count as error_count by src_ip
| sort -error_count
```

### 🤔 Why

Scanning often results in many “Not Found” errors.

---

## 🔍 Step 8: Error Ratio Analysis 

```spl id="p3e7j2"
index=practicelog sourcetype=web_logs
| rex "^(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "\" (?<status>\d{3})"
| stats count as total count(eval(status=404)) as errors by src_ip
| eval error_ratio = errors/total
| where error_ratio > 0.4
```

### ✅ What

Calculate % of failed requests.

<img width="1899" height="591" alt="image" src="https://github.com/user-attachments/assets/888b5d16-3c42-49bb-ac1a-3fd112053b95" />


### 🤔 Why

Legitimate users → low error rate
Attackers → very high error rate

---

## 🔍 Step 9: Time-Based Burst Detection

```spl id="c6m4r8"
index=practicelog sourcetype=web_logs
| rex "^(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| bucket _time span=1m
| stats count by _time src_ip
| where count > 30
```

### 🤔 Why

Scanning tools send rapid bursts of requests.

---

## 🔍 Step 10: Session Analysis (Transaction)

```spl id="j5t9k1"
index=practicelog sourcetype=web_logs
| rex "^(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| transaction src_ip maxspan=2m
```

### 🤔 Why

Group events into attacker sessions.

---
<img width="1915" height="922" alt="image" src="https://github.com/user-attachments/assets/32d4fae2-98ab-4cc2-8ed5-5845983eeb68" />

## 🔍 Step 11: High Activity Sessions

```spl id="g2h8v6"
index=practicelog sourcetype=web_logs
| rex "^(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| transaction src_ip maxspan=2m
| search eventcount > 20
```

### 🤔 Why

High number of requests in short session = automated scan.

---

## 🔍 Step 12: Rare Endpoint Detection

```spl id="z1n6b4"
index=practicelog sourcetype=web_logs
| rex "\"GET (?<uri>\S+)"
| rare uri
```

### 🤔 Why

Attackers often access unusual endpoints.

---
<img width="1903" height="857" alt="image" src="https://github.com/user-attachments/assets/815657a2-c902-4781-afaa-ad76babb7257" />


## 🔍 Step 13: Sequence Pattern Analysis

```spl id="h8y3s7"
index=practicelog sourcetype=web_logs
| rex "^(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "\"GET (?<uri>\S+)"
| stats list(uri) as sequence by src_ip
```

### 🤔 Why

Shows attacker path traversal pattern.

---

## 🔍 Step 14: Final Correlation Query 

```spl id="q4w8x2"
index=practicelog sourcetype=web_logs
| rex "^(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "\"GET (?<uri>\S+)"
| rex "\" (?<status>\d{3})"
| stats 
    count as total_requests
    dc(uri) as unique_paths
    count(eval(status=404)) as errors
    values(uri) as scanned_paths
by src_ip
| eval error_ratio = errors/total_requests
| where total_requests > 50 OR unique_paths > 10 OR error_ratio > 0.5
```

<img width="1896" height="1009" alt="image" src="https://github.com/user-attachments/assets/82a160b4-58a5-4e13-ab74-e76e388242c1" />


---

# 📊 Findings

* IP accessing large number of endpoints
* High number of 404 errors
* Rapid request bursts
* Pattern of probing sensitive paths

---

# 🧠 Correlation Insight
Single signals are weak.

But:

* High request volume

- High unique endpoints
- High error ratio
- Burst activity

👉 = **Confirmed Web Scanning Activity**

---

# ⚠️ Risk Level

⚠️ Medium → High (Recon stage before exploitation)

---

# 🛡️ Recommendations

* Block suspicious IP
* Implement WAF (Web Application Firewall)
* Rate-limit requests
* Monitor sensitive endpoints
* Enable alerting on scanning patterns

---

# 🧭 MITRE ATT&CK Mapping

* T1046 → Network Service Scanning
* T1595 → Active Scanning

---

# 🧠 Analyst Mindset

Beginner:
❌ “Many requests observed”

Advanced:
✔ “This IP systematically probed multiple endpoints with high failure rate → reconnaissance activity before exploitation”

---

## Author:
Varrun Vashisht
