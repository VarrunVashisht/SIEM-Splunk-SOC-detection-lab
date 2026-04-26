## 📤 Use Case 3: Data Exfiltration Detection (Web Logs)

---

## 🎯 Objective

Detect suspicious large data transfers from web logs that may indicate **data exfiltration by an attacker**.

---

## 📂 Data Source

* Index: `practicelog`
* Sourcetype: `web_logs`

### Log Format Example

```
192.168.1.37 - - [20/Apr/2026:00:00:00] "GET /home HTTP/1.1" 200 1503
```

---

## 🧠 Investigation Strategy

We are looking for:

* High data transfer volume 📈
* Same IP downloading large files 📦
* Sudden spikes in traffic ⏱️
* Repeated downloads from same endpoint 🔁

---

# 🔍 STEP-BY-STEP INVESTIGATION

---

## 🔍 Step 1: View Raw Logs

```spl
index=practicelog sourcetype=web_logs
```

### ✅ What

Load raw events.

### 🤔 Why

Understand log structure before parsing.

---

## 🔍 Step 2: Extract Fields (CRITICAL STEP)

```spl
index=practicelog sourcetype=web_logs
| rex "^(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "\"GET (?<uri>\S+)"
| rex "\" (?<status>\d{3}) (?<bytes>\d+)"
```

### ✅ What

Extract:

* src_ip
* uri (endpoint accessed)
* status (HTTP code)
* bytes (data size)

### 🤔 Why

Logs are unstructured → we must create fields for analysis.

---

## 🔍 Step 3: Validate Extraction

```spl
index=practicelog sourcetype=web_logs
| rex "^(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "\"GET (?<uri>\S+)"
| rex "\" (?<status>\d{3}) (?<bytes>\d+)"
| table _time src_ip uri status bytes
```

### Why

Ensure parsing is correct before analysis.

---
<img width="1888" height="878" alt="image" src="https://github.com/user-attachments/assets/e5e2a3eb-162f-4fa4-bc33-0f9074dfda4e" />


## 🔍 Step 4: Total Data Transfer per IP

```spl
index=practicelog sourcetype=web_logs
| rex "^(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "\" (?<status>\d{3}) (?<bytes>\d+)"
| stats sum(bytes) as total_bytes by src_ip
| sort -total_bytes
```


### ✅ What

Calculate total data downloaded per IP.

### 🤔 Why

Exfiltration = unusually high data transfer.

---
<img width="1885" height="696" alt="image" src="https://github.com/user-attachments/assets/19a92b94-2dd8-4bd3-b0f7-fd92bff51b18" />

## 🔍 Step 5: Detect Abnormal Threshold

```spl
index=practicelog sourcetype=web_logs
| rex "^(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "\" (?<status>\d{3}) (?<bytes>\d+)"
| stats sum(bytes) as total_bytes by src_ip
| where total_bytes > 10000000
```

### Why

Normal users don’t download massive data in short time.

---

## 🔍 Step 6: Large Individual Transfers

```spl
index=practicelog sourcetype=web_logs
| rex "^(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "\" (?<status>\d{3}) (?<bytes>\d+)"
| where bytes > 1000000
```

### Why

Large file downloads may indicate data theft.

---
<img width="1865" height="947" alt="image" src="https://github.com/user-attachments/assets/87ec6c57-0a50-4ecf-bf30-637a2e59aa6a" />


## 🔍 Step 7: Identify Targeted Files

```spl
index=practicelog sourcetype=web_logs
| rex "^(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "\"GET (?<uri>\S+)"
| stats count by src_ip uri
| sort -count
```

### Why

Repeated access to same file = potential extraction.

---

<img width="1891" height="758" alt="image" src="https://github.com/user-attachments/assets/10f2ba13-f73d-45ed-abba-7af148956f09" />


## 🔍 Step 8: Time-Based Traffic Analysis

```spl
index=practicelog sourcetype=web_logs
| rex "^(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "\" (?<bytes>\d+)"
| timechart sum(bytes) by src_ip
```

### Why

Detect spikes in traffic over time.

---
<img width="1883" height="969" alt="image" src="https://github.com/user-attachments/assets/5382a079-42d3-4f00-bc95-fd4aa268980c" />


## 🔍 Step 9: Spike Detection
```spl
index=practicelog sourcetype=web_logs
| rex "^(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "\" (?<bytes>\d+)"
| bucket _time span=1m
| stats sum(bytes) by _time src_ip
| where sum(bytes) > 2000000
```

### Why

Exfiltration often happens in short bursts, like 1 min.

---

## 🔍 Step 10: Session-Based Analysis

```spl
index=practicelog sourcetype=web_logs
| rex "^(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| transaction src_ip maxspan=2m
```

### Why

Group activity into sessions → mimic attacker behavior.

---
<img width="1900" height="859" alt="image" src="https://github.com/user-attachments/assets/495d55e0-84a9-4639-92e0-ee16c4eadd92" />


## 🔍 Step 11: High Activity Sessions

```spl
index=practicelog sourcetype=web_logs
| rex "^(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| transaction src_ip maxspan=2m
| search eventcount > 8
```

### Why

High request count in short time = automation/script.
Like, total 9 events in only 2 minutes.

---

<img width="1861" height="903" alt="image" src="https://github.com/user-attachments/assets/6623970a-cb2a-43bb-83b7-82471b304fa3" />

## 🔍 Step 12: Rare Endpoint Detection

```spl
index=practicelog sourcetype=web_logs
| rex "\"GET (?<uri>\S+)"
| rare uri
```

### Why

Attackers often access uncommon endpoints.

---
<img width="1912" height="862" alt="image" src="https://github.com/user-attachments/assets/efa692fc-263f-4524-8c15-64d65459c33d" />


## 🔍 Step 13: Combine Indicators (CORRELATION STEP)

```spl
index=practicelog sourcetype=web_logs
| rex "^(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "\"GET (?<uri>\S+)"
| rex "\" (?<status>\d{3}) (?<bytes>\d+)"
| stats sum(bytes) as total_bytes count as request_count values(uri) as accessed_files by src_ip
| where total_bytes > 10000000 OR request_count > 50
```

### ✅ What

Combine multiple indicators:

* Data volume
* Request count
* Accessed files

### 🤔 Why

Real SOC detection = multiple signals combined.

---
<img width="1868" height="970" alt="image" src="https://github.com/user-attachments/assets/0385a56d-8d85-413d-a311-23b750aa348f" />


# 📊 Findings

* Identified IP with unusually high data transfer
* Multiple large file downloads
* Burst activity within short time

---

# 🧠 Correlation Insight 
Single signal is weak.

But:

* High bytes transferred

- High request count
- Repeated file access
- Short time window

👉 = **Confirmed Data Exfiltration Behavior**

---

# ⚠️ Risk Level

🚨 **Critical**

Sensitive data may be compromised.

---

# 🛡️ Recommendations

* Block suspicious IP
* Monitor outbound traffic
* Implement Data Loss Prevention (DLP)
* Restrict large downloads
* Enable logging for sensitive endpoints

---

# 🧭 MITRE ATT&CK Mapping

* T1041 → Exfiltration Over C2 Channel
* T1020 → Automated Exfiltration

---

# 🧠 Analyst Mindset

Beginner:
❌ “Large traffic seen”

Advanced:
✔ “This IP performed structured high-volume downloads in bursts → indicative of automated exfiltration”

👉 That’s real SOC thinking

---

## Author:
Varrun Vashisht
