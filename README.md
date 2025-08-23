# Project Sentinel: Automated Cyber Defense with Kali Purple

![Status](https://img.shields.io/badge/status-in%20progress-yellow)
![Platform](https://img.shields.io/badge/platform-Kali%20Purple-blueviolet)

This repository contains the configuration files, scripts, and documentation for **Project Sentinel**. [cite_start]The project is a proof-of-concept demonstrating a compact, automated cyber defense environment built on Kali Purple[cite: 2, 5]. [cite_start]It showcases how an integrated security platform can be used to build, test, and validate defensive measures against common cyber attacks[cite: 6].

---

## 🚧 Current Status

**This project is actively in progress.** This repository serves as a living document and a working space. New configuration files, scripts, and documentation will be added to their respective directories as each stage of the project is completed.

---

## 🎯 Project Objectives

[cite_start]The primary goal is to create a streamlined defensive environment that can automatically detect and respond to threats, providing clear, data-driven insights through dashboards and reporting[cite: 6, 11].

* [cite_start]**Platform Deployment & Configuration:** Install and configure Kali Purple's core defensive modules, including its iptables firewall, Suricata IDS/IPS, and OSSEC agents[cite: 8].
* [cite_start]**Attack Simulation:** Develop and execute concise attack scripts, such as network port scans and web application exploits, to generate distinct security alerts[cite: 9].
* [cite_start]**Detection & Response Automation:** Tune detection rules and SOAR playbooks to enable automated containment actions without manual intervention[cite: 10].
* [cite_start]**Visualization & Reporting:** Use built-in dashboards to capture real-time alerts and generate key performance metrics like Mean Time To Detect (MTTD) and Mean Time To Respond (MTTR)[cite: 11].

---

## 🛠️ Technology Stack & Tools

This project utilizes a suite of open-source tools integrated within the Kali Purple ecosystem.

| Tool              | Category               | Purpose                                                                          |
| ----------------- | ---------------------- | -------------------------------------------------------------------------------- |
| **Kali Purple** | Security Distribution  | [cite_start]The core all-in-one platform for defensive security operations[cite: 5].            |
| **`iptables`** | Firewall               | [cite_start]Filters network traffic based on a security policy to block unauthorized access[cite: 8].  |
| **`Suricata`** | IDS / IPS              | [cite_start]Inspects network traffic to detect malicious patterns and known threats[cite: 8].       |
| **`Wazuh (OSSEC)`** | SIEM / HIDS            | [cite_start]Collects, analyzes, and correlates security data from monitored endpoints[cite: 8]. |
| **`TheHive`** | SOAR Platform          | [cite_start]Orchestrates incident response by managing alerts and automating playbooks[cite: 8, 10].     |
| **`nmap` / `curl`** | Attack Simulation      | [cite_start]Tools used to generate test traffic to validate defenses[cite: 9]. |

---

## 🔬 Lab Architecture

[cite_start]The project is built within a minimal virtual lab environment designed for safe and effective testing[cite: 13].

* **Defender VM:** A virtual machine running **Kali Purple**, hosting all the defensive tools (`iptables`, `Suricata`, `Wazuh`).
* **Attacker VM:** A standard **Kali Linux** VM on the same internal network, used to launch the attack simulations.

```
+------------------+                +-----------------------+
|  Attacker VM     |                |   Defender VM         |
|  (Kali Linux)    <-- Internal -- > |   (Kali Purple)       |
|                  |    Network     |                       |
| - nmap           |                | - iptables (Firewall) |
| - curl           |                | - Suricata (IDS)      |
|                  |                | - Wazuh (SIEM)        |
+------------------+                +-----------------------+
```

---

## 📂 Repository Structure

This repository is organized to hold all the artifacts created during the project.

```
/
├── firewall-configs/       # Contains iptables rules and configuration scripts
├── suricata-configs/       # Holds custom Suricata rules and setup notes
├── attack-scripts/         # Scripts for simulating attacks (nmap, curl, etc.)
└── reports/                # Final reports, metrics, and dashboard screenshots
```
