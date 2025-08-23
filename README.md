# Project Sentinel: Automated Cyber Defense with Kali Purple

![Status](https://img.shields.io/badge/status-in%20progress-yellow)
![Platform](https://img.shields.io/badge/platform-Kali%20Purple-blueviolet)

This repository contains the configuration files, scripts, and documentation for **Project Sentinel**. The project is a proof-of-concept demonstrating a compact, automated cyber defense environment built on Kali Purple. It showcases how an integrated security platform can be used to build, test, and validate defensive measures against common cyber attacks.

---

## 🚧 Current Status

**This project is actively in progress.** This repository serves as a living document and a working space. New configuration files, scripts, and documentation will be added to their respective directories as each stage of the project is completed.

---

## 🎯 Project Objectives

The primary goal is to create a streamlined defensive environment that can automatically detect and respond to threats, providing clear, data-driven insights through dashboards and reporting.

* **Platform Deployment & Configuration:** Install and configure Kali Purple's core defensive modules, including its iptables firewall, Suricata IDS/IPS, and OSSEC agents.
* **Attack Simulation:** Develop and execute concise attack scripts, such as network port scans and web application exploits, to generate distinct security alerts.
* **Detection & Response Automation:** Tune detection rules and SOAR playbooks to enable automated containment actions without manual intervention.
* **Visualization & Reporting:** Use built-in dashboards to capture real-time alerts and generate key performance metrics like Mean Time To Detect (MTTD) and Mean Time To Respond (MTTR).

---

## 🛠️ Technology Stack & Tools

This project utilizes a suite of open-source tools integrated within the Kali Purple ecosystem.

| Tool              | Category               | Purpose                                                                          |
| ----------------- | ---------------------- | -------------------------------------------------------------------------------- |
| **Kali Purple** | Security Distribution  | The core all-in-one platform for defensive security operations.            |
| **`iptables`** | Firewall               | Filters network traffic based on a security policy to block unauthorized access.  |
| **`Suricata`** | IDS / IPS              | Inspects network traffic to detect malicious patterns and known threats.       |
| **`Wazuh (OSSEC)`** | SIEM / HIDS            | Collects, analyzes, and correlates security data from monitored endpoints. |
| **`TheHive`** | SOAR Platform          | Orchestrates incident response by managing alerts and automating playbooks.     |
| **`nmap` / `curl`** | Attack Simulation      | Tools used to generate test traffic to validate defenses. |

---

## 🔬 Lab Architecture

The project is built within a minimal virtual lab environment designed for safe and effective testing.

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
