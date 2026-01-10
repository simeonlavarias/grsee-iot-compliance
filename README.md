# GRSee – IoT-Based Compliance Monitoring for Physical Security

GRSee (Governance, Risk, and Security Events) is a **small-scale IoT-based compliance monitoring system** designed to bridge the gap between **physical security events** and **GRC (Governance, Risk, and Compliance) frameworks** in financial institutions.

The system demonstrates how physical security data—such as access control events, motion detection, and environmental monitoring—can be **automatically mapped to compliance standards** like **ISO/IEC 27001** and **PCI DSS** in real time.

This project is developed as a **Final Year Honours Project** for the BSc (Hons) Software Engineering programme at the University of Stirling.

---

## 📌 Project Objectives

* Monitor physical security events using IoT sensors
* Securely transmit sensor data to a central system
* Map detected events to internal security policies
* Align events with ISO 27001 and PCI DSS controls
* Provide a dashboard for real-time monitoring and audit support
* Demonstrate feasibility of low-cost, compliance-aware IoT systems

---

## 🏗️ System Architecture Overview

GRSee follows a modular architecture consisting of:

* **IoT Layer** – Sensors (RFID, motion, temperature, CCTV)
* **Edge Layer** – Raspberry Pi acting as a data gateway
* **Middleware Layer** – Event processing and rules engine
* **Application Layer** – Flask-based dashboard and APIs
* **Compliance Layer** – Rule-based mapping to ISO 27001 and PCI DSS

---

## 🛠️ Technology Stack

* **Programming Language:** Python
* **Web Framework:** Flask
* **Messaging Protocol:** MQTT (planned)
* **Database:** SQLite (prototype)
* **Frontend:** HTML, CSS, Jinja2
* **IoT Platform:** Raspberry Pi (planned)
* **Version Control:** Git & GitHub

---

## 🔬 Evaluation Criteria

The system will be evaluated based on:

* **Event detection accuracy ≥ 90%**
* **Data loss ≤ 1%**
* **System Usability Scale (SUS) ≥ 70**
* **Correct mapping to ISO 27001 and PCI DSS controls**
* **Audit-readiness through simulated audit scenarios**

---

## 🚧 Project Status

This repository currently contains the **software components** of the system.
Hardware integration and live sensor testing will be implemented in later stages.

---

## 👤 Author

**Simeon Carlos Cruz Lavarias**
BSc (Hons) Software Engineering
University of Stirling (UAE)

---

## 📜 Disclaimer

This project is a **prototype and proof of concept** developed for academic purposes.
It is not intended for direct deployment in production financial environments.
