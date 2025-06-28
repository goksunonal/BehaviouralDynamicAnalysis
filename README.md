# Behavioural Dynamic Analysis (BDA)

> **Log-driven sandbox automation + feature engineering + machine-learning models**  
> for dynamic malware behaviour detection on Windows.

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)](#)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](#)
[![Build](https://img.shields.io/badge/Status-Alpha-lightgrey)](#)

---

## ✨ Key Features
| Module | What it does | Folder |
|--------|--------------|--------|
| **Sandbox Manager** | Spins up / reverts a *clean* VM snapshot, runs the sample, collects Windows Event Logs, and ships them back. | `sandboxManager/` |
| **Feature & Model Creator** | Parses raw logs → extracts statistical, contextual & temporal features → trains / evaluates ML models (RF, XGBoost, MLP, …). | `featureAndModelCreator/` |
| **Example Logs** | A small zip of sample benign & malware logs for quick tests. | `ExampleLogsCollectedFromSandbox.zip` |

---

## 🗂 Project Structure
