# Behavioural Dynamic Analysis (BDA)

> **Log-driven sandbox automation + feature engineering + machine-learning models**  
> for dynamic malware behaviour detection on Windows.
>
> ## 📜 License
Distributed under the MIT License. See `LICENSE` for details.

## ✨ Key Features
| Module | What it does | Folder |
|--------|--------------|--------|
| **Sandbox Manager** | Spins up / reverts a *clean* VM snapshot, runs the sample, collects Windows Event Logs, and ships them back. | `sandboxManager/` |
| **Feature & Model Creator** | Parses raw logs → extracts statistical, contextual & temporal features → trains / evaluates ML models (RF, XGBoost, MLP, …). | `featureAndModelCreator/` |
| **Example Logs** | A small zip of sample benign & malware logs for quick tests. | `ExampleLogsCollectedFromSandbox.zip` |

---

## 🗂 Project Structure
