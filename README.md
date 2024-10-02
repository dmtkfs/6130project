# **Containerized IDS Application**

This repository contains a **Containerized Intrusion Detection System (IDS)** designed to monitor and defend against attacks within a container environment. The application is packaged and deployed using Docker, with a focus on logging suspicious activities inside the container.

---

## **Key Components**

### **1. Current Capabilities of the IDS Application**:
- **Process Monitoring**:
    - The IDS monitors **system processes** running inside the container.
    - It detects and logs the execution of **sensitive binaries** (e.g., `/bin/bash`, `/bin/sh`, `/usr/bin/python3`, `/bin/sleep`).
    - The IDS also monitors for **privilege escalation**, logging any instances where a user switches to `root` or runs commands with elevated privileges.

- **File System Monitoring**:
    - The IDS tracks file changes in critical directories such as `/etc`, `/var`, `/home`, and `/tmp`.
    - It logs **file creation, modification, and deletion** events, focusing on important system files like `/etc/passwd` and `/etc/shadow`.

- **SSH Login Monitoring**:
    - The IDS logs both **successful** and **failed SSH login attempts**.
    - The logging includes details about the user who logged in and the source IP address of the login attempt.

- **Logging Events**:
    - All events, including process creation, file system changes, and SSH login attempts, are logged to a central log file inside the container (`/var/log/ids_app/ids.log`).

---

### **2. Container Deployment**:
The IDS is deployed using a **Dockerized environment** and managed through Docker Compose for ease of orchestration. Below are the key components involved in the deployment:

#### **Dockerfile**:
- The Dockerfile is used to create the base image for the IDS container. It is based on **Alpine Linux**, a lightweight and secure Linux distribution.
- Key setup steps include installing **Python**, **Supervisor**, and **OpenSSH**, along with setting up the necessary dependencies for the IDS application.

#### **docker-compose.yml**:
- This file defines the Docker services and their configurations.
- It is used to manage the container lifecycle, defining how the container is built and run.
- The Compose setup allows easy scaling and redeployment of the IDS by automating the creation and management of the container.

#### **supervisord.conf**:
- **Supervisord** is responsible for managing the **IDS application** and **SSHD** (SSH daemon).
- This configuration file tells Supervisor to run and monitor both the IDS app and SSHD services, ensuring they restart if they crash.
- Supervisor is essential in keeping the IDS application running at all times and managing multiple processes within the container.

#### **entrypoint.sh**:
- This is the **entry point script** for the container, responsible for launching Supervisor when the container starts.
- It ensures that both SSH access and the IDS application are started and managed by Supervisor, making the container ready for use immediately after deployment.

#### **deploy.sh**:
- This script automates the deployment process by:
    - Checking if a container is already running, stopping and removing it if necessary.
    - Building a new Docker image based on the Dockerfile.
    - Running the new container with the appropriate configurations.
    - The **deploy.sh** script simplifies the redeployment process and helps in maintaining consistency across different environments.

---

### **3. Development Workflow**:

#### **Git and GitHub for Version Control**:
- The project uses **Git** for version control and **GitHub** for collaboration.
- Development is primarily done on the Azure server, and changes are synced with the remote GitHub repository for backup and collaboration.
- The `.env` file is used to manage sensitive information like configuration variables, which are not included in version control.

#### **Docker Management**:
- The container is built and managed using **Docker Compose** and deployed with the help of the **deploy.sh** script.
- **Environment variables** are passed into the container during runtime via the `.env` file, keeping sensitive data like credentials secure.

#### **Logging and Event Tracking**:
- The IDS application logs key events such as:
    - Process creation and execution of sensitive binaries.
    - File system changes (creation, modification, and deletion of files).
    - SSH login attempts (both successful and failed).
- Logs are stored inside the container at `/var/log/ids_app/ids.log`, and can be accessed using standard log reading commands (e.g., `docker exec -it sec_app_container tail -f /var/log/ids_app/ids.log`).
  
---

### **4. Future Plans**:

The next steps for the project include transitioning from an IDS to an IPS (Intrusion Prevention System) by actively defending against attacks:

1. **Active Prevention (IPS)**:
    - Implementing prevention mechanisms such as terminating unauthorized processes or actions detected by the IDS.
    - For example, blocking file modifications or killing processes that are deemed suspicious.

2. **SSH Brute-Force Defense**:
    - Implementing a **jail system** to ban IP addresses that fail SSH login attempts multiple times (with a threshold of 3 attempts).
    - Administrators will be able to view and manage banned IPs through this system.

3. **Remote Log Storage**:
    - The IDS logs will be stored remotely on the **Azure host**, preventing attackers from tampering with or deleting logs stored inside the container.

4. **Continual Monitoring**:
    - The IDS will continue to run as a **background service**, ensuring consistent logging and monitoring of events without manual intervention.

---

### **Conclusion**:

This document outlines the current state of the IDS, the deployment process, and future development plans. The IDS is currently capable of logging key events and monitoring system activity inside the container, while future enhancements aim to add active prevention capabilities and more robust security measures.
