Here’s the updated README file in Markdown format:

---

# Containerized IDS Application

This project involves building a containerized Intrusion Detection System (IDS) using Docker and Docker Compose. The IDS monitors system activities, detects suspicious behaviors such as SSH login attempts and sensitive file accesses, and provides logging and email alerts.

## Key Components

### 1. **Containerized IDS Application**
- The IDS runs within a container based on an Alpine Linux image.
- **Current functionalities of the IDS include:**
  - Monitoring system processes to detect suspicious root processes or privilege escalation.
  - Detecting potential container escape attempts (e.g., `nsenter` usage or `/proc/1/ns/` access) – note that this feature has limitations in the current environment.
  - Logging file system changes on critical paths such as `/etc/passwd` and `/etc/shadow`.
  - Monitoring SSH login attempts, capturing both successful and failed logins.
  - Sending email notifications to the group email address: `inse6130groupmail@gmail.com`.
  
- **Why Containerized:** Containerizing the IDS isolates it from the host system, enhancing security and portability. The use of containers simplifies deployment and ensures that the IDS can run in any environment.

---

### 2. **Docker Compose Setup**
- The Docker Compose setup manages the lifecycle of the Docker container, ensuring that it can be started, stopped, and recreated easily.
- The `.env` file allows configuration to be managed outside of the code, especially for sensitive information like SMTP credentials.

- **Why Docker Compose:** It automates the process of building and running containers, making it easy to define, manage, and orchestrate containers in a reproducible way. This is critical in a project with multiple configurations and services.

---

### 3. **Environment Variables & Security**
- Sensitive information (like email credentials for alerts) is stored in the `.env` file, which is not included in version control.
- Environment variables are loaded into the container during runtime, providing secure and flexible configurations.

- **Why Use Environment Variables:** Storing credentials and configuration outside of the code improves security by keeping sensitive information out of version control and allows configuration to be changed without modifying the codebase.

---

### 4. **GitHub for Version Control**
- The project is version-controlled using Git and GitHub. A local Git repository on the Azure cloud server is connected to a remote GitHub repository for development.
- The repository allows for team collaboration, with all changes tracked, and supports a secure development workflow.

- **Why GitHub:** Provides version control and a backup of the project. Allows the team to work outside the server when necessary.

---

### 5. **Development Workflow**
- **Git Management:**
  - Local changes are made, tested, and committed on the Azure cloud server.
  - The repository is then synced with the remote GitHub repository for backup and collaboration.
  - Team members can clone the repository and contribute to the project.
  
- **Docker Management:**
  - The container is managed via Docker Compose, using the `deploy.sh` script for automation. This script checks for existing containers, stops and removes them if necessary, then builds and runs a new container.
  - Environment variables are loaded into the container to avoid hardcoding sensitive data.

---
 
### 6. **Future Development**

  - Active Prevention (IDS to IPS): The next step is to implement a prevention mechanism for one type of attack, transitioning from an Intrusion Detection System (IDS) to an Intrusion Prevention System (IPS). For example, upon detecting an illegal file creation, the system will take an active response such as applying a countermeasure to the user performing the action.

  - SSH IP Banning and "Jail": Implement an automated system to ban IP addresses after multiple failed SSH attempts. The "jail" system will allow us to manage banned IPs, where we can view, unban, or manually add IPs as needed.

  - User Logging (if feasible): We will explore the feasibility of logging user actions within the container. While it's uncertain whether detailed user logging is possible, if achievable, it will be implemented for better auditing.

