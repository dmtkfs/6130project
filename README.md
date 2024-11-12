Containerized IDS Application

This repository contains a Containerized Intrusion Detection System (IDS) designed to monitor, detect, and log suspicious activities within a container environment. The application is packaged and deployed using Docker, with security features focusing on logging, resource constraints, and protection against potential attacks.
Key Components
1. IDS Application Capabilities

    Process Monitoring:
        Monitors processes running inside the container, detecting and logging sensitive binaries (e.g., /bin/bash, /bin/sh, /usr/bin/python3, /bin/sleep).
        Tracks privilege escalation attempts, logging any suspicious instances of root access or elevated command executions.

    File System Monitoring:
        Monitors changes in critical directories (e.g., /etc, /var, /home, and /tmp) for file creation, modification, and deletion.
        Logs activities related to key system files, such as /etc/passwd and /etc/shadow, providing insight into any tampering attempts.

    SSH Login Monitoring with Brute-Force Protection:
        Logs both successful and failed SSH login attempts, capturing user and source IP details.
        Implements an IP-based blacklisting mechanism, blocking IPs after a threshold of failed login attempts to mitigate brute-force attacks.

    Centralized Logging:
        All events, including process monitoring, file changes, and SSH attempts, are consolidated in a single log file inside the container (/var/log/ids_app/ids.log), enabling centralized and accessible logging.

2. Container Deployment and Management

The IDS is deployed within a secure Docker container and managed through Docker Compose for streamlined orchestration. Key components of the deployment setup include:

    Dockerfile:
        Creates a lightweight container image based on Alpine Linux, installing necessary dependencies such as Python, Supervisor, and OpenSSH.
        Configures the user environment, permissions, and log directory setup for the IDS application.

    docker-compose.yml:
        Defines container configurations, such as CPU and memory limits, port mappings, capabilities, and environment variables.
        Ensures container resource usage is restricted (e.g., limited to 0.5 CPUs and 512MB RAM) to prevent resource exhaustion on the host.

    supervisord.conf:
        Supervisor manages the IDS application and sshd, ensuring both services run continuously and restart automatically if they crash.
        Consolidates logging for Supervisor activities in /var/log/ids_app, contributing to overall monitoring and stability.

    entrypoint.sh:
        Entry point script responsible for setting up and starting Supervisor, applying ICMP rate-limiting rules, and preparing log files with appropriate permissions.
        Configures iptables to limit ICMP (ping) requests, reducing susceptibility to ICMP flood attacks.

    deploy.sh:
        Automates container deployment, handling container build, stop, and restart tasks.
        Simplifies redeployment by ensuring consistent environment setup with each new deployment.

3. Security Features

This deployment emphasizes security through both configuration and the IDS application’s monitoring functions. Here’s a summary of the defenses in place:

    Configuration-Based Security:
        Selective Capabilities: Only NET_ADMIN capability is granted, minimizing exposure to potentially risky privileges.
        Resource Limits: CPU and memory constraints (0.5 CPUs and 512MB RAM) protect against resource-based denial-of-service (DoS) risks.
        Filesystem Permissions: Central log directory (/var/log/ids_app) is accessible only to ids_user, preventing unauthorized log tampering.
        ICMP Rate Limiting: iptables rules limit ICMP requests to one per second with a burst limit of five, reducing the likelihood of network-based DoS attacks.
        SSH Access Control: SSH access is restricted to ids_user with root login disabled, reducing attack surface.

    IDS Application Security Capabilities:
        Process Monitoring: Tracks unauthorized binaries and privilege escalation attempts, logging suspicious root-level access.
        File System Monitoring: Monitors and logs changes to critical files, alerting administrators to potential tampering.
        SSH Brute-Force Defense: IP blacklisting implemented for SSH, blocking repeated failed login attempts to prevent brute-force access.
        Centralized Logging: Consolidates logs in /var/log/ids_app/ids.log for consistent and streamlined incident tracking.

4. Development Workflow

    Git and GitHub for Version Control:
        Git is used for local version control, and GitHub is used for collaborative work and backup.
        Sensitive configuration variables are managed through an .env file, which is excluded from version control to protect credentials.

    Docker Management:
        Docker Compose is used for container orchestration, and deployment is automated with deploy.sh, enabling efficient deployment and maintenance.
        Environment variables from the .env file are injected during container runtime, keeping credentials secure.
