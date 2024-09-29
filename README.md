Key Components:

1. Containerized IDS Application:
    - The IDS is containerized in an Alpine-based Docker image.
    - Key functionalities of the IDS so far include:
        * Monitoring system processes.
        * Detecting container escapes (problematic for now).
        * Logging file system changes.
        * Monitoring SSH login attempts.
        * Sending e-mail notifications to our group e-mail (inse6130groupmail@gmail.com)
    - Why Containerized (besides being required): Containerization isolates the IDS application from the host system, providing a secure and portable environment. Docker Compose simplifies the deployment and configuration of containers, allowing for a more manageable and scalable solution.
3. Docker Compose Setup:
    - The Docker Compose setup manages the lifecycle of the Docker container, ensuring that it can be started, stopped, and recreated easily.
    - The .env file allows configuration to be managed outside of the code, especially for sensitive information like SMTP credentials.
    - Why Docker Compose: It automates the process of building and running containers, making it easy to define, manage, and orchestrate containers in a reproducible way. This is critical in a project with multiple configurations and services.
4. Environment Variables & Security:
    - Sensitive information (like email credentials for alerts) is stored in the .env file, which is not included in version control.
    - Environment variables are loaded into the container during runtime, providing secure and flexible configurations.
    - Why Use Environment Variables: Storing credentials and configuration outside of code improves security by keeping sensitive information out of version control and allows configuration to be changed without modifying the codebase.
5. GitHub for Version Control:
    - The project is version-controlled using Git and GitHub. A local Git repository on the Azure cloud server is connected to a remote GitHub repository for development.
    - The repository allows (obviously) for team collaboration, with all changes tracked, and supports a secure development workflow.
    - Why GitHub: Provides version control and a backup of the project. Can also work outside the server now.
6. Development Workflow:
    - Git Management:
        * Local changes are made, tested, and committed in the Azure cloud server.
        * The repository is then synced with the remote GitHub repository for backup and collaboration.
        * Team members can clone the repository and contribute to the project.
    - Docker Management:
        * The container is managed via Docker Compose, using the deploy.sh script for automation. It checks for existing containers, stops and removes them if necessary, then builds and runs a new container.
        * Environment variables are loaded into the container to avoid hardcoding sensitive data.
    - Testing and Deployment:
        * The IDS logs and alerts on critical events such as process creations, file modifications, and SSH login attempts.
        * Future development includes testing attack scenarios for container escapes to verify that the IDS properly detects and logs such events. Will also add user logging. Will also make the app running in the background permanently.
        * More to come!