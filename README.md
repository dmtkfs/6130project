Key Components:

1. Containerized IDS Application:
    a. The IDS is containerized in an Alpine-based Docker image.
    b. Key functionalities of the IDS so far include:
        i. Monitoring system processes.
        ii. Detecting container escapes (problematic for now).
        iii. Logging file system changes.
        iv. Monitoring SSH login attempts.
        v. Sending e-mail notifications to our group e-mail (inse6130groupmail@gmail.com)
    c. Why Containerized (besides being required): Containerization isolates the IDS application from the host system, providing a secure and portable environment. Docker Compose simplifies the deployment and configuration of containers, allowing for a more manageable and scalable solution.
3. Docker Compose Setup:
    a. The Docker Compose setup manages the lifecycle of the Docker container, ensuring that it can be started, stopped, and recreated easily.
    b. The .env file allows configuration to be managed outside of the code, especially for sensitive information like SMTP credentials.
    c. Why Docker Compose: It automates the process of building and running containers, making it easy to define, manage, and orchestrate containers in a reproducible way. This is critical in a project with multiple configurations and services.
4. Environment Variables & Security:
    a. Sensitive information (like email credentials for alerts) is stored in the .env file, which is not included in version control.
    b. Environment variables are loaded into the container during runtime, providing secure and flexible configurations.
    c. Why Use Environment Variables: Storing credentials and configuration outside of code improves security by keeping sensitive information out of version control and allows configuration to be changed without modifying the codebase.
5. GitHub for Version Control:
    a. The project is version-controlled using Git and GitHub. A local Git repository on the Azure cloud server is connected to a remote GitHub repository for development.
    b. The repository allows (obviously) for team collaboration, with all changes tracked, and supports a secure development workflow.
    c. Why GitHub: Provides version control and a backup of the project. Can also work outside the server now.
6. Development Workflow:
    a. Git Management:
        i. Local changes are made, tested, and committed in the Azure cloud server.
        ii. The repository is then synced with the remote GitHub repository for backup and collaboration.
        iii. Team members can clone the repository and contribute to the project.
    b. Docker Management:
        i. The container is managed via Docker Compose, using the deploy.sh script for automation. It checks for existing containers, stops and removes them if necessary, then builds and runs a new container.
        ii. Environment variables are loaded into the container to avoid hardcoding sensitive data.
    c. Testing and Deployment:
        i. The IDS logs and alerts on critical events such as process creations, file modifications, and SSH login attempts.
        ii. Future development includes testing attack scenarios for container escapes to verify that the IDS properly detects and logs such events. Will also add user logging. Will also make the app running in the background permanently.
        iii. More to come!
