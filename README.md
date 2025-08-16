# Security Scanner

Security Scanner is a lightweight, Python-based tool designed to detect vulnerabilities in web applications and code repositories. It provides fast scanning, customizable rules, and seamless integration with CI/CD pipelines, making it ideal for developers and security professionals.

## Features

- **Vulnerability Detection**: Identifies common security issues such as XSS, SQL Injection, and exposed secrets.
- **Customizable Rules**: Configure scans to meet specific requirements using custom rules.
- **Docker Support**: Run scans in isolated Docker containers for consistent and reproducible environments.

## Prerequisites

- **Python**: 3.8 or higher (for local installation).
- **Docker**: Required for containerized usage.
- **Git**: For cloning the repository.

## Installation

### Local Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/rabindra789/security-scanner.git
   cd security-scanner
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the `app.py` file

### Docker Installation
Pull the latest image from Docker Hub:
```bash
docker pull rabindra789/security-scanner:latest
```

## Usage
Run the scanner in a Docker container:
```bash
docker run --rm rabindra789/security-scanner:latest
```

### Available Docker Tags
- `latest`: Most recent stable release.
- `sha-<hash>`: Commit-specific builds for traceability (e.g., `sha-1a2b3c4`).

## CI/CD Integration
This repository uses GitHub Actions to automatically build and push Docker images to [Docker Hub](https://hub.docker.com/r/rabindra789/security-scanner) on pushes to the `main` branch.
To set up:
1. Ensure a `Dockerfile` exists in the repository root.
2. Add `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` secrets in GitHub Settings > Secrets and variables > Actions.
3. The workflow in `.github/workflows/docker-build-push.yml` handles building and pushing images.

## Contributing
Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit changes (`git commit -m "Add your feature"`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a pull request.

Please adhere to the [Code of Conduct](CODE_OF_CONDUCT.md) and follow the project’s coding standards.

## License
This project is licensed under the [MIT License](LICENSE).

## Support
For issues or questions, open an issue on [GitHub](https://github.com/rabindra789/security-scanner/issues) or contact [rabindrameher116@gmail.com](mailto:rabindrameher116@gmail.com).
