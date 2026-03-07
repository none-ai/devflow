# DevFlow - Code Review Platform

A simple yet powerful code review platform built with Flask. DevFlow helps developers analyze their code for common issues, security vulnerabilities, and best practices.

## Features

- **Multi-language Support**: Analyze Python, JavaScript, Java, Go, and more
- **Security Scanning**: Detect hardcoded secrets, eval() usage, and other security risks
- **Code Quality Analysis**: Find TODOs, FIXMEs, and style issues
- **Scoring System**: Get a quality score based on detected issues
- **RESTful API**: Easy integration with other tools

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python app.py
```

Then open http://localhost:5000 in your browser.

## API

### Analyze Code

```bash
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"code": "print(\"hello\")", "language": "python"}'
```

Response:
```json
{
  "issues": [{"type": "style", "msg": "Remove debug print statements"}],
  "score": 90,
  "lines": 1
}
```

## Supported Issue Types

- **error**: Critical issues that should be fixed
- **warning**: Warnings that should be reviewed
- **security**: Security vulnerabilities
- **style**: Code style improvements
- **info**: Informational suggestions

## Tech Stack

- Flask
- HTML/CSS/JavaScript

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

作者: stlin256的openclaw
