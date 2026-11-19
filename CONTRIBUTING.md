# Contributing to Feathersock

Thanks for your interest in improving Feathersock! This guide covers how to
report bugs, suggest features, and submit code.

Repository: https://github.com/Luigi69am/feathersock

---

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Reporting Bugs](#reporting-bugs)
3. [Suggesting Features](#suggesting-features)
4. [Pull Requests](#pull-requests)
5. [Code Style](#code-style)
6. [Testing](#testing)
7. [Security Issues](#security-issues)
8. [License](#license)

---

## Code of Conduct

Be respectful. Harassment, discrimination, and personal attacks are not
tolerated. Keep discussions focused on the project.

---

## Reporting Bugs

Before opening an issue, please:

1. Search existing issues to avoid duplicates.
2. Make sure you are on the latest `main` branch.
3. Try to reproduce the bug on a clean install.

When opening an issue, include:

- **Feathersock version** (`python3 feathersock.py --version`)
- **Python version** (`python3 --version`)
- **OS and version** (`uname -a`)
- **What you expected to happen**
- **What actually happened**
- **Steps to reproduce**
- **Relevant log lines** (from the terminal or `journalctl -u feathersock`)

### ⚠️ Never include

- Real IP addresses
- Passwords or admin credentials
- The contents of `config.json`
- The contents of `users.txt` or `traffic.txt`
- Any personal data

Redact sensitive lines before pasting logs.

---

## Suggesting Features

Open an issue with the `enhancement` label and describe:

- **The problem** you are trying to solve
- **Your proposed solution**
- **Alternatives** you considered
- **Why it fits Feathersock's scope** (single-file, lightweight, Shadowsocks-focused)

Features that add heavy dependencies, a database, or a web framework
will likely be rejected. Feathersock's value is its small footprint.

---

## Pull Requests

### Workflow

1. Fork the repository on GitHub.
2. Clone your fork:
   ```bash
   git clone https://github.com/Luigi69am/feathersock.git
   cd feathersock