# Password Manager

A secure password manager built with Python, Flask, and AES encryption. This application allows users to store, generate, and manage their passwords securely. Passwords are encrypted using AES-256, and access is protected by a 4-digit PIN.

## Features

- **Secure Password Storage**: Passwords are encrypted using AES-256 before being saved.
- **Password Generation**: Generate strong, random passwords with customizable length.
- **PIN Protection**: Access to saved passwords requires a 4-digit PIN.
- **Audit Log**: Track user actions such as adding, generating, and deleting passwords.
- **Rate Limiting**: Prevents brute-force attacks by limiting failed login attempts.
- **Search Functionality**: Easily search for saved passwords by service or username.
- **Password Visibility Toggle**: Reveal or hide saved passwords with a click.

## Technologies Used

- **Python**: The core programming language.
- **Flask**: A lightweight web framework for building the application.
- **Cryptography**: Used for AES encryption and key derivation.
- **HTML/CSS/JavaScript**: For the frontend interface.
- **Jinja2**: Templating engine for rendering dynamic content.

## Setup Instructions

### Prerequisites

- Python 3.x
- Pip (Python package manager)

## Structure of the password

password-manager/
├── app.py                  # Main application file
├── requirements.txt        # List of dependencies
├── README.md               # Project documentation
├── static/
│   └── styles.css          # CSS styles for the frontend
├── templates/
│   ├── base.html           # Base template
│   ├── index.html          # Main interface
│   ├── login.html          # Login page
│   ├── setup.html          # PIN setup page
│   └── audit_log.html      # Audit log page
├── salt.bin                # Salt for key derivation
├── validation.bin          # Encrypted validation token
└── passwords.bin           # Encrypted password storage
