# Autsec Two Factor Authentication

This Python script simulates a basic two-factor authentication (2FA) system using TOTP (Time-based One-Time Password) and backup codes. It provides functionalities for user registration, login, and validation of TOTP or backup codes.

# Features

- User Registration: Users can register with their email addresses and generate secret keys, backup codes, and QR codes for 2FA setup.
- Login: Users can log in using either their TOTP generated by an authenticator app or backup codes.
- Rate Limiting: Implements rate limiting to prevent brute-force attacks, blocking users temporarily after exceeding a certain number of failed login attempts.

# How to Use

# Registration:
- Choose the "Register" option.
- Enter your email address to register.
- Follow the instructions to set up 2FA with TOTP and backup codes.
# Login:
- Choose the "Login" option.
- Enter your email address.
- Provide the TOTP from your authenticator app or a backup code when prompted.
# Exit:
- Choose the "Exit" option to terminate the program.
# Security Considerations

This script provides a simulation of a basic 2FA system and is for educational purposes only.
In a real-world scenario, use established libraries and services for implementing secure authentication mechanisms.
