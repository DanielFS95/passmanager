# Daniels Password Manager

This is my personal project where i try out different ideas to gain more knowledge of new technologies i find interesting.

My current project is a simple CLI-Based Password Manager written in Python. The program features a user creation and login system, that lets the user/account store passwords for a specific service, which is then encrypted and kept in a SQL database.

Everything is setup in Docker, and uses Traefik as a Reverse Proxy to gain a TLS certificate for secure HTTPS connections.

# Technologies/features used in this project currently:

- User/Account Creation (With rules for password length and )
- Login system (session based)
- 2FA-Authentication option (ASCII QR-Code in CLI-Program)
- Encryption and Decryption using AES-GCM
- Hashing using Bcrypt
- Flask API
- Rate Limiter
- Use of a Secrets Manager (Doppler)
- Automatic update of API with short downtime (Uses watchtower + Github Actions to achieve this)
