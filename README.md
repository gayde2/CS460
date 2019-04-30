# USB 2-Factor Encryption Management System

This repo contains the python client and server code for an encryption management system. The server maintains a database of users and what files they have encrypted. The user can add and remove files to the encryption management system once they are authenticated. The system checks the user's username, password, and the unique serial number provided from a USB drive of their choice. If the username, password, and USB drive match what is stored in the database, the server well send decryption information to the user.

## Getting Started

This program only works on Windows. It uses a powershell script to extract the serial number from the devices connected to the computer. Both the client and server need the common.py file in the directory they are run from since it contains functions used by both programs. The server also needs the database file which contains functions used to access the database of users.

### Prerequisites

The encryption in this program is handled with python's cryptography library. It was tested with version 2.6.1.

### Security

All the keys are stored in an encrypted database on the server. They are never exposed in plaintext outside of the program's RAM. The client and server first perform an Elliptic-curve Diffie-Hellman key exchange to encrypt their communications. The passwords and serial numbers are hashed using SHA256 before transmission and are not stored in plaintext.

File and database encryption are done with the python's symmetric Fernet function. This is 128-bit AES in CBC mode with SHA256 HMAC for authentication. The initialization vectors are generated using the cryptographically secure os.urandom() function. 

All of the authentication and verification checks are handled on the server side. An attacker could manipulate the client program to send any type of message they want, but it is not possible to get the decryption keys unless the user is legitimately authenticated. This program assumes the system running server is secure. The only known vulnerability with this system is if an attacker gained control of the server and also knew the admin password for the database.


## Authors

* **William Gayde**


