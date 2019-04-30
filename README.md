# USB 2-Factor Encryption Management System

This repo contains the python client and server code for an encryption management system. The server maintains a database of users and what files they have encrypted. The user can add and remove files to the encryption management system once they are authenticated. The system checks the user's username, password, and the unique serial number provided from a USB drive of their choice. If the username, password, and USB drive match what is stored in the database, the server well send decryption information to the user.

## Getting Started

This program only works on Windows. It uses a powershell script to extract the serial number from the devices connected to the computer. Both the client and server need the common.py file in the directory they are run from since it contains functions used by both programs. The server also needs the database file which contains functions used to access the database of users.

To use the program, first open the server and add a new database with a password. Once that is created, log in to the server with the password you just used and start the server. Once the server is up and running, you should create at least one new user. Enter their username and password without the USB key plugged in. The server will collect a baseline of the system's USB devices. After that, enter the USB key that the user will use as their second factor. The server will capture a second reading of the system's USB devices. It will then subtract these two results to get the unique serial number of the USB drive. The server is all ready to go.

Open the client program and establish a tunnel. This performs the DH key exchange and all subsequent messaging will be encrypted. Enter the username and password without the USB drive plugged in and presss submit. If the password is correct, press Verify Device to send the USB serial number to the server. If it's a match the server will let the client know it has been verified. Now the client can add files they wish to be encrypted and delete the originals. 

Click the Browse button to open a file explorer. Select a file you want to encrypt and press Add New File. The file will show up in the tracked files window. Select whatever files you want from the window and press Encrypt Files. They will be encrypted and the keys will be sent to the server. To decrypt files, select from the tracked files window and press Decrypt Files.

If the user wants to change their password, the server must authorize the change. A popup will appear on the server asking for the administrator to verify the request. If it is allowed, the client must verify their old password before entering a new one.

The client and server are both configured to communicate over a the local 127.0.0.1 IP. By changing the HOST IP in the program, the client and server can operate separately on any computers as long as they are connected via a network.

### Prerequisites

The encryption in this program is handled with python's cryptography library. It was tested with version 2.6.1.

### Security

All the keys are stored in an encrypted database on the server. They are never exposed in plaintext outside of the program's RAM. The client and server first perform an Elliptic-curve Diffie-Hellman key exchange to encrypt their communications. The passwords and serial numbers are hashed using SHA256 before transmission and are not stored in plaintext.

File and database encryption are done with the python's symmetric Fernet function. This is 128-bit AES in CBC mode with SHA256 HMAC for authentication. The initialization vectors are generated using the cryptographically secure os.urandom() function. 

All of the authentication and verification checks are handled on the server side. An attacker could manipulate the client program to send any type of message they want, but it is not possible to get the decryption keys unless the user is legitimately authenticated. This program assumes the system running server is secure. The only known vulnerability with this system is if an attacker gained control of the server and also knew the admin password for the database.

Every time a file is encrypted and decrypted, a new key is generated. This prevents an attacker who may have gained access to the database from being able to decrypt all the files. 

### Installation Notes
The terminal currently prints out debugging information helpful to understand how the program works. This includes the Diffie-Hellman key and other sensitive information. These prints should be removed in an actual implementation. This program does not delete the unencrypted file after encrypting it. After the user is done editing the file, they should re-encrypt it and securely delete the original.


## Authors

* **William Gayde**


