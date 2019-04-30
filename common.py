# This file contains common functions used by both the client and server


import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
import base64
import subprocess


# Generate our public and private keys for the diffie-hellman exchange
def genKey():
	private_key = ec.generate_private_key(
	ec.SECP384R1(), default_backend()
	)

	peer_public_key = private_key.public_key()

	serialized_public = peer_public_key.public_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PublicFormat.SubjectPublicKeyInfo
		)
	return serialized_public, private_key


# Decrypt a file with the given key	
def decryptFile(key, inputFile, outputFile):
	if(len(key) is not 44):
		tempKey = key.decode("utf-8")
		trimmed = tempKey[2:len(tempKey)-1]
		newKey = bytes(trimmed, "utf-8")
		f = Fernet(newKey)
	else:
		f = Fernet(key)

	inputData = b''
	with open(inputFile, "rb") as encryptedFile:
		inputData = inputData + encryptedFile.read()

	with open(outputFile, "wb+") as outputFile:
		try:
			outputFile.write(f.decrypt(inputData))
		except:
			print("Invalid decryption key!")
			return

# Encrypt file with the given key
def encryptFile(key, inputFile, outputFile):
	f = Fernet(key)
	inputData = b''
	with open(inputFile, "rb") as rawFile:
		inputData = inputData + rawFile.read()

	token = f.encrypt(inputData)

	with open(outputFile, "wb+") as o:
		o.write(token)


# Send some data to the HOST on a PORT
def sendMessage(data, HOST, PORT):
	try:
		with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
			s.connect((HOST, PORT))
			s.sendall(data)
			data = s.recv(2048)
			s.close()
			return True
	except:
		print("Send message failed")
		return False

# Receive data from the HOST on a PORT
def receiveMessage(HOST, PORT):
	try:
		with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
			s.bind((HOST, PORT))
			s.listen(1)
			conn, addr = s.accept()
			with conn:
			    data = conn.recv(2048)
		return data	        
	except:
		print("Receive message failed")
		return False

# Function to generate the shared key using the partner's public key and our private key
def genSharedKey(server_public_key, peer_private_key):
	loaded_public_key = serialization.load_pem_public_key(
	server_public_key,
	backend=default_backend()
	)     

	shared_key = peer_private_key.exchange(ec.ECDH(), loaded_public_key)
	derived_key = HKDF(
	algorithm=hashes.SHA256(),
	length=32,
	salt=None,
	info=b'handshake data',
	backend=default_backend()
	).derive(shared_key)
	return derived_key

# Encrypt the plaintext message using the derived key and return the ciphertext
def encryptMessage(derived_key, message):
	f = Fernet(base64.urlsafe_b64encode(derived_key))
	token = f.encrypt(message)
	return token

# Send a message to the HOST on a PORT that is encrypted with the derived key
def sendEncryptedData(message, HOST, PORT, derived_key):
	if "str" in str(type(message)):
		message = bytes(message, "utf-8")
	try:
		with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
			s.connect((HOST, PORT))
			s.sendall(encryptMessage(derived_key, message))
			data = s.recv(2048)
			s.close()
		return data
	except:
		print("sendEncryptedData failed")


# Receive a message from the HOST on a PORT that is encrypted with the derived key
def receiveAndDecrypt(HOST, PORT, derived_key):
	try:
		with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
			s.bind((HOST, PORT))
			s.listen(1)
			conn, addr = s.accept()
			with conn:
			    response = conn.recv(2048)

		f = Fernet(base64.urlsafe_b64encode(derived_key))
		token = f.decrypt(response)
		return token
	except:
		print("receiveAndDecrypt failed")

# Call the powershell script to get the device's serial numbers
def getUSBInfo():
	p = subprocess.Popen(["powershell.exe", 
              "./usb-disks.ps1"], 
              stdout=subprocess.PIPE)
	return str(p.stdout.read())

# Parse the output given by the powershell script
def getSNList():
	snList = []
	usbData = getUSBInfo()
	for i in range(len(usbData.split("\\n"))):
		line = usbData.split("\\n")[i]
		newline = line.replace("\\r", "")
		if "Serial Number" in newline:
			splitSN = newline.split(":")
			snList.append(splitSN[1])
	return snList	