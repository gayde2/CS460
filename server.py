# This file contains the functions that implement the server. This includes threads to run the
# connection handler, a thread for each user object, and another thread for the GUI.

import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
import base64
import os
import threading
from database import *
from common import *
import PySimpleGUI as sg	
import sys, signal, queue, subprocess

HOST = '127.0.0.1' # Currently running on localhost but can be changed or given as command argument 
InitialPORT = 5000
InitialResponsePORT = 5001


threads = []
global adminKey
global usedPorts
global Users
global handlerRunning
global toGUIQueue
global fromGUIQueue


# Function to break out of while true loops gracefully
def signal_handler(signal, frame):
    print("\nprogram exiting gracefully")
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


# The class for each user. It stores the username, whether they are authenticated, whether they have
# verified their device serial numbers, what ports they communicate over, and the files and keys 
# associated to their account. It uses 2 queues to communicate with the GUI

class UserClass:
	global toGUIQueue
	global fromGUIQueue
	def __init__(self, RequestPORT, ServerToClientPORT, ClientToServerPORT, derived_key):
		self.user = ''
		self.authenticated = False
		self.verifiedUSB = False
		self.RequestPORT = RequestPORT
		self.ServerToClientPORT = ServerToClientPORT
		self.ClientToServerPORT = ClientToServerPORT
		self.derived_key = derived_key
		self.files = []
		self.keys = []

# Thread to run continuously and handle the message and encryption/decryption requests
	def userConnection(self):
		global Users
		try:
			while True:
				with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s: # Run socket to receive messages from user on their ports
					s.bind((HOST, self.RequestPORT))
					s.listen(1)
					conn, addr = s.accept()
					with conn:
						data = conn.recv(2048)
					text = str(data.decode("utf-8")) # decode received from bytes to string
					f = Fernet(base64.urlsafe_b64encode(self.derived_key)) # decrypt message using the user's key
					text = f.decrypt(data).decode("utf-8")
					if "Authenticate" in text: #User wants to authenticate. Let's see if they are legit
						result , self.user = checkUser(self)
						if(result):
							self.authenticated = True
							if self.user not in Users:
								Users.append(self.user) # If this isn't a duplicate, add them to the users list


					if "Send USB" in text and self.authenticated: # User needs to verify their device serial number
						SNs = receiveAndDecrypt(HOST, self.ClientToServerPORT, self.derived_key)
						self.verifiedUSB = checkSNMatch(self, SNs, adminKey)
						if(self.verifiedUSB):
							self.files, self.keys = readFileDB(self.user+'files.txt', self.user+'keys.txt.enc', adminKey)
							# Send number of files this user manages and then each file name
							sendEncryptedData(str(len(self.files)), HOST, self.ServerToClientPORT, self.derived_key)
							for i in self.files:
								sendEncryptedData(str(i), HOST, self.ServerToClientPORT, self.derived_key)

					if "Decrypt Request" in text and self.authenticated: # User wants to decrypt some files
						if(self.verifiedUSB):
							self.files, self.keys = readFileDB(self.user+'files.txt', self.user+'keys.txt.enc', adminKey)
							receiveDecryptionRequest(self, HOST)
						else:
							print("User not authenticated but they tried to decrypt files")

					if "Remove Files" in text and self.authenticated: # User wants to remove some files from being tracked
						numFiles = int(receiveAndDecrypt(HOST, self.ClientToServerPORT, self.derived_key).decode("utf-8"))
						for i in range(numFiles):
							file = receiveAndDecrypt(HOST, self.ClientToServerPORT, self.derived_key).decode("utf-8")
							if file in self.files:
								idx = self.files.index(file)
								del self.files[idx]
								del self.keys[idx]
								updateFileDB(self.files, self.keys, self.user, adminKey)
							else:
								print("File not found: ", file)
													

					if "Encrypt" in text and self.authenticated: # User wants to encrypt some files
						if(self.verifiedUSB):
							# print("Received Encryption Message")
							newFiles, newKeys = receiveEncryptionRequest(HOST, self.ClientToServerPORT, self.ServerToClientPORT, self.derived_key)
							for i in range(len(newFiles)):
								try:
									idx = self.files.index(newFiles[i])
									self.keys[idx] = newKeys[i]
								except ValueError:
									self.files.append(newFiles[i])
									self.keys.append(newKeys[i])
							updateFileDB(self.files, self.keys, self.user, adminKey)
						else:
							print("User not authenticated but they tried to encrypt files")

					if "changePW" in text and self.authenticated: #User wants to change their password. This is handled in the GUI thread so add messages to queues
						toGUIQueue.put("changePW")
						toGUIQueue.put(self.user)
						toGUIQueue.put(self)

		except KeyboardInterrupt:
			return

# If the admin allowed the user to change their password via the popup, 
# run this function to get the new hashed password over the netowrk and write it back to the DB
	def changePW(self, result):
		if result == "Yes":
			sendEncryptedData("PW Change Allowed", HOST, self.ServerToClientPORT, self.derived_key)
			oldPW = receiveAndDecrypt(HOST, self.ClientToServerPORT, self.derived_key).decode("utf-8")
			newPW = receiveAndDecrypt(HOST, self.ClientToServerPORT, self.derived_key).decode("utf-8")
			print("Old PW ", oldPW, " New PW ", newPW)
			database = readAdminDB("database.txt.enc", adminKey)
			if checkUserMatch(self.user, oldPW, database): # Verify this is a good request by matching previous password before allowing change
				print("Old password matched")
				idx = database[0].index(self.user)
				database[2][idx] = newPW
				updateAdminDB("database.txt.enc", adminKey, database[0], database[1], database[2]) #user, SN, PW
				sendEncryptedData("Success", HOST, self.ServerToClientPORT, self.derived_key)
			else:
				sendEncryptedData("Fail", HOST, self.ServerToClientPORT, self.derived_key)

		else:
			sendEncryptedData("PW Change Not Allowed", HOST, self.ServerToClientPORT, self.derived_key)


# This thread handles all of the initial connections and hands out port assignments for each client that connects
# It also calls the functions that do the diffie-hellman key exchange
def connectionHandler(InitialPORT, InitialResponsePORT):
	global derived_key
	global connectionEstablished
	global adminKey
	global handlerRunning
	print("Connection Handler")
	if(handlerRunning):
		return 
	currentPort = 5002
	handlerRunning = True
	try:
		while True:
			with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
				s.bind((HOST, InitialPORT))
				s.listen(1)
				conn, addr = s.accept()
				with conn:
					data = conn.recv(2048)
				text = str(data.decode("utf-8"))
				# if not (connectionEstablished):
				if "Establish Channel" in text:
					sendMessage(bytes(str(currentPort),"utf-8"), HOST, InitialResponsePORT) #RequestPORT
					currentPort = currentPort + 1
					sendMessage(bytes(str(currentPort),"utf-8"), HOST, InitialResponsePORT) #ServerToClientPORT
					currentPort = currentPort + 1
					sendMessage(bytes(str(currentPort),"utf-8"), HOST, InitialResponsePORT) #ClientToServerPORT
					currentPort = currentPort + 1
					derived_key = createSharedKeyServer(currentPort-1, currentPort-2)
					print(bytesToHexString(derived_key))
					user = UserClass(currentPort-3, currentPort-2, currentPort-1, derived_key)
					t = threading.Thread(target=user.userConnection, args=())
					threads.append(t)
					t.start()
	except KeyboardInterrupt:
		return


# Do the actual Diffie-Hellman key exchange. First generate a public and private key, 
# then receive the client's public key, then send our public key, then combine their
# public key with our private key to generate the shared derived key
def createSharedKeyServer(ClientToServerPORT, ServerToClientPORT):
	serialized_public, server_private_key = genKey()
	client_public_key = receiveMessage(HOST, ClientToServerPORT)
	sendMessage(serialized_public, HOST, ServerToClientPORT)
	derived_key = genSharedKey(client_public_key, server_private_key)
	return derived_key


def bytesToHexString(byteInput):
	b64 = base64.encodebytes(byteInput).decode()
	return base64.b64decode(b64).hex()


def sha256(message):
	if "str" in str(type(message)):
		message = bytes(message, "utf-8")
	digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
	digest.update(message)
	return bytesToHexString(digest.finalize())


# Authenticates the user by verifying their username and hashed password match and are in the database of allowed users
def checkUser(self):
	global adminKey
	global Users
	username = receiveAndDecrypt(HOST, self.ClientToServerPORT, self.derived_key).decode("utf-8")
	password = receiveAndDecrypt(HOST, self.ClientToServerPORT, self.derived_key).decode("utf-8")
	if username in Users:
		print("User is already logged in")
		result = False
		sendEncryptedData("Already Logged In", HOST, self.ServerToClientPORT, self.derived_key)
		return result, username
	database = readAdminDB("database.txt.enc", adminKey)
	updateAdminDB("database.txt.enc", adminKey, database[0], database[1], database[2])
	result = checkUserMatch(username, password, database)
	if(result):
		sendEncryptedData("Authentication Successful", HOST, self.ServerToClientPORT, self.derived_key)
	else:
		sendEncryptedData("Authentication Error", HOST, self.ServerToClientPORT, self.derived_key)
	return result, username


# This function performs the actual comparison between the usernames and hashed passwords
def checkUserMatch(username, password, database):
	userFound = False
	passMatch = False
	try:
		usrIdx = database[0].index(username)
		userFound = True
	except:
		print("Username " + username + " not found")
		return False

	if(userFound):
		if(database[2][usrIdx] == password):
			passMatch = True
			return True
		else:
			print("Password doesn't match")
			return False


# This checks to see if the user's provided device serial numbers match
def checkSNMatch(self, SNs, adminKey):
	database = readAdminDB("database.txt.enc", adminKey)
	snMatch = False
	try:
		usrIdx = database[0].index(self.user)
		userFound = True
	except:
		print("Username " + self.user + " not found")
		return False

	if(database[1][usrIdx] == SNs.decode("utf-8")):
		snMatch = True	
		sendEncryptedData("SN Good", HOST, self.ServerToClientPORT, self.derived_key)
		return True
	else:
		sendEncryptedData("SN Bad", HOST, self.ServerToClientPORT, self.derived_key)
		print("SN didn't match", SNs.decode("utf-8"))
		return False


# This function handles the messaging associated with when the user wants to decrypt some files
def receiveDecryptionRequest(self, HOST):
	filename = receiveAndDecrypt(HOST, self.ClientToServerPORT, self.derived_key)
	try:
		fileIdx = self.files.index(filename.decode("utf-8"))
	except:
		print("File Not Found ", filename)
		sendEncryptedData("File Not Found", HOST, self.ServerToClientPORT, self.derived_key)
		return
	print("Sending Decryption for " + str(filename.decode("utf-8")))
	sendEncryptedData(self.keys[fileIdx], HOST, self.ServerToClientPORT, self.derived_key)


# This function handles the messaging associated with when the user wants to encrypt some files
def receiveEncryptionRequest(HOST, ClientToServerPORT, ServerToClientPORT, derived_key):

	numFiles = int(receiveAndDecrypt(HOST, ClientToServerPORT, derived_key))
	fileList = []
	keyList = []
	for i in range(numFiles):
		fileList.append((receiveAndDecrypt(HOST, ClientToServerPORT, derived_key)).decode("utf-8"))
		keyList.append((receiveAndDecrypt(HOST, ClientToServerPORT, derived_key)).decode("utf-8"))
	return fileList, keyList

# This function generates the admin key from the provided password using the PBKDF2 key derivation function
def genAdminKey(pw):
	global adminKey
	salt = b'cs460'

	password = bytes(pw, "utf-8")
	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=32,
		salt=salt,
		iterations=100000,
		backend=default_backend()
	)
	return base64.urlsafe_b64encode(kdf.derive(password))
	

# This function verifies the password the admin entered was correct for the database. 
# If there is no database or it is empty, verify the password the admin entered matches
# the one they used to create the new database
def checkAdminPassword(pw):
	global handlerRunning
	global adminKey
	key = genAdminKey(pw)
	f = Fernet(key)	
	inputData = b''
	try:
		with open("database.txt.enc", 'rb') as userFile:
			inputData = inputData + userFile.read()	
	except:
		print("No database")
		return 2

	try:
		if inputData == b'' and genAdminKey(pw) == adminKey:
			return 0	
	except:
		return 2

	try:
		decrypted = f.decrypt(inputData)		
		adminKey = key
		return 0
	except:
		print("Incorrect admin password")
		return 1	




# Function to run the GUI and handle the button clicks, popups, and text inputs
def runGUI():
	global handlerRunning
	global Users
	global changePW
	global toGUIQueue
	global fromGUIQueue
	global adminKey

	toGUIQueue = queue.Queue()
	fromGUIQueue = queue.Queue()
	Users = []
	handlerRunning = False
	t = threading.Thread(target=connectionHandler, args=(InitialPORT, InitialResponsePORT))
	threads.append(t)	
	layout = [[sg.Text('Please enter the admin password to begin', size=(50, 1), font=("Helvetica", 14), text_color='blue', key='toptext')],		  
	[sg.InputText(password_char='*'),sg.Submit(), sg.Button('Start Server', button_color =('white', 'green'), disabled=True, key='serverButton')],
	[sg.Text('Connected Users:', size=(40, 1))],
	[sg.Listbox(values=['No Users'], size=(50,6), key='list')],
	[sg.Button('Add New User', disabled=True, key='newUser'), sg.Button('Add New Database', key='newDB')]]
	Window = sg.Window('CS460 Project: Admin Console', auto_size_text=True, size=(450,250), resizable=True, default_element_size=(30, 1)).Layout(layout).Finalize()


	try:
		while True:
			if not toGUIQueue.empty(): # First see if there is anything in the queue indicating a user wants to change their password
				newMessage = toGUIQueue.get()
				if(newMessage == "changePW"):
					user = toGUIQueue.get()
					print(user, " wants to change their password")
					message = "Allow " + user + " to change their password?"
					result = sg.PopupYesNo(message, "Password Change")
					userObj = toGUIQueue.get()
					userObj.changePW(result)
					# processPWChange(result, user)
			if Users:
				Window.FindElement('list').Update(values=Users) # Update the user list on screen 
			event, values = Window.Read(timeout=5)
			if event is None or event == 'Exit':  
				break  			
			# if 'TIME' not in event:
			# 	print(event)
			if event == 'Submit':
				# The admin just entered a password. Check to see if it was correct and update the screen accordingly
				rv = checkAdminPassword(values[0])
				if(rv == 0):
					Window.FindElement('toptext').Update("Password Successful!")
					Window.FindElement('toptext').Update(text_color='green')
					Window.FindElement('serverButton').Update(disabled=False)
					Window.FindElement('newUser').Update(disabled=False)

				elif(rv == 1):
					Window.FindElement('toptext').Update("Bad Password")
					Window.FindElement('toptext').Update(text_color='red')		
				
				elif(rv == 2):
					Window.FindElement('toptext').Update("No Database. Please create one")

			if event == 'newDB': # User wants to create a new database. Show a popup to get the new password
				pw = sg.PopupGetText("Enter New Password", "New DB", password_char='*')
				adminKey = genAdminKey(pw)
				with open("database.txt.enc", 'wb+') as userFile:
					userFile.write(b"")

			if event == 'serverButton' and not handlerRunning: # Start the server thread
				t.start()

				# Admin wants to add a new user
			if event == 'newUser':
				user = sg.PopupGetText("Enter Username", "New User")
				pw = sg.PopupGetText("Enter Password", "New User", password_char='*')
				
				# Collect the serial numbers with and without the USB drive inserted. Use the set difference to get the SN for USB drive alone
				sg.Popup("Collect drive info without USB key")
				snPre = getSNList()
				sg.Popup("Collect drive info with USB key")
				snPost = getSNList()
				justUSB = str(list(set(snPost).difference(snPre)))
				database = readAdminDB("database.txt.enc", adminKey)
				if user not in database[0]: # Add new user to database
					print("Storing SN with ", justUSB)
					database[0].append(user)
					print(database[1])
					print(sha256(justUSB))
					database[1].append(sha256(justUSB))
					database[2].append(sha256(pw))
					updateAdminDB("database.txt.enc", adminKey, database[0], database[1], database[2]) #user, SN, PW

	except KeyboardInterrupt:
		Window.Close()
		return

t = threading.Thread(target=runGUI, args=())
threads.append(t)
t.start()


