from common import *
import threading
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import getpass
import PySimpleGUI as sg	
import sys, signal  
import threading


threads = []
HOST = '127.0.0.1' # Currently running on localhost but can be changed or given as command argument 
InitialPort = 5000
InitialResponsePORT = 5001
global RequestPORT
global ServerToClientPORT
global ClientToServerPORT
global derived_key
global authenticated
global tunneled
global fileList
global verifiedUSB

# Function to break out of while true loops gracefully
def signal_handler(signal, frame):
    print("\nprogram exiting gracefully")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


# Handles the messaging to generate the shared key on the client's side. 
# The client sends their public key first and then waits for the server's response
def createSharedKeyClient():
	global RequestPORT
	global ServerToClientPORT
	global ClientToServerPORT
	global derived_key
	global tunneled
	if(sendMessage(bytes("Establish Channel", "utf-8"), HOST, InitialPort)):
		RequestPORT = int((receiveMessage(HOST, InitialResponsePORT)).decode("utf-8"))
		ServerToClientPORT = int((receiveMessage(HOST, InitialResponsePORT)).decode("utf-8"))
		ClientToServerPORT = int((receiveMessage(HOST, InitialResponsePORT)).decode("utf-8"))
		serialized_public, peer_private_key = genKey()
		sendMessage(serialized_public, HOST, ClientToServerPORT)
		server_public_key = receiveMessage(HOST, ServerToClientPORT)
		derived_key = genSharedKey(server_public_key, peer_private_key)
		print(bytesToHexString(derived_key)) # Printing on for demo purposes. Normally you would turn this off for security
		tunneled = True
		return True
	else:
		return False


def sha256(message):
	if "str" in str(type(message)):
		message = bytes(message, "utf-8")
	digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
	digest.update(message)
	return bytesToHexString(digest.finalize())

# Hash the serial number before sending it
def hashSNs(snList):
	snIntList = []
	for SN in snList:
		snIntList.append(SN.strip())
	snIntList.sort(key=int)
	text = ""
	for SN in snIntList:
		text = text + SN
	return sha256(bytes(text, 'utf-8'))


def bytesToHexString(byteInput):
	b64 = base64.encodebytes(byteInput).decode()
	return base64.b64decode(b64).hex()

# Initiate request to server to authenticate
def authenticate(username, password):
	global RequestPORT
	global ServerToClientPORT
	global ClientToServerPORT
	global derived_key	
	global authenticated
	hashedPassword = sha256(bytes(password, 'utf-8'))
	sendEncryptedData("Authenticate", HOST, RequestPORT, derived_key)
	sendEncryptedData(username, HOST, ClientToServerPORT, derived_key)
	sendEncryptedData(hashedPassword, HOST, ClientToServerPORT, derived_key)
	response = receiveAndDecrypt(HOST, ServerToClientPORT, derived_key)
	if "Authentication Successful" in (response.decode("utf-8")):
		# print("authenticated")
		authenticated = True
		return 0
	elif "Authentication Error" in (response.decode("utf-8")):
		authenticated = False
		return 1
	elif "Already Logged In" in (response.decode("utf-8")):
		authenticated = False
		return 2

# Send the hashed serial number from the USB device
def sendUSB(hashedSN):
	global verifiedUSB
	global RequestPORT
	global ServerToClientPORT
	global ClientToServerPORT
	global derived_key	
	# hashedSNs = hashSNs(SNList)
	# print("Sending SNs ", hashedSNs)
	sendEncryptedData("Send USB", HOST, RequestPORT, derived_key)
	sendEncryptedData(hashedSN, HOST, ClientToServerPORT, derived_key)
	response = receiveAndDecrypt(HOST, ServerToClientPORT, derived_key)
	if "SN Good" in (response.decode("utf-8")):
		verifiedUSB = True
		return True
	else:
		verifiedUSB = False
		return False	

# Send a requrest to the server to decrypt a file
def requestDecrypt(derived_key, HOST, ServerToClientPORT, ClientToServerPORT, filename, RequestPORT):
	sendEncryptedData("Decrypt Request", HOST, RequestPORT, derived_key)
	sendEncryptedData(filename, HOST, ClientToServerPORT, derived_key)
	response = receiveAndDecrypt(HOST, ServerToClientPORT, derived_key)
	if "File Not Found" not in str(response):
		decryptFile(response, filename + ".enc", filename)
		return True
	else:
		return False


# Receive the files we have tracked from the server
def getFileList():
	files = []
	numFiles = int(receiveAndDecrypt(HOST, ServerToClientPORT, derived_key))
	for i in range(numFiles):
		files.append(receiveAndDecrypt(HOST, ServerToClientPORT, derived_key).decode("utf-8"))
	return files

def decryptFiles(fileList):
	global authenticated
	if(authenticated):
		for file in fileList:
			if not (requestDecrypt(derived_key, HOST, ServerToClientPORT,  ClientToServerPORT, file, RequestPORT)):
				print("File: " + file + " not tracked")
		return True
	else:
		return False

# Encrypt our new files. Generate a new unique encryption key and send it to the server to be stored. Then encrypt the file
def encryptFiles(fileList):
	global authenticated
	fileCount = 0
	for file in fileList:
		try:
			f = open(file, 'r')
			fileCount +=1
		except:
			FileNotFoundError
	if(authenticated):	
		sendEncryptedData("Encrypt", HOST, RequestPORT, derived_key)
		sendEncryptedData(str(fileCount), HOST, ClientToServerPORT, derived_key)
		for file in fileList:
			try:
				f = open(file, 'r')
			except FileNotFoundError:
				print("File not found")
				continue
			key = Fernet.generate_key()
			sendEncryptedData(file, HOST, ClientToServerPORT, derived_key)
			sendEncryptedData(key, HOST, ClientToServerPORT, derived_key)
			encryptFile(key, file, file+'.enc')

# Thread to handle the GUI with all its buttons, text inputs, and messaging
def runGUI():
	global tunneled
	global authenticated
	global fileList
	global verifiedUSB
	verifiedUSB = False
	authenticated = False
	tunneled = False
	submitted = False
	username = ''
	fileList = []
	layout = [
	[sg.Text('Not Connected - Please Establish Connection', text_color='red', key='connectionStatus', font=("Helvetica", 16), size=(35,1))],
	[sg.Button('Establish Tunnel', key='tunnel', button_color =('white', 'red')), sg.Submit(disabled=True, key="Submit", button_color =('white', 'red')), sg.Button('Verify Device', key='verifyUSB', button_color =('white', 'red'), disabled=True)],	[sg.Text('Username'), sg.InputText()],
	[sg.Text('Password'), sg.InputText(password_char='*')],
	[sg.Button('Decrypt Files', button_color =('white', 'green'), disabled=True, key="decrypt"), sg.Button('Encrypt Files', button_color =('white', 'orange'), disabled=True, key="encrypt")],
	[sg.Text('Files tracked:', size=(40, 1))],
	[sg.Listbox(values=['No Files'], size=(50,6), key='list', select_mode='multiple')],
	[sg.Button('Add New File', disabled=True, key='newFileButton'), sg.Button('Remove File', disabled=True, key='removeFileButton'),sg.InputText(key="newFileInput", disabled=True), sg.FileBrowse(disabled=True, key="fileBrowser")],
	[sg.Button('Change Password', disabled=True, key='changePW')]
	
	]
	Window = sg.Window('CS460 Project: User Console', auto_size_text=True, resizable=True, default_element_size=(40, 1)).Layout(layout).Finalize()

	try:
		while True:
			event, values = Window.Read(timeout=5)
			if event is None or event == 'Exit':  
				break  			
			if event == 'tunnel':
				if(createSharedKeyClient()):
					Window.FindElement('tunnel').Update('Tunneled!')
					Window.FindElement('connectionStatus').Update('Please Login Now')
					Window.FindElement('tunnel').Update(button_color =('black', 'cyan'))
					Window.FindElement('Submit').Update(disabled=False)
			if ((event == 'Submit') and (tunneled == True) and (submitted is not True)):
				success = authenticate(values[0], values[1]) # If we get authenticated, then enable these buttons
				if(success == 0):
					username = values[0]
					Window.FindElement('connectionStatus').Update(text_color='green')
					Window.FindElement('connectionStatus').Update('Connected. Please verify device')
					Window.FindElement('Submit').Update(button_color =('black', 'cyan'))				
					Window.FindElement('list').Update(values=fileList)	
					Window.FindElement('changePW').Update(disabled=False)
					Window.FindElement('newFileButton').Update(disabled=False)
					Window.FindElement('fileBrowser').Update(disabled=False)
					Window.FindElement('newFileInput').Update(disabled=False)
					Window.FindElement('removeFileButton').Update(disabled=False)
					Window.FindElement('verifyUSB').Update(disabled=False)
					preSNList = getSNList()
					submitted = True
				if (success == 2): # We tried to log in again but we were already logged in
					Window.FindElement('connectionStatus').Update('You are already logged in')


			if event == 'verifyUSB' and authenticated: # User wants to send their devices serial numbers
				postSNList = getSNList()
				print("Pre list", preSNList)
				print("Post list", postSNList)
				justUSB = str(list(set(postSNList).difference(preSNList)))
				print("Verifying SN with ", justUSB)
				print("Hashed SN is ", (sha256(justUSB)))
				if(sendUSB(sha256(justUSB))): # If the server says our serial numbers match, then enable the remaining buttons
					Window.FindElement('decrypt').Update(disabled=False)
					Window.FindElement('encrypt').Update(disabled=False)	
					Window.FindElement('verifyUSB').Update(button_color =('black', 'cyan'))				
					Window.FindElement('connectionStatus').Update('Verified')
					fileList = getFileList()
					Window.FindElement('list').Update(values=fileList)

			if event == 'decrypt' and verifiedUSB: # User wants to decrypt some files
				decryptFileList = values.get("list")

				if(decryptFiles(decryptFileList)): # Try to do the actual decryption
					Window.FindElement('connectionStatus').Update('Files Decrypted')
				else:
					Window.FindElement('connectionStatus').Update('You have to log in first')

			if event == 'encrypt': # We want to encrypt some files
				encryptFileList = values.get("list")
				encryptFiles(encryptFileList)

			if event == 'Start' and not handlerRunning: # We want to start start the client
				t.start()

			if event == 'newFileButton': # We want to add new files to the encryption
				addFile = values.get("newFileInput")
				addFile = addFile.replace("/", "\\")
				try:
					f = open(addFile, 'r') # Check to see if it's a real file
					if addFile not in fileList:
						fileList.append(addFile)
						Window.FindElement('list').Update(values=fileList)		

				except FileNotFoundError:
					print("File not found. Will not encrypt.")
					continue
			
			if event == 'removeFileButton': # We want to remove a file from the encryption. We notify the server and remove it form our list
				removeFileList = values.get('list')
				sendEncryptedData("Remove Files", HOST, RequestPORT, derived_key)
				sendEncryptedData(str(len(removeFileList)), HOST, ClientToServerPORT, derived_key)				
				for removeFile in removeFileList:
					print("removing " + str(len(removeFileList)) + " files")
					print("Removing ", removeFile)
					sendEncryptedData(removeFile, HOST, ClientToServerPORT, derived_key)					
					if removeFile in fileList:
						print("Removed ", removeFile)
						fileList.remove(removeFile)
						Window.FindElement('list').Update(values=fileList)		

			if event == 'changePW': # We want to change our password. The server needs our original password first then the new one
				sendEncryptedData("changePW", HOST, RequestPORT, derived_key)
				pwResonse = receiveAndDecrypt(HOST, ServerToClientPORT, derived_key).decode("utf-8")
				if pwResonse == "PW Change Allowed":
					oldPW = sg.PopupGetText('Please Enter Your Current Password','Password Change',  password_char='*')   
					newPW = sg.PopupGetText('Please Enter Your New Password', 'Password Change', password_char='*')   
					sendEncryptedData(sha256(oldPW), HOST, ClientToServerPORT, derived_key)
					sendEncryptedData(sha256(newPW), HOST, ClientToServerPORT, derived_key)
					pwSuccess = receiveAndDecrypt(HOST, ServerToClientPORT, derived_key).decode("utf-8")
					if pwSuccess == "Success":
						Window.FindElement('connectionStatus').Update('Password Change Successful')	
					if pwSuccess == "Fail":
						Window.FindElement('connectionStatus').Update('Password Change Failed')
				else:
					Window.FindElement('connectionStatus').Update('Password Change Not Allowed')


				


	except KeyboardInterrupt:
		Window.Close()
		return

t = threading.Thread(target=runGUI, args=())
threads.append(t)
t.start()
