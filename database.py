# This file contains functions that read and write to the admin database as well as
# each user's individual database

import getpass
import csv
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
import ast


# This function reads the encrypted info in the connect admin database file
# It then decrypts using the admin key and returns the list of user accounts, their 
# hashed device serial number, and their hashed password
def readAdminDB(filename, key):
	f = Fernet(key)	
	newUsernames = []
	newSNs = []
	newPasswords = []

	inputData = ''
	with open(filename, "r") as inFile:
		inputData = inFile.read()

	if inputData == "":
		print("Initializing New Database")
		output = []
		output.append(newUsernames)
		output.append(newSNs)
		output.append(newPasswords)	
		return output

	encryptedList = ast.literal_eval(inputData)
	decryptedLines = []
	for line in encryptedList:
		decryptedLines.append(f.decrypt(bytes(line, "utf-8")).decode("utf-8"))


	for i in range(len(decryptedLines)):
		decryptedLine = ast.literal_eval(decryptedLines[i])
		newUsernames.append(decryptedLine[0])
		newSNs.append(decryptedLine[1])
		newPasswords.append(decryptedLine[2])	
	
	output = []
	output.append(newUsernames)
	output.append(newSNs)
	output.append(newPasswords)	
	return output


# This function updates the admin database after a new user is added.
# It writes their username, hashed device serial number, and hashed password
def updateAdminDB(filename, key, usernames, SNs, passwords):
	f = Fernet(key)
	assert(len(usernames) == len(SNs) == len(passwords)), "Lenghts of usernames, SNs, and passwords don't match"
	newLines = []
	encryptedLines = []

	for i in range(len(usernames)):
		line = []
		line.append(usernames[i])
		line.append(SNs[i])
		line.append(passwords[i])
		encryptedLines.append(f.encrypt(bytes(str(line), "utf-8")).decode("utf-8"))

	with open(filename, 'w+') as outFile:
		outFile.write(str(encryptedLines))


# This function reads an individual user's list of tracked files and their associated keys
def readFileDB(fileFile, keyFile, key):
	files = []
	keys = []	
	f = Fernet(key)	
	try:
		with open(keyFile, 'r') as keyFile:
			inputData = keyFile.read()
	except:
		file = open(keyFile, 'w+')
		return files, keys	

	if((len(inputData) == 0 ) or (inputData == '[]')):
		print("User file is empty. Must be a new user with no tracked files")
		return files, keys	

	inputData = inputData[:len(inputData)-1]
	rawData = inputData.split(',')
	decrypted = []
	for line in rawData:
		realLine = line[3:len(line)-1]
		try:
			decryptedLine = f.decrypt(bytes(realLine, "utf-8"))
		except Exception as e:
			print("Couldn't decrypt file in readFileDB ", e)
			return files, keys	
		decrypted.append(decryptedLine)

	for i in range(len(decrypted)):
		keys.append(decrypted[i])

	with open(fileFile, 'r') as fileFile:
		line = fileFile.readline().replace("\n", "")
		while line:
			files.append(line)
			line = fileFile.readline().replace("\n", "")

	return files, keys	


# This function updates a specific user's list of tracked files if they choose to 
# add or remove a file. It will also update the encryption key every time the file is re-encrypted
def updateFileDB(files, keys, user, key):
	f = Fernet(key)
	if(len(keys) is not len(files)):
		print("Error! Number of keys didn't match number of files")
		return
	newData = []
	for i in range(len(files)):
		print("Appending key " + str(keys[i]))
		newData.append(keys[i])

	outputData = []
	for i in range(len(newData)):
		print(type(newData[i]))
		if "bytes" in str(type(newData[i])):
			newData[i] = newData[i].decode("utf-8")
		try:
			encrypted = f.encrypt(bytes(newData[i], "utf-8"))
		except:
			print("Couldn't re-encrypt. Bad key")
			return
		outputData.append(encrypted)

	with open(user+"keys.txt.enc", "w+") as o:	
		o.write(str(outputData))		

	with open(user+"files.txt", "w+") as o:	
		for i in files:
			o.write(i)
			o.write("\n")
