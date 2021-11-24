# Based on:
# 	https://gist.github.com/DakuTree/98c8362fb424351b803e
# 	https://gist.github.com/jordan-wright/5770442
# 	https://gist.github.com/DakuTree/428e5b737306937628f2944fbfdc4ffc
# 	https://stackoverflow.com/questions/60416350/chrome-80-how-to-decode-cookies
# 	https://stackoverflow.com/questions/43987779/python-module-crypto-cipher-aes-has-no-attribute-mode-ccm-even-though-pycry
#	
#	Generate a tms connection string to strava heat map with credentials from an existing cookie

import os
import json
import base64
import sqlite3
from shutil import copyfile
import sys

# python.exe -m pip install pypiwin32
import win32crypt

# python.exe -m pip install pycryptodomex
from Cryptodome.Cipher import AES

COOKIE_PATH = os.getenv("APPDATA") + "/../Local/Google/Chrome/User Data/Default/Cookies"
AUTH_PATH = os.getenv("APPDATA") + "/../Local/Google/Chrome/User Data/Local State"


MAP_ACTIVITIES =  ('all', 'ride', 'run', 'water', 'winter')
MAP_COLORS = ('hot', 'blue', 'purple', 'gray', 'bluered')

args = sys.argv[1:]

#default parameters
map_color = MAP_COLORS[0]
map_activity = MAP_ACTIVITIES[0]

#Process parameters
for i,arg in enumerate(args):
	#line color
	if "-c" in arg:
		if args[i+1] in MAP_COLORS:
			map_color = args[i+1]
		else:
			print(f"valid colors: {MAP_COLORS}, default: {map_color}")
	
	#activity
	if "-a" in arg:
		if args[i+1] in MAP_ACTIVITIES:
			map_activity = args[i+1]
		else:
			print(f"valid actvities: {MAP_ACTIVITIES}, default: {map_activity}")
	
	#help
	if "-h" in arg:
		print()
		print("usage: generate_tms.py [-a activity | -c color] ...")
		print(f"activity: {MAP_ACTIVITIES}")
		print(f"color: {MAP_COLORS}")
		quit()
			
#Add display options to template url
TMS_URL = 'tms[15]:https://heatmap-external-{switch:a,b,c}.strava.com/tiles-auth/'+map_activity+'/'+map_color+'/{zoom}/{x}/{y}.png'

# Copy Cookies and Local State to current folder
copyfile(COOKIE_PATH, './local_cookies')

# Load encryption key
encrypted_key = None
with open(AUTH_PATH, 'r') as file:
	encrypted_key = json.loads(file.read())['os_crypt']['encrypted_key']
encrypted_key = base64.b64decode(encrypted_key)
encrypted_key = encrypted_key[5:]
decrypted_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]

cookies = {}

# Connect to the Database
conn = sqlite3.connect('./local_cookies')
cursor = conn.cursor()

# Get the results
cursor.execute('SELECT host_key, name, value, encrypted_value FROM cookies')
for host_key, name, value, encrypted_value in cursor.fetchall():
	# Decrypt the encrypted_value
	try:
		# Try to decrypt as AES (2020 method)
		cipher = AES.new(decrypted_key, AES.MODE_GCM, nonce=encrypted_value[3:3+12])
		decrypted_value = cipher.decrypt_and_verify(encrypted_value[3+12:-16], encrypted_value[-16:])
	except:
		# If failed try with the old method
		decrypted_value = win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1].decode('utf-8') or value or 0

	
	if 'strava' in host_key :
		cookies[name] = decrypted_value

conn.commit()
conn.close()

try:
	#Request specific decrypted cookie values
	key_pair = cookies['CloudFront-Key-Pair-Id'].decode('utf-8')
	policy = cookies['CloudFront-Policy'].decode('utf-8')
	signature = cookies['CloudFront-Signature'].decode('utf-8')

	#Append parameters to template url
	connection_string = TMS_URL + '?Key-Pair-Id=' + key_pair
	connection_string += '&Policy=' + policy
	connection_string += '&Signature=' + signature

	#Print final connection string
	print()
	print(f"activity:{map_activity}, color:{map_color}")
	print(connection_string)

except KeyError:
	print('Keys Not Found. Try logging into strava.com/heatmap')