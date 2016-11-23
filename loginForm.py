# Author: Jake Lawrence
# Date: Sunday, November 22, 15:27:04
# Description: A login form based on sqlite written in python. SQL injection should not work
#			   on this program. If I were to run this on a server I would transfer the input
# 			   in an encrypted format along with the database being encrypted.


# used sqlite3 so I wouldn't need to write a full stack
import sqlite3
import hashlib
from hashlib import md5


# the unencrypted database is:
# ** username *   password  **
# ****************************
# 1* admin    * admin123    **
# 2* jake     * pass        **
# 3* ryan     * secure_pass **
# 4* johndoe  * 1234        **
# 5* 1234     * 4321        **
# 6* user     * pass        **
# 7* Test     * aCcOuNt     **
# 8* alpha#   * !@#$%^&*()' **
# ****************************

# references to the database attached
database = 'encrypted_login_info.sqlite'
nameOfTable = 'login_table'
usernameCol = 'username'
passwordCol = 'password'
fieldType = 'TEXT'

# connect to database
conn = sqlite3.connect(database)
c = conn.cursor()

# login header and input
print("Login Below\n")
username = raw_input("Username: ")
password = raw_input("Password: ")

# converting plain text to md5 hash
m = hashlib.md5()

m.update(username.encode('utf-8'))
md5_username = m.hexdigest()

m.update(password.encode('utf-8'))
md5_password = m.hexdigest()

# determines if the username is in the database
c.execute('SELECT {c1} FROM {tn} WHERE {cn}=?'.\
        format(c1=usernameCol, tn=nameOfTable, cn=usernameCol),(md5_username,))
usernameExists = c.fetchone()

# if the username is in the database
if usernameExists:
	# gets the row index for the username
	c.execute('SELECT rowid, * FROM {tn} WHERE {cn} = ?'.\
		format(tn=nameOfTable, cn=usernameCol),(md5_username,))
	username_row = c.fetchone()[0]
	# determines if the password exists
	c.execute('SELECT {c2} FROM {tn} WHERE {cn}=?'.\
        format(c2=usernameCol, tn=nameOfTable, cn=passwordCol), (md5_password,))
	passwordExists= c.fetchone()
	# gets the row index of the password
	c.execute('SELECT rowid, * FROM {tn} WHERE {cn} = ?'.\
		format(tn=nameOfTable, cn=passwordCol),(md5_password,))
	try:
		# sets the row of the password to a variable
		password_row = c.fetchone()[0]
		#if the username has the row as the password, aka they match
		if(passwordExists and username_row==password_row):
			print("You have successfully logged in")
		else:
			print("Invalid username/password pair")
	except:
		print("Invalid username/password pair")

else:
	print("Invalid username/password pair")

#disconnects from database
conn.close()