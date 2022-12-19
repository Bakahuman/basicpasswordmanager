import os
import re
from os import system
import getpass
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


class BasePasswordManager:
    old_passwords = ["0"]
 
    def __init__(self):
        #print("Creating a new PM object")
        file1 = open("password.txt",'a+')
        #print("Type of self passwords before assigning : ",type(self.old_passwords))
        #print("Type of self passwords after assigning : ",type(self.old_passwords))
        file1.close()
    def get_password(self):
        if len(self.old_passwords)==0:
            return 0
        else:    
            output = self.old_passwords[-1]
            #print("The last password will be",output)
            return output
        
    def is_correct(self,input):
        if input == self.old_passwords[-1]:
            return True
        else:    
            return False

    def updateList(self,inputkey):
        file1 = open("password.txt",'rb')
        message = file1.read()
        #print("The message before decoding will be",message)
        decmessage = self.decodeString(message,inputkey)
        #print("The decoded message will be :",decmessage)
        self.old_passwords = decmessage.split(" ")

    def updateFile(self):
        message = " ".join(self.old_passwords)
        encmessage = self.encodeString(message)
        #print("The encoded message will be :",encmessage)
        file1= open("password.txt",'wb')
        file1.write(encmessage)
        print("Passwords have been saved")
        file1.close()

    def encodeString(self,input):
        key = self.generatekey()
        fernet = Fernet(key)
        encmessage = fernet.encrypt(input.encode())
        return encmessage

    def decodeString(self,input,inputkey):
        try:
            pass_from_user = inputkey
            password = pass_from_user.encode()
            mysalt = b'\xf7\xa0\xd3g<\xe9\xa5\xee!\xb8\xe0\xb9\x1e\xee\x98\xeb'

            kdf = PBKDF2HMAC (
                algorithm=hashes.SHA256,
                length = 32,
                salt = mysalt,
                iterations=100000,
                backend=default_backend()

            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            fernet = Fernet(key)
            decmessage = fernet.decrypt(input)
            return decmessage.decode()
        except Exception:
            print("Invalid Password, Closing Program")
            exit()    
        
    def generatekey(self):
            pass_from_user = self.old_passwords[-1]
            password = pass_from_user.encode()
            mysalt = b'\xf7\xa0\xd3g<\xe9\xa5\xee!\xb8\xe0\xb9\x1e\xee\x98\xeb'

            kdf = PBKDF2HMAC (
                algorithm=hashes.SHA256,
                length = 32,
                salt = mysalt,
                iterations=100000,
                backend=default_backend()

            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            #print(key)
            return key         
          

class PasswordManager(BasePasswordManager):
    def set_password(self,input1):
        if " " not in input1:
            input2=getpass.getpass(prompt="Re-Enter your Password : ")
            if input1 == input2:        
                if len(input1)>5:
                    if self.get_level(input1) > self.get_level(self.old_passwords[-1]) or self.get_level(input1) == 2:
                        #print(type(self.old_passwords))
                        #print("The old passwords are", self.old_passwords)          
                        self.old_passwords.append(input1)
                        #print("The list will be :",self.old_passwords)
                        self.updateFile()
                        
                    else:
                        print("New password must be of the highest security level (2) or higher level than previous password (",self.get_level(self.old_passwords[-1]),") for a successful password change")    
                else:
                    print("New password should be longer than 6 characters")
            else:
                print("Incorrect Password, Password is Unchanged")
        else:
            print("No space allowed in the password")                  
    
    def get_level(self,input):
        #if ' ' in input:
        #    return("Invalid Input, cannot contain any space")
        output = 0        
        if input.isdigit() or input.isalpha():
            output = 0
        elif input.isalnum():
            output = 1
        elif re.search('[a-zA-Z]', input) and re.search('[0-9]', input):
            output = 2
        return output 

if __name__=="__main__":
    #pm1 = PasswordManager()    
    flag=True
    while flag==True:
        print("\n Welcome to your password manager !")

        #change code below to a check for if the password manager file exists
        #if pm1.get_password()==0:
        #print("The password file exists : ",os.path.exists("password.txt"))
        if not os.path.exists("password.txt") or os.stat("password.txt").st_size==0:
            input1 = getpass.getpass(prompt="\nEnter your first Password : ")
            pm1 = PasswordManager() #A new blank file gets created here
            #print("The type of old_passwords are :",type(pm1.old_passwords))
            #pm1.old_passwords.append(input1)
            pm1.set_password(input1)
        else:
            #print("your current password",len(pm1.old_passwords))
            input_password = getpass.getpass(prompt="\nEnter your current Password : ")
            pm1 = PasswordManager()
            pm1.updateList(input_password)
            #print("The current password is : ",pm1.get_password())
            if input_password == pm1.get_password():
                print("Password is valid!")
                print("\n Select your Option :")
                print("\t 1. Get Current Password")
                print("\t 2. Check if input password is correct")
                print("\t 3. Set New Password")
                print("\t 4. Get Current Password Level")            
                print("\t 5. Print ALL Passwords")
                print("\t 6. Clear ALL Passwords")
                print("\t 7. Exit")
                choice = input("Your Choice:")
                if choice=="1":
                    output = pm1.get_password()
                    print(output)
                elif choice=="2":
                    input1=getpass.getpass(prompt="Enter your string : ")
                    print(pm1.is_correct(input1))
                elif choice=="3":
                    input1=getpass.getpass(prompt="\nEnter your new Password : ")                    
                    pm1.set_password(input1)
                elif choice=="4":     
                    pwd = pm1.get_password()               
                    output =pm1.get_level(pwd)
                    print("Your current Level will be :",output)
                elif choice=="5":
                    print(pm1.old_passwords)
                elif choice=="6":
                    input1 = input("are you sure you want to delete all passwords? y/n : ")
                    if input1=="y" or input1=="Y":
                        pm1.old_passwords.clear()
                        print("Exiting the Password_Manager")
                        os.remove("password.txt")
                        exit()
                elif choice=="7":                
                    exit()      
                else:
                    print("\nInvalid choice")

            else:
                print("Password is invalid")
                flag=False

              
        
