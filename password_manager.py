import base64
import os
import argparse
import getpass
import time
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class PasswordManager:

    def __init__(self, add_bool, list_bool, remove_bool):
        self.add_bool = add_bool
        self.list_bool = list_bool
        self.remove_bool = remove_bool
        self.data_name = "password_manager_data.dat"
        self.salt_name = "password_manager_salt.dat"
        self.first_run = self.check_if_first_run()
        self.salt = self.generate_salt()

    def generate_key(self, provided_password):
        password = provided_password.encode()
        salt = self.salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key

    def decrypt(self, key):
        with open(self.data_name, 'rb') as f:
            data = f.read()
        try:
            decrypted = Fernet(key).decrypt(data)
        except InvalidToken:
            print("Incorrect password, please try again")
            if self.add_bool:
                self.add_account()
            elif self.list_bool:
                self.list_accounts()
            elif self.remove_bool:
                self.remove_account()
        with open(self.data_name, 'wb') as f:
            f.write(decrypted)

    def encrypt(self, key):
        with open(self.data_name, 'rb') as f:
            data = f.read()
        os.remove(self.data_name)
        fernet = Fernet(key)
        encrypted = fernet.encrypt(data)
        with open(self.data_name, 'wb') as f:
            f.write(encrypted)

    def check_if_first_run(self):
        try:
            open(self.data_name)
        except FileNotFoundError:
            open(self.data_name, "x")
            open(self.salt_name, "x")
            return True
        else:
            return False

    def generate_salt(self):
        if self.first_run:
            salt = os.urandom(32)
            with open(self.salt_name, "wb") as f:
                f.write(salt)
            return salt
        else:
            with open(self.salt_name, "rb") as f:
                salt = f.read()
            return salt

    def list_accounts(self):
        password = getpass.getpass()
        key = self.generate_key(password)
        self.decrypt(key)
        empty_file = os.stat(self.data_name).st_size == 0
        with open(self.data_name, 'r') as f:
            lines = f.readlines()
        self.encrypt(key)
        if empty_file:
            print("Your password manager is empty")
        else:
            for line in lines:
                convertdict = eval(line)
                print("\n")
                for credential, value in convertdict.items():
                    print("{}: {}".format(credential, value))
                print("\n")

    def add_account(self):
        password = getpass.getpass()
        key = self.generate_key(password)
        self.decrypt(key)
        self.encrypt(key)
        loop = True
        while loop:
            accountname = input("Enter account name: ")
            username = input("Enter username: ")
            password = getpass.getpass("Enter password: ")
            account = dict(Account=accountname, Username=username, Password=password)
            self.decrypt(key)
            with open(self.data_name, 'a') as f:
                f.write(str(account) + "\n")
            self.encrypt(key)
            loop_answer = input("Add another account? (y/n): ").lower()
            if loop_answer == "n" or loop_answer == "no":
                break

    def remove_account(self):
        password = getpass.getpass()
        key = self.generate_key(password)
        self.decrypt(key)
        empty_file = os.stat(self.data_name).st_size == 0
        with open(self.data_name, 'r') as f:
            lines = f.readlines()
        self.encrypt(key)
        if empty_file:
            print("Your password manager is empty")
            quit()
        else:
            for line in lines:
                convertdict = eval(line)
                print("\n")
                for credential, value in convertdict.items():
                    print("{}: {}".format(credential, value))
        remove_answer = input("\nEnter the account name or username of the entry you want to delete: ")
        line_count = 0
        for line in lines:
            convertdict = eval(line)
            for credential, value in convertdict.items():
                if value == remove_answer:
                    lines.pop(line_count)
                    self.decrypt(key)
                    with open(self.data_name, 'a') as w:
                        f.write()
                    self.encrypt(key)
                    for line in lines:
                        write_line = eval(line)
                        self.decrypt(key)
                        with open(self.data_name, 'a') as f:
                            f.write(str(write_line) + "\n")
                        self.encrypt(key)
                    quit()
            line_count += 1

    def setup(self):
        print("You have not set a password yet, please set a password")
        print("WARNING: Do not forget the password, you cannot reset it and you will lose your data if you forget!")
        password = getpass.getpass("Password: ")
        confirmpassword = getpass.getpass("Confirm password: ")
        if password == confirmpassword:
            key = self.generate_key(password)
            self.encrypt(key)
            print("Password set, please sign in")
        else:
            print("The passwords you entered do not match, please make sure both passwords match")
            self.setup()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--add", help="adds an account", action="store_true")
    parser.add_argument("-l", "--list", help="lists your stored accounts", action="store_true")
    parser.add_argument("-r", "--remove", help="removes an account entry", action="store_true")
    args = parser.parse_args()

    execute = PasswordManager(args.add, args.list, args.remove)
    if args.list and execute.first_run:
        execute.setup()
        execute.list_accounts()
    elif args.list:
        execute.list_accounts()
    elif args.add and execute.first_run:
        execute.setup()
        execute.add_account()
    elif args.add:
        execute.add_account()
    elif args.remove and execute.first_run:
        execute.setup()
        execute.remove_account()
    elif args.remove:
        execute.remove_account()
    else:
        print("No arguments were given, please execute this Python script from a command line with one of the arguments below\n")
        parser.print_help()
        time.sleep(5)
