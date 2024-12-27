def func(num, digit):
    index = 0
    while num > 0:
        if num % 10 == digit:
            print(index)
        index += 1
        num = int(num / 10)


# ------------------------------------
def func2(num):
    for i in range(10):
        print(func(num, i))


# ---------------------------------------------
for i in range(1, 101):
    count = 0
    for j in range(2, i):
        if i % j == 0:
            count += 1
    if count == 0:
        print(i)
# -------------------------------------------------
def sum_of_digit(num, n):
    s = 0
    for i in range(0, n):
        s += num % 10
        num = int(num / 10)
    return s


# -----------------------------------------------
names = ["effi", "david", "yoni"]
print(len(names))
for i in names:
    print(i)
names.append("beni")
names.pop(1)
names.remove("effi")

numbers = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
d = 1
for i in numbers:
    d *= i
print(sum(numbers), d, sum(numbers) / len(numbers))
# -----------------------------------------------
def ex15(numbers):
    c = 0
    for i in range(len(numbers)):
        if pow(i+1, 3) == numbers[i]:
            c += 1
    return c


arr = [1, 4, 27]
print(ex15(arr))
# --------------------------------------------------------
def biggest_avg(numbers):
    avg = 0
    to_print = ()
    for i in range((len(numbers) - 1)):
        if (numbers[i] + numbers[i + 1]) / 2 > avg:
            avg = (numbers[i] + numbers[i + 1]) / 2
            to_print = (numbers[i], numbers[i+1])
    print(to_print)


biggest_avg([2, 8, 1, 5, 7, 3, 9, 4, 4, 1, 7, 3, -1])
# --------------------------------------------------------
def ex24(numbers):
    for i in range(0, (len(numbers) - 2) + 2):
        if numbers[i] > numbers[i + 2]:
            return False
    for i in range(1, (len(numbers) - 1) + 2):
        if numbers[i] < numbers[i + 2]:
            return False
    return True


ex24([1, 2, 3, 4, 5, 6, 7, 8, 9])
# --------------------------------------------------------
def ex28_1(num):
    s = 0
    while num > 0:
        s += num % 10
        num = int(num / 10)
    return s


def ex28_2(num):
    c = 0
    for i in range(2, num+1, 2):
        if num % i == 0:
            c += 1
    return c


def ex28_3(numbers):
    c = 0
    for i in numbers:
        if ex28_1(i) == ex28_2(i):
            c += 1
    if c > len(numbers) / 2:
        print("beautiful")
    else:
        print("ugly")
# ---------------------arrays-----------------------------------

def ex3(numbers):
    print(sum(numbers), sum(numbers) / len(numbers))
    for i in numbers:
        if i > sum(numbers) / len(numbers):
            print(i - (sum(numbers) / len(numbers)))
        else:
            print((sum(numbers) / len(numbers)) - i)


def ex4(numbers):
    for i in range(0, len(numbers), 2):
        print(i)


def ex5(numbers):
    temp = numbers[0]
    numbers[0] = numbers[len(numbers) - 1]
    numbers[len(numbers) - 1] = temp
    for i in range(1, (len(numbers) - 1), 2):
        numbers[i] = numbers[i + 1]
    return numbers


# print(ex5([1, 2, 3, 4, 5]))


def ex6(numbers):
    numbers.reverse()
    return numbers


def ex7(numbers):
    for i in range((len(numbers) - 1), 2):
        current = numbers[i]
        numbers[i] = numbers[i + 1]
        numbers[i + 1] = current
    return numbers


def ex8(numbers):
    evens_num = []
    for i in numbers:
        if i % 2 == 0:
            evens_num.append(i)
    return evens_num


def ex9(numbers):
    s = 0
    for i in numbers:
        s += i
        i = s
    return numbers


def ex10(n):
    numbers = [0, 1]
    for i in range(2, n):
        numbers.append(numbers[i - 2] + numbers[i - 1])
    numbers.reverse()
    return numbers


# -----------------------2D arrays-----------------------------------
matrix = [
        [1, 2, 3],
        [4, 5, 6],
        [7, 8, 9]
        ]

def ex1(matrix):
    s = 0
    for i in range(len(matrix)):
        s += matrix[i][i]
    return s


def ex2(matrix):
    s = 0
    j = len(matrix[0])
    for i in range(len(matrix)):
        s += matrix[i][j - 1]
        j -= 1
    return s


def ex3(matrix):
    for i in range(len(matrix)):
        s = 0
        for j in range(len(matrix[i])):
            s += matrix[i][j]
        print(s)


def ex4(matrix):
    c = 0
    for i in range(len(matrix)):
        c += 1
    if len(matrix[0]) == c:
        return True
    return False

# # ------------------------encrypted-------------------------------------

def me(message):  # if the index is even +4 if odd +3
    to_send = ""
    for i in range(len(message)):
        if (i % 2) == 0:
            to_send += chr(ord(message[i]) + 4)
        else:
            to_send += chr(ord(message[i]) + 3)
    return to_send


def you(encrypted_message):  # if the index is even -4 if odd -3
    real = ""
    for i in range(len(encrypted_message)):
        if (i % 2) == 0:
            real += chr(ord(encrypted_message[i]) - 4)
        else:
            real += chr(ord(encrypted_message[i]) - 3)
    return real


print(you("hallo"))
print(you(me("hallo")))

# # ------------------------encrypted with library-------------------------------------

from cryptography.fernet import Fernet


def generate_key():
    return Fernet.generate_key()


def symmetric_encrypt(text, key):
    cipher = Fernet(key)
    encrypted_text = cipher.encrypt(text.encode())
    return encrypted_text


def symmetric_decrypt(encrypted_text, key):
    cipher = Fernet(key)
    decrypted_text = cipher.decrypt(encrypted_text).decode()
    return decrypted_text


original_text = "Hello, World!"
key = generate_key()
encrypted_text = symmetric_encrypt(original_text, key)
print(f"Original Text: {original_text}")
print(f"Encrypted Text: {encrypted_text}")
decrypted_text = symmetric_decrypt(encrypted_text, key)
print(f"Decrypted Text: {decrypted_text}")


# # ------------------------ex-------------------------------------


from cryptography.fernet import Fernet


def generate_key():
    return Fernet.generate_key()


def symmetric_encrypt(number, key):
    return Fernet(key).encrypt(number.encode())


def symmetric_decrypt(encrypted_number, key):
    return Fernet(key).decrypt(encrypted_number.decode())


original_number = "12345"
key = generate_key()
encrypted_number = symmetric_encrypt(original_number, key)
print(f"Original Text: {int(original_number)}")
print(f"Encrypted Text: {encrypted_number}")
decrypted_number = int(symmetric_decrypt(encrypted_number, key))
print(f"Decrypted Number: {decrypted_number}")


def symmetric_encrypt(response, key):
    a = ""
    for i in range(len(response)):
        a += chr(ord(response[i]) ^ key)
        return a


def symmetric_decrypt(ciphertext, key):
    decrypted_request = ""
    for i in range(len(ciphertext)):
        decrypted_request += chr(ord(ciphertext[i]) ^ key)
        return decrypted_request


a = symmetric_encrypt("abc", 1234)
print(a)
print(symmetric_decrypt(a, 1234))

#-------------------------------------------------------------------------------

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.fernet import Fernet

# -----------------asymmetric-----------------------------------------------------------


def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


def generate_key():
    return Fernet.generate_key()


def save_key_to_file(key, filename):
    with open(filename, 'wb') as f:
        f.write(key)


def load_key_from_file(filename):
    with open(filename, 'rb') as f:
        return f.read()


def encrypt_message(message, public_key):
    return public_key.encrypt(message.encode(), padding.PKCS1v15())


def decrypt_message(ciphertext, private_key):
    return private_key.decrypt( ciphertext, padding.PKCS1v15()).decode()


def second_encrypt(text, key):
    return Fernet(key).encrypt(text.encode())


def second_decrypt(encrypted_text, key):
    return Fernet(key).decrypt(encrypted_text).decode()


private_key, public_key = generate_key_pair()
save_key_to_file(private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
), 'private_key.pem')

save_key_to_file(public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
), 'public_key.pem')

loaded_private_key = serialization.load_pem_private_key(
    load_key_from_file('private_key.pem'),
    password=None, backend=default_backend())

loaded_public_key = serialization.load_pem_public_key(
    load_key_from_file('public_key.pem'),
    backend=default_backend())

private_key2 = generate_key()
messages = ["Hello", "asymmetric", "encryption!"]
for i in messages:
    encrypted_message = encrypt_message(i, loaded_public_key)
    print("Encrypted message:", encrypted_message)
    second_encrypted_message = second_encrypt(decrypt_message(encrypted_message, loaded_private_key), private_key2)
    print("Second encrypted message:", second_encrypted_message)
    decrypted_message = second_decrypt(second_encrypted_message, private_key2)
    print("Decrypted message:", decrypted_message)

# -----------------symmetric-------------------------------------------------------------------


def generate_key():
    return Fernet.generate_key()


def symmetric_encrypt(text, key):
    return Fernet(key).encrypt(text.encode())


def symmetric_decrypt(encrypted_text, key):
    return Fernet(key).decrypt(encrypted_text.decode())


def symmetric_encrypt_number(number, key):
    return Fernet(key).encrypt(str(number).encode())


def symmetric_decrypt_number(encrypted_number, key):
    return Fernet(key).decrypt(encrypted_number.decode)

#--------------------------------------client / server--------------------------------------------------------

import socket


def symmetric_encrypt(message, key):
    encrypted_message = ""
    for i in range(len(message)):
        if (i % 2) == 0:
            encrypted_message += chr(ord(message[i]) + key)
        else:
            encrypted_message += chr(ord(message[i]) + (key+1))
    return encrypted_message


def symmetric_decrypt(ciphertext, key):
    decrypted_response = ""
    for i in range(len(ciphertext)):
        if (i % 2) == 0:
            decrypted_response += chr(ord(ciphertext[i]) - key)
        else:
            decrypted_response += chr(ord(ciphertext[i]) - (key+1))
    return decrypted_response


def client():
    key = 1234
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 10000))
    message = "Hello from the client!"
    encrypted_message = symmetric_encrypt(message, key)
    client_socket.send(encrypted_message.encode('utf-8'))
    response = client_socket.recv(1024).decode('utf-8')
    decrypted_response = symmetric_decrypt(response, key)
    print(f"Encrypted received response from server: {response}")
    print(f"Decrypted received response from server: {decrypted_response}")
    client_socket.close()


if __name__ == "__main__":
    client()

#-----------------------------------------------------------------------------------------

import socket
import threading


def symmetric_encrypt(response, key):
    encrypted_response = ""
    for i in range(len(response)):
        if (i % 2) == 0:
            encrypted_response += chr(ord(response[i]) + key)
        else:
            encrypted_response += chr(ord(response[i]) + (key+1))
    return encrypted_response


def symmetric_decrypt(ciphertext, key):
    decrypted_request = ""
    for i in range(len(ciphertext)):
        if (i % 2) == 0:
            decrypted_request += chr(ord(ciphertext[i]) - key)
        else:
            decrypted_request += chr(ord(ciphertext[i]) - (key+1))
    return decrypted_request


def handle_client(client_socket):
    key = 1234
    request = client_socket.recv(1024).decode('utf-8')
    decrypted_request = symmetric_decrypt(request, key)
    print(f"Encrypted received data from client: {request}")
    print(f"Decrypted received data from client: {decrypted_request}")
    response = "Hello from the server!"
    encrypted_response = symmetric_encrypt(response, key)
    client_socket.send(encrypted_response.encode('utf-8'))
    client_socket.close()


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 10000))
    server.listen(5)

    print("[*] Server listening on port 10000")

    while True:
        client, addr = server.accept()
        print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")

        client_handler = threading.Thread(target=handle_client, args=(client,))
        client_handler.start()


if __name__ == "__main__":
    start_server()