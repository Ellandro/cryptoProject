import rsa
# create a key pair with 1024 bits key length
(public_key, private_key) = rsa.newkeys(1024)

# Encrypting a message
message = b"Hello, world!"
encrypted_message = rsa.encrypt(message, public_key)

# Decrypting the message
decrypted_message = rsa.decrypt(encrypted_message, private_key)

print("Encrypted message:", encrypted_message)
print("Decrypted message:", decrypted_message.decode())