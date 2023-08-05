from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
import base64
import struct
from PIL import Image

def get_key_from_password(password, salt):
    # Derive a 256-bit key from the provided password and salt
    key = PBKDF2(password, salt, dkLen=32, count=1000000)
    return key

def aes_encrypt(plaintext, key):
    # Generate a random salt
    salt = get_random_bytes(16)
    key = get_key_from_password(key.encode(), salt)

    # Generate a random IV (Initialization Vector)
    iv = get_random_bytes(16)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return base64.b64encode(salt + iv + ciphertext).decode('utf-8')

def aes_decrypt(ciphertext, key):
    # Decode the base64 ciphertext and extract salt and IV
    ciphertext = base64.b64decode(ciphertext)
    salt = ciphertext[:16]
    iv = ciphertext[16:32]
    ciphertext = ciphertext[32:]
    key = get_key_from_password(key.encode(), salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted.decode('utf-8')

def embed_message_into_image(plaintext, key, input_image_path, output_image_path):
    # Encrypt the plaintext using AES
    encrypted_message = aes_encrypt(plaintext.encode(), key)

    # Encode the message length as a 4-byte integer
    message_length_bytes = struct.pack('>I', len(encrypted_message))
    encrypted_message_with_length = message_length_bytes + encrypted_message.encode()

    # Load the input image and convert to RGBA mode
    image = Image.open(input_image_path).convert('RGBA')

    # Ensure the image size can accommodate the encrypted message
    image_size = image.width * image.height * 4
    message_size = len(encrypted_message_with_length)
    if message_size > image_size:
        raise ValueError("Message is too large to embed in the image.")

    # Embed the encrypted message into the image's pixels
    pixel_values = list(image.getdata())
    for i, byte in enumerate(encrypted_message_with_length):
        pixel_values[i] = (*pixel_values[i][:3], byte)

    # Create a new image with the updated pixel values
    new_image = Image.new('RGBA', image.size)
    new_image.putdata(pixel_values)

    # Save the new image with the secret message
    new_image.save(output_image_path)

def extract_message_from_image(key, image_path):
    # Load the image with the hidden message and convert to RGBA mode
    image = Image.open(image_path).convert('RGBA')

    # Extract the first 4 bytes to get the message length
    first_pixels = list(image.getdata())[:4]
    message_length_bytes = bytes([p[3] for p in first_pixels])
    message_length = struct.unpack('>I', message_length_bytes)[0]

    # Extract the encrypted message bytes from the subsequent pixels
    encrypted_message_bytes = []
    for i in range(4, message_length + 4):
        pixel_value = image.getdata()[i]
        encrypted_message_bytes.append(pixel_value[3])

    # Convert the bytes to a string and decrypt using AES
    encrypted_message = bytes(encrypted_message_bytes).decode('utf-8')
    decrypted_message = aes_decrypt(encrypted_message, key)

    return decrypted_message

def main():
    while True:
        print("1. Embed Message into Image")
        print("2. Extract Message from Image")
        print("3. Exit")
        choice = input("Enter your choice (1/2/3): ")

        if choice == '1':
            password = input("Enter the encryption key: ")
            message = input("Enter the message to be embedded: ")
            input_image = input("Enter the path to the input image: ")
            output_image = input("Enter the path to save the output image: ")
            try:
                embed_message_into_image(message, password, input_image, output_image)
                print("Message embedded and image saved.")
            except ValueError as e:
                print("Error:", e)
        elif choice == '2':
            password = input("Enter the decryption key: ")
            image_path = input("Enter the path to the image with the hidden message: ")
            extracted_message = extract_message_from_image(password, image_path)
            print("Extracted Message:", extracted_message)
        elif choice == '3':
            break
        else:
            print("Invalid choice. Please select 1, 2, or 3.")

if __name__ == "__main__":
    main()
