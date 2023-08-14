from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.templating import Jinja2Templates
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
import base64
import struct
from PIL import Image
import os

app = FastAPI()
templates = Jinja2Templates(directory="templates")

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


def embed_message_into_image(plaintext, key, input_image_file, output_image_path):
    # Encrypt the plaintext using AES
    encrypted_message = aes_encrypt(plaintext.encode(), key)

    # Encode the message length as a 4-byte integer
    message_length_bytes = struct.pack('>I', len(encrypted_message))
    encrypted_message_with_length = message_length_bytes + encrypted_message.encode()

    # Load the input image and convert to RGBA mode
    image = Image.open(input_image_file).convert('RGBA')

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
def extract_message_from_image(key, image_file):
    # Load the image with the hidden message and convert to RGBA mode
    image = Image.open(image_file).convert('RGBA')

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

@app.on_event("startup")
async def startup_event():
    # Create the 'uploads' directory if it doesn't exist
    if not os.path.exists("uploads"):
        os.makedirs("uploads")

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/embed", response_class=HTMLResponse)
async def embed_page(request: Request):
    return templates.TemplateResponse("embed.html", {"request": request})

@app.post("/embed/")
async def embed_message(
    request: Request,
    password: str = Form(...),
    message: str = Form(...),
    image: UploadFile = File(...),
):
    output_image_path = os.path.join("uploads", "output.png")

    with open(output_image_path, "wb") as output_file:
        try:
            embed_message_into_image(message, password, image.file, output_file)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    return FileResponse(output_image_path, headers={"Content-Disposition": "attachment; filename=output.png"})

@app.get("/extract", response_class=HTMLResponse)
async def extract_page(request: Request):
    return templates.TemplateResponse("extract.html", {"request": request})

@app.post("/extract/")
async def extract_message(
    request: Request,
    password: str = Form(...),
    image: UploadFile = File(...),
):
    try:
        extracted_message = extract_message_from_image(password, image.file)
        return {"extracted_message": extracted_message}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
