from flask import Flask, render_template, request, redirect, url_for
import os
import hashlib
import random
import string
import subprocess
app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    _, ext = os.path.splitext(filename)
    return ext.lower() == '.py'

def generate_random_hash():
    return hashlib.sha256(str(random.getrandbits(256)).encode()).hexdigest()
    
def clean_file_content(content: bytes) -> bytes:
    return content.translate(bytes.maketrans(b"()}{|?!^", b"        "))  

def check_token(content: bytes):
    if b"TomorinIsCuteAndILovePython" in content:
        return 0
    else:
        return 1

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    if file and allowed_file(file.filename):
        ext = file.filename.split('.', 1)[1].lower()
        random_hash = generate_random_hash()
        filename = os.path.join(app.config['UPLOAD_FOLDER'], f'main_{random_hash}.{ext}')
        file_content = file.read()
        if check_token(file_content):
            return f"Token not found!"
        clean_content = clean_file_content(file_content)

        with open(filename, 'wb') as f:
            f.write(b'exit()\n')
            f.write(clean_content)

        try:
            result = subprocess.run(
                ['python3', filename],
                capture_output=True, 
                text=True,          
                timeout=10    
            )

            print(result.stdout)  
            if result.stderr:
                print(result.stderr) 

            return f'Success Execute! But if you don\'t get flag...You Lose...'

        except subprocess.TimeoutExpired as e:
            return f'Timeout Error! You Lose ... '
        except Exception as e:
            return f"Something went wrong! You Lose"

    return 'Your file is not \'.py\'.'

if __name__ == '__main__':
    app.run(host="0.0.0.0",port="10000",debug=False)
