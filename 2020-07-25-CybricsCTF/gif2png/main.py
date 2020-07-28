import logging
import re
import subprocess
import uuid
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_bootstrap import Bootstrap
import os
from werkzeug.utils import secure_filename
import filetype


ALLOWED_EXTENSIONS = {'gif'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = './uploads'
app.config['SECRET_KEY'] = '********************************'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024  # 500Kb
ffLaG = "cybrics{********************************}"
Bootstrap(app)
logging.getLogger().setLevel(logging.DEBUG)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    logging.debug(request.headers)
    if request.method == 'POST':
        if 'file' not in request.files:
            logging.debug('No file part')
            flash('No file part', 'danger')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            logging.debug('No selected file')
            flash('No selected file', 'danger')
            return redirect(request.url)

        if not allowed_file(file.filename):
            logging.debug(f'Invalid file extension of file: {file.filename}')
            flash('Invalid file extension', 'danger')
            return redirect(request.url)

        if file.content_type != "image/gif":
            logging.debug(f'Invalid Content type: {file.content_type}')
            flash('Content type is not "image/gif"', 'danger')
            return redirect(request.url)

        if not bool(re.match("^[a-zA-Z0-9_\-. '\"\=\$\(\)\|]*$", file.filename)) or ".." in file.filename:
            logging.debug(f'Invalid symbols in filename: {file.content_type}')
            flash('Invalid filename', 'danger')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))

            mime_type = filetype.guess_mime(f'uploads/{file.filename}')
            if mime_type != "image/gif":
                logging.debug(f'Invalid Mime type: {mime_type}')
                flash('Mime type is not "image/gif"', 'danger')
                return redirect(request.url)

            uid = str(uuid.uuid4())
            os.mkdir(f"uploads/{uid}")

            logging.debug(f"Created: {uid}. Command: ffmpeg -i 'uploads/{file.filename}' \"uploads/{uid}/%03d.png\"")

            command = subprocess.Popen(f"ffmpeg -i 'uploads/{file.filename}' \"uploads/{uid}/%03d.png\"", shell=True)
            command.wait(timeout=15)
            logging.debug(command.stdout)

            flash('Successfully saved', 'success')
            return redirect(url_for('result', uid=uid))

    return render_template("form.html")


@app.route('/result/<uid>/')
def result(uid):
    images = []
    for image in os.listdir(f"uploads/{uid}"):
        mime_type = filetype.guess(str(Path("uploads") / uid / image))
        if image.endswith(".png") and mime_type is not None and mime_type.EXTENSION == "png":
            images.append(image)

    return render_template("result.html", uid=uid, images=images)


@app.route('/uploads/<uid>/<image>')
def image(uid, image):
    logging.debug(request.headers)
    dir = str(Path(app.config['UPLOAD_FOLDER']) / uid)
    return send_from_directory(dir, image)


@app.errorhandler(413)
def request_entity_too_large(error):
    return "File is too large", 413


if __name__ == "__main__":
    app.run(host='localhost', port=5000, debug=False, threaded=True)
