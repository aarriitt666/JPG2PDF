from flask import Flask, render_template, request, send_from_directory, jsonify
from flask_uploads import UploadSet, configure_uploads, IMAGES
from flask_wtf.csrf import CSRFProtect
from PIL import Image
import PyPDF2
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')  # Please change this to a secure key

csrf = CSRFProtect(app)

photos = UploadSet('photos', IMAGES)
app.config['UPLOADED_PHOTOS_DEST'] = 'uploads'
configure_uploads(app, photos)


def sanitize_directory(directory):
    # Remove any up-level references and redundant separators
    sanitized = os.path.normpath(directory)

    # Get the base name to prevent directory traversal
    sanitized = os.path.basename(sanitized)

    if not sanitized or sanitized == ".":
        raise ValueError("Invalid directory name provided")

    return sanitized


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST' and 'photo' in request.files:
        try:
            # Get the directory from user input
            directory = sanitize_directory(request.form.get('directory'))

        except ValueError as e:
            # Return a JSON error message for AJAX
            return jsonify(success=False, error=str(e))

        # Ensure the base directory 'my_uploads' exists
        base_dir = 'my_uploads'
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)

        # Set the upload destination dynamically
        upload_dest = os.path.join(base_dir, directory)
        app.config['UPLOADED_PHOTOS_DEST'] = upload_dest

        # Reconfigure the UploadSet
        configure_uploads(app, photos)

        # Ensure the directory exists
        if not os.path.exists(upload_dest):
            os.makedirs(upload_dest)

        # Save uploaded images
        uploaded_files = request.files.getlist('photo')
        filenames = [photos.save(file) for file in uploaded_files]

        # Convert images to PDFs
        pdf_files = []
        for filename in filenames:
            with Image.open(os.path.join(app.config['UPLOADED_PHOTOS_DEST'], filename)) as img:
                pdf_filename = filename + ".pdf"
                img.convert('RGB').save(os.path.join(app.config['UPLOADED_PHOTOS_DEST'], pdf_filename))
                pdf_files.append(pdf_filename)

        # Merge PDFs and add bookmarks
        merger = PyPDF2.PdfMerger()
        for index, pdf_file in enumerate(pdf_files):
            with open(os.path.join(app.config['UPLOADED_PHOTOS_DEST'], pdf_file), 'rb') as f:
                merger.append(f)
                merger.add_outline_item(title=f"Image {index + 1}", pagenum=index, parent=None)

        # Save the merged PDF
        output_pdf = "merged.pdf"
        with open(os.path.join(app.config['UPLOADED_PHOTOS_DEST'], output_pdf), 'wb') as out:
            merger.write(out)

        # Clean up individual PDFs and images
        for file in pdf_files + filenames:
            os.remove(os.path.join(app.config['UPLOADED_PHOTOS_DEST'], file))

        # After successfully processing the images and creating the merged PDF
        relative_path = os.path.join(directory, output_pdf)
        return jsonify(success=True, path=relative_path)

    return render_template('upload.html')


@app.route('/<path:filename>', methods=['GET', 'POST'])
def download(filename):
    return send_from_directory(directory='my_uploads', filename=filename)


if __name__ == '__main__':
    app.run(debug=True)
