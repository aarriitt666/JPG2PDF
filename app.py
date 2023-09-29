# This app is using an older flask version because it relies on flask_uploads which isn't compatible to the newer
# flask version.

from flask import Flask, render_template, request, send_from_directory, jsonify
from flask_uploads import UploadSet, configure_uploads, IMAGES
from flask_wtf.csrf import CSRFProtect
from PIL import Image
import PyPDF2
import os
from dotenv import load_dotenv
from flask import redirect, url_for

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')  # Please change this to a secure key

csrf = CSRFProtect(app)

photos = UploadSet('photos', IMAGES)
app.config['UPLOADED_PHOTOS_DEST'] = 'uploads'
configure_uploads(app, photos)

MAX_IMAGES = int(os.getenv('MAX_IMAGES'))
MAX_PDF_SIZE_MB = int(os.getenv('MAX_PDF_SIZE_MB'))
MAX_PDF_SIZE_BYTES = MAX_PDF_SIZE_MB * 1024 * 1024  # Convert MB to Bytes


def sanitize_directory(directory):
    # Remove any up-level references and redundant separators
    sanitized = os.path.normpath(directory)

    # Get the base name to prevent directory traversal
    sanitized = os.path.basename(sanitized)

    if not sanitized or sanitized == ".":
        raise ValueError("Invalid directory name provided")

    return sanitized


@app.route('/')
def index():
    return redirect(url_for('upload'))


# @app.route('/upload', methods=['GET', 'POST'])
# def upload():
#     if request.method == 'POST' and 'photo' in request.files:
#         try:
#             # Get the directory from user input
#             directory = sanitize_directory(request.form.get('directory'))
#
#         except ValueError as e:
#             # Return a JSON error message for AJAX
#             return jsonify(success=False, error=str(e))
#
#         # Ensure the base directory 'my_uploads' exists
#         base_dir = 'my_uploads'
#         if not os.path.exists(base_dir):
#             os.makedirs(base_dir)
#
#         # Set the upload destination dynamically
#         upload_dest = os.path.join(base_dir, directory)
#         app.config['UPLOADED_PHOTOS_DEST'] = upload_dest
#
#         # Reconfigure the UploadSet
#         configure_uploads(app, photos)
#
#         # Ensure the directory exists
#         if not os.path.exists(upload_dest):
#             os.makedirs(upload_dest)
#
#         # Save uploaded images
#         uploaded_files = request.files.getlist('photo')
#         filenames = [photos.save(file) for file in uploaded_files]
#
#         # Convert images to PDFs
#         pdf_files = []
#         for filename in filenames:
#             with Image.open(os.path.join(app.config['UPLOADED_PHOTOS_DEST'], filename)) as img:
#                 pdf_filename = filename + ".pdf"
#                 img.convert('RGB').save(os.path.join(app.config['UPLOADED_PHOTOS_DEST'], pdf_filename))
#                 pdf_files.append(pdf_filename)
#
#         # Merge PDFs and add bookmarks
#         merger = PyPDF2.PdfMerger()
#         for index, pdf_file in enumerate(pdf_files):
#             with open(os.path.join(app.config['UPLOADED_PHOTOS_DEST'], pdf_file), 'rb') as f:
#                 merger.append(f)
#                 merger.add_outline_item(title=f"Image {index + 1}", pagenum=index, parent=None)
#
#         # Save the merged PDF
#         output_pdf = "merged.pdf"
#         with open(os.path.join(app.config['UPLOADED_PHOTOS_DEST'], output_pdf), 'wb') as out:
#             merger.write(out)
#
#         # Clean up individual PDFs and images
#         for file in pdf_files + filenames:
#             os.remove(os.path.join(app.config['UPLOADED_PHOTOS_DEST'], file))
#
#         # After successfully processing the images and creating the merged PDF
#         relative_path = os.path.join(directory, output_pdf)
#         return jsonify(success=True, path=relative_path)
#
#     return render_template('upload.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST' and 'photo' in request.files:
        uploaded_files = request.files.getlist('photo')

        # Check for number of images
        if len(uploaded_files) > MAX_IMAGES:
            return jsonify(success=False, error=f"Exceeded the limit of {MAX_IMAGES} images.")

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

        # Check for size of the generated PDF
        output_pdf_path = os.path.join(app.config['UPLOADED_PHOTOS_DEST'], output_pdf)
        if os.path.getsize(output_pdf_path) > MAX_PDF_SIZE_BYTES:
            os.remove(output_pdf_path)
            return jsonify(success=False, error=f"Generated PDF exceeds the size limit of {MAX_PDF_SIZE_MB} MB.")

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


@app.route('/list_pdfs', methods=['GET'])
def list_pdfs():
    base_dir = 'my_uploads'
    page = int(request.args.get('page', 1))
    items_per_page = 3  # Adjust as needed
    start_index = (page - 1) * items_per_page
    end_index = start_index + items_per_page

    pdfs = {}
    all_folders = sorted(os.listdir(base_dir))
    paginated_folders = all_folders[start_index:end_index]

    for folder in paginated_folders:
        folder_path = os.path.join(base_dir, folder)
        if os.path.isdir(folder_path):
            pdfs[folder] = [f for f in os.listdir(folder_path) if f.endswith('.pdf')]

    return jsonify({
        "pdfs": pdfs,
        "total_pages": -(-len(all_folders) // items_per_page)  # Ceiling division
    })


if __name__ == '__main__':
    app.run(debug=True)
