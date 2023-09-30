# This app is using an older flask version because it relies on flask_uploads which isn't compatible to the newer
# flask version. If this is your first time running this script or database got refresh somehow, you need to do [
# flask initdb] in the terminal.

# TODO:  Need to encrypt users' password.  Right now if user registers for an account the password is in plain text.
# TODO:  Implement admin panel
# TODO:  Implement user panel
# TODO:  Admin and User panel should have Inbox for receiving messages from each other user.
# TODO:  Implement request to download a pdf file if the file isn't belonging to the same user.
#  If it's then no need to ask for permission.  The request would go to the inbox and if the other user approves inside
#  the inbox then the message would return to the request user with a specific download link for this specific pdf
#  file with expiration date and time.


from flask import Flask, render_template, request, send_from_directory, jsonify, flash
from flask_uploads import UploadSet, configure_uploads, IMAGES
from flask_wtf.csrf import CSRFProtect
from PIL import Image
import PyPDF2
import os
from dotenv import load_dotenv
from flask import redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, validators
from flask.cli import with_appcontext
from flask_migrate import init as _init
import shutil
from werkzeug.security import generate_password_hash, check_password_hash

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

DATABASE_URI = os.getenv('DATABASE_URI')
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

flask_app = os.getenv('FLASK_APP')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class PasswordChangeForm(FlaskForm):
    current_password = PasswordField('Current Password', [
        validators.DataRequired(),
    ])
    new_password = PasswordField('New Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm_new', message='New passwords must match')
    ])
    confirm_new = PasswordField('Confirm New Password')
    submit = SubmitField('Change Password')


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = PasswordChangeForm()
    if form.validate_on_submit():
        # Verify if the current password is correct
        is_correct_plain_text = current_user.password == form.current_password.data
        is_correct_hashed = check_password_hash(current_user.password, form.current_password.data)

        if not is_correct_plain_text and not is_correct_hashed:
            flash('Current password is incorrect.', 'danger')
            return render_template('change_password.html', form=form)

        # Update the password with the new hashed password
        hashed_password = generate_password_hash(form.new_password.data, method='sha256')
        current_user.password = hashed_password
        db.session.commit()

        # Update the needs_password_update flag
        current_user.needs_password_update = False
        db.session.commit()

        flash('Your password has been updated!', 'success')
        return redirect(url_for('index'))

    return render_template('change_password.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    login_failed = False
    if request.method == 'POST':
        # Get the form data
        username = request.form['username']
        password = request.form['password']

        # Check the database for this user
        user = User.query.filter_by(username=username).first()

        # Validate the user
        if user and user.check_password(password):  # Using the check_password method
            login_user(user)

            # Check if the user is an admin with a plain text password
            if user.is_admin or user.password == password:
                user.needs_password_update = True
                db.session.commit()

            # Redirect to change password if necessary
            if user.needs_password_update:
                flash('You need to update your password.', 'warning')
                return redirect(url_for('change_password'))

            return redirect(url_for('index'))
        else:
            login_failed = True

    return render_template('login.html', login_failed=login_failed)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # Add this line
    uploads = db.relationship('Upload', backref='user', lazy=True)
    needs_password_update = db.Column(db.Boolean, default=True)

    def check_password(self, password):
        # First check for plain text match
        if self.password == password:
            return True

        # Then check for hashed password match
        return check_password_hash(self.password, password)


class Upload(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


def sanitize_directory(directory):
    # Remove any up-level references and redundant separators
    sanitized = os.path.normpath(directory)

    # Get the base name to prevent directory traversal
    sanitized = os.path.basename(sanitized)

    if not sanitized or sanitized == ".":
        raise ValueError("Invalid directory name provided")

    return sanitized


class RegistrationForm(FlaskForm):
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email Address', [validators.Length(min=6, max=35)])
    password = PasswordField('New Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password')
    submit = SubmitField('Register')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_users = User.query.all()
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, password=hashed_password)
        new_user.needs_password_update = False

        # If this is the first user, set them as admin
        if not existing_users:
            new_user.is_admin = True

        db.session.add(new_user)
        db.session.commit()

        # Here, you would typically hash the password and save the user details to the database
        # For demonstration purposes, let's just print the form data
        print(f"Registered user: {form.username.data}, Email: {form.email.data}")
        # Redirect to a success page or login page
        return redirect(url_for('index'))
    return render_template('register.html', form=form)


@app.route('/')
def index():
    return redirect(url_for('upload'))


@app.route('/upload', methods=['GET', 'POST'])
@login_required
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

        full_output_path = directory + '/' + output_pdf
        upload_record = Upload(filename=full_output_path, user_id=current_user.id)
        db.session.add(upload_record)
        db.session.commit()

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
@login_required
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

    # Add ownership information
    ownerships = {}
    for folder in all_folders:
        uploads = Upload.query.filter_by(filename=f"{folder}/merged.pdf").first()
        if uploads:
            ownerships[folder] = uploads.user_id

    print("Ownerships:", ownerships)

    return jsonify({
        "pdfs": pdfs,
        "ownerships": ownerships,
        "current_user_id": current_user.id if current_user.is_authenticated else None,
        "is_admin": current_user.is_admin if current_user.is_authenticated else False,
        "total_pages": -(-len(all_folders) // items_per_page)  # Ceiling division
    })


@app.route('/delete/<path:filename>', methods=['POST'])
@login_required
def delete_file(filename):
    filepath = os.path.join('my_uploads', filename)

    # Check if the file exists
    if not os.path.exists(filepath):
        return jsonify(success=False, error="File does not exist."), 404

    # Try to remove the file
    try:
        os.remove(filepath)
    except Exception as e:
        return jsonify(success=False, error=f"Error deleting file: {str(e)}"), 500

    # Try to remove the parent folder (only if it's empty)
    parent_folder = os.path.dirname(filepath)
    try:
        # We use shutil.rmtree to ensure the folder is deleted even if not empty.
        # However, be cautious with this. Make sure you really want to delete everything inside that folder.
        shutil.rmtree(parent_folder)
    except Exception as e:
        return jsonify(success=False, error=f"Error deleting folder: {str(e)}"), 500

    # If there's a reference in the database, remove it
    upload_record = Upload.query.filter_by(filename=filename).first()
    if upload_record:
        db.session.delete(upload_record)
        db.session.commit()

    return jsonify(success=True, message="File and parent folder deleted successfully."), 200


@app.cli.command("initdb")
@with_appcontext
def init_db_command():
    """Initialize the database."""
    _init(directory="migrations")
    print("Initialized the database.")


if __name__ == '__main__':
    app.run(debug=True)
