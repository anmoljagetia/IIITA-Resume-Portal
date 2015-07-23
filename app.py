import os
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, session
from werkzeug import secure_filename
from flask_oauth import OAuth
from rauth import OAuth2Service
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager,UserMixin,current_user,current_app,login_user,logout_user,login_required
import re
from flask_mime import Mime

SECRET_KEY = 'file_uploader'
DEBUG = True
GOOGLE_APP_ID = '46444198916-1m2o90tf898hfv8jeq62j6ah4mljgjvm.apps.googleusercontent.com'
GOOGLE_REVOKE_URI = 'https://accounts.google.com/o/oauth2/revoke'
GOOGLE_BASE_URL = 'https://www.googleapis.com/plus/v1/'
GOOGLE_APP_SECRET = '1qyc907t322yxcgu2qwpnj7R'
GOOGLE_AUTH_URI = 'https://accounts.google.com/o/oauth2/auth'
GOOGLE_TOKEN_URI = 'https://accounts.google.com/o/oauth2/token'
REDIRECT_URI = '/upload'  # one of the Redirect URIs from Google APIs console

# Initialize the Flask application
app = Flask(__name__)
app.debug = DEBUG
app.secret_key = SECRET_KEY
login_manager = LoginManager()
db = SQLAlchemy(app)
login_manager.init_app(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'

google = OAuth2Service(
    name='google',
    client_id = GOOGLE_APP_ID,
    client_secret = GOOGLE_APP_SECRET,
    access_token_url=GOOGLE_TOKEN_URI,
    authorize_url=GOOGLE_AUTH_URI,
    base_url = None)

redirect_uri = 'http://localhost:5000/callback'

class User(db.Model):
    id = db.Column(db.Integer,primary_key = True)
    name = db.Column(db.String(80))
    google_id = db.Column(db.String(200),unique=True)
    email = db.Column(db.String(40))

    def __init__(self,name,google_id,email):
        self.name = name
        self.google_id = google_id
        self.email = email

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):

        try:
            return unicode(self.id)

        except NameError:
            return str(self.id)

    @staticmethod
    def get_or_create(name,google_id,email):
        user = User.query.filter_by(google_id=google_id).first()

        if user is None:
            user = User(name,google_id,email)
            db.session.add(user)
            db.session.commit()
        return user


# This is the path to the upload directory
app.config['UPLOAD_FOLDER'] = 'uploads/'
# These are the extension that we are accepting to be uploaded
app.config['ALLOWED_EXTENSIONS'] = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])


# For a given file, return whether it's an allowed type or not
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in app.config['ALLOWED_EXTENSIONS']

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

# This route will show a form to perform an AJAX request
# jQuery is loaded to execute the request and update the
# value of the operation
@app.route('/')
def index():
    if current_user.is_authenticated():
        return redirect(url_for('uploadDisplay'))
    else:
        return render_template('login.html')

#Google login
@app.route('/login/google')
def googleLogin():
    params = {'scope': 'https://www.googleapis.com/auth/userinfo.email',
              'access_type': 'offline',
              'response_type': 'code',
              'redirect_uri': redirect_uri}
    return redirect(google.get_authorize_url(**params))

@app.route('/callback')
def callback():
    response = google.get_raw_access_token(data = {'code': request.args['code'],
            'grant_type': 'authorization_code',
            'redirect_uri': redirect_uri})

    response = response.json()
    session = google.get_session(response['access_token'])
    user = session.get('https://www.googleapis.com/oauth2/v1/userinfo').json()
    if 'hd' not in user:
        return redirect(url_for('index')) 

    if user['hd'] != 'iiita.ac.in':
        return redirect(url_for('index')) 

    me = User.get_or_create(user['name'],user['id'],user['email'])
    login_user(me)
    return redirect(url_for('uploadDisplay'))

@app.route('/uploadFile')
@login_required
def uploadDisplay():
    return render_template('index.html')

# Route that will process the file upload
@app.route('/upload', methods=['POST'])
@login_required
def upload():
    # Get the name of the uploaded file
    file = request.files['file']
    # Check if the file is one of the allowed types/extensions
    if file and allowed_file(file.filename):
        extract = re.findall('([^@]+)',current_user.email)
        file.filename = extract[0] + ".pdf"
        # Make the filename safe, remove unsupported chars
        #filename = secure_filename(file.filename)
        # Move the file form the temporal folder to
        # the upload folder we setup
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))
        # Redirect the user to the uploaded_file route, which
        # will basicaly show on the browser the uploaded file
        return render_template('uploaded.html', email = file.filename)


# This route is expecting a parameter containing the name
# of a file. Then it will locate that file on the upload
# directory and show it on the browser, so if the user uploads
# an image, that image is going to be show after the upload
@app.route('/uploads/<file>', methods=['GET'])
@login_required
def uploaded_file(file):
    return send_from_directory(app.config['UPLOAD_FOLDER'], file)

@app.route('/view/<file>')
@login_required
def viewFile(file):
    return redirect(url_for('uploaded_file',
                             file=file))

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
