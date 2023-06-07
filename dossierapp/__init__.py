from datetime import datetime,timedelta,timezone,time
from urllib import request
from flask import Flask,session,flash
from flask_mail import Mail,Message
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect


app = Flask(__name__, instance_relative_config=True, template_folder='templates')
app.config.from_pyfile('config.py', silent=False)
app.permanent_session_lifetime = timedelta(minutes=5)

@app.before_request
def timestamp():
    if 'time_stamp' in session:
        check_time = datetime.now(timezone.utc) - session['time_stamp']
        if check_time > app.permanent_session_lifetime:
            flash('session expired, please login again')
            session.clear()
    session['time_stamp'] = datetime.utcnow().replace(tzinfo = timezone.utc)



app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = "dossier.sevenlives@gmail.com"
app.config['MAIL_PASSWORD'] = "flemwjgjkbbzhrmc"
mail = Mail(app)



db = SQLAlchemy(app)
csrf = CSRFProtect(app)



from dossierapp import adminroutes, staffroutes
