import re, os,datetime,jwt,logging
from threading import Thread
from crypt import methods
from flask import render_template, redirect, flash, session, request,url_for,jsonify,current_app
from sqlalchemy.sql import text
from werkzeug.security import generate_password_hash, check_password_hash
from dossierapp import app,db,mail,Message
from dossierapp.models import Office, Department, Managementreport, Staffreport, Admin






@app.route('/adminregister/', methods=['POST','GET'])
def adminreg():
    if request.method == 'GET':
        return render_template('adminregister.html')
    else:
        name = request.form.get('fullname')
        mail = request.form.get('email')
        pwd = request.form.get('pwd')
        pwd2 = request.form.get('confirm_pwd')
        phone = request.form.get('phone')
        addr = request.form.get('address')
        
        if name != "" and mail != "" and pwd != "" and phone != "" and addr != "":
            pwd_pattern = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)([a-zA-Z\d]{8,})$"
            phone_pattern = "0[7-9][0-1]([0-9]){8}"
            pwd_check = re.match(pwd_pattern,pwd)
            phone_check = re.match(phone_pattern,phone)
            if pwd_check:
                if phone_check:
                    if pwd == pwd2:
                        pwdhash = generate_password_hash(pwd)
                        fetch = db.session.query(Admin).filter(Admin.admin_mail == mail).first()
                        if fetch:
                            flash('username already exist!')
                            return redirect('/adminregister')
                        else:
                            addup = Admin(admin_fullname = name, admin_mail = mail, admin_pwd = pwdhash, admin_phone = phone, admin_address = addr)
                            db.session.add(addup)
                            db.session.commit()
                            flash('Account created successfully, login with your Username and password to continue', category='success')
                            return redirect(url_for('/adminregister'))
                    else:
                        flash('Password must match')
                        return redirect(url_for('adminreg'))
                else:
                    flash('Invalid phone number', category='error')
                    return redirect(url_for('adminreg'))
            else:
                flash('Please check the password requirements', category='error')
                return redirect(url_for('adminreg'))
        else:
            flash('Please complete the fields')
            return redirect(url_for('adminreg'))




@app.route('/admin/', methods=['GET', 'POST'])
def adminlogin():
    if request.method == 'GET':
        return render_template('adminlogin.html')
    else:
        mail = request.form.get('email')
        pwd = request.form.get('pwd')

        admin = db.session.query(Admin).filter(Admin.admin_mail == mail).first()

        if admin is not None:
            check = check_password_hash(admin.admin_pwd, pwd)
            if check:
                session['admin'] = admin.admin_id
                return redirect(url_for('admindashboard'))
            else:
                flash('Username or password is incorrect.', category='error')
                return render_template('adminlogin.html')
        else:
            flash('Username or password does not match any of our records.', category='error')
            return render_template('adminlogin.html')






@app.route('/adminpasswordforgot', methods=['GET', 'POST'])
def adminforgot():
    if request.method == 'POST':
        email = request.form.get('email')
        admin = Admin.query.filter_by(admin_mail = email).first()
        if admin:
            jwt_token = jwt.encode({'admin': admin.admin_mail, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)}, current_app.config['SECRET_KEY'], algorithm='HS256')
            reset_link = url_for('adminreset', token=jwt_token, _external = True)
            def send_link(app,msg):
                    with app.app_context():
                        mail.send(msg)
            msg = Message(subject = "Password Reset Request", recipients = [email], body = f"Dear {email},\n\nYou requested to reset your password, if this was you please click the link below and follow the instructions to reset your password.\n\n{reset_link}\n(Expires in 10mins).\n\nHowever if this wasn\'t your action you may need to change your password as someone might be trying to manipulate your credentials.\n\nBest regards,\nDossier", sender = 'awoofgistblogspot@gmail.com')
            Thread(target = send_link, args = (app, msg)).start()
            flash(f'Password reset link has been sent to {email}', category='success')
            return redirect('/adminpasswordforgot')
        else:
            flash(f'{email} does not seem to exist in our records')
            return redirect(url_for('adminforgot'))
    else:
        return render_template('adminforgot.html')






@app.route('/adminpasswordreset/', methods = ["POST", 'GET'])
def adminreset():
    if request.method == 'POST':
        newpwd = request.form.get('pwd')
        newpwd2 = request.form.get('confirm-pwd')
        token = request.form.get('token')
        if token != None and newpwd != "" and newpwd2 != "":
            try:
                email = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])['admin']
            except jwt.exceptions.DecodeError:
                flash('Token not valid')
                return redirect(url_for('staffreset'))
            admin = Admin.query.filter(Admin.admin_mail == email).first()
            if admin:
                if newpwd == newpwd2:
                    pattern = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)([a-zA-Z\d]{8,})$"
                    patt = re.match(pattern,newpwd)
                    if patt:
                        pwdhash = generate_password_hash(newpwd)
                        admin.admin_pwd = pwdhash
                        db.session.commit()
                        flash('Password updated successfully,<br> you can now login with your new password!', category='success')
                        return redirect(url_for('adminlogin'))
                    else:
                        flash('Please check password requirements')
                        return redirect(url_for('adminreset'))
                else:
                    flash('Password must match')
                    return redirect(url_for('adminreset'))
            else:
                flash('Email doesn\'t exist', category='error')
                return redirect(url_for('adminreset'))
        else:
            flash('Please complete the form')
            return redirect(url_for('adminreset'))
    else:
        token = request.args.get('token')
        if token:
            email = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms= ['HS256'])['admin']
            check_admin = Admin.query.filter_by(admin_mail = email).first()
            if check_admin:
               return render_template('adminreset.html', token = token)
            else:
                flash('Record not found')
                return redirect(url_for('adminforgot'))
        else:
            jwt.exceptions.DecodeError
            flash('Something went wrong, the operation cannot be completed, please try again')
            return redirect(url_for('adminforgot'))




@app.route('/admindashboard/')
def admindashboard():
        if session.get('admin') is not None:
                adminquery = Admin.query.get(session['admin'])
                alladminquery = Admin.query.all()
                staffreports = db.session.query(Staffreport).all()
                mgtreports = Managementreport.query.all()
                return render_template('admindashboard.html', staffreports = staffreports, adminquery = adminquery, mgtreports = mgtreports, alladminquery = alladminquery)
        else:
            return redirect('/admin')
        




@app.route('/management/report/approve/<id>', methods = ['POST'])
def mgt_approve(id):
    if session.get('admin') != None:
        if request.method == 'POST':
            reportid = request.form.get('reportid')
            stat = request.form.get('stat')
            fetch = Managementreport.query.get(reportid)
            fetch.report_status = stat
            db.session.commit()
            return redirect('/admindashboard')

    return redirect('/adminlogin')



@app.route('/staff/report/approve/<id>', methods = ['POST'])
def staff_approve(id):
    if session.get('admin') != None:
        if request.method == 'POST':
            reportid = request.form.get('reportid')
            stat = request.form.get('stat')
            fetch = Staffreport.query.get(reportid)
            fetch.report_status = stat
            db.session.commit()
            return redirect('/admindashboard')

    return redirect('/adminlogin')



@app.route('/adminlogout')
def adminlogout():
    if session.get('admin') != None:
        session.pop('admin', None)
        return redirect('/admin')



