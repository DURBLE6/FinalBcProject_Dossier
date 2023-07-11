import re, os, smtplib, datetime,jwt,logging,time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from threading import Thread
from flask import render_template, redirect, flash, session, request, url_for, current_app
from sqlalchemy.sql import text
from werkzeug.security import generate_password_hash, check_password_hash
from dossierapp import app,db,Message,mail
from dossierapp.models import Department, Employees, Office, Staffreport, Managementreport
from dossierapp.forms import SignupForm







@app.route('/dossier', methods = ['POST', 'GET']) 
@app.route('/', methods = ['POST', 'GET'])
def staffhome():
    if request.method == 'GET':
        offices = Office.query.all()
        return render_template('home.html',offices = offices)
    else:
        deets = request.form.get('pick')
        if deets == 'New staff':
            return redirect('/staffregister')
        else:
            return redirect('/stafflogin')
        



@app.route('/staffregister', methods=['POST', 'GET'])
def staffregister():
    if request.method == 'GET':
        offices = Office.query.all()
        depts = Department.query.all()
        return render_template('staffreg.html', offices = offices, depts = depts)
    else:
        name = request.form.get('fullname')
        mail = request.form.get('email')
        pwd = request.form.get('pwd')
        pwd2 = request.form.get('pwd2')
        phone = request.form.get('phone')
        office = request.form.get('office')
        department = request.form.get('depts')
        
        if name != "" and mail != "" and pwd != "" and phone != "" and office != None and department != None:
            mail_pattern = "^[a-zA-Z0-9._%+-]+@[a-zA-Z]+\.[a-zA-Z]{2,}$"
            check_mail = re.match(mail_pattern,mail)
            if check_mail:
                fetch = db.session.query(Employees).filter(Employees.employee_email == mail).first()
                if fetch:
                    flash('Username already exist!')
                    return redirect(url_for('staffregister'))
                else:
                    pwd_pattern = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)([a-zA-Z\d]{8,})$"
                    phone_pattern = "0[7-9][0-1]([0-9]){8}"
                    pwd_check = re.match(pwd_pattern,pwd)
                    phone_check = re.match(phone_pattern,phone)
    
                    if pwd_check:
                        if phone_check:
                            if  pwd == pwd2:
                                pwdhash = generate_password_hash(pwd)
                                add_user = Employees(employee_email = mail, employee_password = pwdhash, employee_phone = phone, employee_fullname = name, office_id = office, dept_id = department)
                                db.session.add(add_user)
                                db.session.commit()
                                flash('Account created successfully, you can now login with your username and password', category='success')
                                return redirect(url_for('staffregister'))
                            else:
                                flash('password must match')
                                return redirect(url_for('staffregister'))
                        else:
                            flash('Invalid phone number!', category='error')
                            return redirect(url_for('staffregister'))
                    else:
                        flash('Please check password requirements')
                        return redirect(url_for('staffregister'))                           
            else:
                flash("Invalid mail address", category='error')
                return redirect(url_for('staffregister'))
        else:
            flash('please complete all the fields')
            return redirect(url_for('staffregister'))







@app.route('/stafflogin/', methods = ["POST", 'GET'])
def stafflogin():
    if request.method == 'GET':
        return render_template('stafflogin.html')
    else:
        mail= request.form.get('email') 
        pwd = request.form.get('pwd')
        fetch = db.session.query(Employees).filter(Employees.employee_email == mail).first()
        if fetch != None:
            check = check_password_hash(fetch.employee_password,pwd)
            if check:
                session['staff'] = fetch.employee_id
                session['office'] = fetch.office_id
                session.modified = True
                return redirect(url_for('staffdashboard'))
            else:
                flash('Username or Password Incorrect', category='error')
                return redirect(url_for('stafflogin'))
        else:
            flash('Details doesn\'t match any of our records', category='error')
            return redirect(url_for('stafflogin'))








@app.route('/forgotpassword', methods=['GET', 'POST'])
def forgotpassword():
    if request.method == 'POST':
        email = request.form.get('email')
        users = Employees.query.filter_by(employee_email=email).first()
        if users:
            jwt_token = jwt.encode({'user': users.employee_email, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)}, current_app.config['SECRET_KEY'], algorithm='HS256')
            reset_link = url_for('staffreset', token=jwt_token, _external = True)
            def send_link(app,msg):
                    with app.app_context():
                        mail.send(msg)
            msg = Message(subject = "Password Reset Request", recipients = [email], body = f"Dear {email},\n\nYou requested to reset your password, if this was you please click the link below and follow the instructions to reset your password.\n\n{reset_link}\n(Expires in 10mins).\n\nHowever if this wasn\'t your action you may need to change your password as someone might be trying to manipulate your credentials.\n\nBest regards,\nDossier", sender = 'dossier.sevenlives@gmail.com')
            Thread(target = send_link, args = (app, msg)).start()
            flash(f'Password reset link has been sent to {email}', category='success')
            return redirect('/forgotpassword')
        else:
            flash(f'{email} does not seem to exist in our records')
            return redirect(url_for('forgotpassword'))
    else:
        return render_template('forgotpassword.html')






@app.route('/passwordreset/', methods = ["POST", "GET"])
def staffreset():
    if  request.method == 'POST':
        newpwd = request.form.get('pwd')
        newpwd2 = request.form.get('confirm-pwd')
        token = request.form.get('token')
        if token != None and newpwd != "" and newpwd2 != "":
            users = Employees.query.filter(Employees.employee_email == email).first()
            if users:
                if newpwd == newpwd2:
                    pattern = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)([a-zA-Z\d]{8,})$"
                    patt = re.match(pattern,newpwd)
                    if patt:
                        pwdhash = generate_password_hash(newpwd)
                        users.employee_password = pwdhash
                        db.session.commit()
                        flash('Password updated successfully,<br> you can now login with your new password!', category='success')
                        return render_template('passwordreset.html')
                    else:
                        flash('Please check password requirements')
                        return redirect(url_for('staffreset'))
                else:
                    flash('Password must match')
                    return redirect(url_for('staffreset'))

            else:
                flash('Email doesn\'t exist', category='error')
                return redirect(url_for('staffreset'))
        else:
            flash('Please complete the form')
            return redirect(url_for('staffreset'))

    else:
        token = request.args.get('token')
        if token:
            email = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])['user']
            check_user = Employees.query.filter_by(employee_email=email).first()
            if check_user:
                return render_template('passwordreset.html', token=token)
            else:
                flash('User not found')
                return redirect(url_for('forgotpassword'))
        else:
            jwt.exceptions.DecodeError
            flash('Something went wrong and the operation cannot be completed, please try again')
            return redirect(url_for('forgotpassword'))
        



@app.route('/staffdashboard/') 
def staffdashboard():
    if session.get('staff') is not None:
        staff = Employees.query.get(session['staff'])
        total = Managementreport.query.filter(Managementreport.employee == session['staff']).all()
        reports = db.session.query(Managementreport).filter(Managementreport.report_status == 1).all()
        return render_template('staffdashboard.html', reports = reports, staff = staff, total = total)
    else:
        return redirect('/stafflogin')

@app.route('/report/', methods=['POST', 'GET'])
def report():
    if 'staff' in session and 'office' in session:
        staff = session['staff']
        office = session['office']
        if request.method == 'GET':
            getid = Employees.query.get(staff)
            department = getid.dept_id
            mgt = Office.query.filter(Office.office_id != 3).all()
            depts = Department.query.filter_by(dept_id = department).all()

            if session['office'] == 1 or session['office'] == 2: 
                workers = Employees.query.filter(Employees.office_id == 3).filter(Employees.dept_id == department).all()
            elif session['office'] == 3:
                workers = Employees.query.filter(Employees.office_id != 3).filter(Employees.dept_id == department).all()

            mgt_report = Managementreport.query.filter(Managementreport.reported_by == staff).all()
            reports = Staffreport.query.filter(Staffreport.reported_by == staff).all()
            return render_template('report.html', workers = workers, mgt = mgt, depts = depts, getid = getid, reports = reports, mgt_report = mgt_report)
        else:            
            text = request.form.get('report')
            about = request.form.get('workers')
            offices = request.form.get('offices')
            depts = request.form.get('depts')
            if text != "" and about != "" and depts != "": 
                if session['office'] == 1 or session['office'] == 2:
                    insert = Managementreport(report_msg = text, employee = about, department = depts, reported_by = office)
                    db.session.add(insert)
                    db.session.commit()
                    flash("Your report has been submitted,<br>approved reports will be available in the dashboard", category='success')
                    return redirect('/report')
                elif session['office'] == 3:
                    add = Staffreport(report_msg = text, office= offices, department = depts, employee = about, reported_by = staff)
                    db.session.add(add)
                    db.session.commit()
                    flash('Thanks for submitting the report, it will looked into and the status will appear at the notification center as soon as possible!', category='success')
                    return redirect('/report')
                else:
                    flash("something went wrong, please refresh this page and try again", category='error')
                    return redirect('/report')
            else:
                flash("Your message is empty, unable to process an empty message", category='error')
                return redirect('/report')               
    else:
        return redirect('/stafflogin')


@app.route('/stafflogout')
def stafflogout():
    if session.get('staff') != None:
        session.pop('staff', None)
        return redirect('/stafflogin')


@app.errorhandler(Exception)
def handle_errors(e):
    return render_template('errorpage.html', error = e),500
