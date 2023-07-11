
from datetime import datetime
from flask import current_app
from email.policy import default
from sqlalchemy import ForeignKey
from dossierapp import db,app





 

 
class Admin(db.Model): 
    admin_id = db.Column(db.Integer, autoincrement = True, primary_key = True)
    admin_fullname = db.Column(db.String(55), nullable = True)
    admin_mail = db.Column(db.String(60), nullable = True)
    admin_pwd = db.Column(db.String(120), nullable = True)
    admin_phone = db.Column(db.String(20), nullable = True)
    admin_address = db.Column(db.String(100), nullable = True)




class Employees(db.Model):
    employee_id = db.Column(db.Integer, autoincrement=True,primary_key=True)
    employee_fullname = db.Column(db.String(100),nullable=True)
    employee_email = db.Column(db.String(120),nullable = True) 
    employee_password = db.Column(db.String(120),nullable=True)
    employee_phone = db.Column(db.String(120),nullable=True)
    office_id = db.Column(db.Integer, db.ForeignKey('office.office_id'))
    dept_id = db.Column(db.Integer, db.ForeignKey('department.dept_id'))
    office_rel = db.relationship('Office', back_populates = 'employee_rel')
    staff_report = db.relationship('Staffreport', back_populates = 'employee_rel', foreign_keys='Staffreport.employee')
    staff_report_2 = db.relationship('Staffreport', back_populates = 'employee_rel_2', foreign_keys='Staffreport.reported_by')
    mng_report = db.relationship('Managementreport', back_populates = 'employee_rel', foreign_keys='Managementreport.employee')
    dept_rel = db.relationship('Department', back_populates = 'employee_rel')
 



class Office(db.Model):
    office_id = db.Column(db.Integer, autoincrement=True,primary_key=True)
    office_name = db.Column(db.String(100),nullable=True)
    employee_rel = db.relationship('Employees', back_populates ='office_rel')
    staff_report = db.relationship('Staffreport', back_populates = 'office_rel', cascade = 'all, delete-orphan')
    mng_report = db.relationship('Managementreport', back_populates = 'office_rel')




class Department(db.Model): 
    dept_id = db.Column(db.Integer, autoincrement=True,primary_key=True)
    dept_name = db.Column(db.String(100), nullable=True)
    employee_rel = db.relationship('Employees', back_populates = 'dept_rel', cascade = 'all, delete-orphan')
    mng_report = db.relationship('Managementreport', back_populates = 'dept_rel')
    staff_report = db.relationship('Staffreport', back_populates = 'dept_rel')




class Managementreport(db.Model):
    report_id = db.Column(db.Integer, autoincrement=True,primary_key=True)
    report_msg = db.Column(db.Text(), nullable=True)
    employee = db.Column(db.Integer, db.ForeignKey('employees.employee_id'))
    department = db.Column(db.Integer, db.ForeignKey('department.dept_id'))
    reported_by = db.Column(db.Integer, db.ForeignKey('office.office_id'))
    report_status = db.Column(db.Enum('1','0'), nullable=False, server_default = ('0'))
    report_date = db.Column(db.Date, default = datetime.utcnow)
    employee_rel = db.relationship('Employees', back_populates = 'mng_report')
    office_rel = db.relationship('Office', back_populates = 'mng_report')
    dept_rel = db.relationship('Department', back_populates = 'mng_report')



 

class Staffreport(db.Model):
    report_id = db.Column(db.Integer, autoincrement=True,primary_key=True)
    report_msg = db.Column(db.Text(), nullable=True)
    employee = db.Column(db.Integer, db.ForeignKey('employees.employee_id'))
    office = db.Column(db.Integer, db.ForeignKey('office.office_id'), nullable = True)
    department = db.Column(db.Integer, db.ForeignKey('department.dept_id'))
    reported_by = db.Column(db.Integer, db.ForeignKey('employees.employee_id'), nullable = True)
    report_date = db.Column(db.Date, default = datetime.utcnow)
    report_status = db.Column(db.Enum('1','0'), nullable=False, server_default = ('0'))
    employee_rel = db.relationship('Employees', back_populates = 'staff_report', foreign_keys=[reported_by])
    employee_rel_2 = db.relationship('Employees', back_populates = 'staff_report_2', foreign_keys=[employee])
    office_rel = db.relationship('Office', back_populates = 'staff_report')
    dept_rel = db.relationship('Department', back_populates = 'staff_report')
    
