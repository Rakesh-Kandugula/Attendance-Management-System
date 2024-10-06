from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import date, datetime
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
import io
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
import logging
import re

app = Flask(__name__)

# Configure the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///attendance.db'
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Replace with a strong secret key

db = SQLAlchemy(app)
csrf = CSRFProtect(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin_login'  # Redirect to 'admin_login' when login is required

# Configure Logging
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
)

# Context processor to inject csrf_token into all templates
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf())

# User loader callback for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return Admin.query.get(int(user_id))

# Models
class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    full_name = db.Column(db.String(100), default='Admin')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    attendance_records = db.relationship('Attendance', backref='student', lazy=True)

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(10), nullable=False)  # 'Present' or 'Absent'

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(message="Username is required.")])
    password = PasswordField('Password', validators=[DataRequired(message="Password is required.")])
    submit = SubmitField('Login')

class ProfileForm(FlaskForm):
    old_password = PasswordField('Old Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password', message="Passwords must match")])
    submit = SubmitField('Update Password')

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data.strip()
        admin = Admin.query.filter_by(username=username).first()
        if admin and admin.check_password(password):
            login_user(admin)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid Credentials. Please try again.', 'danger')
    return render_template('admin_login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('admin_login'))

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    total_students = Student.query.count()
    total_classes = Attendance.query.with_entities(Attendance.date).distinct().count()
    total_present = Attendance.query.filter_by(status='Present').count()
    overall_attendance = (total_present / (total_classes * total_students) * 100) if total_classes > 0 and total_students > 0 else 0
    return render_template(
        'admin_dashboard.html',
        total_students=total_students,
        total_classes=total_classes,
        overall_attendance=overall_attendance,
        show_navbar=True
    )

# Mark Attendance Route
@app.route('/mark_attendance', methods=['GET', 'POST'])
@login_required
def mark_attendance():
    students = Student.query.all()
    
    if request.method == 'POST':
        try:
            # Process the form data
            date_str = request.form.get('date', '').strip()
            attendance_date = datetime.strptime(date_str, '%Y-%m-%d').date()
            
            for student in students:
                status = request.form.get(str(student.id))
                if status not in ['Present', 'Absent']:
                    continue  # Ignore invalid statuses
                
                existing_record = Attendance.query.filter_by(student_id=student.id, date=attendance_date).first()
                if existing_record:
                    existing_record.status = status  # Update existing record
                else:
                    new_record = Attendance(student_id=student.id, date=attendance_date, status=status)
                    db.session.add(new_record)
            
            db.session.commit()
            flash('Attendance records updated successfully.', 'success')
            return redirect(url_for('admin_dashboard'))
        
        except Exception as e:
            app.logger.error(f"Error in mark_attendance: {str(e)}")
            flash('An error occurred while submitting attendance.', 'danger')
            return redirect(url_for('mark_attendance'))
    
    today = date.today().isoformat()
    return render_template('mark_attendance.html', students=students, today=today, show_navbar=True)


# Check if Attendance Exists for a Given Date
@app.route('/check_attendance/<date_str>', methods=['GET'])
@login_required
def check_attendance(date_str):
    try:
        # Parse the date string
        attendance_date = datetime.strptime(date_str, '%Y-%m-%d').date()
    except ValueError:
        return jsonify({'error': 'Invalid date format.'}), 400

    # Check if any attendance records exist for the selected date
    records_exist = Attendance.query.filter_by(date=attendance_date).first() is not None

    return jsonify({'exists': records_exist}), 200

# View Attendance Route
@app.route('/view_attendance')
@login_required
def view_attendance():
    students = Student.query.all()

    # Student-based attendance data
    attendance_data = []
    total_classes = Attendance.query.with_entities(Attendance.date).distinct().count()
    for student in students:
        present_days = Attendance.query.filter_by(student_id=student.id, status='Present').count()
        percentage = (present_days / total_classes * 100) if total_classes > 0 else 0
        attendance_data.append({
            'id': student.id,
            'full_name': student.full_name,
            'email': student.email,
            'percentage': percentage
        })

    return render_template(
        'view_attendance.html',
        attendance_data=attendance_data,
        show_navbar=True
    )

# Update Student Route
@app.route('/update_student', methods=['POST'])
@login_required
def update_student():
    try:
        data = request.get_json()
        student_id = data.get('student_id')
        full_name = data.get('full_name')
        email = data.get('email')

        # Validate inputs
        if not full_name or not email:
            return jsonify({'success': False, 'message': 'Full Name and Email are required.'})

        if not student_id:
            return jsonify({'success': False, 'message': 'Student ID is required.'})

        try:
            student_id = int(student_id)
        except ValueError:
            return jsonify({'success': False, 'message': 'Invalid Student ID.'})

        student = Student.query.get(student_id)
        if not student:
            return jsonify({'success': False, 'message': 'Student not found.'})

        # Check if new email already exists for another student
        existing_student = Student.query.filter_by(email=email).first()
        if existing_student and existing_student.id != student.id:
            return jsonify({'success': False, 'message': 'A student with this email already exists.'})

        # Update student details
        student.full_name = full_name
        student.email = email
        db.session.commit()

        return jsonify({'success': True})
    except Exception as e:
        logging.error(f"Error in /update_student: {e}")
        return jsonify({'success': False, 'message': 'An unexpected error occurred.'}), 500

# Student Details Route
@app.route('/student/<int:student_id>')
@login_required
def student_details(student_id):
    try:
        student = Student.query.get_or_404(student_id)
        # Query attendance records for the student, ordered by date
        attendance_records = Attendance.query.filter_by(student_id=student.id).order_by(Attendance.date).all()
        total_classes = Attendance.query.with_entities(Attendance.date).distinct().count()
        present_days = Attendance.query.filter_by(student_id=student.id, status='Present').count()
        percentage = (present_days / total_classes * 100) if total_classes > 0 else 0
        return render_template(
            'student_details.html',
            student=student,
            records=attendance_records,
            percentage=percentage,
            show_navbar=True
        )
    except Exception as e:
        logging.error(f"Error in /student/<student_id>: {e}")
        flash('An unexpected error occurred.', 'danger')
        return redirect(url_for('view_attendance'))

# Add Student via AJAX Route
@app.route('/add_student_ajax', methods=['POST'])
@login_required
def add_student_ajax():
    try:
        data = request.get_json()
        full_name = data.get('full_name')
        email = data.get('email')

        if not full_name or not email:
            return jsonify({'success': False, 'message': 'Full Name and Email are required.'})

        # Validate email format (simple regex)
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return jsonify({'success': False, 'message': 'Invalid email format.'})

        if Student.query.filter_by(email=email).first():
            return jsonify({'success': False, 'message': 'A student with this email already exists.'})

        new_student = Student(full_name=full_name, email=email)
        db.session.add(new_student)
        db.session.commit()

        return jsonify({'success': True, 'student_id': new_student.id})
    except Exception as e:
        logging.error(f"Error in /add_student_ajax: {e}")
        return jsonify({'success': False, 'message': 'An unexpected error occurred.'}), 500

# Remove Student Route
@app.route('/remove_student/<int:student_id>', methods=['POST'])
@login_required
def remove_student(student_id):
    try:
        student = Student.query.get_or_404(student_id)
        db.session.delete(student)
        db.session.commit()
        flash('Student removed successfully.', 'success')
        return redirect(url_for('view_attendance'))
    except Exception as e:
        logging.error(f"Error in /remove_student/<student_id>: {e}")
        flash('An unexpected error occurred.', 'danger')
        return redirect(url_for('view_attendance'))

# Profile Route for Admin to Change Password
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm()
    admin = current_user
    if form.validate_on_submit():
        old_password = form.old_password.data
        new_password = form.new_password.data

        if not admin.check_password(old_password):
            flash('Old password is incorrect.', 'danger')
            return redirect(url_for('profile'))

        admin.set_password(new_password)
        db.session.commit()
        flash('Password updated successfully.', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('profile.html', form=form, admin=admin, show_navbar=True)

# Export Attendance Route
@app.route('/export_attendance')
@login_required
def export_attendance():
    try:
        students = Student.query.all()
        # Get all unique dates from attendance records
        dates = Attendance.query.with_entities(Attendance.date).distinct().order_by(Attendance.date).all()
        dates = [date_tuple[0] for date_tuple in dates]  # Extract dates from tuples

        # Prepare data for DataFrame
        data = []
        for idx, student in enumerate(students, start=1):
            student_data = {
                'Sl. No': idx,
                'Full Name': student.full_name,
                'Email': student.email
            }
            # Initialize attendance status for each date
            attendance_status = {record_date.strftime('%d-%m-%Y'): '' for record_date in dates}
            for record in student.attendance_records:
                attendance_status[record.date.strftime('%d-%m-%Y')] = record.status
            student_data.update(attendance_status)
            data.append(student_data)

        # Create DataFrame
        df = pd.DataFrame(data)

        # Reorder columns: 'Sl. No', 'Full Name', 'Email', date1, date2, ...
        columns = ['Sl. No', 'Full Name', 'Email'] + [record_date.strftime('%d-%m-%Y') for record_date in dates]
        df = df[columns]

        # Save DataFrame to an Excel file in memory
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Attendance')

        output.seek(0)

        # Send the Excel file as a response
        return send_file(output, download_name='attendance.xlsx', as_attachment=True)
    except Exception as e:
        logging.error(f"Error in /export_attendance: {e}")
        flash('An unexpected error occurred while exporting attendance.', 'danger')
        return redirect(url_for('view_attendance'))

if __name__ == '__main__':
    # Create the database tables if they don't exist
    with app.app_context():
        db.create_all()

        # Create an admin user if none exists
        if not Admin.query.first():
            admin = Admin(username='admin')
            admin.set_password('admin')  # Set a default password
            db.session.add(admin)
            db.session.commit()
            print('Admin user created with username "admin" and password "admin". Please change the password immediately.')

    app.run(debug=True)
