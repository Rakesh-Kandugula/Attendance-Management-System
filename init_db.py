from app import app, db, Admin, Student

with app.app_context():
    db.create_all()

    # Check if the admin already exists to prevent duplicates
    admin = Admin.query.filter_by(username='admin').first()
    if not admin:
        # Create dummy admin credentials
        admin = Admin(username='admin')
        admin.password = 'password'  # This will hash the password
        db.session.add(admin)
        db.session.commit()
        print('Admin user created.')
    else:
        print('Admin user already exists.')

    # Add some dummy students if they don't already exist
    students_data = [
        {'full_name': 'Student One', 'email': 'student1@college.com'},
        {'full_name': 'Student Two', 'email': 'student2@college.com'},
        {'full_name': 'Student Three', 'email': 'student3@college.com'},
    ]

    for student_info in students_data:
        student = Student.query.filter_by(email=student_info['email']).first()
        if not student:
            student = Student(full_name=student_info['full_name'], email=student_info['email'])
            db.session.add(student)
    db.session.commit()
    print('Students added or already exist.')

print('Database initialized successfully.')
