from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from database.database import get_connection, create_tables
from datetime import datetime
from functools import wraps
import os
import shutil
from pathlib import Path


app = Flask(__name__)
def role_required(*allowed_roles):

    def decorator(function):

        @wraps(function)
        def wrapper(*args, **kwargs):

            if "user_id" not in session:
                return redirect(url_for("login"))

            user_role = session.get("role")

            if user_role not in allowed_roles:
                return "Access Denied: You do not have permission to access this page.", 403

            return function(*args, **kwargs)

        return wrapper

    return decorator

app.secret_key = "hospital-development-secret-key"

create_tables()

@app.route("/users", methods=["GET", "POST"])
@role_required("Administrator")
def users():

    connection = get_connection()

    if request.method == "POST":

        username = request.form["username"].strip()
        password = request.form["password"]
        role = request.form["role"]

        if not username or not password or not role:
            connection.close()
            return "All fields are required.", 400

        # Check if username already exists
        existing_user = connection.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if existing_user:
            connection.close()
            return "Username already exists.", 400

        # Hash password before saving
        hashed_password = generate_password_hash(password)

        connection.execute("""
            INSERT INTO users (username, password, role)
            VALUES (?, ?, ?)
        """, (
            username,
            hashed_password,
            role
        ))

        connection.commit()

    # Get all users
    users_list = connection.execute("""
        SELECT id, username, role
        FROM users
        ORDER BY id DESC
    """).fetchall()

    connection.close()

    return render_template(
        "users.html",
        users=users_list
    )


@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        connection = get_connection()
        

        user = connection.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        connection.close()

        if user and check_password_hash(user["password"], password):

            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            return redirect(url_for("dashboard"))

        return render_template(
            "login.html",
            error="Invalid username or password."
        )

    return render_template("login.html")



@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_connection()

    # Total patients
    total_patients = connection.execute(
        "SELECT COUNT(*) FROM patients"
    ).fetchone()[0]

    # Total doctors
    total_doctors = connection.execute(
        "SELECT COUNT(*) FROM doctors"
    ).fetchone()[0]

    # Total medicines
    total_medicines = connection.execute(
        "SELECT COUNT(*) FROM medicines"
    ).fetchone()[0]

    # Low stock medicines
    low_stock_medicines = connection.execute("""
        SELECT COUNT(*)
        FROM medicines
        WHERE quantity > 0
        AND quantity <= 10
    """).fetchone()[0]

    # Out of stock medicines
    out_of_stock_medicines = connection.execute("""
        SELECT COUNT(*)
        FROM medicines
        WHERE quantity = 0
    """).fetchone()[0]

    # Today's appointments
    today_appointments = connection.execute("""
        SELECT COUNT(*)
        FROM appointments
        WHERE date(appointment_date) = date('now')
    """).fetchone()[0]

    # Today's pharmacy sales
    today_sales = connection.execute("""
        SELECT COALESCE(SUM(total_amount), 0)
        FROM pharmacy_sales
        WHERE date(sale_date) = date('now')
    """).fetchone()[0]

    connection.close()

    return render_template(
        "dashboard.html",
        total_patients=total_patients,
        total_doctors=total_doctors,
        total_medicines=total_medicines,
        low_stock_medicines=low_stock_medicines,
        out_of_stock_medicines=out_of_stock_medicines,
        today_appointments=today_appointments,
        today_sales=today_sales
    )

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))
@app.route("/patients", methods=["GET", "POST"])
@role_required("Administrator", "Doctor", "Receptionist")
def patients():

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_connection()

    if request.method == "POST":

        patient_number = request.form["patient_number"]
        first_name = request.form["first_name"]
        last_name = request.form["last_name"]
        date_of_birth = request.form["date_of_birth"]
        gender = request.form["gender"]
        phone = request.form["phone"]
        address = request.form["address"]
        blood_group = request.form["blood_group"]
        emergency_contact = request.form["emergency_contact"]

        connection.execute("""
            INSERT INTO patients (
                patient_number,
                first_name,
                last_name,
                date_of_birth,
                gender,
                phone,
                address,
                blood_group,
                emergency_contact,
                registration_date
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """, (
            patient_number,
            first_name,
            last_name,
            date_of_birth,
            gender,
            phone,
            address,
            blood_group,
            emergency_contact
        ))

        connection.commit()

        connection.close()

        return redirect(url_for("patients"))

    search = request.args.get("search", "").strip()

    if search:

        patients_list = connection.execute("""
            SELECT * FROM patients
            WHERE patient_number LIKE ?
               OR first_name LIKE ?
               OR last_name LIKE ?
               OR phone LIKE ?
            ORDER BY id DESC
        """, (
            f"%{search}%",
            f"%{search}%",
            f"%{search}%",
            f"%{search}%"
        )).fetchall()

    else:

        patients_list = connection.execute("""
            SELECT * FROM patients
            ORDER BY id DESC
        """).fetchall()

    connection.close()

    return render_template(
        "patients.html",
        patients=patients_list,
        search=search
    )
@app.route("/patients/<int:patient_id>")
def view_patient(patient_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_connection()

    patient = connection.execute(
        "SELECT * FROM patients WHERE id = ?",
        (patient_id,)
    ).fetchone()

    connection.close()

    if patient is None:
        return "Patient not found", 404

    return render_template(
        "view_patient.html",
        patient=patient
    )
@app.route("/patients/<int:patient_id>/edit", methods=["GET", "POST"])
def edit_patient(patient_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_connection()

    patient = connection.execute(
        "SELECT * FROM patients WHERE id = ?",
        (patient_id,)
    ).fetchone()

    if patient is None:
        connection.close()
        return "Patient not found", 404

    if request.method == "POST":

        patient_number = request.form["patient_number"]
        first_name = request.form["first_name"]
        last_name = request.form["last_name"]
        date_of_birth = request.form["date_of_birth"]
        gender = request.form["gender"]
        phone = request.form["phone"]
        address = request.form["address"]
        blood_group = request.form["blood_group"]
        emergency_contact = request.form["emergency_contact"]

        connection.execute("""
            UPDATE patients
            SET patient_number = ?,
                first_name = ?,
                last_name = ?,
                date_of_birth = ?,
                gender = ?,
                phone = ?,
                address = ?,
                blood_group = ?,
                emergency_contact = ?
            WHERE id = ?
        """, (
            patient_number,
            first_name,
            last_name,
            date_of_birth,
            gender,
            phone,
            address,
            blood_group,
            emergency_contact,
            patient_id
        ))

        connection.commit()
        connection.close()

        return redirect(url_for("view_patient", patient_id=patient_id))

    connection.close()

    return render_template(
        "edit_patient.html",
        patient=patient
    )
@app.route("/patients/<int:patient_id>/delete", methods=["POST"])
def delete_patient(patient_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_connection()

    connection.execute(
        "DELETE FROM patients WHERE id = ?",
        (patient_id,)
    )

    connection.commit()
    connection.close()

    return redirect(url_for("patients"))
@app.route("/doctors", methods=["GET", "POST"])
@role_required("Administrator", "Doctor")
def doctors():

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_connection()

    # Register Doctor
    if request.method == "POST":

        doctor_number = request.form["doctor_number"]
        first_name = request.form["first_name"]
        last_name = request.form["last_name"]
        specialization = request.form["specialization"]
        phone = request.form["phone"]
        email = request.form["email"]
        department = request.form["department"]

        connection.execute("""
            INSERT INTO doctors (
                doctor_number,
                first_name,
                last_name,
                specialization,
                phone,
                email,
                department,
                registration_date
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """, (
            doctor_number,
            first_name,
            last_name,
            specialization,
            phone,
            email,
            department
        ))

        connection.commit()
        connection.close()

        return redirect(url_for("doctors"))
  
    # Search Doctors
    search = request.args.get("search", "").strip()

    if search:

        doctors_list = connection.execute("""
            SELECT * FROM doctors
            WHERE doctor_number LIKE ?
               OR first_name LIKE ?
               OR last_name LIKE ?
               OR specialization LIKE ?
               OR phone LIKE ?
            ORDER BY id DESC
        """, (
            f"%{search}%",
            f"%{search}%",
            f"%{search}%",
            f"%{search}%",
            f"%{search}%"
        )).fetchall()

    else:

        doctors_list = connection.execute("""
            SELECT * FROM doctors
            ORDER BY id DESC
        """).fetchall()

    connection.close()

    return render_template(
        "doctors.html",
        doctors=doctors_list,
        search=search
    )



@app.route("/appointments", methods=["GET", "POST"])
@role_required("Administrator", "Doctor", "Receptionist")
def appointments():
    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_connection()

    # Get patients for the patient dropdown
    patients_list = connection.execute("""
        SELECT id, patient_number, first_name, last_name
        FROM patients
        ORDER BY first_name
    """).fetchall()

    # Get doctors for the doctor dropdown
    doctors_list = connection.execute("""
        SELECT id, doctor_number, first_name, last_name, specialization
        FROM doctors
        ORDER BY first_name
    """).fetchall()

    # Register Appointment
    if request.method == "POST":

        appointment_number = request.form["appointment_number"]
        patient_id = request.form["patient_id"]
        doctor_id = request.form["doctor_id"]
        appointment_date = request.form["appointment_date"]
        appointment_time = request.form["appointment_time"]
        reason = request.form["reason"]
        status = request.form["status"]

        connection.execute("""
            INSERT INTO appointments (
                appointment_number,
                patient_id,
                doctor_id,
                appointment_date,
                appointment_time,
                reason,
                status,
                registration_date
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """, (
            appointment_number,
            patient_id,
            doctor_id,
            appointment_date,
            appointment_time,
            reason,
            status
        ))

        connection.commit()
        connection.close()

        return redirect(url_for("appointments"))

    # Search Appointments
    search = request.args.get("search", "").strip()

    if search:

        appointments_list = connection.execute("""
            SELECT
                appointments.*,
                patients.first_name AS patient_first_name,
                patients.last_name AS patient_last_name,
                doctors.first_name AS doctor_first_name,
                doctors.last_name AS doctor_last_name
            FROM appointments
            JOIN patients
                ON appointments.patient_id = patients.id
            JOIN doctors
                ON appointments.doctor_id = doctors.id
            WHERE appointments.appointment_number LIKE ?
               OR patients.first_name LIKE ?
               OR patients.last_name LIKE ?
               OR doctors.first_name LIKE ?
               OR doctors.last_name LIKE ?
               OR appointments.status LIKE ?
            ORDER BY appointments.appointment_date DESC,
                     appointments.appointment_time DESC
        """, (
            f"%{search}%",
            f"%{search}%",
            f"%{search}%",
            f"%{search}%",
            f"%{search}%",
            f"%{search}%"
        )).fetchall()

    else:

        # Get all appointments
        appointments_list = connection.execute("""
            SELECT
                appointments.*,
                patients.first_name AS patient_first_name,
                patients.last_name AS patient_last_name,
                doctors.first_name AS doctor_first_name,
                doctors.last_name AS doctor_last_name
            FROM appointments
            JOIN patients
                ON appointments.patient_id = patients.id
            JOIN doctors
                ON appointments.doctor_id = doctors.id
            ORDER BY appointments.appointment_date DESC,
                     appointments.appointment_time DESC
        """).fetchall()

    connection.close()

    return render_template(
        "appointments.html",
        appointments=appointments_list,
        patients=patients_list,
        doctors=doctors_list,
        search=search
    )
@app.route("/laboratory", methods=["GET", "POST"])
@role_required("Administrator", "Doctor", "Laboratory Technician")
def laboratory():

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_connection()

    # Get patients
    patients_list = connection.execute("""
        SELECT id, patient_number, first_name, last_name
        FROM patients
        ORDER BY first_name
    """).fetchall()

    # Get doctors
    doctors_list = connection.execute("""
        SELECT id, doctor_number, first_name, last_name, specialization
        FROM doctors
        ORDER BY first_name
    """).fetchall()

    # Register laboratory test
    if request.method == "POST":

        test_number = request.form["test_number"]
        patient_id = request.form["patient_id"]
        doctor_id = request.form["doctor_id"]
        test_name = request.form["test_name"]
        test_date = request.form["test_date"]
        result = request.form.get("result", "")
        status = request.form["status"]
        notes = request.form.get("notes", "")

        connection.execute("""
            INSERT INTO laboratory_tests (
                test_number,
                patient_id,
                doctor_id,
                test_name,
                test_date,
                result,
                status,
                notes
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            test_number,
            patient_id,
            doctor_id,
            test_name,
            test_date,
            result,
            status,
            notes
        ))

        connection.commit()
        connection.close()

        return redirect(url_for("laboratory"))

    # Search laboratory tests
    search = request.args.get("search", "").strip()

    if search:

        tests_list = connection.execute("""
            SELECT
                laboratory_tests.*,

                patients.patient_number,
                patients.first_name AS patient_first_name,
                patients.last_name AS patient_last_name,

                doctors.doctor_number,
                doctors.first_name AS doctor_first_name,
                doctors.last_name AS doctor_last_name

            FROM laboratory_tests

            JOIN patients
                ON laboratory_tests.patient_id = patients.id

            JOIN doctors
                ON laboratory_tests.doctor_id = doctors.id

            WHERE laboratory_tests.test_number LIKE ?
               OR laboratory_tests.test_name LIKE ?
               OR patients.patient_number LIKE ?
               OR patients.first_name LIKE ?
               OR patients.last_name LIKE ?

            ORDER BY laboratory_tests.id DESC

        """, (
            f"%{search}%",
            f"%{search}%",
            f"%{search}%",
            f"%{search}%",
            f"%{search}%"
        )).fetchall()

    else:

        tests_list = connection.execute("""
            SELECT
                laboratory_tests.*,

                patients.patient_number,
                patients.first_name AS patient_first_name,
                patients.last_name AS patient_last_name,

                doctors.doctor_number,
                doctors.first_name AS doctor_first_name,
                doctors.last_name AS doctor_last_name

            FROM laboratory_tests

            JOIN patients
                ON laboratory_tests.patient_id = patients.id

            JOIN doctors
                ON laboratory_tests.doctor_id = doctors.id

            ORDER BY laboratory_tests.id DESC

        """).fetchall()

    connection.close()

    return render_template(
        "laboratory.html",
        patients=patients_list,
        doctors=doctors_list,
        tests=tests_list,
        search=search
    )
@app.route("/billing", methods=["GET", "POST"])
@role_required("Administrator", "Receptionist")
def billing():

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_connection()

    # Get patients
    patients = connection.execute("""
        SELECT id, patient_number, first_name, last_name
        FROM patients
        ORDER BY first_name
    """).fetchall()

    # Create manual bill
    if request.method == "POST":

        patient_id = request.form["patient_id"]
        description = request.form["description"]
        amount = float(request.form["amount"])
        payment_status = request.form["payment_status"]

        bill_number = "BILL-" + datetime.now().strftime("%Y%m%d%H%M%S")

        connection.execute("""
            INSERT INTO bills (
                bill_number,
                patient_id,
                description,
                amount,
                payment_status
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            bill_number,
            patient_id,
            description,
            amount,
            payment_status
        ))

        connection.commit()

    # Manual bills
    bills = connection.execute("""
        SELECT
            bills.*,
            patients.patient_number,
            patients.first_name,
            patients.last_name
        FROM bills
        JOIN patients
            ON bills.patient_id = patients.id
        ORDER BY bills.id DESC
    """).fetchall()

    # Pharmacy charges
    pharmacy_charges = connection.execute("""
        SELECT
            pharmacy_sales.id,
            pharmacy_sales.sale_number,
            pharmacy_sales.patient_id,
            pharmacy_sales.quantity,
            pharmacy_sales.unit_price,
            pharmacy_sales.total_amount,
            medicines.medicine_name,
            patients.patient_number,
            patients.first_name,
            patients.last_name
        FROM pharmacy_sales
        JOIN medicines
            ON pharmacy_sales.medicine_id = medicines.id
        JOIN patients
            ON pharmacy_sales.patient_id = patients.id
        ORDER BY pharmacy_sales.id DESC
    """).fetchall()

    # Calculate totals
    manual_total = connection.execute("""
        SELECT COALESCE(SUM(amount), 0)
        FROM bills
    """).fetchone()[0]

    pharmacy_total = connection.execute("""
        SELECT COALESCE(SUM(total_amount), 0)
        FROM pharmacy_sales
    """).fetchone()[0]

    grand_total = manual_total + pharmacy_total

    connection.close()

    return render_template(
        "billing.html",
        patients=patients,
        bills=bills,
        pharmacy_charges=pharmacy_charges,
        manual_total=manual_total,
        pharmacy_total=pharmacy_total,
        grand_total=grand_total
    )

@app.route("/appointments/<int:appointment_id>")
def view_appointment(appointment_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_connection()

    appointment = connection.execute("""
        SELECT
            appointments.*,
            patients.first_name AS patient_first_name,
            patients.last_name AS patient_last_name,
            patients.patient_number,
            doctors.first_name AS doctor_first_name,
            doctors.last_name AS doctor_last_name,
            doctors.doctor_number,
            doctors.specialization
        FROM appointments
        JOIN patients
            ON appointments.patient_id = patients.id
        JOIN doctors
            ON appointments.doctor_id = doctors.id
        WHERE appointments.id = ?
    """, (appointment_id,)).fetchone()

    connection.close()

    if appointment is None:
        return "Appointment not found", 404

    return render_template(
        "view_appointment.html",
        appointment=appointment
    )

@app.route("/appointments/<int:appointment_id>/edit", methods=["GET", "POST"])
def edit_appointment(appointment_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_connection()

    # Get the appointment
    appointment = connection.execute("""
        SELECT * FROM appointments
        WHERE id = ?
    """, (appointment_id,)).fetchone()

    if appointment is None:
        connection.close()
        return "Appointment not found", 404

    # Get patients
    patients_list = connection.execute("""
        SELECT id, patient_number, first_name, last_name
        FROM patients
        ORDER BY first_name
    """).fetchall()

    # Get doctors
    doctors_list = connection.execute("""
        SELECT id, doctor_number, first_name, last_name, specialization
        FROM doctors
        ORDER BY first_name
    """).fetchall()

    # Update appointment
    if request.method == "POST":

        appointment_number = request.form["appointment_number"]
        patient_id = request.form["patient_id"]
        doctor_id = request.form["doctor_id"]
        appointment_date = request.form["appointment_date"]
        appointment_time = request.form["appointment_time"]
        reason = request.form["reason"]
        status = request.form["status"]

        connection.execute("""
            UPDATE appointments
            SET appointment_number = ?,
                patient_id = ?,
                doctor_id = ?,
                appointment_date = ?,
                appointment_time = ?,
                reason = ?,
                status = ?
            WHERE id = ?
        """, (
            appointment_number,
            patient_id,
            doctor_id,
            appointment_date,
            appointment_time,
            reason,
            status,
            appointment_id
        ))

        connection.commit()
        connection.close()

        return redirect(
            url_for(
                "view_appointment",
                appointment_id=appointment_id
            )
        )

    connection.close()

    return render_template(
        "edit_appointment.html",
        appointment=appointment,
        patients=patients_list,
        doctors=doctors_list
    )
@app.route("/appointments/<int:appointment_id>/delete", methods=["POST"])
def delete_appointment(appointment_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_connection()

    appointment = connection.execute("""
        SELECT id FROM appointments
        WHERE id = ?
    """, (appointment_id,)).fetchone()

    if appointment is None:
        connection.close()
        return "Appointment not found", 404

    connection.execute("""
        DELETE FROM appointments
        WHERE id = ?
    """, (appointment_id,))

    connection.commit()
    connection.close()

    return redirect(url_for("appointments"))
@app.route("/pharmacy/dispense", methods=["GET", "POST"])
@role_required("Administrator", "Pharmacist")
def dispense_medicine():

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_connection()

    if request.method == "POST":

        patient_id = request.form["patient_id"]
        medicine_id = request.form["medicine_id"]
        quantity = int(request.form["quantity"])

        medicine = connection.execute("""
            SELECT *
            FROM medicines
            WHERE id = ?
        """, (medicine_id,)).fetchone()

        if medicine is None:
            connection.close()
            return "Medicine not found", 404

        available_quantity = int(medicine["quantity"])
        unit_price = float(medicine["unit_price"])

        if quantity <= 0:
            connection.close()
            return "Invalid quantity", 400

        if quantity > available_quantity:
            connection.close()
            return (
                f"Not enough stock available. "
                f"Available: {available_quantity}, "
                f"Requested: {quantity}"
            ), 400

        total_amount = quantity * unit_price

        sale_number = "SALE-" + datetime.now().strftime("%Y%m%d%H%M%S")

        connection.execute("""
            INSERT INTO pharmacy_sales (
                sale_number,
                patient_id,
                medicine_id,
                quantity,
                unit_price,
                total_amount
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            sale_number,
            patient_id,
            medicine_id,
            quantity,
            unit_price,
            total_amount
        ))

        new_quantity = available_quantity - quantity

        connection.execute("""
            UPDATE medicines
            SET quantity = ?
            WHERE id = ?
        """, (
            new_quantity,
            medicine_id
        ))

        connection.commit()
        connection.close()

        return redirect(url_for("pharmacy_receipt", sale_number=sale_number))
    patients = connection.execute("""
        SELECT id, patient_number, first_name, last_name
        FROM patients
        ORDER BY first_name
    """).fetchall()

    medicines = connection.execute("""
        SELECT id, medicine_number, medicine_name, quantity, unit_price
        FROM medicines
        ORDER BY medicine_name
    """).fetchall()

    connection.close()

    return render_template(
        "dispense_medicine.html",
        patients=patients,
        medicines=medicines
    )
@app.route("/pharmacy/receipt/<sale_number>")
def pharmacy_receipt(sale_number):

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_connection()

    sale = connection.execute("""
        SELECT
            pharmacy_sales.*,
            patients.patient_number,
            patients.first_name AS patient_first_name,
            patients.last_name AS patient_last_name,
            medicines.medicine_number,
            medicines.medicine_name
        FROM pharmacy_sales
        JOIN patients
            ON pharmacy_sales.patient_id = patients.id
        JOIN medicines
            ON pharmacy_sales.medicine_id = medicines.id
        WHERE pharmacy_sales.sale_number = ?
    """, (sale_number,)).fetchone()

    connection.close()

    if sale is None:
        return "Sale not found", 404

    return render_template(
        "pharmacy_receipt.html",
        sale=sale
    )
@app.route("/pharmacy/sales")
@role_required("Administrator" , "Pharmacist")
def pharmacy_sales():
    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_connection()

    sales = connection.execute("""
        SELECT
            pharmacy_sales.*,
            patients.patient_number,
            patients.first_name AS patient_first_name,
            patients.last_name AS patient_last_name,
            medicines.medicine_number,
            medicines.medicine_name
        FROM pharmacy_sales
        JOIN patients
            ON pharmacy_sales.patient_id = patients.id
        JOIN medicines
            ON pharmacy_sales.medicine_id = medicines.id
        ORDER BY pharmacy_sales.id DESC
    """).fetchall()

    total_sales = connection.execute("""
        SELECT COALESCE(SUM(total_amount), 0)
        FROM pharmacy_sales
    """).fetchone()[0]

    connection.close()

    return render_template(
        "pharmacy_sales.html",
        sales=sales,
        total_sales=total_sales
    )

@app.route("/medical_records", methods=["GET", "POST"])
@role_required("Administrator", "Doctor")
def medical_records():

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_connection()

    # Get patients for dropdown
    patients_list = connection.execute("""
        SELECT id, patient_number, first_name, last_name
        FROM patients
        ORDER BY first_name
    """).fetchall()

    # Get doctors for dropdown
    doctors_list = connection.execute("""
        SELECT id, doctor_number, first_name, last_name, specialization
        FROM doctors
        ORDER BY first_name
    """).fetchall()

    # Register medical record
    if request.method == "POST":

        record_number = request.form["record_number"]
        patient_id = request.form["patient_id"]
        doctor_id = request.form["doctor_id"]
        visit_date = request.form["visit_date"]
        symptoms = request.form["symptoms"]
        diagnosis = request.form["diagnosis"]
        treatment = request.form["treatment"]
        prescription = request.form["prescription"]
        follow_up_date = request.form["follow_up_date"]

        connection.execute("""
            INSERT INTO medical_records (
                record_number,
                patient_id,
                doctor_id,
                visit_date,
                symptoms,
                diagnosis,
                treatment,
                prescription,
                follow_up_date
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            record_number,
            patient_id,
            doctor_id,
            visit_date,
            symptoms,
            diagnosis,
            treatment,
            prescription,
            follow_up_date
        ))

        connection.commit()
        connection.close()

        return redirect(url_for("medical_records"))

 # Search Medical Records
    search = request.args.get("search", "").strip()

    if search:
        records_list = connection.execute("""
            SELECT
                medical_records.*,
                patients.patient_number,
                patients.first_name AS patient_first_name,
                patients.last_name AS patient_last_name,
                doctors.doctor_number,
                doctors.first_name AS doctor_first_name,
                doctors.last_name AS doctor_last_name,
                doctors.specialization
            FROM medical_records
            JOIN patients
                ON medical_records.patient_id = patients.id
            JOIN doctors
                ON medical_records.doctor_id = doctors.id
            WHERE medical_records.record_number LIKE ?
                OR patients.patient_number LIKE ?
                OR patients.first_name LIKE ?
                OR patients.last_name LIKE ?
                OR doctors.first_name LIKE ?
                OR doctors.last_name LIKE ?
                OR medical_records.diagnosis LIKE ?
            ORDER BY medical_records.visit_date DESC
        """, (
            f"%{search}%",
            f"%{search}%",
            f"%{search}%",
            f"%{search}%",
            f"%{search}%",
            f"%{search}%",
            f"%{search}%"
        )).fetchall()

    else:
        records_list = connection.execute("""
            SELECT
                medical_records.*,
                patients.patient_number,
                patients.first_name AS patient_first_name,
                patients.last_name AS patient_last_name,
                doctors.doctor_number,
                doctors.first_name AS doctor_first_name,
                doctors.last_name AS doctor_last_name,
                doctors.specialization
            FROM medical_records
            JOIN patients
                ON medical_records.patient_id = patients.id
            JOIN doctors
                ON medical_records.doctor_id = doctors.id
            ORDER BY medical_records.visit_date DESC
        """).fetchall()

    connection.close()

    return render_template(
        "medical_records.html",
        records=records_list,
        patients=patients_list,
        doctors=doctors_list,
        search=search
    )

@app.route("/medical-record/<int:record_id>")
@role_required("Administrator", "Doctor")
def view_medical_record(record_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_connection()

    record = connection.execute("""
        SELECT
            medical_records.*,
            patients.patient_number,
            patients.first_name AS patient_first_name,
            patients.last_name AS patient_last_name,
            doctors.doctor_number,
            doctors.first_name AS doctor_first_name,
            doctors.last_name AS doctor_last_name,
            doctors.specialization
        FROM medical_records
        JOIN patients
            ON medical_records.patient_id = patients.id
        JOIN doctors
            ON medical_records.doctor_id = doctors.id
        WHERE medical_records.id = ?
    """, (record_id,)).fetchone()

    connection.close()

    if record is None:
        return "Medical record not found", 404

    return render_template(
        "view_medical_record.html",
        record=record
    )
@app.route("/backup-restore", methods=["GET", "POST"])
@role_required("Administrator")
def backup_restore():

    if "user_id" not in session:
        return redirect(url_for("login"))

    database_path = Path(__file__).parent / "database" / "hospital.db"
    backup_folder = Path(__file__).parent / "database" / "backups"

    backup_folder.mkdir(exist_ok=True)

    if request.method == "POST":

        action = request.form.get("action")

        # BACKUP DATABASE
        if action == "backup":

            backup_name = "hospital_backup.db"
            backup_path = backup_folder / backup_name

            shutil.copy2(database_path, backup_path)

            return render_template(
                "backup_restore.html",
                message="Database backup created successfully.",
                message_type="success"
            )

        # RESTORE DATABASE
        elif action == "restore":

            backup_path = backup_folder / "hospital_backup.db"

            if not backup_path.exists():
                return render_template(
                    "backup_restore.html",
                    message="No database backup was found.",
                    message_type="error"
                )

            shutil.copy2(backup_path, database_path)

            return render_template(
                "backup_restore.html",
                message="Database restored successfully. Please restart the system.",
                message_type="success"
            )

    return render_template("backup_restore.html")
@app.route("/medical-records/<int:record_id>/edit", methods=["GET", "POST"])
def edit_medical_record(record_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_connection()

    record = connection.execute("""
        SELECT *
        FROM medical_records
        WHERE id = ?
    """, (record_id,)).fetchone()

    if record is None:
        connection.close()
        return "Medical record not found", 404

    if request.method == "POST":

        record_number = request.form["record_number"]
        patient_id = request.form["patient_id"]
        doctor_id = request.form["doctor_id"]
        visit_date = request.form["visit_date"]
        symptoms = request.form["symptoms"]
        diagnosis = request.form["diagnosis"]
        treatment = request.form["treatment"]
        prescription = request.form["prescription"]
        follow_up_date = request.form["follow_up_date"]

        connection.execute("""
            UPDATE medical_records
            SET record_number = ?,
                patient_id = ?,
                doctor_id = ?,
                visit_date = ?,
                symptoms = ?,
                diagnosis = ?,
                treatment = ?,
                prescription = ?,
                follow_up_date = ?
            WHERE id = ?
        """, (
            record_number,
            patient_id,
            doctor_id,
            visit_date,
            symptoms,
            diagnosis,
            treatment,
            prescription,
            follow_up_date,
            record_id
        ))

        connection.commit()
        connection.close()

        return redirect(
            url_for(
                "view_medical_record",
                record_id=record_id
            )
        )

    patients_list = connection.execute("""
        SELECT id, patient_number, first_name, last_name
        FROM patients
        ORDER BY first_name
    """).fetchall()

    doctors_list = connection.execute("""
        SELECT id, doctor_number, first_name, last_name, specialization
        FROM doctors
        ORDER BY first_name
    """).fetchall()

    connection.close()

    return render_template(
        "edit_medical_record.html",
        record=record,
        patients=patients_list,
        doctors=doctors_list
    )
@app.route("/medical-records/<int:record_id>/delete", methods=["POST"])
def delete_medical_record(record_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_connection()

    connection.execute("""
        DELETE FROM medical_records
        WHERE id = ?
    """, (record_id,))

    connection.commit()
    connection.close()

    return redirect(url_for("medical_records"))
@app.route("/medicines", methods=["GET", "POST"])
@role_required("Administrator", "Pharmacist")
def medicines():
    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_connection()

    # Register medicine
    if request.method == "POST":

        medicine_number = request.form["medicine_number"]
        medicine_name = request.form["medicine_name"]
        category = request.form["category"]
        quantity = request.form["quantity"]
        unit_price = request.form["unit_price"]
        expiry_date = request.form["expiry_date"]
        supplier = request.form["supplier"]
        description = request.form["description"]

        connection.execute("""
            INSERT INTO medicines (
                medicine_number,
                medicine_name,
                category,
                quantity,
                unit_price,
                expiry_date,
                supplier,
                description,
                registration_date
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """, (
            medicine_number,
            medicine_name,
            category,
            quantity,
            unit_price,
            expiry_date,
            supplier,
            description
        ))

        connection.commit()

    # Search medicines
    search = request.args.get("search", "").strip()

    if search:

        medicines_list = connection.execute("""
            SELECT *
            FROM medicines
            WHERE medicine_number LIKE ?
               OR medicine_name LIKE ?
               OR category LIKE ?
               OR supplier LIKE ?
            ORDER BY id DESC
        """, (
            f"%{search}%",
            f"%{search}%",
            f"%{search}%",
            f"%{search}%"
        )).fetchall()

    else:

        medicines_list = connection.execute("""
            SELECT *
            FROM medicines
            ORDER BY id DESC
        """).fetchall()

    # Stock and expiry status
    medicines_with_status = []

    total_medicines = 0
    low_stock_count = 0
    out_of_stock_count = 0

    from datetime import date, datetime, timedelta

    today = date.today()

    for medicine in medicines_list:

        quantity = int(medicine["quantity"])

        total_medicines += 1

        # Stock status
        if quantity == 0:

            stock_status = "Out of Stock"
            out_of_stock_count += 1

        elif quantity <= 10:

            stock_status = "Low Stock"
            low_stock_count += 1

        else:

            stock_status = "In Stock"

        # Expiry status
        expiry_status = "No Expiry Date"

        if medicine["expiry_date"]:

            try:

                expiry = datetime.strptime(
                    medicine["expiry_date"],
                    "%Y-%m-%d"
                ).date()

                days_remaining = (expiry - today).days

                if days_remaining < 0:

                    expiry_status = "Expired"

                elif days_remaining <= 30:

                    expiry_status = "Expiring Soon"

                else:

                    expiry_status = "Valid"

            except ValueError:

                expiry_status = "Invalid Date"

        medicines_with_status.append({
            "medicine": medicine,
            "stock_status": stock_status,
            "expiry_status": expiry_status
        })

    connection.close()

    return render_template(
        "medicines.html",
        medicines=medicines_with_status,
        search=search,
        total_medicines=total_medicines,
        low_stock_count=low_stock_count,
        out_of_stock_count=out_of_stock_count
    )
@app.route("/medicines/<int:medicine_id>/edit", methods=["GET", "POST"])
def edit_medicine(medicine_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_connection()

    medicine = connection.execute("""
        SELECT *
        FROM medicines
        WHERE id = ?
    """, (medicine_id,)).fetchone()

    if medicine is None:
        connection.close()
        return "Medicine not found", 404

    if request.method == "POST":

        medicine_number = request.form["medicine_number"]
        medicine_name = request.form["medicine_name"]
        category = request.form["category"]
        quantity = request.form["quantity"]
        unit_price = request.form["unit_price"]
        expiry_date = request.form["expiry_date"]
        supplier = request.form["supplier"]
        description = request.form["description"]

        connection.execute("""
            UPDATE medicines
            SET medicine_number = ?,
                medicine_name = ?,
                category = ?,
                quantity = ?,
                unit_price = ?,
                expiry_date = ?,
                supplier = ?,
                description = ?
            WHERE id = ?
        """, (
            medicine_number,
            medicine_name,
            category,
            quantity,
            unit_price,
            expiry_date,
            supplier,
            description,
            medicine_id
        ))

        connection.commit()
        connection.close()

        return redirect(url_for("medicines"))

    connection.close()

    return render_template(
        "edit_medicine.html",
        medicine=medicine
    )


@app.route("/medicines/<int:medicine_id>/delete", methods=["POST"])
def delete_medicine(medicine_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_connection()

    connection.execute("""
        DELETE FROM medicines
        WHERE id = ?
    """, (medicine_id,))

    connection.commit()
    connection.close()

    return redirect(url_for("medicines"))



@app.route("/doctors/<int:doctor_id>/edit", methods=["GET", "POST"])
def edit_doctor(doctor_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_connection()

    doctor = connection.execute(
        "SELECT * FROM doctors WHERE id = ?",
        (doctor_id,)
    ).fetchone()

    if doctor is None:
        connection.close()
        return "Doctor not found", 404

    if request.method == "POST":

        doctor_number = request.form["doctor_number"]
        first_name = request.form["first_name"]
        last_name = request.form["last_name"]
        specialization = request.form["specialization"]
        phone = request.form["phone"]
        email = request.form["email"]
        department = request.form["department"]

        connection.execute("""
            UPDATE doctors
            SET doctor_number = ?,
                first_name = ?,
                last_name = ?,
                specialization = ?,
                phone = ?,
                email = ?,
                department = ?
            WHERE id = ?
        """, (
            doctor_number,
            first_name,
            last_name,
            specialization,
            phone,
            email,
            department,
            doctor_id
        ))

        connection.commit()
        connection.close()

        return redirect(url_for("view_doctor", doctor_id=doctor_id))

    connection.close()

    return render_template(
        "edit_doctor.html",
        doctor=doctor
    )
@app.route("/doctors/<int:doctor_id>/delete", methods=["POST"])
def delete_doctor(doctor_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_connection()

    connection.execute(
        "DELETE FROM doctors WHERE id = ?",
        (doctor_id,)
    )

    connection.commit()
    connection.close()

    return redirect(url_for("doctors"))

@app.route("/reports")
@role_required("Administrator", "Doctor")
def reports():

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_connection()

    # Total patients
    total_patients = connection.execute(
        "SELECT COUNT(*) FROM patients"
    ).fetchone()[0]

    # Total doctors
    total_doctors = connection.execute(
        "SELECT COUNT(*) FROM doctors"
    ).fetchone()[0]

    # Today's appointments
    today_appointments = connection.execute("""
        SELECT COUNT(*)
        FROM appointments
        WHERE appointment_date = date('now')
    """).fetchone()[0]

    # Total appointments
    total_appointments = connection.execute("""
        SELECT COUNT(*)
        FROM appointments
    """).fetchone()[0]

    # Today's pharmacy sales
    today_sales = connection.execute("""
        SELECT COALESCE(SUM(total_amount), 0)
        FROM pharmacy_sales
        WHERE date(sale_date) = date('now')
    """).fetchone()[0]

    # Total pharmacy sales
    total_sales = connection.execute("""
        SELECT COALESCE(SUM(total_amount), 0)
        FROM pharmacy_sales
    """).fetchone()[0]

    # Total laboratory tests
    total_laboratory_tests = connection.execute("""
        SELECT COUNT(*)
        FROM laboratory_tests
    """).fetchone()[0]

    # Completed laboratory tests
    completed_tests = connection.execute("""
        SELECT COUNT(*)
        FROM laboratory_tests
        WHERE LOWER(status) = 'completed'
    """).fetchone()[0]

    # Total medicines
    total_medicines = connection.execute(
        "SELECT COUNT(*) FROM medicines"
    ).fetchone()[0]

    # Low-stock medicines
    low_stock = connection.execute("""
        SELECT COUNT(*)
        FROM medicines
        WHERE quantity > 0 AND quantity <= 10
    """).fetchone()[0]

    # Out-of-stock medicines
    out_of_stock = connection.execute("""
        SELECT COUNT(*)
        FROM medicines
        WHERE quantity = 0
    """).fetchone()[0]

    connection.close()

    return render_template(
        "reports.html",
        total_patients=total_patients,
        total_doctors=total_doctors,
        today_appointments=today_appointments,
        today_sales=today_sales,
        total_sales=total_sales,
        total_laboratory_tests=total_laboratory_tests,
        completed_tests=completed_tests,
        total_medicines=total_medicines,
        total_appointments=total_appointments,
        low_stock=low_stock,
        out_of_stock=out_of_stock
    )
if __name__ == "__main__":
    app.run(debug=True)