import os
import shutil
from pathlib import Path
from datetime import datetime
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    abort
)

from flask_wtf.csrf import CSRFProtect,CSRFError

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from dotenv import load_dotenv

from database.database import (
    get_connection,
    initialize_database
)

# =========================================================
# LOAD ENVIRONMENT VARIABLES
# =========================================================

load_dotenv()


# =========================================================
# FLASK APPLICATION
# =========================================================

app = Flask(__name__)

initialize_database()


# =========================================================
# SECURITY CONFIGURATION
# =========================================================

secret_key = os.getenv("SECRET_KEY")

if not secret_key:
    raise RuntimeError(
        "SECRET_KEY is missing. Please add SECRET_KEY to your .env file."
    )

app.config["SECRET_KEY"] = secret_key

# Protect session cookies from JavaScript
app.config["SESSION_COOKIE_HTTPONLY"] = True

# Helps protect against cross-site request attacks
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Keep False while running on local HTTP.
# Change to True when deployed with HTTPS.
app.config["SESSION_COOKIE_SECURE"] = False

# Session timeout: 30 minutes
app.config["PERMANENT_SESSION_LIFETIME"] = 1800


# =========================================================
# CSRF PROTECTION
# =========================================================

csrf = CSRFProtect(app)


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

initialize_database()

# =========================================================
# ROLE PROTECTION
# =========================================================

def role_required(*allowed_roles):

    def decorator(function):

        @wraps(function)
        def wrapper(*args, **kwargs):

            # User must be logged in
            if "user_id" not in session:
                return redirect(url_for("login"))

            # Get current user's role
            user_role = session.get("role")

            # Verify role
            if user_role not in allowed_roles:
                abort(403)

            return function(*args, **kwargs)

        return wrapper

    return decorator


# =========================================================
# ERROR HANDLERS
# =========================================================

@app.errorhandler(403)
def forbidden(error):

    return render_template(
        "error.html",
        error_code=403,
        error_message="Access denied. You do not have permission to access this page."
    ), 403


@app.errorhandler(404)
def page_not_found(error):

    return render_template(
        "error.html",
        error_code=404,
        error_message="The requested page could not be found."
    ), 404

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    print("CSRF ERROR:", e.description)

    return f"""
    <h1>CSRF Error</h1>
    <p>{e.description}</p>
    <p>Please go back and try again.</p>
    """, 400
@app.errorhandler(400)
def bad_request(error):


    return render_template(
        "error.html",
        error_code=400,
        error_message="The request could not be processed."
    ), 400


# =========================================================
# USERS / USER MANAGEMENT
# =========================================================

@app.route("/users", methods=["GET", "POST"])
@role_required("Administrator")
def users():

    connection = get_connection()

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "").strip()

        allowed_roles = {
            "Administrator",
            "Doctor",
            "Pharmacist",
            "Laboratory Technician",
            "Receptionist"
        }

        if not username or not password or not role:
            connection.close()
            return "All fields are required.", 400

        if role not in allowed_roles:
            connection.close()
            return "Invalid role selected.", 400

        if len(username) < 3:
            connection.close()
            return "Username must contain at least 3 characters.", 400

        if len(password) < 8:
            connection.close()
            return "Password must contain at least 8 characters.", 400

        existing_user = connection.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if existing_user:
            connection.close()
            return "Username already exists.", 400

        hashed_password = generate_password_hash(password)

        connection.execute("""
            INSERT INTO users (
                username,
                password,
                role
            )
            VALUES (?, ?, ?)
        """, (
            username,
            hashed_password,
            role
        ))

        connection.commit()

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


# =========================================================
# LOGIN
# =========================================================

@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:

            return render_template(
                "login.html",
                error="Username and password are required."
            )

        connection = get_connection()

        user = connection.execute(
            """
            SELECT *
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        connection.close()

        if user and check_password_hash(
            user["password"],
            password
        ):

            # Clear any previous session data
            session.clear()

            # Store only necessary information
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            # Make session temporary
            session.permanent = True

            return redirect(url_for("dashboard"))

        return render_template(
            "login.html",
            error="Invalid username or password."
        )

    return render_template("login.html")


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
@role_required(
    "Administrator",
    "Doctor",
    "Pharmacist",
    "Laboratory Technician",
    "Receptionist"
)
def dashboard():

    connection = get_connection()

    total_patients = connection.execute(
        "SELECT COUNT(*) FROM patients"
    ).fetchone()[0]

    total_doctors = connection.execute(
        "SELECT COUNT(*) FROM doctors"
    ).fetchone()[0]

    total_medicines = connection.execute(
        "SELECT COUNT(*) FROM medicines"
    ).fetchone()[0]

    low_stock_medicines = connection.execute("""
        SELECT COUNT(*)
        FROM medicines
        WHERE quantity > 0
        AND quantity <= 10
    """).fetchone()[0]

    out_of_stock_medicines = connection.execute("""
        SELECT COUNT(*)
        FROM medicines
        WHERE quantity = 0
    """).fetchone()[0]

    today_appointments = connection.execute("""
        SELECT COUNT(*)
        FROM appointments
        WHERE date(appointment_date) = date('now')
    """).fetchone()[0]

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


# =========================================================
# PATIENTS
# =========================================================

@app.route("/patients", methods=["GET", "POST"])
@role_required(
    "Administrator",
    "Doctor",
    "Receptionist"
)
def patients():

    connection = get_connection()

    if request.method == "POST":

        patient_number = request.form.get("patient_number", "").strip()
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        date_of_birth = request.form.get("date_of_birth", "").strip()
        gender = request.form.get("gender", "").strip()
        phone = request.form.get("phone", "").strip()
        address = request.form.get("address", "").strip()
        blood_group = request.form.get("blood_group", "").strip()
        emergency_contact = request.form.get("emergency_contact", "").strip()

        if not patient_number or not first_name or not last_name:

            connection.close()

            return "Required patient fields are missing.", 400

        try:

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

        except Exception as e:

            print(
                "PATIENT REGISTRATION ERROR:",
                repr(e)
            )

            connection.rollback()
            connection.close()

            return f"PATIENT DATABASE ERROR: {e}", 400

        connection.close()

        return redirect(url_for("patients"))

    search = request.args.get(
        "search",
        ""
    ).strip()

    if search:

        patients_list = connection.execute("""
            SELECT *
            FROM patients
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
            SELECT *
            FROM patients
            ORDER BY id DESC
        """).fetchall()

    connection.close()

    return render_template(
        "patients.html",
        patients=patients_list,
        search=search
    )
# =========================================================
# VIEW PATIENT
@app.route("/patients/<int:patient_id>")
@role_required(
    "Administrator",
    "Doctor",
    "Receptionist"
)
def view_patient(patient_id):

    connection = get_connection()

    patient = connection.execute(
        """
        SELECT *
        FROM patients
        WHERE id = ?
        """,
        (patient_id,)
    ).fetchone()

    connection.close()

    if patient is None:
        return "Patient not found", 404

    return render_template(
        "view_patient.html",
        patient=patient
    )


# =========================================================
# EDIT PATIENT
# =========================================================

@app.route(
    "/patients/<int:patient_id>/edit",
    methods=["GET", "POST"]
)
@role_required(
    "Administrator",
    "Doctor",
    "Receptionist"
)
def edit_patient(patient_id):

    connection = get_connection()

    patient = connection.execute(
        """
        SELECT *
        FROM patients
        WHERE id = ?
        """,
        (patient_id,)
    ).fetchone()

    if patient is None:

        connection.close()

        return "Patient not found", 404

    if request.method == "POST":

        patient_number = request.form.get(
            "patient_number", ""
        ).strip()

        first_name = request.form.get(
            "first_name", ""
        ).strip()

        last_name = request.form.get(
            "last_name", ""
        ).strip()

        date_of_birth = request.form.get(
            "date_of_birth", ""
        ).strip()

        gender = request.form.get(
            "gender", ""
        ).strip()

        phone = request.form.get(
            "phone", ""
        ).strip()

        address = request.form.get(
            "address", ""
        ).strip()

        blood_group = request.form.get(
            "blood_group", ""
        ).strip()

        emergency_contact = request.form.get(
            "emergency_contact", ""
        ).strip()

        if not patient_number or not first_name or not last_name:

            connection.close()

            return "Required patient fields are missing.", 400

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

        return redirect(
            url_for(
                "view_patient",
                patient_id=patient_id
            )
        )

    connection.close()

    return render_template(
        "edit_patient.html",
        patient=patient
    )


# =========================================================
# DELETE PATIENT
# =========================================================
@app.route("/delete_patient/<int:patient_id>", methods=["POST"])
@role_required("Administrator")
def delete_patient(patient_id):

    connection = get_connection()

    patient = connection.execute(
        """
        SELECT id
        FROM patients
        WHERE id = ?
        """,
        (patient_id,)
    ).fetchone()

    if patient is None:
        connection.close()
        return "Patient not found", 404

    try:

        connection.execute(
            """
            DELETE FROM patients
            WHERE id = ?
            """,
            (patient_id,)
        )

        connection.commit()

    except Exception as e:

        connection.rollback()
        connection.close()

        print("DELETE PATIENT ERROR:", repr(e))

        return (
            f"Patient could not be deleted. Database error: {e}",
            400
        )

    connection.close()

    return redirect(url_for("patients"))
# =========================================================
# DOCTORS
# =========================================================

@app.route("/doctors", methods=["GET", "POST"])
@role_required(
    "Administrator",
    "Doctor"
)
def doctors():

    connection = get_connection()

    if request.method == "POST":

        doctor_number = request.form.get(
            "doctor_number", ""
        ).strip()

        first_name = request.form.get(
            "first_name", ""
        ).strip()

        last_name = request.form.get(
            "last_name", ""
        ).strip()

        specialization = request.form.get(
            "specialization", ""
        ).strip()

        phone = request.form.get(
            "phone", ""
        ).strip()

        email = request.form.get(
            "email", ""
        ).strip()

        department = request.form.get(
            "department", ""
        ).strip()

        if not doctor_number or not first_name or not last_name:

            connection.close()

            return "Required doctor fields are missing.", 400

        try:

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

        except Exception:

            connection.close()

            return "Unable to register doctor. Check that the doctor number is unique.", 400

        connection.close()

        return redirect(url_for("doctors"))

    search = request.args.get(
        "search",
        ""
    ).strip()

    if search:

        doctors_list = connection.execute("""
            SELECT *
            FROM doctors
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
            SELECT *
            FROM doctors
            ORDER BY id DESC
        """).fetchall()

    connection.close()

    return render_template(
        "doctors.html",
        doctors=doctors_list,
        search=search
    )


# =========================================================
# EDIT DOCTOR
# =========================================================

@app.route(
    "/doctors/<int:doctor_id>/edit",
    methods=["GET", "POST"]
)
@role_required(
    "Administrator",
    "Doctor"
)
def edit_doctor(doctor_id):

    connection = get_connection()

    doctor = connection.execute(
        """
        SELECT *
        FROM doctors
        WHERE id = ?
        """,
        (doctor_id,)
    ).fetchone()

    if doctor is None:

        connection.close()

        return "Doctor not found", 404

    if request.method == "POST":

        doctor_number = request.form.get(
            "doctor_number", ""
        ).strip()

        first_name = request.form.get(
            "first_name", ""
        ).strip()

        last_name = request.form.get(
            "last_name", ""
        ).strip()

        specialization = request.form.get(
            "specialization", ""
        ).strip()

        phone = request.form.get(
            "phone", ""
        ).strip()

        email = request.form.get(
            "email", ""
        ).strip()

        department = request.form.get(
            "department", ""
        ).strip()

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

        return redirect(
            url_for(
                "doctors"
            )
        )

    connection.close()

    return render_template(
        "edit_doctor.html",
        doctor=doctor
    )


# =========================================================
# DELETE DOCTOR
# =========================================================

@app.route(
    "/doctors/<int:doctor_id>/delete",
    methods=["POST"]
)
@role_required("Administrator")
def delete_doctor(doctor_id):

    connection = get_connection()

    doctor = connection.execute(
        """
        SELECT id
        FROM doctors
        WHERE id = ?
        """,
        (doctor_id,)
    ).fetchone()

    if doctor is None:

        connection.close()

        return "Doctor not found", 404

    try:

        connection.execute(
            """
            DELETE FROM doctors
            WHERE id = ?
            """,
            (doctor_id,)
        )

        connection.commit()

    except Exception:

        connection.close()

        return (
            "Doctor cannot be deleted because related records exist.",
            400
        )

    connection.close()

    return redirect(url_for("doctors"))


# =========================================================
# APPOINTMENTS
# =========================================================

@app.route(
    "/appointments",
    methods=["GET", "POST"]
)
@role_required(
    "Administrator",
    "Doctor",
    "Receptionist"
)
def appointments():

    connection = get_connection()

    patients_list = connection.execute("""
        SELECT
            id,
            patient_number,
            first_name,
            last_name
        FROM patients
        ORDER BY first_name
    """).fetchall()

    doctors_list = connection.execute("""
        SELECT
            id,
            doctor_number,
            first_name,
            last_name,
            specialization
        FROM doctors
        ORDER BY first_name
    """).fetchall()

    if request.method == "POST":

        appointment_number = request.form.get(
            "appointment_number", ""
        ).strip()

        patient_id = request.form.get(
            "patient_id", ""
        )

        doctor_id = request.form.get(
            "doctor_id", ""
        )

        appointment_date = request.form.get(
            "appointment_date", ""
        )

        appointment_time = request.form.get(
            "appointment_time", ""
        )

        reason = request.form.get(
            "reason", ""
        ).strip()

        status = request.form.get(
            "status", ""
        ).strip()

        if not appointment_number or not patient_id or not doctor_id:

            connection.close()

            return "Required appointment fields are missing.", 400

        try:

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

        except Exception:

            connection.close()

            return "Unable to create appointment.", 400

        connection.close()

        return redirect(
            url_for("appointments")
        )

    search = request.args.get(
        "search",
        ""
    ).strip()

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


# =========================================================
# VIEW APPOINTMENT
# =========================================================

@app.route("/appointments/<int:appointment_id>")
@role_required(
    "Administrator",
    "Doctor",
    "Receptionist"
)
def view_appointment(appointment_id):

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


# =========================================================
# EDIT APPOINTMENT
# =========================================================

@app.route(
    "/appointments/<int:appointment_id>/edit",
    methods=["GET", "POST"]
)
@role_required(
    "Administrator",
    "Doctor",
    "Receptionist"
)
def edit_appointment(appointment_id):

    connection = get_connection()

    appointment = connection.execute("""
        SELECT *
        FROM appointments
        WHERE id = ?
    """, (appointment_id,)).fetchone()

    if appointment is None:

        connection.close()

        return "Appointment not found", 404

    patients_list = connection.execute("""
        SELECT
            id,
            patient_number,
            first_name,
            last_name
        FROM patients
        ORDER BY first_name
    """).fetchall()

    doctors_list = connection.execute("""
        SELECT
            id,
            doctor_number,
            first_name,
            last_name,
            specialization
        FROM doctors
        ORDER BY first_name
    """).fetchall()

    if request.method == "POST":

        appointment_number = request.form.get(
            "appointment_number", ""
        ).strip()

        patient_id = request.form.get(
            "patient_id", ""
        )

        doctor_id = request.form.get(
            "doctor_id", ""
        )

        appointment_date = request.form.get(
            "appointment_date", ""
        )

        appointment_time = request.form.get(
            "appointment_time", ""
        )

        reason = request.form.get(
            "reason", ""
        ).strip()

        status = request.form.get(
            "status", ""
        ).strip()

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


# =========================================================
# DELETE APPOINTMENT
# =========================================================

@app.route(
    "/appointments/<int:appointment_id>/delete",
    methods=["POST"]
)
@role_required("Administrator")
def delete_appointment(appointment_id):

    connection = get_connection()

    appointment = connection.execute("""
        SELECT id
        FROM appointments
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

    return redirect(
        url_for("appointments")
    )


# =========================================================
# LABORATORY
# =========================================================

@app.route(
    "/laboratory",
    methods=["GET", "POST"]
)
@role_required(
    "Administrator",
    "Doctor",
    "Laboratory Technician"
)
def laboratory():

    connection = get_connection()

    patients_list = connection.execute("""
        SELECT
            id,
            patient_number,
            first_name,
            last_name
        FROM patients
        ORDER BY first_name
    """).fetchall()

    doctors_list = connection.execute("""
        SELECT
            id,
            doctor_number,
            first_name,
            last_name,
            specialization
        FROM doctors
        ORDER BY first_name
    """).fetchall()

    if request.method == "POST":

        test_number = request.form.get(
            "test_number", ""
        ).strip()

        patient_id = request.form.get(
            "patient_id", ""
        )

        doctor_id = request.form.get(
            "doctor_id", ""
        )

        test_name = request.form.get(
            "test_name", ""
        ).strip()

        test_date = request.form.get(
            "test_date", ""
        )

        result = request.form.get(
            "result",
            ""
        ).strip()

        status = request.form.get(
            "status",
            ""
        ).strip()

        notes = request.form.get(
            "notes",
            ""
        ).strip()

        if not test_number or not patient_id or not doctor_id or not test_name:

            connection.close()

            return "Required laboratory fields are missing.", 400

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

        return redirect(
            url_for("laboratory")
        )

    search = request.args.get(
        "search",
        ""
    ).strip()

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


# =========================================================
# BILLING
# =========================================================

@app.route(
    "/billing",
    methods=["GET", "POST"]
)
@role_required(
    "Administrator",
    "Receptionist"
)
def billing():

    connection = get_connection()

    patients = connection.execute("""
        SELECT
            id,
            patient_number,
            first_name,
            last_name
        FROM patients
        ORDER BY first_name
    """).fetchall()

    if request.method == "POST":

        patient_id = request.form.get(
            "patient_id",
            ""
        )

        description = request.form.get(
            "description",
            ""
        ).strip()

        amount_text = request.form.get(
            "amount",
            ""
        )

        payment_status = request.form.get(
            "payment_status",
            ""
        ).strip()

        try:

            amount = float(amount_text)

        except (ValueError, TypeError):

            connection.close()

            return "Invalid billing amount.", 400

        if amount <= 0:

            connection.close()

            return "Billing amount must be greater than zero.", 400

        if not patient_id or not description or not payment_status:

            connection.close()

            return "All billing fields are required.", 400

        bill_number = (
            "BILL-" +
            datetime.now().strftime("%Y%m%d%H%M%S%f")
        )

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


# =========================================================
# PHARMACY - DISPENSE
# =========================================================

@app.route(
    "/pharmacy/dispense",
    methods=["GET", "POST"]
)
@role_required(
    "Administrator",
    "Pharmacist"
)
def dispense_medicine():

    connection = get_connection()

    if request.method == "POST":

        patient_id = request.form.get(
            "patient_id",
            ""
        )

        medicine_id = request.form.get(
            "medicine_id",
            ""
        )

        quantity_text = request.form.get(
            "quantity",
            ""
        )

        try:

            quantity = int(quantity_text)

        except (ValueError, TypeError):

            connection.close()

            return "Invalid quantity.", 400

        if quantity <= 0:

            connection.close()

            return "Quantity must be greater than zero.", 400

        medicine = connection.execute("""
            SELECT *
            FROM medicines
            WHERE id = ?
        """, (medicine_id,)).fetchone()

        if medicine is None:

            connection.close()

            return "Medicine not found", 404

        available_quantity = int(
            medicine["quantity"]
        )

        unit_price = float(
            medicine["unit_price"]
        )

        if quantity > available_quantity:

            connection.close()

            return (
                f"Not enough stock available. "
                f"Available: {available_quantity}, "
                f"Requested: {quantity}"
            ), 400

        total_amount = quantity * unit_price

        sale_number = (
            "SALE-" +
            datetime.now().strftime("%Y%m%d%H%M%S%f")
        )

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

        return redirect(
            url_for(
                "pharmacy_receipt",
                sale_number=sale_number
            )
        )

    patients = connection.execute("""
        SELECT
            id,
            patient_number,
            first_name,
            last_name
        FROM patients
        ORDER BY first_name
    """).fetchall()

    medicines = connection.execute("""
        SELECT
            id,
            medicine_number,
            medicine_name,
            quantity,
            unit_price
        FROM medicines
        WHERE quantity > 0
        ORDER BY medicine_name
    """).fetchall()

    connection.close()

    return render_template(
        "dispense_medicine.html",
        patients=patients,
        medicines=medicines
    )


# =========================================================
# PHARMACY RECEIPT
# =========================================================

@app.route(
    "/pharmacy/receipt/<sale_number>"
)
@role_required(
    "Administrator",
    "Pharmacist"
)
def pharmacy_receipt(sale_number):

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


# =========================================================
# PHARMACY SALES
# =========================================================

@app.route("/pharmacy/sales")
@role_required(
    "Administrator",
    "Pharmacist"
)
def pharmacy_sales():

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


# =========================================================
# MEDICAL RECORDS
# =========================================================

@app.route(
    "/medical_records",
    methods=["GET", "POST"]
)
@role_required(
    "Administrator",
    "Doctor"
)
def medical_records():

    connection = get_connection()

    patients_list = connection.execute("""
        SELECT
            id,
            patient_number,
            first_name,
            last_name
        FROM patients
        ORDER BY first_name
    """).fetchall()

    doctors_list = connection.execute("""
        SELECT
            id,
            doctor_number,
            first_name,
            last_name,
            specialization
        FROM doctors
        ORDER BY first_name
    """).fetchall()

    if request.method == "POST":

        record_number = request.form.get(
            "record_number",
            ""
        ).strip()

        patient_id = request.form.get(
            "patient_id",
            ""
        )

        doctor_id = request.form.get(
            "doctor_id",
            ""
        )

        visit_date = request.form.get(
            "visit_date",
            ""
        )

        symptoms = request.form.get(
            "symptoms",
            ""
        ).strip()

        diagnosis = request.form.get(
            "diagnosis",
            ""
        ).strip()

        treatment = request.form.get(
            "treatment",
            ""
        ).strip()

        prescription = request.form.get(
            "prescription",
            ""
        ).strip()

        follow_up_date = request.form.get(
            "follow_up_date",
            ""
        )

        if not record_number or not patient_id or not doctor_id:

            connection.close()

            return "Required medical record fields are missing.", 400

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

        return redirect(
            url_for("medical_records")
        )

    search = request.args.get(
        "search",
        ""
    ).strip()

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


# =========================================================
# VIEW MEDICAL RECORD
# =========================================================

@app.route(
    "/medical-record/<int:record_id>"
)
@role_required(
    "Administrator",
    "Doctor"
)
def view_medical_record(record_id):

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


# =========================================================
# EDIT MEDICAL RECORD
# =========================================================

@app.route(
    "/medical-records/<int:record_id>/edit",
    methods=["GET", "POST"]
)
@role_required(
    "Administrator",
    "Doctor"
)
def edit_medical_record(record_id):

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

        record_number = request.form.get(
            "record_number",
            ""
        ).strip()

        patient_id = request.form.get(
            "patient_id",
            ""
        )

        doctor_id = request.form.get(
            "doctor_id",
            ""
        )

        visit_date = request.form.get(
            "visit_date",
            ""
        )

        symptoms = request.form.get(
            "symptoms",
            ""
        ).strip()

        diagnosis = request.form.get(
            "diagnosis",
            ""
        ).strip()

        treatment = request.form.get(
            "treatment",
            ""
        ).strip()

        prescription = request.form.get(
            "prescription",
            ""
        ).strip()

        follow_up_date = request.form.get(
            "follow_up_date",
            ""
        )

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
        SELECT
            id,
            patient_number,
            first_name,
            last_name
        FROM patients
        ORDER BY first_name
    """).fetchall()

    doctors_list = connection.execute("""
        SELECT
            id,
            doctor_number,
            first_name,
            last_name,
            specialization
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


# =========================================================
# DELETE MEDICAL RECORD
# =========================================================

@app.route(
    "/medical-records/<int:record_id>/delete",
    methods=["POST"]
)
@role_required("Administrator")
def delete_medical_record(record_id):

    connection = get_connection()

    connection.execute("""
        DELETE FROM medical_records
        WHERE id = ?
    """, (record_id,))

    connection.commit()
    connection.close()

    return redirect(
        url_for("medical_records")
    )


# =========================================================
# MEDICINES
# =========================================================

@app.route(
    "/medicines",
    methods=["GET", "POST"]
)
@role_required(
    "Administrator",
    "Pharmacist"
)
def medicines():

    connection = get_connection()

    if request.method == "POST":

        medicine_number = request.form.get(
            "medicine_number",
            ""
        ).strip()

        medicine_name = request.form.get(
            "medicine_name",
            ""
        ).strip()

        category = request.form.get(
            "category",
            ""
        ).strip()

        quantity_text = request.form.get(
            "quantity",
            ""
        )

        unit_price_text = request.form.get(
            "unit_price",
            ""
        )

        expiry_date = request.form.get(
            "expiry_date",
            ""
        )

        supplier = request.form.get(
            "supplier",
            ""
        ).strip()

        description = request.form.get(
            "description",
            ""
        ).strip()

        try:

            quantity = int(quantity_text)
            unit_price = float(unit_price_text)

        except (ValueError, TypeError):

            connection.close()

            return "Invalid quantity or unit price.", 400

        if quantity < 0:

            connection.close()

            return "Quantity cannot be negative.", 400

        if unit_price < 0:

            connection.close()

            return "Unit price cannot be negative.", 400

        if not medicine_number or not medicine_name:

            connection.close()

            return "Medicine number and name are required.", 400

        try:

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

        except Exception:

            connection.close()

            return "Unable to register medicine. Check that the medicine number is unique.", 400

    search = request.args.get(
        "search",
        ""
    ).strip()

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

    medicines_with_status = []

    total_medicines = 0
    low_stock_count = 0
    out_of_stock_count = 0

    from datetime import date

    today = date.today()

    for medicine in medicines_list:

        quantity = int(
            medicine["quantity"]
        )

        total_medicines += 1

        if quantity == 0:

            stock_status = "Out of Stock"
            out_of_stock_count += 1

        elif quantity <= 10:

            stock_status = "Low Stock"
            low_stock_count += 1

        else:

            stock_status = "In Stock"

        expiry_status = "No Expiry Date"

        if medicine["expiry_date"]:

            try:

                expiry = datetime.strptime(
                    medicine["expiry_date"],
                    "%Y-%m-%d"
                ).date()

                days_remaining = (
                    expiry - today
                ).days

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


# =========================================================
# EDIT MEDICINE
# =========================================================

@app.route(
    "/medicines/<int:medicine_id>/edit",
    methods=["GET", "POST"]
)
@role_required(
    "Administrator",
    "Pharmacist"
)
def edit_medicine(medicine_id):

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

        medicine_number = request.form.get(
            "medicine_number",
            ""
        ).strip()

        medicine_name = request.form.get(
            "medicine_name",
            ""
        ).strip()

        category = request.form.get(
            "category",
            ""
        ).strip()

        quantity_text = request.form.get(
            "quantity",
            ""
        )

        unit_price_text = request.form.get(
            "unit_price",
            ""
        )

        expiry_date = request.form.get(
            "expiry_date",
            ""
        )

        supplier = request.form.get(
            "supplier",
            ""
        ).strip()

        description = request.form.get(
            "description",
            ""
        ).strip()

        try:

            quantity = int(quantity_text)
            unit_price = float(unit_price_text)

        except (ValueError, TypeError):

            connection.close()

            return "Invalid quantity or unit price.", 400

        if quantity < 0 or unit_price < 0:

            connection.close()

            return "Quantity and price cannot be negative.", 400

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

        return redirect(
            url_for("medicines")
        )

    connection.close()

    return render_template(
        "edit_medicine.html",
        medicine=medicine
    )


# =========================================================
# DELETE MEDICINE
# =========================================================

@app.route(
    "/medicines/<int:medicine_id>/delete",
    methods=["POST"]
)
@role_required("Administrator")
def delete_medicine(medicine_id):

    connection = get_connection()

    medicine = connection.execute(
        """
        SELECT id
        FROM medicines
        WHERE id = ?
        """,
        (medicine_id,)
    ).fetchone()

    if medicine is None:

        connection.close()

        return "Medicine not found", 404

    try:

        connection.execute(
            """
            DELETE FROM medicines
            WHERE id = ?
            """,
            (medicine_id,)
        )

        connection.commit()

    except Exception:

        connection.close()

        return (
            "Medicine cannot be deleted because sales records exist.",
            400
        )

    connection.close()

    return redirect(
        url_for("medicines")
    )


# =========================================================
# BACKUP & RESTORE
# =========================================================

@app.route(
    "/backup-restore",
    methods=["GET", "POST"]
)
@role_required("Administrator")
def backup_restore():

    database_path = (
        Path(__file__).parent /
        "database" /
        "hospital.db"
    )

    backup_folder = (
        Path(__file__).parent /
        "database" /
        "backups"
    )

    backup_folder.mkdir(
        exist_ok=True
    )

    if request.method == "POST":

        action = request.form.get(
            "action"
        )

        if action == "backup":

            backup_name = "hospital_backup.db"

            backup_path = (
                backup_folder /
                backup_name
            )

            shutil.copy2(
                database_path,
                backup_path
            )

            return render_template(
                "backup_restore.html",
                message="Database backup created successfully.",
                message_type="success"
            )

        elif action == "restore":

            backup_path = (
                backup_folder /
                "hospital_backup.db"
            )

            if not backup_path.exists():

                return render_template(
                    "backup_restore.html",
                    message="No database backup was found.",
                    message_type="error"
                )

            shutil.copy2(
                backup_path,
                database_path
            )

            return render_template(
                "backup_restore.html",
                message="Database restored successfully. Please restart the system.",
                message_type="success"
            )

        return render_template(
            "backup_restore.html",
            message="Invalid backup operation.",
            message_type="error"
        )

    return render_template(
        "backup_restore.html"
    )


# =========================================================
# REPORTS
# =========================================================

@app.route("/reports")
@role_required(
    "Administrator",
    "Doctor"
)
def reports():

    connection = get_connection()

    total_patients = connection.execute(
        "SELECT COUNT(*) FROM patients"
    ).fetchone()[0]

    total_doctors = connection.execute(
        "SELECT COUNT(*) FROM doctors"
    ).fetchone()[0]

    today_appointments = connection.execute("""
        SELECT COUNT(*)
        FROM appointments
        WHERE appointment_date = date('now')
    """).fetchone()[0]

    total_appointments = connection.execute("""
        SELECT COUNT(*)
        FROM appointments
    """).fetchone()[0]

    today_sales = connection.execute("""
        SELECT COALESCE(SUM(total_amount), 0)
        FROM pharmacy_sales
        WHERE date(sale_date) = date('now')
    """).fetchone()[0]

    total_sales = connection.execute("""
        SELECT COALESCE(SUM(total_amount), 0)
        FROM pharmacy_sales
    """).fetchone()[0]

    total_laboratory_tests = connection.execute("""
        SELECT COUNT(*)
        FROM laboratory_tests
    """).fetchone()[0]

    completed_tests = connection.execute("""
        SELECT COUNT(*)
        FROM laboratory_tests
        WHERE LOWER(status) = 'completed'
    """).fetchone()[0]

    total_medicines = connection.execute(
        "SELECT COUNT(*) FROM medicines"
    ).fetchone()[0]

    low_stock = connection.execute("""
        SELECT COUNT(*)
        FROM medicines
        WHERE quantity > 0
        AND quantity <= 10
    """).fetchone()[0]

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


# =========================================================
# APPLICATION START
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=False,
        host="127.0.0.1",
        port=5000
    )