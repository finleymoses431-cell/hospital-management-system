import sqlite3
from pathlib import Path
from werkzeug.security import generate_password_hash


# =========================================================
# DATABASE LOCATION
# =========================================================

DATABASE = Path(__file__).parent / "hospital.db"


# =========================================================
# DATABASE CONNECTION
# =========================================================

def get_connection():

    connection = sqlite3.connect(DATABASE)

    connection.row_factory = sqlite3.Row

    # Enable foreign keys
    connection.execute("PRAGMA foreign_keys = ON")

    return connection


# =========================================================
# CREATE ALL TABLES
# =========================================================

def create_tables():

    connection = get_connection()
    cursor = connection.cursor()

    # =====================================================
    # USERS
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            username TEXT NOT NULL UNIQUE,

            password TEXT NOT NULL,

            role TEXT NOT NULL

        )
    """)

    # =====================================================
    # PATIENTS
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS patients (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            patient_number TEXT NOT NULL UNIQUE,

            first_name TEXT NOT NULL,

            last_name TEXT NOT NULL,

            date_of_birth TEXT NOT NULL,

            gender TEXT NOT NULL,

            phone TEXT NOT NULL,

            address TEXT,

            blood_group TEXT,

            emergency_contact TEXT,

            registration_date TEXT NOT NULL

        )
    """)

    # =====================================================
    # DOCTORS
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS doctors (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            doctor_number TEXT NOT NULL UNIQUE,

            first_name TEXT NOT NULL,

            last_name TEXT NOT NULL,

            specialization TEXT NOT NULL,

            phone TEXT NOT NULL,

            email TEXT,

            department TEXT,

            registration_date TEXT NOT NULL

        )
    """)

    # =====================================================
    # APPOINTMENTS
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS appointments (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            appointment_number TEXT NOT NULL UNIQUE,

            patient_id INTEGER NOT NULL,

            doctor_id INTEGER NOT NULL,

            appointment_date TEXT NOT NULL,

            appointment_time TEXT NOT NULL,

            reason TEXT,

            status TEXT NOT NULL,

            registration_date TEXT NOT NULL,

            FOREIGN KEY (patient_id)
                REFERENCES patients(id),

            FOREIGN KEY (doctor_id)
                REFERENCES doctors(id)

        )
    """)

    # =====================================================
    # MEDICAL RECORDS
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS medical_records (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            record_number TEXT NOT NULL UNIQUE,

            patient_id INTEGER NOT NULL,

            doctor_id INTEGER NOT NULL,

            visit_date TEXT NOT NULL,

            symptoms TEXT,

            diagnosis TEXT,

            treatment TEXT,

            prescription TEXT,

            follow_up_date TEXT,

            registration_date TEXT
                DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (patient_id)
                REFERENCES patients(id),

            FOREIGN KEY (doctor_id)
                REFERENCES doctors(id)

        )
    """)

    # =====================================================
    # MEDICINES
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS medicines (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            medicine_number TEXT NOT NULL UNIQUE,

            medicine_name TEXT NOT NULL,

            category TEXT,

            quantity INTEGER DEFAULT 0,

            unit_price REAL DEFAULT 0,

            expiry_date TEXT,

            supplier TEXT,

            description TEXT,

            registration_date TEXT

        )
    """)

    # =====================================================
    # PHARMACY SALES
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pharmacy_sales (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            sale_number TEXT NOT NULL UNIQUE,

            patient_id INTEGER NOT NULL,

            medicine_id INTEGER NOT NULL,

            quantity INTEGER NOT NULL,

            unit_price REAL NOT NULL,

            total_amount REAL NOT NULL,

            sale_date TEXT
                DEFAULT (datetime('now')),

            FOREIGN KEY (patient_id)
                REFERENCES patients(id),

            FOREIGN KEY (medicine_id)
                REFERENCES medicines(id)

        )
    """)

    # =====================================================
    # BILLS
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS bills (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            bill_number TEXT NOT NULL UNIQUE,

            patient_id INTEGER NOT NULL,

            description TEXT NOT NULL,

            amount REAL NOT NULL,

            payment_status TEXT NOT NULL
                DEFAULT 'Pending',

            billing_date TEXT NOT NULL
                DEFAULT (datetime('now')),

            FOREIGN KEY (patient_id)
                REFERENCES patients(id)

        )
    """)

    # =====================================================
    # LABORATORY TESTS
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS laboratory_tests (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            test_number TEXT NOT NULL UNIQUE,

            patient_id INTEGER NOT NULL,

            doctor_id INTEGER NOT NULL,

            test_name TEXT NOT NULL,

            test_date TEXT NOT NULL,

            result TEXT,

            status TEXT NOT NULL
                DEFAULT 'Pending',

            notes TEXT,

            registration_date TEXT
                DEFAULT (datetime('now')),

            FOREIGN KEY (patient_id)
                REFERENCES patients(id),

            FOREIGN KEY (doctor_id)
                REFERENCES doctors(id)

        )
    """)

    # =====================================================
    # SAVE CHANGES
    # =====================================================

    connection.commit()
    connection.close()


# =========================================================
# CREATE ADMINISTRATOR
# =========================================================

def create_admin():

    connection = get_connection()
    cursor = connection.cursor()

    # Check whether administrator already exists
    cursor.execute(
        "SELECT id FROM users WHERE username = ?",
        ("admin",)
    )

    existing_admin = cursor.fetchone()

    if existing_admin is None:

        password_hash = generate_password_hash(
            "Admin@123"
        )

        cursor.execute("""
            INSERT INTO users (
                username,
                password,
                role
            )
            VALUES (?, ?, ?)
        """, (
            "admin",
            password_hash,
            "Administrator"
        ))

        connection.commit()

        print("Administrator account created successfully.")
        print("Username: admin")
        print("Password: Admin@123")

    else:

        print("Administrator account already exists.")

    connection.close()


# =========================================================
# INITIALIZE DATABASE
# =========================================================

def initialize_database():

    create_tables()
    create_admin()


# =========================================================
# RUN DATABASE SETUP DIRECTLY
# =========================================================

if __name__ == "__main__":

    initialize_database()

    print("Hospital database setup completed.")