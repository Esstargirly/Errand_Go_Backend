from flask import Blueprint, request, jsonify
from app import db
from app.models import User
from app.email_service import generate_otp, send_otp_email
from flask_jwt_extended import create_access_token
from datetime import datetime, timedelta
import bcrypt
import re

auth = Blueprint("auth", __name__)

# HELPER FUNCTIONS
def is_valid_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email)

def is_valid_password(password):
    return len(password) >= 8

# REGISTER 
@auth.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    # Validate input
    email = data.get("email", "").strip().lower()
    password = data.get("password", "").strip()
    location = data.get("location", "").strip()

    if not email:
        return jsonify({"error": "Email is required"}), 400

    if not is_valid_email(email):
        return jsonify({"error": "Please enter a valid email address"}), 400

    if not password:
        return jsonify({"error": "Password is required"}), 400

    if not is_valid_password(password):
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    if not location:
        return jsonify({"error": "Please select or enter your location"}), 400

    # Check if email already exists
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({"error": "An account with this email already exists"}), 409

    # Hash password
    hashed_password = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    # Generate OTP
    otp = generate_otp()
    otp_expiry = datetime.utcnow() + timedelta(minutes=15)

    # Save user to database
    new_user = User(
        email=email,
        password=hashed_password,
        auth_method="email",
        location=location,
        is_verified=False,
        otp_code=otp,
        otp_expires_at=otp_expiry
    )
    db.session.add(new_user)
    db.session.commit()

    # Send OTP email
    email_sent = send_otp_email(email, otp)
    if not email_sent:
        return jsonify({
            "error": "Account created but we could not send the verification email. Please use resend OTP."
        }), 500

    return jsonify({
        "message": "Account created successfully. Please check your email for your verification code.",
        "email": email
    }), 201

# VERIFY EMAIL
@auth.route("/verify-email", methods=["POST"])
def verify_email():
    data = request.get_json()

    email = data.get("email", "").strip().lower()
    otp_code = data.get("otp_code", "").strip()

    if not email or not otp_code:
        return jsonify({"error": "Email and OTP code are required"}), 400

    # Find user
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "Account not found"}), 404

    # Already verified? 
    if user.is_verified:
        return jsonify({"message": "Account is already verified. Please log in."}), 200

    # Check OTP match
    if user.otp_code != otp_code:
        return jsonify({"error": "Invalid verification code"}), 400

    # Check OTP expiry 
    if datetime.utcnow() > user.otp_expires_at:
        return jsonify({"error": "Verification code has expired. Please request a new one."}), 400

    # Verify the account
    user.is_verified = True
    user.otp_code = None
    user.otp_expires_at = None
    db.session.commit()

    # Generate JWT
    token = create_access_token(identity=str(user.id))

    return jsonify({
        "message": "Account Verified! Welcome to ErrandGo. Let’s get things done for you.",
        "token": token
    }), 200


# RESEND OTP
@auth.route("/resend-otp", methods=["POST"])
def resend_otp():
    data = request.get_json()
    email = data.get("email", "").strip().lower()

    if not email:
        return jsonify({"error": "Email is required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "Account not found"}), 404

    if user.is_verified:
        return jsonify({"message": "Account is already verified. Please log in."}), 200

    # Generate new OTP
    otp = generate_otp()
    otp_expiry = datetime.utcnow() + timedelta(minutes=15)

    user.otp_code = otp
    user.otp_expires_at = otp_expiry
    db.session.commit()

    email_sent = send_otp_email(email, otp)
    if not email_sent:
        return jsonify({"error": "Could not send email. Please try again."}), 500

    return jsonify({
        "message": "A new verification code has been sent to your email."
    }), 200


# LOGIN 
@auth.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    email = data.get("email", "").strip().lower()
    password = data.get("password", "").strip()

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    # Find user
    user = User.query.filter_by(email=email).first()

    # Generic error for security
    if not user or user.auth_method != "email":
        return jsonify({"error": "Invalid email or password"}), 401

    # Check if verified 
    if not user.is_verified:
        return jsonify({
            "error": "Please verify your email before logging in."
        }), 403

    # Check password
    password_matches = bcrypt.checkpw(
        password.encode("utf-8"),
        user.password.encode("utf-8")
    )
    if not password_matches:
        return jsonify({"error": "Invalid email or password"}), 401

    # Generate JWT
    token = create_access_token(identity=str(user.id))

    return jsonify({
        "message": "Login successful. Welcome back!",
        "token": token
    }), 200