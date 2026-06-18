from app import db, limiter
from flask import Blueprint, request, jsonify
from app import db
from app.models import User
from app.email_service import generate_otp, send_otp_email
from flask_jwt_extended import create_access_token
from datetime import datetime, timedelta
import bcrypt
import re
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import os

auth = Blueprint("auth", __name__)

# HELPER FUNCTIONS
def is_valid_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email)

def is_valid_password(password):
    return len(password) >= 8
def is_valid_mobile(mobile_number):
    """Mobile number must be 10-15 digits, optional + at start"""
    pattern = r'^\+?\d{10,15}$'
    return re.match(pattern, mobile_number)


# REGISTER

@auth.route("/register", methods=["POST"])
@limiter.limit("5 per minute")
def register():
    data = request.get_json()

    # Validate input
    email = data.get("email", "").strip().lower()
    password = data.get("password", "").strip()
    mobile_number = data.get("mobile_number", "").strip()
    country = data.get("country", "").strip()
    city_community = data.get("city_community", "").strip()
    gender = data.get("gender", "").strip().lower()

    if not email:
        return jsonify({"error": "Email is required"}), 400

    if not is_valid_email(email):
        return jsonify({"error": "Please enter a valid email address"}), 400

    if not password:
        return jsonify({"error": "Password is required"}), 400

    if not is_valid_password(password):
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    if not mobile_number:
        return jsonify({"error": "Mobile number is required"}), 400

    if not is_valid_mobile(mobile_number):
        return jsonify({"error": "Please enter a valid mobile number"}), 400

    if not country:
        return jsonify({"error": "Country is required"}), 400

    if not city_community:
        return jsonify({"error": "City/Community is required"}), 400

    if not gender:
        return jsonify({"error": "Gender is required"}), 400

    if gender not in ["male", "female", "other"]:
        return jsonify({"error": "Gender must be male, female, or other"}), 400

    # Check if email already exists
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({"error": "An account with this email already exists"}), 409

    # Check if mobile number already exists
    existing_mobile = User.query.filter_by(mobile_number=mobile_number).first()
    if existing_mobile:
        return jsonify({"error": "An account with this mobile number already exists"}), 409

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
        mobile_number=mobile_number,
        country=country,
        city_community=city_community,
        gender=gender,
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
@limiter.limit("5 per minute")
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
@limiter.limit("5 per minute")
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
@limiter.limit("5 per minute")
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

# GOOGLE AUTH 
@auth.route("/google-auth", methods=["POST"])
@limiter.limit("5 per minute")
def google_auth():
    data = request.get_json()

    google_token = data.get("google_token", "").strip()
    mobile_number = data.get("mobile_number", "").strip()
    country = data.get("country", "").strip()
    city_community = data.get("city_community", "").strip()
    gender = data.get("gender", "").strip().lower()

    if not google_token:
        return jsonify({"error": "Google token is required"}), 400

    if not mobile_number:
        return jsonify({"error": "Mobile number is required"}), 400

    if not is_valid_mobile(mobile_number):
        return jsonify({"error": "Please enter a valid mobile number"}), 400

    if not country:
        return jsonify({"error": "Country is required"}), 400

    if not city_community:
        return jsonify({"error": "City/Community is required"}), 400

    if not gender:
        return jsonify({"error": "Gender is required"}), 400

    if gender not in ["male", "female", "other"]:
        return jsonify({"error": "Gender must be male, female, or other"}), 400

    # Verify token with Google
    try:
        client_ids = [
            os.getenv("GOOGLE_CLIENT_ID"),
            os.getenv("GOOGLE_ANDROID_CLIENT_ID"),
            os.getenv("GOOGLE_IOS_CLIENT_ID"),
        ]
        # Remove None values in case any env var is missing
        client_ids = [cid for cid in client_ids if cid]

        id_info = id_token.verify_oauth2_token(
            google_token,
            google_requests.Request(),
            audience=None
        )

        # Manually check audience matches one of our client IDs
        if id_info.get("aud") not in client_ids:
            return jsonify({"error": "Invalid Google token"}), 401

    except ValueError:
        return jsonify({"error": "Invalid Google token"}), 401

    google_id = id_info.get("sub")
    email = id_info.get("email")
    is_email_verified = id_info.get("email_verified", False)

    if not is_email_verified:
        return jsonify({"error": "Google account email is not verified"}), 401

    # Existing user → log in 
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        token = create_access_token(identity=str(existing_user.id))
        return jsonify({
            "message": "Login successful. Welcome back!",
            "token": token
        }), 200

    # Check mobile number uniqueness for new user
    existing_mobile = User.query.filter_by(mobile_number=mobile_number).first()
    if existing_mobile:
        return jsonify({"error": "An account with this mobile number already exists"}), 409

    # New user → save
    new_user = User(
        email=email,
        password=None,
        google_id=google_id,
        auth_method="google",
        mobile_number=mobile_number,
        country=country,
        city_community=city_community,
        gender=gender,
        is_verified=True,
    )
    db.session.add(new_user)
    db.session.commit()

    token = create_access_token(identity=str(new_user.id))

    return jsonify({
        "message": "Account created successfully. Welcome to ErrandGo!",
        "token": token
    }), 201
