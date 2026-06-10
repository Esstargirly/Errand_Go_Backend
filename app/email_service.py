from flask_mail import Message
from app import mail
import random

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(email, otp_code):
    try:
        msg = Message(
            subject="Verify your ErrandGo account",
            recipients=[email],
            body=f""" Hi there, Welcome to ErrandGo!
                Your verification code is:
        {otp_code}
                This code expires in 15 minutes
                If you did not create an ErrandGo account, please ignore this email.
                The ErrandGo Team
            """
        )
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Email sending failed: {e}")
        return False



