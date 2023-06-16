import requests
import os
import random
from twilio.rest import Client
from smtplib import SMTPAuthenticationError
from django.core.mail import send_mail
from rest_framework.response import Response
from rest_framework import status


def send_wa_msg(s):
    account_sid = "ACf692485845f83d3f27da8265b4bc6ad2"
    auth_token = "68392ba606eb7a4a67a39e407f8fb9d1"
    client = Client(account_sid, auth_token)

    message = client.messages.create(from_="+13614507855", body=s, to="+916353995184")

    print(message.sid)


def generate_otp():
    return random.randint(100000, 999999)


def send_otp_email(email, otp):
    subject = "OTP Verification"
    message = f"Your OTP is: {otp}"
    from_email = "samarthshinde247@gmail.com"
    recipient_list = [email]
    try:
        send_mail(subject, message, from_email, recipient_list)
    except SMTPAuthenticationError:
        # Handle the authentication error here
        return Response(
            "Failed to send email. SMTP authentication error.",
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
