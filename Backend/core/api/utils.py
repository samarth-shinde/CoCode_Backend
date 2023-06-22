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


def send_reminder_email(contest, sender_email, recipient_email, eta=None):
    subject = f'<span style="font-family: Arial, sans-serif; font-weight: bold;">CoCode Reminder: {contest["name"]}</span>'
    message = f"""
        <p><strong>Reminder:</strong></p>
        <p>The contest <strong>{contest["name"]}</strong> will start in 30 minutes.</p>
        <p><strong>Time:</strong> {contest['start_time']} - {contest['end_time']}</p>
        <p><strong>Link:</strong> <a href='{contest['url']}'>{contest['url']}</a></p>
    """

    try:
        if eta is not None:
            send_mail(subject, message, sender_email, [recipient_email], eta=eta)
        else:
            send_mail(subject, message, sender_email, [recipient_email])

    except SMTPAuthenticationError:
        # Handle the authentication error here
        print("SMTP authentication error occurred.")
    except Exception as e:
        # Print the exception and continue with other contests
        print("An error occurred while sending the reminder email.", e)
