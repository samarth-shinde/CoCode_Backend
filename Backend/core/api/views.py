import json, os, traceback, requests
from opentok import Client
from urllib import request
from django.shortcuts import render, get_object_or_404
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User
from .models import Playground, OpenTokSession
from rest_framework.exceptions import ValidationError
from django.shortcuts import get_object_or_404
from .serializers import UserSerializer, PlaygroundSerializer
from .utils import send_wa_msg, generate_otp, send_otp_email, send_reminder_email
from rest_framework.status import HTTP_500_INTERNAL_SERVER_ERROR
from django.core.mail import send_mail
from smtplib import SMTPAuthenticationError
from datetime import timedelta
from django.views.decorators.csrf import csrf_exempt


@api_view(["POST"])
def register(request):
    data = request.data
    print(data)
    serializer = UserSerializer(data=data)
    print(serializer)
    if not serializer.is_valid():
        print("is not serializable")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    username = serializer.validated_data.get("username")
    email = serializer.validated_data.get("email")

    # Check if username or email already exists
    if User.objects.filter(username=username).exists():
        print("username already exists")
        raise ValidationError("Username already exists.")

    if User.objects.filter(email=email).exists():
        print("Email validation sucks")
        raise ValidationError("Email already exists.")

    serializer.save()
    user_obj = get_object_or_404(User, id=serializer.data["id"])
    token = get_object_or_404(Token, user=user_obj)

    # Generate OTP for the user
    otp = generate_otp()

    # Send OTP email
    send_otp_email(email, otp)

    return Response(
        {
            "serializer-data": serializer.data,
            "token": token.key,
            "username": user_obj.username,
        },
        status=status.HTTP_201_CREATED,
    )


@api_view(["POST"])
def get_user_details(request):
    data = request.data
    token_key = data["token"]
    token = get_object_or_404(Token, key=token_key)
    user_obj = token.user
    print(user_obj)
    serializer = UserSerializer(user_obj)
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(["GET"])
def get_playground_details(request, name):
    if playground := Playground.objects.filter(owner__username=name):
        serializer = PlaygroundSerializer(playground[0])
        print(serializer.data)
        return Response(serializer.data, status=status.HTTP_200_OK)
    else:
        return Response(
            {"message": "No playground found"}, status=status.HTTP_404_NOT_FOUND
        )


@api_view(["POST"])
def invite_others(request):
    try:
        data = request.data
        phone_no = data["no"]
        link = data["link"]
        s = (
            "Someone has invited you to join the CodeTogether Room. Please click on the link to join the room "
            + " \n "
            + str(link)
        )
        send_wa_msg(s)
        return Response({"message": "Invitation sent"}, status=status.HTTP_200_OK)
    except Exception:
        return Response(
            {"message": "Something went wrong", Exception: Exception},
            status=status.HTTP_400_BAD_REQUEST,
        )


api_key = "47724171"
api_secret = "74637064ed799dd14c06a1ab795af794ea81e7a8"


@api_view(["POST"])
def generate_opentok_session_token(request):
    print(request.data)
    opentok_sdk = Client(api_key, api_secret)
    data = request.data
    print("generate_opentok_session_token")
    user_name = data.get("user_name")
    group_name = data.get("groupname")
    print(user_name)
    print(group_name)
    user_obj = get_object_or_404(User, username=group_name)
    print(user_obj)
    obj, created = OpenTokSession.objects.get_or_create(owner=user_obj)
    print(obj.session_id, created)

    if created:
        session = opentok_sdk.create_session()
        print(session.session_id)
        obj.session_id = session.session_id
        obj.save()
        sessionID = session.session_id
    else:
        sessionID = obj.session_id
        token = opentok_sdk.generate_token(sessionID, data=f"{user_name}")
        print(token)

    return Response(
        {
            "session_id": sessionID,
            "token": token,
        },
        status=status.HTTP_200_OK,
    )


# "token": "T1==cGFydG5lcl9pZD00NzcyNDE3MSZzaWc9ZjgwMGQ4OGNkNDhhOWY5YWY5Mjk4OWRlMDlmZDE2NzI2MWFmY2U3NDpzZXNzaW9uX2lkPTFfTVg0ME56Y3lOREUzTVg1LU1UWTROakEwT1RnME9ETTROMzVLWkRWd1JtZFVOV0Y0ZDJsa2FqWlJlRkYxYkhaQmRHWi1mbjQmY3JlYXRlX3RpbWU9MTY4NjA0OTg1NCZub25jZT0wLjE5OTI1MzE0NDc2NTA3MDA2JnJvbGU9cHVibGlzaGVyJmV4cGlyZV90aW1lPTE2ODYxMzYyNTQmaW5pdGlhbF9sYXlvdXRfY2xhc3NfbGlzdD0=",


try:
    from googlesearch import search
except ImportError:
    print("Couldn't import googlesearch module")
from .scraper import scrape


@api_view(["POST"])
def help_portal(request):
    try:
        data = request.data
        print("Request data:", request.user)
        query = data["query"]
        print("Search query:", query)
        data_list = [
            j
            for j in search(query, num_results=10)
            if "www.geeksforgeeks.org" in str(j)
        ]
        print("Data list:", data_list)
        article = scrape(str(data_list[0]))

        return Response(
            {"message": "Help portal", "article": article, "link": data_list[0]},
            status=status.HTTP_200_OK,
        )
    except Exception as e:
        print("Exception:", e)
        return Response(
            {"message": "Something went wrong"}, status=status.HTTP_400_BAD_REQUEST
        )


@api_view(["GET"])
def list_of_keywords(request, filter):
    all_keywords = ["keyword1", "keyword2", "keyword3"]
    filtered_keywords = [keyword for keyword in all_keywords if filter in keyword]
    return Response({"filteredKeywords": filtered_keywords})


@api_view(["POST"])
def verify_otp(request):
    otp = request.data.get("otp")
    auth_token = request.GET.get("token")

    try:
        token = Token.objects.get(key=auth_token)
        user = token.user

        if otp == user.otp:
            # Update the user's OTP verification status or perform any other necessary actions
            user.is_otp_verified = True
            user.save()
            return Response({"detail": "OTP verification successful"})
        else:
            # OTP verification failed
            return Response(
                {"detail": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST
            )
    except Token.DoesNotExist:
        # Token does not exist or is invalid
        return Response(
            {"detail": "Token does not exist or is invalid"},
            status=status.HTTP_404_NOT_FOUND,
        )


import logging

logger = logging.getLogger(__name__)


@csrf_exempt
@api_view(["POST"])
def send_email(request):
    data = request.data
    contests = data.get("contests", [])
    send_reminders = data.get("selectedReminders", [])
    print(contests)
    logger.info(f"Received contests: {contests}")

    # Replace the placeholders with your own email details
    sender_email = "samarthshinde247@gmail.com"
    recipient_email = "samarthshinde247@gmail.com"

    try:
        for contest in contests:
            subject = f'<span style="font-family: Arial, sans-serif; font-weight: bold;">CoCode Invitation for {contest["name"]}</span>'
            message = f"""
                <p><strong>CoCode Invitation Details:</strong></p>
                <p><strong>Time:</strong> {contest['start_time']} - {contest['end_time']}</p>
                <p><strong>Link:</strong> <a href='{contest['url']}'>{contest['url']}</a></p>
            """

            try:
                send_mail(subject, message, sender_email, [recipient_email])

                # Send reminders if selected option is not "none"
                for reminder_option in send_reminders:
                    if reminder_option == "30min":
                        send_reminder_email.apply_async(
                            args=[contest, sender_email, recipient_email],
                            eta=contest["start_time"] - timedelta(minutes=30),
                        )
                    elif reminder_option == "1day":
                        send_reminder_email.apply_async(
                            args=[contest, sender_email, recipient_email],
                            eta=contest["start_time"] - timedelta(days=1),
                        )
                    elif reminder_option == "1week":
                        send_reminder_email.apply_async(
                            args=[contest, sender_email, recipient_email],
                            eta=contest["start_time"] - timedelta(weeks=1),
                        )

            except SMTPAuthenticationError:
                return Response(
                    "Failed to send email. SMTP authentication error.",
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

        return Response({"message": "Emails sent successfully"})

    except Exception as e:
        logger.exception("An error occurred while processing the request.")
        return Response(
            {"message": "An error occurred while processing the request."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
