import traceback
import json
from opentok import Client
from opentok import Roles
from urllib import request
from django.shortcuts import render, get_object_or_404
from requests import session
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User
from .models import Playground, OpenTokSession
from rest_framework.exceptions import ValidationError
from django.shortcuts import get_object_or_404
from .serializers import UserSerializer, PlaygroundSerializer
from .utils import send_wa_msg, generate_otp, send_otp_email
from google.oauth2 import credentials
from googleapiclient.discovery import build
from rest_framework.status import HTTP_500_INTERNAL_SERVER_ERROR


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
        print("Request data:", data)
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


@api_view(["POST"])
def create_batch_events(request):
    try:
        credential_data = json.loads(request.data.get("credential"))
        dropped_contests_data = json.loads(request.data.get("droppedContests"))
        print(credential_data, dropped_contests_data)

        # Load the credential data into a Credentials object
        creds = credentials.Credentials.from_authorized_user_info(credential_data)
        print("--------------------------------")
        print(creds)
        # Build the Google Calendar API service
        service = build("calendar", "v3", credentials=creds)

        # Iterate over the droppedContests data and create events
        for dropped_contest in dropped_contests_data:
            event = {
                "summary": dropped_contest["summary"],
                "start": {
                    "dateTime": dropped_contest["startDateTime"],
                },
                "end": {
                    "dateTime": dropped_contest["endDateTime"],
                },
            }
            service.events().insert(calendarId="primary", body=event).execute()

        return Response({"message": "Batch events created successfully"})
    except Exception as e:
        traceback.print_exc()
        return Response({"error": str(e)}, status=HTTP_500_INTERNAL_SERVER_ERROR)
