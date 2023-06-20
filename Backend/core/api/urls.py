from django.urls import path
from . import views


urlpatterns = [
    path("register/", views.register, name="register"),
    path("get_user_details/", views.get_user_details, name="get_user_details"),
    path(
        "get_playground_details/<str:name>/",
        views.get_playground_details,
        name="get_playground_details",
    ),
    path("invite-others/", views.invite_others, name="invite_others"),
    path(
        "opentok-token/",
        views.generate_opentok_session_token,
        name="generate_opentok_session_token",
    ),
    path("help_portal/", views.help_portal, name="help_portal"),
    path("verify_otp/", views.verify_otp, name="verify_otp"),
    path("send_email", views.send_email, name="send_email"),
]
