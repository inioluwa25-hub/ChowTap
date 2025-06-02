import base64
import hashlib
import hmac
import json
from os import getenv

import boto3
from pydantic import BaseModel, EmailStr
from aws_lambda_powertools.utilities import parameters
from utils import (
    make_response,
    handle_exceptions,
    logger,
    create_document,
)

# Environment variables
STAGE = getenv("STAGE")
APP_NAME = getenv("APP_NAME")

POOL_ID = parameters.get_parameter(f"/{APP_NAME}/{STAGE}/POOL_ID")
CLIENT_ID = parameters.get_parameter(f"/{APP_NAME}/{STAGE}/CLIENT_ID")
CLIENT_SECRET = parameters.get_parameter(
    f"/{APP_NAME}/{STAGE}/CLIENT_SECRET", decrypt=True
)

# AWS client
client = boto3.client("cognito-idp")


class LoginSchema(BaseModel):
    email: EmailStr
    password: str

    def validate_password(self, data, **kwargs):
        password = data.get("password")
        if not password:
            raise ValueError("Password is required.")
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        if not any(c.isupper() for c in password):
            raise ValueError("Password must contain at least one capital letter.")
        if not any(c.isdigit() for c in password):
            raise ValueError("Password must contain at least one digit.")
        if not any(c in "@$!%*?&-.,.#`~^()" for c in password):
            raise ValueError("Password must contain at least one special character.")


def get_secret_hash(username: str) -> str:
    """
    Generate the secret hash using the username and Cognito client credentials.

    Args:
        username (str): The username for the user.

    Returns:
        str: The secret hash for the user.
    """
    message = f"{username}{CLIENT_ID}".encode("utf-8")
    secret = CLIENT_SECRET.encode("utf-8")
    digest = hmac.new(secret, msg=message, digestmod=hashlib.sha256).digest()
    return base64.b64encode(digest).decode()


def handle_cookies(event: dict, sub: str) -> str:
    """
    Create and update a cookie document with headers from the event.

    Args:
        event (dict): The incoming event containing headers.
        sub (str): The user's sub (unique identifier).
    """
    cookies_document = {"pk": "cookies", "sk": f"user_{sub}"}
    if headers := event.get("headers"):
        cookies_document.update(headers)
        create_document(cookies_document)


def admin_get_user(cognito_client, user_pool_id, username):
    response = cognito_client.admin_get_user(UserPoolId=user_pool_id, Username=username)
    data = {attr.get("Name"): attr.get("Value") for attr in response["UserAttributes"]}
    return data


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def main(event, context=None):
    """
    Authenticate a user and generate tokens using AWS Cognito, with vendor check.
    """
    status_code = 400
    response = {
        "error": True,
        "success": False,
        "message": "Server error",
        "data": None,
    }

    try:
        body = json.loads(event["body"])
        payload = LoginSchema(**body)
        username = payload.email
        password = payload.password

        # First check user attributes before authentication
        user_attributes = admin_get_user(client, POOL_ID, username)

        # Check if user has is_vendor attribute set to true
        if user_attributes.get("custom:is_vendor", "false").lower() != "true":
            status_code = 403
            response["message"] = "Access denied: Not a registered vendor"
            return make_response(status_code, response)

        # Proceed with authentication if user is vendor
        secret_hash = get_secret_hash(username)
        auth_response = client.initiate_auth(
            ClientId=CLIENT_ID,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={
                "USERNAME": username,
                "SECRET_HASH": secret_hash,
                "PASSWORD": password,
            },
            ClientMetadata={"username": username, "password": password},
        )

        if "AuthenticationResult" in auth_response:
            tokens = auth_response["AuthenticationResult"]
            response["data"] = {
                "id_token": tokens["IdToken"],
                "refresh_token": tokens["RefreshToken"],
                "access_token": tokens["AccessToken"],
                "expires_in": tokens["ExpiresIn"],
                "token_type": tokens["TokenType"],
            }

            user_sub = user_attributes["sub"]
            handle_cookies(event, user_sub)

            status_code = 200
            response.update(
                error=False, success=True, message="Vendor login successful"
            )

    except ValueError as e:
        response["message"] = str(e)
    except client.exceptions.NotAuthorizedException:
        response["message"] = "Incorrect username or password"
    except client.exceptions.UserNotConfirmedException:
        response["message"] = "User not confirmed"
    except client.exceptions.UserNotFoundException:
        response["message"] = "User not found"
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        status_code = 500
        response["message"] = "An unexpected error occurred"

    return make_response(status_code, response)


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def handler(event, context):
    return main(event, context)
