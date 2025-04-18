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


class AuthorizerSchema(BaseModel):
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
def main(event, context):
    """
    Authenticate a user and generate tokens using AWS Cognito.

    Args:
        event (dict): Event data including user input and headers.
        context (dict): Lambda context (unused).

    Returns:
        dict: A response containing authentication tokens or error messages.
    """
    status_code = 400
    response = {
        "error": True,
        "success": False,
        "message": "Server error",
        "data": None,
    }

    logger.info(event)
    try:
        body = json.loads(event["body"])  # Explicit JSON parsing
        payload = AuthorizerSchema(**body)
        logger.info(f"Payload: {payload}")
        username = payload["email"]
        password = payload["password"]

        # Authenticate user with Cognito
        secret_hash = get_secret_hash(username)
        logger.info(f"Generated secret hash for {username}")
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

        # Extract authentication results
        tokens = auth_response["AuthenticationResult"]
        response["data"] = {
            "id_token": tokens["IdToken"],
            "refresh_token": tokens["RefreshToken"],
            "access_token": tokens["AccessToken"],
            "expires_in": tokens["ExpiresIn"],
            "token_type": tokens["TokenType"],
        }

        # Handle cookies and user-specific operations
        user_sub = admin_get_user(client, POOL_ID, username)["sub"]
        handle_cookies(event, user_sub)

        status_code = 200
        response.update(error=False, success=True, message="Login successful")

    except ValueError as e:
        logger.error(f"Error: {e}")
        # Extract ValuenError message
        response["message"] = (
            list(e.messages.values())[0][0] if isinstance(e.messages, dict) else str(e)
        )
    except client.exceptions.NotAuthorizedException:
        logger.error("Authentication failed: Incorrect username or password")
        response["message"] = "Incorrect username or password"
    except client.exceptions.UserNotConfirmedException:
        logger.error("Authentication failed: User not confirmed")
        response["message"] = "User not confirmed"
    except client.exceptions.UserNotFoundException:
        logger.error("Authentication failed: User not found")
        response["message"] = "User not found"
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        status_code = 500
        response["message"] = "An unexpected error occurred"

    return make_response(status_code, response)
