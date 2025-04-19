import base64
import hashlib
import hmac
import traceback
import json
from os import getenv

import boto3
from pydantic import BaseModel, EmailStr
from aws_lambda_powertools.utilities import parameters
from utils import (
    make_response,
    handle_exceptions,
    logger,
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


class SignupSchema(BaseModel):
    email: EmailStr
    first_name: str
    last_name: str
    phone_number: str
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


def get_secret_hash_individual(username: str) -> str:
    """
    Generate the secret hash using the username and Cognito client credentials.

    Args:
        username (str): The username for the user.

    Returns:
        str: The secret hash for the user.
    """
    msg = username + CLIENT_ID
    dig = hmac.new(
        str(CLIENT_SECRET).encode("utf-8"),
        msg=str(msg).encode("utf-8"),
        digestmod=hashlib.sha256,
    ).digest()
    d2 = base64.b64encode(dig).decode()
    return d2


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def main(event, context=None):
    """
    Authenticate a user and generate tokens using AWS Cognito.

    Args:
        event (dict): Event data including user input and headers.

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
        body = json.loads(event["body"])
        payload = SignupSchema(**body)
        logger.info(f"payload - {payload}")
        user_attr = [
            {"Name": "email", "Value": payload["email"]},
            {"Name": "first_name", "Value": payload["first_name"]},
            {"Name": "last_name", "Value": payload["last_name"]},
            {"Name": "phone_number", "Value": payload["phone_number"]},
        ]
        client.sign_up(
            ClientId=CLIENT_ID,
            SecretHash=get_secret_hash_individual(payload["email"]),
            Username=payload["email"],
            Password=payload["password"],
            UserAttributes=user_attr,
            ValidationData=[{"Name": "email", "Value": payload["email"]}],
        )
        status_code = 200
        response["error"] = False
        response["success"] = True
        response["message"] = "please confirm signup"
    except client.exceptions.UsernameExistsException as e:
        logger.error(e)
        response_string = str(e)
        response["message"] = response_string.split(":", 1)[-1].strip()
    except client.exceptions.InvalidPasswordException as e:
        response_string = str(e)
        response["message"] = response_string.split(":", 1)[-1].strip()
    except client.exceptions.UserLambdaValidationException as e:
        response_string = str(e)
        response["message"] = response_string.split(":", 1)[-1].strip()
    except client.exceptions.UserNotConfirmedException as e:
        logger.error(e)
        response_string = str(e)
        response["message"] = response_string.split(":", 1)[-1].strip()
    except client.exceptions.InvalidParameterException as e:
        response_string = str(e)
        response["message"] = response_string.split(":", 1)[-1].strip()
    except client.exceptions.UsernameExistsException as e:
        response_string = str(e)
        response["message"] = response_string.split(":", 1)[-1].strip()
    except ValueError as e:
        logger.error(e)
        error_message = {}
        for field, errors in e.messages.items():
            error_message[field] = errors[0]
        response["message"] = error_message
    except KeyError:
        traceback.print_exc()
    except Exception as e:
        status_code = 500
        logger.error(e)
    return make_response(status_code, response)


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def handler(event, context):
    return main(event, context)
