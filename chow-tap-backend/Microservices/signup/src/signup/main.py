import base64
import hashlib
import hmac
import json
import re
import traceback
import requests
from os import getenv
import dns.resolver
import smtplib
import socket
import boto3
from aws_lambda_powertools.utilities import parameters
from pydantic import BaseModel, EmailStr, validator
from utils import handle_exceptions, logger, make_response

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

    @validator("phone_number")
    def validate_phone_number(cls, phone_number):
        # Validate Nigerian phone number format
        if not re.match(r"^0[7-9][0-1]\d{8}$", phone_number):
            raise ValueError(
                "Phone number must be a valid Nigerian number (e.g., 07056463857)"
            )
        return phone_number

    @validator("password")
    def validate_password(cls, password):
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        if not any(c.isupper() for c in password):
            raise ValueError("Password must contain at least one capital letter.")
        if not any(c.isdigit() for c in password):
            raise ValueError("Password must contain at least one digit.")
        if not any(c in "@$!%*?&-.,.#`~^_()" for c in password):
            raise ValueError("Password must contain at least one special character.")
        return password


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


# def verify_email_api(email: str) -> bool:
#     try:
#         api_key = "05e73f2c-266f-43e2-a1db-5b4a696400f0"
#         response = requests.get(
#             f"https://api.mails.so/v1/validate?email={email}",
#             headers={"x-mails-api-key": api_key},
#             timeout=3,
#         )
#         response.raise_for_status()
#         data = response.json()

#         # Check the actual response structure from your API
#         if data.get("error") is not None:
#             logger.error(f"Email verification API error: {data.get('error')}")
#             return True  # Fail open

#         # Use the correct field from your API response
#         return data.get("data", {}).get("result") == "deliverable"

#     except requests.exceptions.RequestException as e:
#         logger.error(f"Email verification API request failed: {str(e)}")
#         return True  # Fallback to true if service fails
#     except json.JSONDecodeError as e:
#         logger.error(f"Invalid JSON response from email verification API: {str(e)}")
#         return True  # Fallback to true
#     except Exception as e:
#         logger.error(f"Unexpected error in email verification: {str(e)}")
#         return True  # Fail open


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def main(event, context=None):
    status_code = 400
    response = {
        "error": True,
        "success": False,
        "message": "Server error",
        "data": None,
    }

    try:
        body = json.loads(event["body"])
        payload = SignupSchema(**body)

        # # Verify email before proceeding
        # if not verify_email_api(payload.email):
        #     return make_response(
        #         400,
        #         {
        #             "error": True,
        #             "success": False,
        #             "message": "Please provide a valid, deliverable email address",
        #             "data": None,
        #         },
        #     )

        e164_phone = "+234" + payload.phone_number[1:]
        user_attr = [
            {"Name": "email", "Value": payload.email},
            {"Name": "given_name", "Value": payload.first_name},
            {"Name": "family_name", "Value": payload.last_name},
            {"Name": "phone_number", "Value": e164_phone},
        ]

        client.sign_up(
            ClientId=CLIENT_ID,
            SecretHash=get_secret_hash_individual(payload.email),
            Username=payload.email,
            Password=payload.password,
            UserAttributes=user_attr,
            ValidationData=[{"Name": "email", "Value": payload.email}],
        )
        status_code = 200
        response["error"] = False
        response["success"] = True
        response["message"] = "please confirm signup"

    except client.exceptions.UsernameExistsException as e:
        logger.error(e)
        response.update(
            {"message": "User already exists", "error": True, "success": False}
        )
        status_code = 409
    except client.exceptions.InvalidParameterException as e:
        if "Username should be an email" in str(e):
            response["message"] = (
                "Server configuration error: Phone number as username not enabled"
            )
        else:
            response["message"] = str(e).split(":", 1)[-1].strip()
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
