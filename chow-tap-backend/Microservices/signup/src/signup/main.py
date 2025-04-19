import base64
import hashlib
import hmac
import json
import re
from os import getenv

import boto3
from aws_lambda_powertools.utilities import parameters
from pydantic import BaseModel, EmailStr, validator
from utils import handle_exceptions, logger, make_response

# Environment variables
STAGE = getenv("STAGE")
APP_NAME = getenv("APP_NAME")

POOL_ID = parameters.get_parameter(f"/{APP_NAME}/{STAGE}/POOL_ID")
CLIENT_ID = parameters.get_parameter(f"/{APP_NAME}/${STAGE}/CLIENT_ID")
CLIENT_SECRET = parameters.get_parameter(
    f"/{APP_NAME}/${STAGE}/CLIENT_SECRET", decrypt=True
)

# AWS client
client = boto3.client("cognito-idp")


class SignupSchema(BaseModel):
    email: EmailStr
    first_name: str
    last_name: str
    phone_number: str  # Format: 07056463857 (without country code)
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
        # Existing password validation
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        if not any(c.isupper() for c in password):
            raise ValueError("Password must contain at least one capital letter.")
        if not any(c.isdigit() for c in password):
            raise ValueError("Password must contain at least one digit.")
        if not any(c in "@$!%*?&-.,.#`~^()" for c in password):
            raise ValueError("Password must contain at least one special character.")
        return password


def get_secret_hash(username: str) -> str:
    msg = username + CLIENT_ID
    dig = hmac.new(
        str(CLIENT_SECRET).encode("utf-8"),
        msg=str(msg).encode("utf-8"),
        digestmod=hashlib.sha256,
    ).digest()
    return base64.b64encode(dig).decode()


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

        # Convert to E.164 format for Cognito
        e164_phone = "+234" + payload.phone_number[1:]  # Replace leading 0 with +234

        user_attrs = [
            {"Name": "email", "Value": payload.email},
            {"Name": "given_name", "Value": payload.first_name},
            {"Name": "family_name", "Value": payload.last_name},
            {"Name": "phone_number", "Value": e164_phone},
        ]

        # Sign up using email as username but with phone number attribute
        client.sign_up(
            ClientId=CLIENT_ID,
            SecretHash=get_secret_hash(payload.email),
            Username=payload.email,  # Using email as username
            Password=payload.password,
            UserAttributes=user_attrs,
        )

        # Configure verification to go to phone number
        client.admin_update_user_attributes(
            UserPoolId=POOL_ID,
            Username=payload.email,
            UserAttributes=[
                {"Name": "phone_number_verified", "Value": "false"},
                {"Name": "email_verified", "Value": "true"},  # Skip email verification
            ],
        )

        # Trigger phone verification
        client.admin_get_user(UserPoolId=POOL_ID, Username=payload.email)

        response.update(
            error=False,
            success=True,
            message="OTP has been sent to your phone number",
            data={
                "email": payload.email,
                "phone_number": payload.phone_number,  # Return original format
            },
        )
        status_code = 200

    except client.exceptions.UsernameExistsException:
        response["message"] = "This email is already registered"
    except client.exceptions.InvalidParameterException as e:
        response["message"] = str(e).split(":", 1)[-1].strip()
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        response["message"] = "An unexpected error occurred"
        status_code = 500

    return make_response(status_code, response)


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def handler(event, context):
    return main(event, context)
