import base64
import hashlib
import hmac
import json
import re
import traceback
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


class EmailVerifier:
    @staticmethod
    def verify_email(email: str) -> bool:
        """Perform comprehensive email verification"""
        if not EmailVerifier._check_syntax(email):
            return False
        if not EmailVerifier._check_domain(email.split("@")[1]):
            return False
        return EmailVerifier._check_smtp(email)

    @staticmethod
    def _check_syntax(email: str) -> bool:
        """Basic syntax check (Pydantic already does this)"""
        return bool(re.match(r"[^@]+@[^@]+\.[^@]+", email))

    @staticmethod
    def _check_domain(domain: str) -> bool:
        """Check if domain has valid MX records"""
        try:
            return bool(dns.resolver.resolve(domain, "MX"))
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
        ):
            return False

    @staticmethod
    def _check_smtp(email: str, timeout: int = 5) -> bool:
        """Check if email exists by simulating SMTP conversation"""
        domain = email.split("@")[1]
        try:
            records = dns.resolver.resolve(domain, "MX")
            mx_record = str(records[0].exchange)

            with smtplib.SMTP(timeout=timeout) as smtp:
                smtp.connect(mx_record)
                smtp.helo()
                smtp.mail("test@example.com")
                code, _ = smtp.rcpt(email)
                return code == 250
        except (smtplib.SMTPException, socket.timeout, socket.error):
            return False


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

        # Verify email before proceeding
        if not EmailVerifier.verify_email(payload.email):
            return make_response(
                400,
                {
                    "error": True,
                    "success": False,
                    "message": "Invalid email address",
                    "data": None,
                },
            )

        # Rest of your signup logic...
        e164_phone = "+234" + payload.phone_number[1:]
        user_attr = [
            {"Name": "email", "Value": payload.email},
            {"Name": "given_name", "Value": payload.first_name},
            {"Name": "family_name", "Value": payload.last_name},
            {"Name": "phone_number", "Value": e164_phone},
        ]

        signup_response = client.sign_up(
            ClientId=CLIENT_ID,
            SecretHash=get_secret_hash_individual(payload.email),
            Username=payload.email,
            Password=payload.password,
            UserAttributes=user_attr,
        )

        response = {
            "error": False,
            "success": True,
            "message": "User created and automatically confirmed",
            "data": {"email": payload.email, "status": "CONFIRMED"},
        }
        status_code = 200

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
