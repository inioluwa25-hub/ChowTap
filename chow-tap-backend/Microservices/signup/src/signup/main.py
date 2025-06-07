import base64
import hashlib
import hmac
import json
import re
import traceback
from os import getenv
import boto3
from botocore.exceptions import ClientError
from aws_lambda_powertools.utilities import parameters
from pydantic import BaseModel, EmailStr, validator
from utils import handle_exceptions, logger, make_response, get_template_from_s3

# Environment variables
STAGE = getenv("STAGE")
APP_NAME = getenv("APP_NAME")

POOL_ID = parameters.get_parameter(f"/{APP_NAME}/{STAGE}/POOL_ID")
CLIENT_ID = parameters.get_parameter(f"/{APP_NAME}/{STAGE}/CLIENT_ID")
CLIENT_SECRET = parameters.get_parameter(
    f"/{APP_NAME}/{STAGE}/CLIENT_SECRET", decrypt=True
)

# AWS clients
cognito_client = boto3.client("cognito-idp")
s3_client = boto3.client("s3")


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


def configure_user_pool_with_s3_template(template_key: str) -> bool:
    """
    Configure Cognito User Pool to use S3 template for verification emails

    Args:
        template_key (str): S3 object key for the template

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Load template from S3
        template_content = get_template_from_s3(template_key)

        # Configure Cognito User Pool with the template
        response = cognito_client.update_user_pool(
            UserPoolId=POOL_ID,
            VerificationMessageTemplate={
                "EmailMessage": template_content,
                "EmailSubject": "Verify Your Account - Welcome! 🎉",
                "DefaultEmailOption": "CONFIRM_WITH_CODE",
            },
        )

        logger.info("Successfully configured User Pool with S3 template")
        return True

    except ClientError as e:
        logger.error(f"Error configuring User Pool with S3 template: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error configuring User Pool: {e}")
        return False


def sign_up_user_with_template(payload: SignupSchema) -> dict:
    """
    Sign up user and ensure User Pool is configured with S3 template

    Args:
        payload (SignupSchema): User signup data

    Returns:
        dict: Response with success status and details
    """
    try:
        # First, ensure the User Pool is configured with our S3 template
        # This is idempotent - safe to call multiple times
        template_configured = configure_user_pool_with_s3_template("chowtap-media")

        if not template_configured:
            logger.warning(
                "Failed to configure S3 template, proceeding with default template"
            )

        # Convert Nigerian phone number to E.164 format
        e164_phone = "+234" + payload.phone_number[1:]

        # Prepare user attributes
        user_attributes = [
            {"Name": "email", "Value": payload.email},
            {"Name": "given_name", "Value": payload.first_name},
            {"Name": "family_name", "Value": payload.last_name},
            {"Name": "phone_number", "Value": e164_phone},
        ]

        # Sign up the user
        response = cognito_client.sign_up(
            ClientId=CLIENT_ID,
            SecretHash=get_secret_hash_individual(payload.email),
            Username=payload.email,
            Password=payload.password,
            UserAttributes=user_attributes,
            ValidationData=[{"Name": "email", "Value": payload.email}],
        )

        logger.info(f"User {payload.email} signed up successfully")
        logger.info(
            f"Verification email sent using {'S3 template' if template_configured else 'default template'}"
        )

        return {
            "success": True,
            "user_sub": response["UserSub"],
            "message": "User signed up successfully. Please check your email for verification code.",
            "template_used": (
                "S3 template" if template_configured else "default template"
            ),
        }

    except cognito_client.exceptions.UsernameExistsException:
        return {
            "success": False,
            "error_code": "UsernameExistsException",
            "message": "User already exists",
        }
    except cognito_client.exceptions.InvalidPasswordException as e:
        return {
            "success": False,
            "error_code": "InvalidPasswordException",
            "message": str(e).split(":", 1)[-1].strip(),
        }
    except cognito_client.exceptions.InvalidParameterException as e:
        return {
            "success": False,
            "error_code": "InvalidParameterException",
            "message": str(e).split(":", 1)[-1].strip(),
        }
    except Exception as e:
        logger.error(f"Unexpected error during signup: {e}")
        return {
            "success": False,
            "error_code": "InternalError",
            "message": "An unexpected error occurred during signup",
        }


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
        # Parse request body
        body = json.loads(event["body"])
        payload = SignupSchema(**body)

        # Sign up user with S3 template
        signup_result = sign_up_user_with_template(payload)

        logger.info(f"Sign up result: {signup_result}")

        if signup_result["success"]:
            status_code = 200
            response.update(
                {
                    "error": False,
                    "success": True,
                    "message": signup_result["message"],
                    "data": {
                        "user_sub": signup_result["user_sub"],
                        "template_used": signup_result["template_used"],
                    },
                }
            )
        else:
            # Handle specific Cognito errors
            if signup_result["error_code"] == "UsernameExistsException":
                status_code = 409
            elif signup_result["error_code"] in [
                "InvalidPasswordException",
                "InvalidParameterException",
            ]:
                status_code = 400
            else:
                status_code = 500

            response.update(
                {"error": True, "success": False, "message": signup_result["message"]}
            )

    except ValueError as e:
        # Handle Pydantic validation errors
        logger.error(f"Validation error: {e}")
        error_messages = {}

        if hasattr(e, "errors"):
            for error in e.errors():
                field = error["loc"][-1] if error["loc"] else "unknown"
                error_messages[field] = error["msg"]
        else:
            error_messages = {"validation": str(e)}

        response["message"] = error_messages
        status_code = 400

    except json.JSONDecodeError:
        logger.error("Invalid JSON in request body")
        response["message"] = "Invalid JSON in request body"
        status_code = 400

    except KeyError as e:
        logger.error(f"Missing required field: {e}")
        response["message"] = f"Missing required field: {e}"
        status_code = 400

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        traceback.print_exc()
        status_code = 500
        response["message"] = "Internal server error"

    return make_response(status_code, response)


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def handler(event, context):
    return main(event, context)
