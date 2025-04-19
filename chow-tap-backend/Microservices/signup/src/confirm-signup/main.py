import base64
import hashlib
import hmac
import json
import re
from os import getenv

import boto3
from pydantic import BaseModel
from aws_lambda_powertools.utilities import parameters
from utils import (
    make_response,
    handle_exceptions,
    logger,
    create_document,
    admin_get_user,
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


class ConfirmsignupSchema(BaseModel):
    email: str  # Changed from phone_number to email
    code: str
    phone_number: str  # Added phone number for verification


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
        payload = ConfirmsignupSchema(**body)
        logger.info(f"payload - {payload}")

        # Convert to E.164 format for verification
        e164_phone = (
            "+234" + payload.phone_number[1:]
            if payload.phone_number.startswith("0")
            else payload.phone_number
        )

        # Verify the confirmation code
        client.verify_user_attribute(
            AccessToken=get_access_token(
                payload.email
            ),  # You'll need to implement this
            AttributeName="phone_number",
            Code=payload.code,
        )

        # Alternative approach if above doesn't work:
        # client.confirm_sign_up(
        #     ClientId=CLIENT_ID,
        #     SecretHash=get_secret_hash(payload.email),
        #     Username=payload.email,
        #     ConfirmationCode=payload.code,
        #     ForceAliasCreation=False,
        # )

        # Mark phone as verified
        client.admin_update_user_attributes(
            UserPoolId=POOL_ID,
            Username=payload.email,
            UserAttributes=[
                {"Name": "phone_number_verified", "Value": "true"},
                {"Name": "phone_number", "Value": e164_phone},
            ],
        )

        # Get user data
        user_data = admin_get_user(client, POOL_ID, payload.email)
        customer = {
            "pk": "user",
            "sk": f"user_{user_data['sub']}",
            "email": payload.email,
            "phone_number": payload.phone_number,
            "phone_verified": True,
        }

        # Load user permissions
        with open("user_permissions.json", "r", encoding="utf-8") as file:
            permissions = json.load(file)

        customer["permissions"] = permissions
        customer.update(user_data)
        create_document(customer)

        response.update(
            error=False,
            success=True,
            message="Phone number has been verified and signup completed",
            data={"email": payload.email, "phone_verified": True},
        )
        status_code = 200

    except client.exceptions.UserNotFoundException:
        response["message"] = "User not found"
    except client.exceptions.CodeMismatchException:
        response["message"] = "Invalid verification code"
    except client.exceptions.ExpiredCodeException:
        response["message"] = "Verification code has expired"
    except client.exceptions.NotAuthorizedException:
        response["message"] = "Verification failed - please try again"
    except Exception as e:
        logger.error(f"Verification error: {str(e)}")
        response["message"] = "Verification process failed"
        status_code = 500

    return make_response(status_code, response)


# Helper function to get access token (implement based on your auth flow)
def get_access_token(username: str) -> str:
    # Implement token retrieval logic here
    # This might involve calling initiate_auth or checking session
    pass


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def handler(event, context):
    return main(event, context)
