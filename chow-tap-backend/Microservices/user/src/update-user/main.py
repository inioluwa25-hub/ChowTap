from os import getenv
import json
import boto3
import base64
import re
import hashlib
import hmac
from aws_lambda_powertools.utilities import parameters
from pydantic import BaseModel, EmailStr, validator
from utils import (
    make_response,
    handle_exceptions,
    logger,
)

# Environment variables
STAGE = getenv("STAGE")
APP_NAME = getenv("APP_NAME")

# Fix the parameter store path to match SAM template
POOL_ID = parameters.get_parameter(f"/chow-tap/{STAGE}/POOL_ID")
CLIENT_ID = parameters.get_parameter(f"/{APP_NAME}/{STAGE}/CLIENT_ID")
CLIENT_SECRET = parameters.get_parameter(
    f"/{APP_NAME}/{STAGE}/CLIENT_SECRET", decrypt=True
)

# AWS client
client = boto3.client("cognito-idp")
db = boto3.resource("dynamodb")
table = db.Table("chow-tap-prod-main-table")


class UserSchema(BaseModel):
    email: EmailStr | None = None
    first_name: str | None = None
    last_name: str | None = None
    phone_number: str | None = None

    @validator("phone_number")
    def validate_phone_number(cls, phone_number):
        # Validate Nigerian phone number format
        if not re.match(r"^0[7-9][0-1]\d{8}$", phone_number):
            raise ValueError(
                "Phone number must be a valid Nigerian number (e.g., 07056463857)"
            )
        return phone_number


def admin_get_user(cognito_client, user_pool_id, username):
    try:
        logger.info(
            f"Calling admin_get_user with pool_id={user_pool_id}, username={username}"
        )
        response = cognito_client.admin_get_user(
            UserPoolId=user_pool_id, Username=username
        )
        # Add check for UserAttributes in response
        if "UserAttributes" not in response:
            logger.error("No UserAttributes in response")
            return {}

        data = {
            attr.get("Name"): attr.get("Value")
            for attr in response["UserAttributes"]
            if attr.get("Name") and attr.get("Value")
        }
        return data
    except Exception as e:
        logger.error(f"Error in admin_get_user: {str(e)}")
        raise


def get_secret_hash_individual(username):
    msg = username + CLIENT_ID
    dig = hmac.new(
        str(CLIENT_SECRET).encode("utf-8"),
        msg=str(msg).encode("utf-8"),
        digestmod=hashlib.sha256,
    ).digest()
    d2 = base64.b64encode(dig).decode()
    return d2


def update_ddb_record(sub):
    user = admin_get_user(client, POOL_ID, sub)
    user.update({"pk": "user", "sk": f"user_{sub}"})
    table.put_item(Item=user)


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
        # Enhanced claims extraction
        request_context = event.get("requestContext", {})
        authorizer = request_context.get("authorizer") or {}

        try:
            body = json.loads(event.get("body", "{}") or "{}")
        except json.JSONDecodeError:
            body = {}
        try:
            payload = UserSchema(**body)
            logger.info(f"payload - {payload}")
        except Exception as e:
            logger.error(f"Invalid payload: {str(e)}")
            return make_response(
                400, {"error": True, "success": False, "message": str(e), "data": None}
            )

        claims = authorizer.get("claims") or authorizer

        if not isinstance(claims, dict) or not claims:
            logger.error("No valid claims found in event")
            logger.info(f"Full event structure: {json.dumps(event, indent=2)}")
            status_code = 401
            response["message"] = "Unauthorized - No claims found"
            return make_response(status_code, response)

        # Extract user_id from claims
        user_id = claims.get("sub") or claims.get("cognito:username")
        if not user_id:
            logger.error("No user identifier found in claims")
            status_code = 401
            response["message"] = "Unauthorized - No user identifier"
            return make_response(status_code, response)

        # Get POOL_ID
        try:
            logger.info(f"Retrieved POOL_ID: {POOL_ID}")
        except Exception as e:
            logger.error(f"Failed to get POOL_ID: {str(e)}")
            status_code = 500
            response["message"] = "Configuration error"
            return make_response(status_code, response)

        if payload.phone_number:
            e164_phone = "+234" + payload.phone_number[1:]
        else:
            e164_phone = None

        # Update user data
        user_attr = []
        if payload.get("email"):
            user_attr.append({"Name": "email", "Value": payload.email})
        if payload.get("phone_number"):
            user_attr.append({"Name": "phone_number", "Value": e164_phone})
        if payload.get("first_name"):
            user_attr.append({"Name": "given_name", "Value": payload.first_name})
        if payload.get("last_name"):
            user_attr.append({"Name": "family_name", "Value": payload.last_name})

        client.admin_update_user_attributes(
            UserAttributes=user_attr,
            UserPoolId=POOL_ID,
            Username=user_id,
        )
        update_ddb_record(user_id)
        status_code = 200
        response["error"] = False
        response["success"] = True
        response["message"] = "successfully updated"

    except client.exceptions.NotAuthorizedException as e:
        logger.error(f"Not authorized: {str(e)}")
        status_code = 403
        response["message"] = "Access denied"
    except Exception as e:
        logger.error(f"Unexpected error: {type(e).__name__}: {str(e)}")
        status_code = 500
        response["message"] = "Internal server error"

    return make_response(status_code, response)


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def handler(event, context):
    return main(event, context)
