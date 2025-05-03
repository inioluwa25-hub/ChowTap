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

# AWS client
client = boto3.client("cognito-idp")
db = boto3.resource("dynamodb")
table = db.Table("chow-tap-prod-main-table")


class DeleteSchema(BaseModel):
    delete: bool


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
            payload = DeleteSchema(**body)
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

        if payload.delete:
            client.admin_delete_user(UserPoolId=POOL_ID, Username=user_id)
            table.delete_item(Key={"pk": "user", "sk": f"user_{user_id}"})
            response["message"] = "User account and data deleted successfully"
        else:
            response["message"] = "Invalid Request"

        status_code = 200
        response["error"] = False
        response["success"] = True

    except client.exceptions.UserNotFoundException as e:
        logger.error(e)
        response_string = str(e)
        response["message"] = response_string.split(":", 1)[-1].strip()
    except client.exceptions.ResourceNotFoundException as e:
        logger.error(e)
        response_string = str(e)
        response["message"] = response_string.split(":", 1)[-1].strip()
    except client.exceptions.InvalidParameterException as e:
        logger.error(e)
        response_string = str(e)
        response["message"] = response_string.split(":", 1)[-1].strip()
    except client.exceptions.NotAuthorizedException as e:
        logger.error(e)
        response_string = str(e)
        response["message"] = response_string.split(":", 1)[-1].strip()
    except client.exceptions.InternalErrorException as e:
        logger.error(e)
        response_string = str(e)
        response["message"] = response_string.split(":", 1)[-1].strip()
    except ValueError as err:
        logger.error(err)
        response["message"] = err.messages
    except Exception as e:
        status_code = 500
        logger.error(e)
        response["message"] = str(e)
    return make_response(status_code, response)


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def handler(event, context):
    return main(event, context)
