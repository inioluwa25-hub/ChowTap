from os import getenv
import json
import boto3
from aws_lambda_powertools.utilities import parameters
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


def admin_get_user(cognito_client, user_pool_id, username):
    try:
        logger.info(
            f"Calling admin_get_user with pool_id={user_pool_id}, username={username}"
        )
        response = cognito_client.admin_get_user(
            UserPoolId=user_pool_id, Username=username
        )
        data = {
            attr.get("Name"): attr.get("Value") for attr in response["UserAttributes"]
        }
        return data
    except Exception as e:
        logger.error(f"Error in admin_get_user: {str(e)}")
        raise


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
        authorizer = request_context.get("authorizer", {})

        # Multiple possible claim locations
        claims = authorizer.get("claims") or authorizer

        if not claims:
            logger.error("No claims found in event")
            logger.info(f"Full event structure: {json.dumps(event, indent=2)}")
            status_code = 401
            response["message"] = "Unauthorized - No claims found"
            return make_response(status_code, response)

        logger.info(f"Claims structure: {json.dumps(claims, indent=2)}")

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

        # Get user data
        user = admin_get_user(client, POOL_ID, user_id)
        if user:
            status_code = 200
            response.update(
                {"error": False, "success": True, "message": "success", "data": user}
            )
        else:
            status_code = 404
            response["message"] = "User not found"

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
