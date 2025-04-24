from os import getenv

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

POOL_ID = parameters.get_parameter(f"/{APP_NAME}/{STAGE}/POOL_ID")

# AWS client
client = boto3.client("cognito-idp")


def admin_get_user(cognito_client, user_pool_id, username):
    response = cognito_client.admin_get_user(UserPoolId=user_pool_id, Username=username)
    data = {attr.get("Name"): attr.get("Value") for attr in response["UserAttributes"]}
    return data


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
        claims = event["requestContext"]["authorizer"]["claims"]
        user_id = claims["sub"]
        user = admin_get_user(client, POOL_ID, user_id)
        if user:
            status_code = 200
            response["message"] = "success"
            response["data"] = user
        else:
            status_code = 404
            response["message"] = "Invalid request"
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


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def handler(event, context):
    return main(event, context)
