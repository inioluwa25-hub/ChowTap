import base64
import hashlib
import hmac
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


class ResendCodeSchema(BaseModel):
    email: EmailStr


def get_secret_hash(username, client_id, client_secret):
    msg = username + client_id
    dig = hmac.new(
        str(client_secret).encode("utf-8"),
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
        payload = ResendCodeSchema(**body)
        logger.info(f"payload - {payload}")
        client.resend_confirmation_code(
            ClientId=CLIENT_ID,
            SecretHash=get_secret_hash(payload.email, CLIENT_ID, CLIENT_SECRET),
            Username=payload.email,
        )
        status_code = 200
        response["error"] = False
        response["success"] = True
        response["message"] = "code sent successful"
    except client.exceptions.UserNotFoundException as e:
        logger.error(e)
        response["message"] = "user not found"
    except client.exceptions.CodeMismatchException as e:
        logger.error(e)
        response["message"] = "invalid code"
    except client.exceptions.ExpiredCodeException as e:
        logger.error(e)
        response["message"] = "invalid code"
    except client.exceptions.InvalidParameterException as e:
        logger.error(e)
        response["message"] = "user already confirmed"
    except client.exceptions.NotAuthorizedException as e:
        logger.error(e)
        response["message"] = "User cannot be confirmed."
    except ValueError as e:
        logger.error(e)
        error_message = {}
        for field, errors in e.messages.items():
            error_message[field] = errors[0]
        response["message"] = error_message
    except Exception as e:
        logger.error(e)
        response["message"] = str(e)
        status_code = 500
    return make_response(status_code, response)


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def handler(event, context):
    return main(event, context)
