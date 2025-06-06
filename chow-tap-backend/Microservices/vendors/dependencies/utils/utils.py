import logging
import boto3
import json
from json import dumps
from functools import wraps
from decimal import Decimal
from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.parser import parse

if logging.getLogger().hasHandlers():
    logging.getLogger().setLevel(logging.INFO)
else:
    logging.basicConfig(level=logging.INFO)

logger = Logger()
context = logging.getLogger()

db = boto3.resource("dynamodb")
table = db.Table("chow-tap-prod-main-table")

response = {
    "statusCode": 500,
    "headers": {"access-control-allow-origin": "*"},
    "body": None,
}


def validate_payload(event, model):
    """
    Validate the input payload against a given model.

    Args:
        event (dict): The input payload to be validated.
        model (class): The model to validate the payload against.

    Returns:
        dict: The parsed and validated payload.

    Raises:
        ValueError: If the payload is invalid.
    """
    logger.info("INSIDE VALIDATE PAYLOAD FUNCTION")
    try:
        logger.info(f"Payload to validate: {event}")
        return parse(event=event, model=model)
    except ValueError as e:
        raise ValueError(f"Invalid payload: {e}") from e


def convert_decimal_to_float(obj):
    if isinstance(obj, Decimal):
        return float(obj)
    raise TypeError(
        "Object of type {} is not JSON serializable".format(type(obj).__name__)
    )


def make_response(status, message, log=True):
    if log:
        context.info(f"Response: status-{status}, body-{message}")
    return {
        "statusCode": status,
        "body": json.dumps(message, default=convert_decimal_to_float),
        "headers": {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
            "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
            "Access-Control-Allow-Credentials": "true",
        },
    }


def create_document(data):
    table.put_item(Item=data)


def handle_exceptions(func):
    """Handle exception in the function"""

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
            return result
        except ValueError as error:
            logger.error("User error in function %s: %s", func.__name__, str(error))
            response["statusCode"] = 400
            response["body"] = dumps({"error": str(error)})
        except Exception as error:
            logger.error("Error in function %s: %s", func.__name__, error)
            response["statusCode"] = 500
            response["body"] = dumps({"error": "Something went wrong"})
            return response

    return wrapper
