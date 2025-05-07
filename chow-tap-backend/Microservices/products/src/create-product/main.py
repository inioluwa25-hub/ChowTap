from os import getenv
import json
import re
import boto3
from time import time
from decimal import Decimal
from aws_lambda_powertools.utilities import parameters
from pydantic import BaseModel, field_validator
from uuid import uuid4
from typing import Literal
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


class ProductSchema(BaseModel):
    food_name: str
    description: str
    price: int
    image: str
    is_available: bool
    preparation_time: int
    category: str

    @field_validator("category")
    def validate_category(cls, v):
        allowed = ["main_dish", "side_dish", "protein", "drink", "snack"]
        if v not in allowed:
            raise ValueError(f"Category must be one of: {allowed}")
        return v


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
            payload = ProductSchema(**body)
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

        vendor = table.get_item(Key={"pk": "Vendor", "sk": f"Vendor#{user_id}"}).get(
            "Item"
        )
        if not vendor:
            response["message"] = "complete registration to become a vendor"
            return make_response(status_code, response)

        product_id = f"Product#{uuid4()}"
        timestamp = int(time())

        product_payload = payload.update(
            {
                "pk": "car",
                "sk": product_id,
                "user_id": user_id,
                "created_at": timestamp,
                "updated_at": timestamp,
            }
        )

        table.put_item(Item=product_payload)

        del response["message"]
        response.update({"error": False, "success": True, "data": product_id})
        status_code = 200

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
