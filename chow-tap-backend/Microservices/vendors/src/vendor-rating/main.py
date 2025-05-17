import json
from os import getenv
from time import time
from uuid import uuid4

import boto3
from aws_lambda_powertools.utilities import parameters
from pydantic import BaseModel, validator
from utils import handle_exceptions, logger, make_response

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
    vendor_id: str
    review: str | None = None
    rate: int

    @validator("rate")
    def check_rate_range(cls, v):
        if v < 1 or v > 5:
            raise ValueError("rate must be between 1 and 5")
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
                400,
                {
                    "error": True,
                    "success": False,
                    "message": str(e),
                    "data": None,
                },
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

        vendor = table.get_item(Key={"pk": "Vendor", "sk": payload.vendor_id}).get(
            "Item"
        )
        if not vendor:
            response["message"] = "complete registration to become a vendor"
            return make_response(status_code, response)

        timestamp = int(time())

        vendor_id = payload.vendor_id
        product_payload = payload.dict()
        product_payload.update(
            {
                "pk": "review",
                "sk": f"{vendor_id}#{str(uuid4())}#{int(time())}",
                "vendor_name": vendor.get("business_name"),
                "user_id": claims["sub"],
                "reviewed_by": claims,
                "created_at": timestamp,
                "updated_at": timestamp,
            }
        )

        table.put_item(Item=product_payload)

        normalize_review = table.get_item(
            Key={"pk": "review", "sk": payload.vendor_id}
        ).get("Item")
        if normalize_review:
            normalize_review["count"] = normalize_review["count"] + 1
            normalize_review["sum"] = normalize_review["sum"] + payload.rate
            normalize_review["avg_review"] = str(
                normalize_review["sum"] / normalize_review["count"]
            )
        else:
            normalize_review = {
                "pk": "review",
                "sk": payload.vendor_id,
                "sum": payload.rate,
                "count": 1,
                "avg_review": str(payload.rate),
            }
        table.put_item(Item=normalize_review)
        status_code = 200
        response["error"], response["success"] = False, True
        response["message"] = "success"

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
