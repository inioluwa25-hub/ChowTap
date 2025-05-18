import json
from os import getenv
from time import time

import boto3
from aws_lambda_powertools.utilities import parameters
from pydantic import BaseModel
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


class FavoriteSchema(BaseModel):
    vendor_id: str
    like: bool


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
            payload = FavoriteSchema(**body)
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
            response["message"] = "Invalid Request"
            return make_response(status_code, response)

        if payload.get("like"):
            payload.update(
                {
                    "pk": "fav",
                    "sk": f"{user_id}#{payload.vendor_id}",
                    "liked_by": user_id,
                    "created_at": int(time()),
                    "updated_at": int(time()),
                }
            )
            table.put_item(Item=payload)
            vendor["total_likes"] = (
                str(int(vendor["total_likes"]) + 1)
                if vendor.get("total_likes")
                else str(1)
            )
            vendor["updated_at"] = int(time())
        else:
            table.delete_item(Key={"pk": "fav", "sk": f"{user_id}#{payload.vendor_id}"})
            vendor["total_likes"] = (
                str(int(vendor["total_likes"]) - 1)
                if vendor.get("total_likes") and int(vendor["total_likes"]) > 0
                else str(0)
            )
        table.put_item(Item=vendor)

        status_code = 200
        response["error"], response["success"] = False, True
        del response["message"]

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
