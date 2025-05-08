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
    food_name: str
    description: str
    price: int
    image: str
    is_available: bool
    preparation_time: int
    category: str

    @validator("category")
    def validate_category(cls, v):
        allowed = ["main_dish", "side_dish", "protein", "drink", "snack"]
        if v not in allowed:
            raise ValueError(f"Category must be one of: {allowed}")
        return v


class BulkProductSchema(BaseModel):
    products: list[ProductSchema]

    @validator("products")
    def validate_products(cls, v):
        if not v:
            raise ValueError("At least one product must be provided")
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
            body = json.loads(event.get("body"))
        except json.JSONDecodeError:
            body = {}

        successful_uploads = []
        failed_uploads = []

        for payload in body:
            try:
                try:
                    validated_payload = ProductSchema(**body)
                    logger.info(f"payload - {validated_payload}")
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

                vendor = table.get_item(
                    Key={"pk": "Vendor", "sk": f"Vendor#{user_id}"}
                ).get("Item")
                if not vendor:
                    response["message"] = "complete registration to become a vendor"
                    return make_response(status_code, response)

                product_id = f"Product#{user_id}#{uuid4()}"
                timestamp = int(time())

                product_payload = payload.dict()
                product_payload.update(
                    {
                        "pk": "Product",
                        "sk": product_id,
                        "vendor_name": vendor.get("business_name"),
                        "vendor_id": vendor.get("sk"),
                        "user_id": user_id,
                        "created_at": timestamp,
                        "updated_at": timestamp,
                    }
                )

                table.put_item(Item=product_payload)

                successful_uploads.append(product_payload)
            except ValueError as e:
                logger.error(f"Validation error for product entry: {e}")
            except Exception as e:
                logger.error(f"Error processing product entry: {e}")

        status_code = 200
        response["error"], response["success"] = False, True
        response["message"] = "Bulk product upload processed"
        response["successful_uploads"] = successful_uploads
        response["failed_uploads"] = failed_uploads

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
