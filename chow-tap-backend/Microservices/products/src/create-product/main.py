import json
from os import getenv
from time import time
from uuid import uuid4
from typing import Optional, List

import boto3
from aws_lambda_powertools.utilities import parameters
from pydantic import BaseModel, validator, Field
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
    food_name: str = Field(..., min_length=2, max_length=100)
    description: str = Field(..., min_length=10, max_length=500)
    price: int = Field(..., gt=0)
    image: str = Field(..., regex=r"^https?://")
    is_available: bool = True
    preparation_time: int = Field(..., gt=0, description="Preparation time in minutes")
    category: str
    complementary_products: Optional[List[str]] = Field(
        default_factory=list,
        description="List of product IDs that pair well with this product. "
        "All categories allowed (including main+main combinations)",
    )

    @validator("category")
    def validate_category(cls, v):
        allowed = ["main_dish", "side_dish", "protein", "drink", "snack"]
        if v not in allowed:
            raise ValueError(f"Category must be one of: {allowed}")
        return v

    @validator("complementary_products")
    def validate_complementary_products(cls, v):
        if v is None:
            return []
        if len(v) > 15:
            raise ValueError("Maximum of 15 complementary products allowed")
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

        # Get vendor information
        vendor = table.get_item(Key={"pk": "Vendor", "sk": f"Vendor#{user_id}"}).get(
            "Item"
        )
        if not vendor:
            response["message"] = "Complete registration to become a vendor"
            return make_response(status_code, response)

        product_id = f"Product#{vendor.get('sk')}#{uuid4()}"
        timestamp = int(time())

        # Build product payload
        product_payload = payload.dict()
        product_payload.update(
            {
                "pk": "Product",
                "sk": product_id,
                "gsi1pk": f"Vendor#{user_id}",  # Allows querying all vendor's products
                "gsi1sk": f"Product#{product_payload['category']}",  # Allows querying by category
                "vendor_name": vendor.get("business_name"),
                "vendor_id": f"Vendor#{user_id}",
                "user_id": user_id,
                "created_at": timestamp,
                "updated_at": timestamp,
                "is_active": True,
            }
        )

        # Validate complementary products if provided
        if product_payload.get("complementary_products"):
            valid_products = []
            # Batch get all complementary products for efficiency
            keys = [
                {"pk": "Product", "sk": pid}
                for pid in product_payload["complementary_products"]
            ]
            batch_response = (
                db.batch_get_item(RequestItems={table.name: {"Keys": keys}})
                .get("Responses", {})
                .get(table.name, [])
            )

            # Create mapping of product IDs to their data
            complementary_products_map = {item["sk"]: item for item in batch_response}

            for comp_product_id in product_payload["complementary_products"]:
                product = complementary_products_map.get(comp_product_id)
                if product and product.get("vendor_id") == f"Vendor#{user_id}":
                    # Allow any category combination but log unusual ones
                    if (
                        product_payload["category"] == "main_dish"
                        and product.get("category") == "main_dish"
                    ):
                        logger.info(
                            f"Main dish combo: {product_id} + {comp_product_id}"
                        )
                    valid_products.append(comp_product_id)
                else:
                    logger.warning(f"Invalid complementary product: {comp_product_id}")

            product_payload["complementary_products"] = valid_products

            # If main dish, automatically add popular complements if none specified
            if product_payload["category"] == "main_dish" and not valid_products:
                # Query for popular complementary items from this vendor
                complements = table.query(
                    IndexName="gsi1",
                    KeyConditionExpression="gsi1pk = :vendor",
                    ExpressionAttributeValues={
                        ":vendor": f"Vendor#{user_id}",
                        ":cat1": "side_dish",
                        ":cat2": "protein",
                        ":cat3": "drink",
                        ":cat4": "snack",
                    },
                    Limit=5,
                    ScanIndexForward=False,  # Assuming higher price = more popular
                    FilterExpression="category IN (:cat1, :cat2, :cat3, :cat4)",
                ).get("Items", [])

                # Add top complements (prioritizing side dishes if available)
                side_dishes = [
                    item for item in complements if item["category"] == "side_dish"
                ]
                other_complements = [
                    item for item in complements if item["category"] != "side_dish"
                ]

                suggested_complements = (
                    side_dishes[:3] if side_dishes else []
                ) + other_complements[: 3 - len(side_dishes)]
                product_payload["complementary_products"] = [
                    item["sk"] for item in suggested_complements[:3]
                ]

        # Use a transaction to ensure atomicity
        from boto3.dynamodb.conditions import Attr

        try:
            # Create product summary for vendor record
            product_summary = {
                "product_id": product_id,
                "food_name": product_payload["food_name"],
                "category": product_payload["category"],
                "price": product_payload["price"],
                "is_available": product_payload["is_available"],
                "created_at": timestamp,
            }

            # Perform transaction - create product and update vendor
            table.meta.client.transact_write_items(
                TransactItems=[
                    {
                        "Put": {
                            "TableName": table.name,
                            "Item": {
                                k: (
                                    {"S": str(v)}
                                    if isinstance(v, str)
                                    else (
                                        {"N": str(v)}
                                        if isinstance(v, (int, float))
                                        else (
                                            {"BOOL": v}
                                            if isinstance(v, bool)
                                            else (
                                                {"L": [{"S": item} for item in v]}
                                                if isinstance(v, list)
                                                else {"S": str(v)}
                                            )
                                        )
                                    )
                                )
                                for k, v in product_payload.items()
                            },
                        }
                    },
                    {
                        "Update": {
                            "TableName": table.name,
                            "Key": {
                                "pk": {"S": "Vendor"},
                                "sk": {"S": f"Vendor#{user_id}"},
                            },
                            "UpdateExpression": "SET product_count = if_not_exists(product_count, :zero) + :inc, updated_at = :timestamp ADD products :product_summary",
                            "ExpressionAttributeValues": {
                                ":inc": {"N": "1"},
                                ":zero": {"N": "0"},
                                ":timestamp": {"N": str(timestamp)},
                                ":product_summary": {
                                    "SS": [json.dumps(product_summary)]
                                },
                            },
                        }
                    },
                ]
            )

            logger.info(
                f"Product created and vendor updated successfully: {product_id}"
            )

        except Exception as transaction_error:
            logger.error(f"Transaction failed: {str(transaction_error)}")
            # Fallback to individual operations if transaction fails
            try:
                # Create the product first
                table.put_item(Item=product_payload)

                # Then update the vendor record
                table.update_item(
                    Key={"pk": "Vendor", "sk": f"Vendor#{user_id}"},
                    UpdateExpression="SET product_count = if_not_exists(product_count, :zero) + :inc, updated_at = :timestamp ADD products :product_summary",
                    ExpressionAttributeValues={
                        ":inc": 1,
                        ":zero": 0,
                        ":timestamp": timestamp,
                        ":product_summary": {json.dumps(product_summary)},
                    },
                )
                logger.info(f"Fallback operations successful for product: {product_id}")

            except Exception as fallback_error:
                logger.error(f"Fallback operations also failed: {str(fallback_error)}")
                raise fallback_error

        response.update(
            {
                "error": False,
                "success": True,
                "data": {
                    "product_id": product_id,
                    "vendor_id": f"Vendor#{user_id}",
                    "complementary_products": product_payload.get(
                        "complementary_products", []
                    ),
                },
                "message": "Product created successfully and vendor updated",
            }
        )
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
