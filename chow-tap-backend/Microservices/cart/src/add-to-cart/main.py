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


class AddToCartRequest(BaseModel):
    product_id: str
    quantity: int

    @validator("quantity")
    def validate_quantity(cls, quantity):
        if quantity < 1:
            raise ValueError("Quantity must be at least 1")
        return quantity


def get_user_cart(user_id: str):
    """Retrieve user's cart from DynamoDB"""
    try:
        response = table.get_item(Key={"pk": f"User#{user_id}", "sk": "Cart"})
        return response.get("Item", {}).get("items", [])
    except table.meta.client.exceptions.ClientError as e:
        logger.error(f"DynamoDB get error: {str(e)}")
        raise


def update_user_cart(user_id: str, cart_items: list):
    """Update user's cart in DynamoDB"""
    try:
        table.put_item(
            Item={
                "pk": f"User#{user_id}",
                "sk": "Cart",
                "items": cart_items,
                "updated_at": int(time()),
                "ttl": int(time()) + 86400,  # Auto-expire cart after 24 hours
            }
        )
    except table.meta.client.exceptions.ClientError as e:
        logger.error(f"DynamoDB put error: {str(e)}")
        raise


def get_product_item(product_id: str):
    """Retrieve product item details from catalog"""
    try:
        response = table.get_item(Key={"pk": "Product", "sk": product_id})
        item = response.get("Item")
        if not item:
            raise ValueError("Product item not found")
        return item
    except table.meta.client.exceptions.ClientError as e:
        logger.error(f"DynamoDB get error: {str(e)}")
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
        authorizer = request_context.get("authorizer") or {}

        try:
            body = json.loads(event.get("body", "{}") or "{}")
        except json.JSONDecodeError:
            body = {}
        try:
            payload = AddToCartRequest(**body)
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

        product_item = get_product_item(payload.product_id)

        cart_items = get_user_cart(user_id)

        existing_item = next(
            (item for item in cart_items if item["product_id"] == payload.product_id),
            None,
        )

        if existing_item:
            existing_item["quantity"] += payload.quantity
            existing_item["updated_at"] = int(time())
        else:
            cart_items.append(
                {
                    "cart_item_id": str(uuid4()),
                    "food_id": payload.product_id,
                    "name": product_item["food_name"],
                    "price": float(product_item["price"]),
                    "quantity": payload.quantity,
                    "image": product_item.get("image"),
                    "added_at": int(time()),
                    "updated_at": int(time()),
                }
            )

        # 6. Persist updated cart
        update_user_cart(user_id, cart_items)

        # 7. Calculate cart summary
        total_items = sum(item["quantity"] for item in cart_items)
        total_price = sum(item["price"] * item["quantity"] for item in cart_items)

        # 8. Prepare success response
        return make_response(
            200,
            {
                "error": False,
                "success": True,
                "message": "Item added to cart successfully",
                "data": {
                    "cart_item_count": total_items,
                    "cart_total": round(total_price, 2),
                    "added_item": {
                        "food_id": payload.food_id,
                        "name": product_item["food_name"],
                        "quantity": payload.quantity,
                        "price": float(product_item["price"]),
                    },
                },
            },
        )

    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        return make_response(
            404, {"error": True, "success": False, "message": str(e), "data": None}
        )
    except Exception as e:
        logger.error(f"Unexpected error: {type(e).__name__}: {str(e)}")
        return make_response(
            500,
            {
                "error": True,
                "success": False,
                "message": "Internal server error",
                "data": None,
            },
        )


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def handler(event, context):
    return main(event, context)
