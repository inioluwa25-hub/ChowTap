import json
from os import getenv
from time import time
from uuid import uuid4
from decimal import Decimal
import boto3
from aws_lambda_powertools.utilities import parameters
from pydantic import BaseModel, validator
from utils import handle_exceptions, logger, make_response

# Environment variables
STAGE = getenv("STAGE")
APP_NAME = getenv("APP_NAME")

# AWS clients
db = boto3.resource("dynamodb")
table = db.Table("chow-tap-prod-main-table")


class RemoveFromCartRequest(BaseModel):
    cart_item_id: str  # The unique ID of the cart item to remove
    quantity: int = 1  # Quantity to remove (default 1, can remove partial quantities)

    @validator("quantity")
    def validate_quantity(cls, quantity):
        if quantity < 1:
            raise ValueError("Quantity to remove must be at least 1")
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
    """Update user's cart in DynamoDB with Decimal conversion"""
    try:
        # Convert all floats to decimals before saving
        cart_items = convert_floats_to_decimals(cart_items)

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


def convert_floats_to_decimals(obj):
    """Recursively convert float values to Decimal in a dictionary"""
    if isinstance(obj, dict):
        return {k: convert_floats_to_decimals(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [convert_floats_to_decimals(v) for v in obj]
    elif isinstance(obj, float):
        return Decimal(str(obj))
    return obj


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def main(event, context=None):
    status_code = 400
    response = {
        "error": True,
        "success": False,
        "message": "Unable to process request",
        "data": None,
    }

    try:
        # 1. Extract and validate user identity
        request_context = event.get("requestContext", {})
        authorizer = request_context.get("authorizer") or {}
        claims = authorizer.get("claims") or authorizer

        if not isinstance(claims, dict):
            logger.error("Invalid claims format")
            return make_response(
                401,
                {
                    "error": True,
                    "success": False,
                    "message": "Unauthorized - Invalid token",
                    "data": None,
                },
            )

        user_id = claims.get("sub")
        if not user_id:
            logger.error("No user identifier in claims")
            return make_response(
                401,
                {
                    "error": True,
                    "success": False,
                    "message": "Unauthorized - No user identifier",
                    "data": None,
                },
            )

        # 2. Parse and validate request payload
        try:
            body = json.loads(event.get("body", "{}"))
            payload = RemoveFromCartRequest(**body)
            logger.info(f"Valid payload received: {payload}")
        except json.JSONDecodeError:
            return make_response(
                400,
                {
                    "error": True,
                    "success": False,
                    "message": "Invalid JSON format",
                    "data": None,
                },
            )
        except Exception as e:
            return make_response(
                400, {"error": True, "success": False, "message": str(e), "data": None}
            )

        # 3. Get current cart
        cart_items = get_user_cart(user_id)

        # 4. Find the item to remove
        item_to_remove = next(
            (
                item
                for item in cart_items
                if item["cart_item_id"] == payload.cart_item_id
            ),
            None,
        )

        if not item_to_remove:
            return make_response(
                404,
                {
                    "error": True,
                    "success": False,
                    "message": "Item not found in cart",
                    "data": None,
                },
            )

        # 5. Update or remove the item
        if payload.quantity >= item_to_remove["quantity"]:
            # Remove the entire item
            cart_items = [
                item
                for item in cart_items
                if item["cart_item_id"] != payload.cart_item_id
            ]
        else:
            # Reduce the quantity
            item_to_remove["quantity"] -= payload.quantity
            item_to_remove["updated_at"] = int(time())

        # 6. Persist updated cart
        update_user_cart(user_id, cart_items)

        # 7. Calculate cart summary
        total_items = sum(item["quantity"] for item in cart_items)
        total_price = float(
            sum(Decimal(str(item["price"])) * item["quantity"] for item in cart_items)
        )

        # 8. Prepare success response
        return make_response(
            200,
            {
                "error": False,
                "success": True,
                "message": "Item removed from cart successfully",
                "data": {
                    "cart_item_count": total_items,
                    "cart_total": round(total_price, 2),
                    "removed_item": {
                        "cart_item_id": payload.cart_item_id,
                        "quantity_removed": payload.quantity,
                        "remaining_quantity": (
                            0
                            if payload.quantity >= item_to_remove["quantity"]
                            else item_to_remove["quantity"] - payload.quantity
                        ),
                    },
                },
            },
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
