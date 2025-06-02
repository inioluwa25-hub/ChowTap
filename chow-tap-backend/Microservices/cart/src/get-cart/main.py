from time import time
from os import getenv
from decimal import Decimal
import boto3
from utils import handle_exceptions, logger, make_response

# Environment variables
STAGE = getenv("STAGE")
APP_NAME = getenv("APP_NAME")

# AWS clients
db = boto3.resource("dynamodb")
table = db.Table("chow-tap-prod-main-table")


def get_user_cart(user_id: str):
    """Retrieve user's cart from DynamoDB with proper Decimal conversion"""
    try:
        response = table.get_item(Key={"pk": f"User#{user_id}", "sk": "Cart"})
        cart_data = response.get("Item", {})

        if not cart_data:
            return {
                "items": [],
                "created_at": int(time()),
                "updated_at": int(time()),
                "cart_total": 0.0,
                "item_count": 0,
            }

        # Convert Decimal to float for response
        cart_data["items"] = convert_decimals_to_floats(cart_data.get("items", []))
        cart_data["cart_total"] = float(
            sum(item["price"] * item["quantity"] for item in cart_data["items"])
        )
        cart_data["item_count"] = sum(item["quantity"] for item in cart_data["items"])

        return cart_data

    except table.meta.client.exceptions.ClientError as e:
        logger.error(f"DynamoDB get error: {str(e)}")
        raise


def convert_decimals_to_floats(obj):
    """Recursively convert Decimal values to float in a dictionary"""
    if isinstance(obj, dict):
        return {k: convert_decimals_to_floats(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [convert_decimals_to_floats(v) for v in obj]
    elif isinstance(obj, Decimal):
        return float(obj)
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

        # 2. Get cart data
        cart_data = get_user_cart(user_id)

        # 3. Prepare success response
        return make_response(
            200,
            {
                "error": False,
                "success": True,
                "message": "Cart retrieved successfully",
                "data": {
                    "items": cart_data["items"],
                    "meta": {
                        "item_count": cart_data["item_count"],
                        "cart_total": round(cart_data["cart_total"], 2),
                        "last_updated": cart_data.get(
                            "updated_at", cart_data.get("created_at")
                        ),
                    },
                },
            },
        )

    except Exception as e:
        logger.error(f"Unexpected error: {type(e).__name__}: {str(e)}")
        response["message"] = "Internal server error"

    return make_response(status_code, response)


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def handler(event, context):
    return main(event, context)
