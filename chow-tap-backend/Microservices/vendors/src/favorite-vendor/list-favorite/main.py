from os import getenv
import boto3
import json
from utils import make_response, handle_exceptions, logger
from typing import Optional
from pydantic import BaseModel
from boto3.dynamodb.conditions import Key

# Environment variables
STAGE = getenv("STAGE")
APP_NAME = getenv("APP_NAME")

# AWS clients
db = boto3.resource("dynamodb")
table = db.Table("chow-tap-prod-main-table")

paginator = db.meta.client.get_paginator("query")


class FavoriteListSchema(BaseModel):
    last_evaluated_key: Optional[str] = None


def get_vendors(user_id, page_config, last_evaluated_key=None):
    query_params = {
        "KeyConditionExpression": Key("pk").eq("fav") & Key("sk").begins_with(user_id)
    }
    query_params.update({"TableName": table.name, "PaginationConfig": page_config})
    if last_evaluated_key:
        page_config["StartingToken"] = last_evaluated_key
    resp_iter = paginator.paginate(**query_params)
    response = resp_iter.build_full_result()
    data = []
    if response.get("Items"):
        data = response["Items"]
    next_token = response.get("NextToken")
    return data, next_token


def fetch_all_items(payload):
    items = []
    while True:
        resp = table.query(**payload)
        items.extend(resp.get("Items"))
        if "LastEvaluatedKey" not in resp:
            break
        else:
            payload["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    return items


def favourite_car(user_id):
    payload = {
        "KeyConditionExpression": (Key("pk").eq("fav") & Key("sk").begins_with(user_id))
    }
    return fetch_all_items(payload)


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def main(event, context=None):
    status_code = 200
    response = {
        "error": False,
        "success": True,
        "message": "",
        "data": {"favorites": [], "last_evaluated_key": None},
    }

    try:
        # Claims extraction
        request_context = event.get("requestContext", {})
        authorizer = request_context.get("authorizer") or {}

        # Parse body
        try:
            body = json.loads(event.get("body", "{}") or "{}")
            payload = FavoriteListSchema(**body)
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

        # Get user ID from claims
        claims = authorizer.get("claims") or authorizer
        if not isinstance(claims, dict) or not claims:
            logger.error("No valid claims found in event")
            return make_response(
                401,
                {
                    "error": True,
                    "success": False,
                    "message": "Unauthorized - No claims found",
                    "data": None,
                },
            )

        user_id = claims.get("sub") or claims.get("cognito:username")
        if not user_id:
            return make_response(
                401,
                {
                    "error": True,
                    "success": False,
                    "message": "Unauthorized - No user identifier",
                    "data": None,
                },
            )

        # Get favorite vendors
        page_config = {"MaxItems": 10}
        fav_vendors, next_token = get_vendors(
            user_id, page_config, last_evaluated_key=payload.last_evaluated_key
        )

        # Process favorites with full vendor details
        favorites = []
        if fav_vendors:
            for fav in fav_vendors:
                parts = fav["sk"].split("#")
                if len(parts) >= 3:
                    vendor_id = f"{parts[1]}#{parts[2]}"

                    # Get full vendor details from DynamoDB
                    vendor = table.get_item(Key={"pk": "Vendor", "sk": vendor_id}).get(
                        "Item", {}
                    )

                    if vendor:
                        favorites.append(
                            {
                                "vendor": vendor,  # Full vendor payload
                                "favorite_info": {  # Favorite relationship details
                                    "favorite_id": fav.get("pk") + "#" + fav.get("sk"),
                                    "liked_by": user_id,
                                    "liked_at": fav.get("created_at"),
                                    "updated_at": fav.get("updated_at"),
                                },
                            }
                        )

            response["data"]["favorites"] = favorites
            if next_token:
                response["data"]["last_evaluated_key"] = next_token
        else:
            status_code = 404
            response["message"] = "No favorite vendors found"

    except table.meta.client.exceptions.ValidationException:
        logger.error("Invalid query parameters")
        return make_response(
            400,
            {
                "error": True,
                "success": False,
                "message": "Invalid query parameters",
                "data": None,
            },
        )
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return make_response(
            500,
            {
                "error": True,
                "success": False,
                "message": "Failed to retrieve favorites",
                "data": None,
            },
        )

    return make_response(status_code, response)


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def handler(event, context):
    return main(event, context)
