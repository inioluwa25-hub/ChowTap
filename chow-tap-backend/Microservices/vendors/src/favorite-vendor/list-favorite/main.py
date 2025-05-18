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
        "data": {"products": [], "pagination_token": None},
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

        page_config = {
            "MaxItems": 10,
        }
        fav_vendors, next_token = get_vendors(
            user_id, page_config, last_evaluated_key=payload.last_evaluated_key
        )
        vendors = []
        if fav_vendors:
            for vendor in fav_vendors:
                sk = vendor["sk"].split("#")[1]
                vendors.append(sk)
            status_code = 200
            response["error"] = False
            response["success"] = True
            del response["message"]
        else:
            status_code = 404
            response["message"] = "No vendors found"
        if next_token:
            response["data"]["last_evaluated_key"] = next_token
        response["data"]["vendors"] = vendors

    except table.meta.client.exceptions.ValidationException as e:
        logger.error(f"Invalid query: {str(e)}")
        status_code = 400
        response.update(
            {"error": True, "success": False, "message": "Invalid query parameters"}
        )
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        status_code = 500
        response.update(
            {"error": True, "success": False, "message": "Failed to retrieve products"}
        )

    return make_response(status_code, response)


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def handler(event, context):
    return main(event, context)
