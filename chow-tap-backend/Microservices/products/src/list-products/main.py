from os import getenv
import boto3
import json
import base64
from aws_lambda_powertools.utilities import parameters
from utils import make_response, handle_exceptions, logger
from typing import List, Optional
from pydantic import BaseModel
from boto3.dynamodb.conditions import Key

# Environment variables
STAGE = getenv("STAGE")
APP_NAME = getenv("APP_NAME")

# AWS clients
db = boto3.resource("dynamodb")
table = db.Table("chow-tap-prod-main-table")


class ProductListSchema(BaseModel):
    limit: Optional[int] = 60
    pagination_token: Optional[str] = None
    attributes_to_get: Optional[List[str]] = None


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
        # Parse query parameters
        query_params = event.get("queryStringParameters", {}) or {}
        params = ProductListSchema(**query_params)

        # Prepare DynamoDB query parameters
        query_kwargs = {
            "KeyConditionExpression": Key("pk").eq("Product"),
            "Limit": min(params.limit, 100),
            "ScanIndexForward": False,
        }

        if params.pagination_token:
            query_kwargs["ExclusiveStartKey"] = json.loads(
                base64.b64decode(params.pagination_token).decode("utf-8")
            )

        # Execute query
        result = table.query(**query_kwargs)

        # Format response
        response["data"]["products"] = result.get("Items", [])

        if "LastEvaluatedKey" in result:
            response["data"]["pagination_token"] = base64.b64encode(
                json.dumps(result["LastEvaluatedKey"]).encode("utf-8")
            ).decode("utf-8")

        response["message"] = f"Found {len(response['data']['products'])} products"

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
