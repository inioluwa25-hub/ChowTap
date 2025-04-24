from os import getenv
import boto3
from aws_lambda_powertools.utilities import parameters
from utils import make_response, handle_exceptions, logger
from typing import List, Optional
from pydantic import BaseModel

# Environment variables
STAGE = getenv("STAGE")
APP_NAME = getenv("APP_NAME")
POOL_ID = parameters.get_parameter(f"/{APP_NAME}/{STAGE}/POOL_ID")

# AWS client
client = boto3.client("cognito-idp")


class UserListSchema(BaseModel):
    limit: Optional[int] = 60
    pagination_token: Optional[str] = None
    attributes_to_get: Optional[List[str]] = None


def format_user_attributes(user: dict) -> dict:
    """Format Cognito user attributes into a more usable dictionary"""
    attributes = {attr["Name"]: attr["Value"] for attr in user.get("Attributes", [])}
    return {
        "username": user["Username"],
        "enabled": user["Enabled"],
        "status": user["UserStatus"],
        "created": user["UserCreateDate"].isoformat(),
        "modified": user["UserLastModifiedDate"].isoformat(),
        **attributes,
    }


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def main(event, context=None):
    """
    List all users in the Cognito user pool with pagination support

    Args:
        event (dict): Event data including query parameters

    Returns:
        dict: Response containing user list and pagination token
    """
    status_code = 200
    response = {
        "error": False,
        "success": True,
        "message": "",
        "data": {"users": [], "pagination_token": None},
    }

    try:
        # Parse query parameters
        query_params = event.get("queryStringParameters", {}) or {}
        params = UserListSchema(**query_params)

        # Prepare list users parameters
        list_users_kwargs = {
            "UserPoolId": POOL_ID,
            "Limit": min(params.limit, 60),  # Cognito max limit is 60
        }

        if params.pagination_token:
            list_users_kwargs["PaginationToken"] = params.pagination_token

        if params.attributes_to_get:
            list_users_kwargs["AttributesToGet"] = params.attributes_to_get

        # Get users from Cognito
        result = client.list_users(**list_users_kwargs)

        # Format users and set response
        response["data"]["users"] = [
            format_user_attributes(user) for user in result["Users"]
        ]
        response["data"]["pagination_token"] = result.get("PaginationToken")
        response["message"] = (
            f"Successfully retrieved {len(response['data']['users'])} users"
        )

    except client.exceptions.InvalidParameterException as e:
        logger.error(f"Invalid parameters: {str(e)}")
        status_code = 400
        response.update(
            {"error": True, "success": False, "message": "Invalid request parameters"}
        )
    except client.exceptions.UserPoolNotFoundException as e:
        logger.error(f"User pool not found: {str(e)}")
        status_code = 404
        response.update(
            {"error": True, "success": False, "message": "User pool not found"}
        )
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        status_code = 500
        response.update(
            {"error": True, "success": False, "message": "Failed to retrieve users"}
        )

    return make_response(status_code, response)


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def handler(event, context):
    return main(event, context)
