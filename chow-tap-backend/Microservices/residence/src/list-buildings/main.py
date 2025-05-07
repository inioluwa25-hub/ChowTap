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

# List of available buildings for delivery
BUILDINGS = [
    {"id": "bldg-001", "name": "Colcom", "location": "North Campus", "is_active": True},
    {"id": "bldg-002", "name": "Atuwatse", "location": "East Wing", "is_active": True},
    {
        "id": "bldg-003",
        "name": "Faye Curtis",
        "location": "South Campus",
        "is_active": True,
    },
    {"id": "bldg-004", "name": "Emerald", "location": "West Campus", "is_active": True},
    {
        "id": "bldg-005",
        "name": "Sapphire",
        "location": "Central Area",
        "is_active": True,
    },
    {
        "id": "bldg-006",
        "name": "Diamond",
        "location": "North Campus",
        "is_active": False,
    },
    {"id": "bldg-007", "name": "Ruby", "location": "South Campus", "is_active": True},
    {"id": "bldg-008", "name": "Crystal", "location": "East Wing", "is_active": True},
]


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def main(event, context=None):
    """
    Function to return a list of available buildings for delivery.
    This can be called by the frontend to populate the building selection dropdown.
    """
    status_code = 200
    response = {
        "error": False,
        "success": True,
        "message": "",
        "data": {"buildings": []},
    }

    try:
        # Get query parameters (if any)
        query_params = event.get("queryStringParameters", {}) or {}

        # Option to filter by active status
        active_only = query_params.get("active_only", "true").lower() == "true"

        # Filter buildings if needed
        if active_only:
            filtered_buildings = [b for b in BUILDINGS if b["is_active"]]
        else:
            filtered_buildings = BUILDINGS

        # Return the buildings
        response["data"]["buildings"] = filtered_buildings
        response["message"] = f"Found {len(filtered_buildings)} buildings"

    except Exception as e:
        logger.error(f"Error retrieving buildings: {str(e)}")
        status_code = 500
        response.update(
            {"error": True, "success": False, "message": "Failed to retrieve buildings"}
        )

    return make_response(status_code, response)


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def handler(event, context):
    return main(event, context)
