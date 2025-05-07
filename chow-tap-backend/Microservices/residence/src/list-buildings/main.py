from os import getenv
from utils import make_response, handle_exceptions, logger

# Environment variables
STAGE = getenv("STAGE")
APP_NAME = getenv("APP_NAME")

# List of available buildings for delivery
BUILDINGS = [
    {"id": "bldg-001", "name": "ADMIN", "is_active": True},
    {"id": "bldg-002", "name": "ATUWASE HALL", "is_active": True},
    {"id": "bldg-003", "name": "BADEJO HALL", "is_active": True},
    {"id": "bldg-004", "name": "CHAPEL", "is_active": True},
    {"id": "bldg-005", "name": "CLINIC", "is_active": True},
    {"id": "bldg-006", "name": "CFM MALE HOSTEL", "is_active": True},
    {"id": "bldg-007", "name": "COLCOM", "is_active": True},
    {"id": "bldg-008", "name": "COLHUM", "is_active": True},
    {"id": "bldg-009", "name": "COLNAS", "is_active": True},
    {"id": "bldg-010", "name": "COSMAS", "is_active": True},
    {"id": "bldg-011", "name": "FAROMBI HALL", "is_active": True},
    {"id": "bldg-012", "name": "FAYE CURTIS 1 HALL", "is_active": True},
    {"id": "bldg-013", "name": "FAYE CURTIS 2 HALL", "is_active": True},
    {"id": "bldg-014", "name": "FWI HALL", "is_active": True},
    {"id": "bldg-015", "name": "GLENN BURRIS HALL", "is_active": True},
    {"id": "bldg-016", "name": "JEHOVAH SHAMMAH HALL", "is_active": True},
    {"id": "bldg-017", "name": "LIBRARY", "is_active": True},
    {"id": "bldg-018", "name": "NURSING COLLEGE", "is_active": True},
    {"id": "bldg-019", "name": "ODUNAIKE HALL", "is_active": True},
    {"id": "bldg-020", "name": "SPORT COMPLEX", "is_active": True},
    {"id": "bldg-021", "name": "VC's LODGE", "is_active": True},
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
