from os import getenv
import json
import re
import uuid
import base64
import boto3
from botocore.client import Config
from datetime import datetime
from enum import Enum
from aws_lambda_powertools.utilities import parameters
from pydantic import BaseModel
from utils import (
    make_response,
    handle_exceptions,
    logger,
)

# Environment variables
STAGE = getenv("STAGE")
APP_NAME = getenv("APP_NAME")

s3 = boto3.client("s3", config=Config(signature_version="s3v4"))
bucket_name = "chowtap-media"
allowed_extentions = ["jpg", "jpeg", "png", "mp4"]

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


class FolderEnum(str, Enum):
    PROFILE = "profile"


class InputSchema(BaseModel):
    contents: list[str]
    folder: FolderEnum | None = None

    class Config:
        use_enum_values = True


def admin_get_user(cognito_client, user_pool_id, username):
    try:
        logger.info(
            f"Calling admin_get_user with pool_id={user_pool_id}, username={username}"
        )
        response = cognito_client.admin_get_user(
            UserPoolId=user_pool_id, Username=username
        )
        data = {
            attr.get("Name"): attr.get("Value") for attr in response["UserAttributes"]
        }
        return data
    except Exception as e:
        logger.error(f"Error in admin_get_user: {str(e)}")
        raise


def update_ddb_record(sub):
    user = admin_get_user(client, POOL_ID, sub)
    user.update({"pk": "user", "sk": f"user_{sub}"})
    table.put_item(Item=user)


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
            payload = InputSchema(**body)
            logger.info(f"payload - {payload}")
        except Exception as e:
            logger.error(f"Invalid payload: {str(e)}")
            return make_response(
                400, {"error": True, "success": False, "message": str(e), "data": None}
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

        file_contents = payload.get("contents", [])
        markers = ":(.*?);"
        now = int(datetime.now().timestamp() * 1000)
        if not file_contents:
            response = {"success": False, "error": True, "message": "No files provided"}
            return make_response(status_code, response)
        urls = []
        for file_content in file_contents:
            unique_id = str(uuid.uuid4())
            file_details = str(file_content.split(",")[0])
            mime_type = re.search(markers, file_details).group(1)
            logger.info(mime_type)
            file_ext = mime_type.split("/")[1]
            if file_ext not in allowed_extentions:
                response = {
                    "success": False,
                    "error": True,
                    "message": "Unsupported file type",
                }
                return make_response(status_code, response)
            file_name = f"{unique_id}-{now}.{file_ext}"
            file_content = str(file_content.split(",")[1])
            file_content = base64.b64decode(file_content)
            file_url = None
            if not payload.get("folder"):
                folder = f"vecul/{user_id}/images"
            else:
                folder = f"vecul/{user_id}/{payload.folder}"
            domain = "https://d2nie45f5nhxu7.cloudfront.net"
            file_url = f"{domain}/{folder}/{file_name}"
            s3.put_object(
                Body=file_content,
                Bucket=bucket_name,
                Key=f"{folder}/{file_name}",
                ContentType=mime_type,
                ACL="private",
            )
            urls.append(file_url)
        if payload.get("folder") and payload.folder == "profile":
            client.admin_update_user_attributes(
                UserAttributes=[{"Name": "picture", "Value": urls[0]}],
                UserPoolId=POOL_ID,
                Username=claims["sub"],
            )
            update_ddb_record(user_id)
        status_code = 200
        response["data"] = urls
        response["error"], response["success"] = False, True
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
