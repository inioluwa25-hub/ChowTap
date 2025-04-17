import base64
import hashlib
import hmac
import os

import boto3
from aws_lambda_powertools import Logger

logger = Logger()

# Environment variables
STAGE = os.getenv("STAGE")
APP_NAME = os.getenv("APP_NAME")
POOL_ID = os.getenv("POOL_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")

# AWS client
client = boto3.client("cognito-idp")


def validate_input(email: str, password: str):
    """Validate email and password meet requirements"""
    if not email or "@" not in email:
        raise ValueError("A valid email address is required.")

    if not password:
        raise ValueError("Password is required.")
    if len(password) < 6:
        raise ValueError("Password must be at least 6 characters long.")
    if not any(c.isupper() for c in password):
        raise ValueError("Password must contain at least one capital letter.")
    if not any(c.isdigit() for c in password):
        raise ValueError("Password must contain at least one digit.")
    if not any(c in "@$!%*?&-.,.#`~^()" for c in password):
        raise ValueError("Password must contain at least one special character.")


def get_secret_hash(username: str) -> str:
    """Generate secret hash for Cognito authentication"""
    message = f"{username}{CLIENT_ID}".encode("utf-8")
    secret = CLIENT_SECRET.encode("utf-8")
    digest = hmac.new(secret, msg=message, digestmod=hashlib.sha256).digest()
    return base64.b64encode(digest).decode()


def authenticate_user(email: str, password: str) -> dict:
    """Authenticate user with Cognito and return tokens"""
    try:
        secret_hash = get_secret_hash(email)
        response = client.initiate_auth(
            ClientId=CLIENT_ID,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={
                "USERNAME": email,
                "SECRET_HASH": secret_hash,
                "PASSWORD": password,
            },
        )
        result = response["AuthenticationResult"]

        # Verify token expiration is reasonable (between 5 min and 1 day)
        if not 300 <= result["ExpiresIn"] <= 86400:
            logger.warning(f"Unusual token expiration: {result['ExpiresIn']} seconds")

        return result
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        raise


def generate_policy(
    principal_id: str, effect: str, resource: str, context: dict = None
) -> dict:
    """Generate IAM policy for API Gateway authorizer with CORS support"""
    policy = {
        "principalId": principal_id,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {"Action": "execute-api:Invoke", "Effect": effect, "Resource": resource}
            ],
        },
    }

    if context:
        policy["context"] = context
        # Add CORS headers to context
        policy["context"].update(
            {
                "Access-Control-Allow-Origin": "'*'",
                "Access-Control-Allow-Methods": "'DELETE,OPTIONS,GET,HEAD,PATCH,POST,PUT'",
                "Access-Control-Allow-Headers": "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,X-Amz-User-Agent,X-Amzn-Trace-Id'",
            }
        )

    return policy


@logger.inject_lambda_context(log_event=True)
def handler(event, context):
    """Lambda authorizer entry point"""
    logger.info("Authorizer event", extra={"event": event})

    try:
        # Validate environment variables
        if not all([POOL_ID, CLIENT_ID, CLIENT_SECRET]):
            logger.error("Missing required environment variables")
            return generate_policy(None, "Deny", event["methodArn"])

        # Extract credentials from the request
        if "authorizationToken" not in event:
            return generate_policy(
                None,
                "Deny",
                event["methodArn"],
                context={"message": "Authorization header missing"},
            )

        token_parts = event["authorizationToken"].split(" ")
        if len(token_parts) != 2 or token_parts[0].lower() != "basic":
            return generate_policy(
                None,
                "Deny",
                event["methodArn"],
                context={"message": "Invalid Authorization format"},
            )

        # Decode and validate Basic Auth credentials
        try:
            decoded = base64.b64decode(token_parts[1]).decode("utf-8")
            email, password = decoded.split(":", 1)
            validate_input(email, password)
        except Exception as e:
            logger.error(f"Credential decoding error: {str(e)}")
            return generate_policy(
                None,
                "Deny",
                event["methodArn"],
                context={"message": "Invalid credentials format"},
            )

        # Authenticate with Cognito
        auth_result = authenticate_user(email, password)
        user_info = client.get_user(AccessToken=auth_result["AccessToken"])
        user_attributes = {
            attr["Name"]: attr["Value"] for attr in user_info["UserAttributes"]
        }

        # Create policy with context
        return generate_policy(
            principal_id=user_attributes.get("sub"),
            effect="Allow",
            resource=event["methodArn"],
            context={
                "email": email,
                "user_id": user_attributes.get("sub"),
                "tenant_id": user_attributes.get("custom:tenant_id", ""),
                "cognito:username": user_attributes.get("cognito:username", ""),
                "access_token": auth_result["AccessToken"],
                "id_token": auth_result["IdToken"],
                "Access-Control-Allow-Origin": "'*'",
                "Access-Control-Allow-Methods": "'DELETE,OPTIONS,GET,HEAD,PATCH,POST,PUT'",
                "Access-Control-Allow-Headers": "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,X-Amz-User-Agent,X-Amzn-Trace-Id'",
            },
        )

    except client.exceptions.NotAuthorizedException:
        logger.error("Authentication failed: Invalid credentials")
        return generate_policy(
            None, "Deny", event["methodArn"], context={"message": "Invalid credentials"}
        )
    except client.exceptions.UserNotConfirmedException:
        logger.error("Authentication failed: User not confirmed")
        return generate_policy(
            None, "Deny", event["methodArn"], context={"message": "User not confirmed"}
        )
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return generate_policy(
            None,
            "Deny",
            event["methodArn"],
            context={"message": "Internal server error"},
        )
