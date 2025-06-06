import json
from os import getenv
from time import time
from uuid import uuid4
from typing import Optional, List

import boto3
from aws_lambda_powertools.utilities import parameters
from pydantic import BaseModel, validator, Field
from utils import handle_exceptions, logger, make_response

# Environment variables
STAGE = getenv("STAGE")
APP_NAME = getenv("APP_NAME")

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


class ProductSchema(BaseModel):
    food_name: str = Field(..., min_length=2, max_length=100)
    description: str = Field(..., min_length=10, max_length=500)
    price: int = Field(..., gt=0)
    image: str = Field(..., regex=r"^https?://")
    is_available: bool = True
    preparation_time: int = Field(..., gt=0, description="Preparation time in minutes")
    category: str
    complementary_products: Optional[List[str]] = Field(
        default_factory=list,
        description="List of product IDs that pair well with this product. "
        "All categories allowed (including main+main combinations)",
    )

    @validator("category")
    def validate_category(cls, v):
        allowed = ["main_dish", "side_dish", "protein", "drink", "snack"]
        if v not in allowed:
            raise ValueError(f"Category must be one of: {allowed}")
        return v

    @validator("complementary_products")
    def validate_complementary_products(cls, v):
        if v is None:
            return []
        if len(v) > 15:
            raise ValueError("Maximum of 15 complementary products allowed")
        return v


class BulkProductSchema(BaseModel):
    products: List[ProductSchema]

    @validator("products")
    def validate_products(cls, v):
        if not v:
            raise ValueError("At least one product must be provided")
        if len(v) > 25:  # Limit bulk uploads to prevent timeouts
            raise ValueError("Maximum of 25 products allowed per bulk upload")
        return v


def validate_complementary_products_batch(products_list, vendor_user_id, table):
    """Validate complementary products for all products in batch"""
    # Collect all unique complementary product IDs
    all_comp_ids = set()
    for product in products_list:
        if product.get("complementary_products"):
            all_comp_ids.update(product["complementary_products"])

    if not all_comp_ids:
        return {}

    # Batch get all complementary products
    keys = [{"pk": "Product", "sk": pid} for pid in all_comp_ids]
    batch_response = (
        db.batch_get_item(RequestItems={table.name: {"Keys": keys}})
        .get("Responses", {})
        .get(table.name, [])
    )

    # Create mapping and filter valid products
    valid_comp_map = {}
    for item in batch_response:
        if item.get("vendor_id") == f"Vendor#{vendor_user_id}":
            valid_comp_map[item["sk"]] = item

    return valid_comp_map


def get_suggested_complements(vendor_user_id, table, limit=5):
    """Get suggested complementary products for main dishes"""
    try:
        complements = table.query(
            IndexName="gsi1",
            KeyConditionExpression="gsi1pk = :vendor",
            ExpressionAttributeValues={
                ":vendor": f"Vendor#{vendor_user_id}",
                ":cat1": "side_dish",
                ":cat2": "protein",
                ":cat3": "drink",
                ":cat4": "snack",
                ":available": True,
            },
            Limit=limit * 2,  # Get more to filter later
            ScanIndexForward=False,
            FilterExpression="category IN (:cat1, :cat2, :cat3, :cat4) AND is_available = :available",
        ).get("Items", [])

        # Prioritize side dishes
        side_dishes = [item for item in complements if item["category"] == "side_dish"]
        other_complements = [
            item for item in complements if item["category"] != "side_dish"
        ]

        suggested = (side_dishes[:3] if side_dishes else []) + other_complements[
            : limit - len(side_dishes[:3])
        ]
        return [item["sk"] for item in suggested[:limit]]

    except Exception as e:
        logger.error(f"Error getting suggested complements: {str(e)}")
        return []


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

        # Validate the payload structure
        try:
            if isinstance(body, list):
                # Handle direct array of products
                validated_payload = BulkProductSchema(products=body)
            elif isinstance(body, dict) and "products" in body:
                # Handle object with products array
                validated_payload = BulkProductSchema(**body)
            else:
                raise ValueError(
                    "Invalid payload structure. Expected array of products or object with 'products' key"
                )

            logger.info(
                f"Validated {len(validated_payload.products)} products for bulk upload"
            )
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

        # Get vendor information
        vendor = table.get_item(Key={"pk": "Vendor", "sk": f"Vendor#{user_id}"}).get(
            "Item"
        )
        if not vendor:
            response["message"] = "Complete registration to become a vendor"
            return make_response(status_code, response)

        timestamp = int(time())
        successful_uploads = []
        failed_uploads = []

        # Convert products to dictionaries for processing
        products_list = [product.dict() for product in validated_payload.products]

        # Validate all complementary products in batch
        valid_comp_map = validate_complementary_products_batch(
            products_list, user_id, table
        )

        # Get suggested complements for main dishes without complements
        suggested_complements = get_suggested_complements(user_id, table)

        # Prepare all product payloads
        product_payloads = []
        product_summaries = []

        for i, product_data in enumerate(products_list):
            try:
                product_id = f"Product#{vendor.get('sk')}#{uuid4()}"

                # Build product payload
                product_payload = product_data.copy()
                product_payload.update(
                    {
                        "pk": "Product",
                        "sk": product_id,
                        "gsi1pk": f"Vendor#{user_id}",
                        "gsi1sk": f"Product#{product_payload['category']}",
                        "vendor_name": vendor.get("business_name"),
                        "vendor_id": f"Vendor#{user_id}",
                        "user_id": user_id,
                        "created_at": timestamp,
                        "updated_at": timestamp,
                        "is_active": True,
                    }
                )

                # Handle complementary products
                if product_payload.get("complementary_products"):
                    valid_products = []
                    for comp_id in product_payload["complementary_products"]:
                        if comp_id in valid_comp_map:
                            valid_products.append(comp_id)
                            # Log unusual combinations
                            comp_product = valid_comp_map[comp_id]
                            if (
                                product_payload["category"] == "main_dish"
                                and comp_product.get("category") == "main_dish"
                            ):
                                logger.info(
                                    f"Main dish combo: {product_id} + {comp_id}"
                                )
                        else:
                            logger.warning(f"Invalid complementary product: {comp_id}")

                    product_payload["complementary_products"] = valid_products

                # Auto-suggest complements for main dishes without any
                if (
                    product_payload["category"] == "main_dish"
                    and not product_payload.get("complementary_products")
                    and suggested_complements
                ):
                    product_payload["complementary_products"] = suggested_complements[
                        :3
                    ]

                # Create product summary for vendor record
                product_summary = {
                    "product_id": product_id,
                    "food_name": product_payload["food_name"],
                    "category": product_payload["category"],
                    "price": product_payload["price"],
                    "is_available": product_payload["is_available"],
                    "created_at": timestamp,
                }

                product_payloads.append(product_payload)
                product_summaries.append(product_summary)

            except Exception as e:
                logger.error(f"Error preparing product {i}: {str(e)}")
                failed_uploads.append(
                    {
                        "product_index": i,
                        "product": product_data,
                        "error": f"Preparation failed: {str(e)}",
                    }
                )

        if not product_payloads:
            return make_response(
                400,
                {
                    "error": True,
                    "success": False,
                    "message": "No valid products to upload",
                    "data": {"failed_uploads": failed_uploads},
                },
            )

        # Batch write products and update vendor
        try:
            # Use batch write for efficiency (max 25 items per batch)
            with table.batch_writer() as batch:
                for product_payload in product_payloads:
                    batch.put_item(Item=product_payload)

            # Update vendor record with new products
            try:
                table.update_item(
                    Key={"pk": "Vendor", "sk": f"Vendor#{user_id}"},
                    UpdateExpression="SET product_count = if_not_exists(product_count, :zero) + :inc, updated_at = :timestamp ADD products :product_summaries",
                    ExpressionAttributeValues={
                        ":inc": len(product_payloads),
                        ":zero": 0,
                        ":timestamp": timestamp,
                        ":product_summaries": {
                            json.dumps(summary) for summary in product_summaries
                        },
                    },
                )
                logger.info(f"Vendor updated with {len(product_payloads)} new products")
            except Exception as vendor_update_error:
                logger.error(
                    f"Failed to update vendor record: {str(vendor_update_error)}"
                )
                # Products were created successfully, so we continue

            # Mark successful uploads
            for i, payload in enumerate(product_payloads):
                successful_uploads.append(
                    {
                        "product_id": payload["sk"],
                        "food_name": payload["food_name"],
                        "category": payload["category"],
                        "complementary_products": payload.get(
                            "complementary_products", []
                        ),
                    }
                )

        except Exception as batch_error:
            logger.error(f"Batch write failed: {str(batch_error)}")
            # Fallback to individual writes
            for i, product_payload in enumerate(product_payloads):
                try:
                    table.put_item(Item=product_payload)
                    successful_uploads.append(
                        {
                            "product_id": product_payload["sk"],
                            "food_name": product_payload["food_name"],
                            "category": product_payload["category"],
                            "complementary_products": product_payload.get(
                                "complementary_products", []
                            ),
                        }
                    )
                except Exception as individual_error:
                    logger.error(
                        f"Individual write failed for product {i}: {str(individual_error)}"
                    )
                    failed_uploads.append(
                        {
                            "product_index": i,
                            "product": products_list[i],
                            "error": f"Write failed: {str(individual_error)}",
                        }
                    )

            # Update vendor count for successful uploads only
            if successful_uploads:
                try:
                    successful_summaries = [
                        {
                            "product_id": item["product_id"],
                            "food_name": item["food_name"],
                            "category": item["category"],
                            "price": next(
                                p["price"]
                                for p in product_payloads
                                if p["sk"] == item["product_id"]
                            ),
                            "is_available": next(
                                p["is_available"]
                                for p in product_payloads
                                if p["sk"] == item["product_id"]
                            ),
                            "created_at": timestamp,
                        }
                        for item in successful_uploads
                    ]

                    table.update_item(
                        Key={"pk": "Vendor", "sk": f"Vendor#{user_id}"},
                        UpdateExpression="SET product_count = if_not_exists(product_count, :zero) + :inc, updated_at = :timestamp ADD products :product_summaries",
                        ExpressionAttributeValues={
                            ":inc": len(successful_uploads),
                            ":zero": 0,
                            ":timestamp": timestamp,
                            ":product_summaries": {
                                json.dumps(summary) for summary in successful_summaries
                            },
                        },
                    )
                except Exception as fallback_vendor_error:
                    logger.error(
                        f"Fallback vendor update failed: {str(fallback_vendor_error)}"
                    )

        # Prepare response
        total_processed = len(successful_uploads) + len(failed_uploads)
        success_rate = (
            len(successful_uploads) / total_processed if total_processed > 0 else 0
        )

        response.update(
            {
                "error": len(failed_uploads) > 0,
                "success": len(successful_uploads) > 0,
                "message": f"Bulk upload processed: {len(successful_uploads)} successful, {len(failed_uploads)} failed",
                "data": {
                    "successful_uploads": successful_uploads,
                    "failed_uploads": failed_uploads,
                    "summary": {
                        "total_processed": total_processed,
                        "successful_count": len(successful_uploads),
                        "failed_count": len(failed_uploads),
                        "success_rate": f"{success_rate:.2%}",
                    },
                },
            }
        )

        # Set appropriate status code
        if len(successful_uploads) > 0 and len(failed_uploads) == 0:
            status_code = 200  # All successful
        elif len(successful_uploads) > 0:
            status_code = 207  # Partial success
        else:
            status_code = 400  # All failed

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
