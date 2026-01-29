"""
Test the lambda_functions non-authorizers.

Local test harness for non-authorizer Lambda functions
invoked via API Gateway proxy integration.

Run this file directly in PyCharm to debug Lambdas
outside of AWS.
"""

import json
import os
import sys
import importlib
from dataclasses import dataclass

# Ensure repo root is on sys.path so lambda_functions imports work
REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, REPO_ROOT)

@dataclass
class MockLambdaContext:
    """
    Minimal stand-in for AWS Lambda context object.
    """
    function_name: str
    memory_limit_in_mb: int = 128
    aws_request_id: str = "local-debug-request"

def build_proxy_event(
    *,
    path: str,
    http_method: str,
    api_id: str,
    stage: str,
    region: str,
    account_id: str,
) -> dict:
    """
    Construct a representative API Gateway *proxy* event.

    NOTE ON ARN DATA
    ----------------
    Non-authorizer Lambdas NEVER receive `methodArn`.

    If your Lambda logic needs to infer ARN-like information,
    it must come from `requestContext`, which is where API
    Gateway exposes:
      - apiId
      - stage
      - resourcePath
      - region
      - accountId

    THIS IS THE ONLY PLACE YOU PROVIDE ARN-RELATED INFORMATION.
    """

    return {
        "resource": "/{proxy+}",
        "path": path,
        "httpMethod": http_method,
        "headers": {},
        "queryStringParameters": None,
        "pathParameters": {
            "proxy": path.lstrip("/")
        },
        "requestContext": {
            "accountId": account_id,
            "region": region,
            "apiId": api_id,
            "stage": stage,
            "resourcePath": "/{proxy+}",
            "httpMethod": http_method,
            "path": path,
            # -----------------------------------------------------------
        },
        "body": None,
        "isBase64Encoded": False,
    }


def run_lambda(module_name: str, event: dict) -> dict:
    """
    Import and invoke a Lambda module by name from lambda_functions.
    """
    print(f"\n=== Running {module_name}.lambda_handler ===")
    # print(f"Event:\n{json.dumps(event, indent=2)}")

    module = importlib.import_module(f"lambda_functions.{module_name}")
    handler = getattr(module, "lambda_handler")

    context = MockLambdaContext(function_name=module_name)

    result = handler(event, context)
    # print(f"\nResult:\n{json.dumps(result, indent=2)}")
    return result


def assert_status(result: dict, expected_status: int) -> None:
    assert "statusCode" in result
    assert result["statusCode"] == expected_status
    print(f"✔ statusCode == {expected_status}")


def assert_body_message(result: dict, expected_substring: str) -> None:
    assert "body" in result
    body = json.loads(result["body"])
    assert expected_substring in body.get("message", "")
    print(f"✔ body contains '{expected_substring}'")


def main():
    # ------------------------------------------------------------------
    # API Gateway identity (EDIT THESE IF YOU NEED REALISTIC ARN VALUES)
    # ------------------------------------------------------------------
    REGION = "us-east-1"
    ACCOUNT_ID = "450834107946"
    API_ID = "0gwixh7ht0"
    STAGE = "prod"
    # ------------------------------------------------------------------

    # ---- search_api_v2 redirect Lambda (307) ----
    search_v2_event = build_proxy_event(
        path="/status",
        http_method="GET",
        region=REGION,
        account_id=ACCOUNT_ID,
        api_id=API_ID,
        stage=STAGE,
    )

    result = run_lambda(
        module_name="search_api_v2",
        event=search_v2_event,
    )

    assert_status(result, 307)
    assert_body_message(result, "Please migrate to use search-api with /v3/ in the base URL")


    # ---- 404 catch-all Lambda ----
    not_found_event = build_proxy_event(
        path="/this/endpoint/does/not/exist",
        http_method="GET",
        region=REGION,
        account_id=ACCOUNT_ID,
        api_id=API_ID,
        stage=STAGE,
    )

    result = run_lambda(
        module_name="404",
        event=not_found_event,
    )

    assert_status(result, 404)
    assert_body_message(result, "Unable to find the requested resource")


if __name__ == "__main__":
    main()
