"""
Test the lambda_functions authorizers, with good and bad tokens.

Run this file directly in PyCharm to debug the authorizer
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
    Add attributes here if the authorizer references them.
    """
    function_name: str
    memory_limit_in_mb: int = 128
    invoked_function_arn: str = ""
    aws_request_id: str = "local-debug-request"

    def __post_init__(self):
        if not self.invoked_function_arn:
            self.invoked_function_arn = (
                f"arn:aws:lambda:local:0:function:{self.function_name}"
            )


def build_token_event(token: str, method_arn: str | None = None) -> dict:
    """
    Construct a representative API Gateway authorizer event.
    """
    return {
        # For TOKEN authorizer (rather than REQUEST authorizer.)
        "type": "TOKEN",
        "authorizationToken": token,
        "methodArn": method_arn
                     or "arn:aws:execute-api:us-east-1:111111111111:example/prod/GET/resource"
    }

def run_authorizer(module_name: str, event: dict):
    """
    Import and invoke a Lambda authorizer module by name.
    """
    print(f"\n=== Running {module_name}.lambda_handler ===")
    #print(f"Event:\n{json.dumps(event, indent=2)}")

    module = importlib.import_module(f"lambda_functions.{module_name}")
    handler = getattr(module, "lambda_handler")

    context = MockLambdaContext(function_name=module_name)

    result = handler(event, context)

    # print(f"\nResult:\n{json.dumps(result, indent=2)}")
    return result

def assert_policy_effect(authorizer_result:dict, expected_effect:str)->None:
    assert('policyDocument' in authorizer_result)
    assert('Statement' in authorizer_result['policyDocument'])
    assert(len(authorizer_result['policyDocument']['Statement'])>0)
    assert('Effect' in authorizer_result['policyDocument']['Statement'][0])
    assert(authorizer_result['policyDocument']['Statement'][0]['Effect'] == expected_effect)
    print(  f"\u2714"
            f" Read Authorizer successfully got"
            f" {expected_effect}"
            f" policy effect expected for token.")

def main():
    # Replace with:
    #  - a real Globus token
    #  - or the internal process secret
    read_write_admin_token = "Bearer AgBKBbPN5oKwgdPB635pOeVWW2rGGYeWJw1v0xXGDdgbk28WyEHyCBdqmvJXVjDWWDBeBpyQpO3omOcQernQlSn44v"
    phony_token =            "Bearer xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    expectation_dict = {
        read_write_admin_token: {
            'read': 'Allow',
            'admin': 'Allow',
            'create': 'Allow'
        },
        phony_token: {
            'read': 'Deny',
            'admin': 'Deny',
            'create': 'Deny'
        }
    }

    DONOR_WITH_DESCENDANTS = 'HBM846.QDZK.947'
    for token in expectation_dict.keys():
        # ---- Read authorizer ----
        read_group_authorizer_modern_arn =  f"arn:aws:execute-api:us-east-1:450834107946:0gwixh7ht0/*/GET/descendants/" \
                                            f"{DONOR_WITH_DESCENDANTS}"

        read_group_authorizer_event = build_token_event(token=token
                                                        , method_arn=read_group_authorizer_modern_arn)
        result = run_authorizer(module_name="read_group_authorizer"
                                , event=read_group_authorizer_event)
        assert_policy_effect(   authorizer_result=result
                                , expected_effect=expectation_dict[token]['read'])

        # ---- Data admin authorizer ----
        data_admin_group_authorizer_modern_arn = f"arn:aws:execute-api:us-east-1:450834107946:0gwixh7ht0/*/DELETE/flush-all-cache"

        data_admin_group_authorizer_event = build_token_event(  token=token
                                                                , method_arn=data_admin_group_authorizer_modern_arn)
        result = run_authorizer(module_name="data_admin_group_authorizer"
                                , event=data_admin_group_authorizer_event)
        assert_policy_effect(   authorizer_result=result
                                , expected_effect=expectation_dict[token]['admin'])

        # ---- Create authorizer ----
        create_group_authorizer_modern_arn =    f"arn:aws:execute-api:us-east-1:450834107946:0gwixh7ht0/*/POST/entities/donor"

        create_group_authorizer_event = build_token_event(token=token
                                                        , method_arn=create_group_authorizer_modern_arn)
        result = run_authorizer(module_name="create_group_authorizer"
                                , event=create_group_authorizer_event)
        assert_policy_effect(   authorizer_result=result
                                , expected_effect=expectation_dict[token]['create'])

if __name__ == "__main__":
    main()
