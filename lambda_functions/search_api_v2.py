import json

# Simply returns 307 response on any resources
# - Add an `ANY` method to the root API that proxy's to this Lambda
# - Add a `/{proxy+}/ANY` method to the root API that proxy's to this Lambda
def lambda_handler(event, context):
    response_body = {
        'message': 'Please migrate to use search-api with /v3/ in the base URL'
    }
    return {
        'statusCode': 307,
        'body': json.dumps(response_body)
    }
