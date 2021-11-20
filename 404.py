import json

# Simply returns 404 response on any unmatched resources
# - Add an `ANY` method to the root API that proxy's to this Lambda
# - Add a `/{proxy+}/ANY` method to the root API that proxy's to this Lambda
def lambda_handler(event, context):
    return {
        'statusCode': 404,
        'body': json.dumps('Not Found')
    }
