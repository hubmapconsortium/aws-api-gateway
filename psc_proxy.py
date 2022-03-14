import os
import json
import logging
import requests
# Don't confuse urllib (Python native library) with urllib3 (3rd-party library, requests also uses urllib3)
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# To correctly use the logging library in the AWS Lambda context, we need to 
# set the log-level for the root-logger
logging.getLogger().setLevel(logging.DEBUG)

# Set logging format and level (default is warning)
# All the API logging is forwarded to the uWSGI server and gets written into the log file `uwsgi-hubmap-auth.log`
# Log rotation is handled via logrotate on the host system with a configuration file
# Do NOT handle log file and rotation via the Python logging to avoid issues with multi-worker processes
logging.basicConfig(format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s', level=logging.DEBUG, datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)

# Suppress InsecureRequestWarning warning when requesting status on https with ssl cert verify disabled
requests.packages.urllib3.disable_warnings(category = InsecureRequestWarning)

def lambda_handler(event, context):
    # logger.debug(event)
    
    request_method = event['httpMethod'].upper()
    # Remove leading slash if any
    path = event['path'].lstrip('/')
    request_headers = event['headers']
    request_body = event['body']
    stage = event['requestContext']['stage'].upper()
    
    target_api_stage = f'INGEST_API_{stage}'

    # Remove trailing slash in case the environment variable has one
    base_url = os.environ[target_api_stage].rstrip('/')
    target_url = f'{base_url}/{path}'
    
    logger.debug(f'Proxy target: {request_method} {target_url}')

    response = None
    # Disable ssl certificate verification for all requests
    if request_method == 'GET':
        # AWS API Gateway doesn't support request body on GET
        response = requests.get(url = target_url, headers = request_headers, verify = False) 
    elif request_method == 'POST':
        response = requests.post(url = target_url, headers = request_headers, data = request_body, verify = False)
    elif request_method == 'PUT':
        response = requests.put(url = target_url, headers = request_headers, data = request_body, verify = False)
    elif request_method == 'OPTIONS':
        response = requests.options(url = target_url, headers = request_headers, verify = False)
    else:
        # Won't ever happen since we have API Gateway?
        logger.error(f'Unsupported HTTP method {request_method}')
        
    return {
        'statusCode': response.status_code,
        'body': response.text
    }

