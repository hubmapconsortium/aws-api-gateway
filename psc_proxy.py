import json
import requests
import logging

# To correctly use the logging library in the AWS Lambda context, we need to 
# set the log-level for the root-logger
logging.getLogger().setLevel(logging.DEBUG)

# Set logging format and level (default is warning)
# All the API logging is forwarded to the uWSGI server and gets written into the log file `uwsgi-hubmap-auth.log`
# Log rotation is handled via logrotate on the host system with a configuration file
# Do NOT handle log file and rotation via the Python logging to avoid issues with multi-worker processes
logging.basicConfig(format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s', level=logging.DEBUG, datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)

def lambda_handler(event, context):
    target_url = 'https://ingest.api.hubmapconsortium.org/'
    user_token = ''
    request_headers = _create_request_headers(user_token)

    # Disable ssl certificate verification
    response = requests.get(url = target_url, headers = request_headers, verify = False) 
    
    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda!')
    }



####################################################################################################
## Internal functions
####################################################################################################

"""
Create a dict of HTTP Authorization header with Bearer token for making calls to uuid-api
Parameters
----------
user_token: str
    The user's globus groups token
Returns
-------
dict
    The headers dict to be used by requests
"""
def _create_request_headers(user_token):
    auth_header_name = 'Authorization'
    auth_scheme = 'Bearer'

    headers_dict = {
        # Don't forget the space between scheme and the token value
        auth_header_name: auth_scheme + ' ' + user_token
    }

    return headers_dict
