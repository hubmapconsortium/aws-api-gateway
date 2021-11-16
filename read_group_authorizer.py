import os
import logging
from flask import Response

# # HuBMAP commons
from hubmap_commons.hm_auth import AuthHelper

# To correctly use the logging library in the AWS Lambda context, we need to 
# set the log-level for the root-logger
logging.getLogger().setLevel(logging.DEBUG)

# Set logging format and level (default is warning)
# All the API logging is forwarded to the uWSGI server and gets written into the log file `uwsgi-hubmap-auth.log`
# Log rotation is handled via logrotate on the host system with a configuration file
# Do NOT handle log file and rotation via the Python logging to avoid issues with multi-worker processes
logging.basicConfig(format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s', level=logging.DEBUG, datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)

# Load environment variables
GLOBUS_APP_CLIENT_ID = os.environ['GLOBUS_APP_CLIENT_ID']
GLOBUS_APP_CLIENT_SECRET = os.environ['GLOBUS_APP_CLIENT_SECRET']
HUBMAP_READ_GROUP_UUID = os.environ['HUBMAP_READ_GROUP_UUID']

# Initialize AuthHelper class and ensure singleton
try:
    if AuthHelper.isInitialized() == False:
        auth_helper_instance = AuthHelper.create(GLOBUS_APP_CLIENT_ID, GLOBUS_APP_CLIENT_SECRET)

        logger.info("Initialized AuthHelper class successfully :)")
    else:
        auth_helper_instance = AuthHelper.instance()
except Exception:
    msg = "Failed to initialize the AuthHelper class"
    # Log the full stack trace, prepend a line with our message
    logger.exception(msg)


def lambda_handler(event, context):
    token = event['authorizationToken']
    method_arn = event['methodArn']
    
    logger.debug("Client token: " + token)
    logger.debug("Method ARN: " + method_arn)

    # The principal user identifier associated with the token
    principal_id = "default_user|a1b2c3d4"

    # you can send a 401 Unauthorized response to the client by failing like so:
    #raise Exception('Unauthorized')

    # if the token is valid, a policy must be generated which will allow or deny access to the client
    # depending on your use case, you might store policies in a DB, or generate them on the fly
    # if access is denied, the client will recieve a 403 Access Denied response
    # if access is allowed, API Gateway will proceed with the backend integration configured on the method that was called
    # keep in mind, the policy is cached for 5 minutes by default (TTL is configurable in the authorizer)
    # and will apply to subsequent calls to any method/resource in the RestApi made with the same token
    
    effect = 'Deny'
    try:
        status_code = api_access_allowed(token, HUBMAP_READ_GROUP_UUID)
        
        logger.debug(f'Resulting status code: {status_code}')
        if status_code == 200:
            # Get the principal user identifier associated with the token
            principal_id = get_user_sub(token)
            effect = 'Allow'
    except Exception as e:
        logger.exception(e)
        raise Exception(e)
        
    policy = AuthPolicy(principal_id, effect, method_arn)

    # Finally, build the policy
    authResponse = policy.build()
 
    """ Commented out for now
    # new! -- add additional key-value pairs associated with the authenticated principal
    # these are made available by APIGW like so: $context.authorizer.<key>
    # additional context is cached
    context = {
        'key': 'value', # $context.authorizer.key -> value
        'number' : 1,
        'bool' : True
    }
    # context['arr'] = ['foo'] <- this is invalid, APIGW will not accept it
    # context['obj'] = {'foo':'bar'} <- also invalid
 
    authResponse['context'] = context
    """
    
    return authResponse

#=========================================================================

# Check if access to the given endpoint item is allowed
# Also check if the globus token associated user is a member of the specified group associated with the endpoint item
def api_access_allowed(token, target_group_uuid):
    # Returns one of the following codes
    ok = 200
    unauthorized = 401
    forbidden = 403
 
    try:
        # Check if using modified version of the globus app secret as internal token
        if is_secrect_token(token):
            return ok
        
        # Make sure the given token is valid
        if is_valid_token(token):
            # Further validate the group
                if user_belongs_to_target_group(token, target_group_uuid):
                    return ok
                
                return forbidden
            
        return unauthorized
    except Exception as e:
            logger.exception(e)
            raise
    

# Always pass through the requests with using modified version of the globus app secret as internal token
def is_secrect_token(token):
    secrect_token = auth_helper_instance.getProcessSecret()

    if token == secrect_token:
        return True

    return False


# Validate the provided token
def is_valid_token(token):
    # Check if the parased token is invalid or expired
    # Set the second paremeter as False to skip groups check
    user_info_dict = auth_helper_instance.getUserInfo(token, False)

    if isinstance(user_info_dict, Response):
        msg = user_info_dict.get_data().decode()
        # Log the full stack trace, prepend a line with our message
        logger.exception(msg)

        return False
    
    return True


"""
    A dict containing all the user info
    {
        "scope": "urn:globus:auth:scope:nexus.api.globus.org:groups",
        "name": "First Last",
        "iss": "https://auth.globus.org",
        "client_id": "21f293b0-5fa5-4ee1-9e0e-3cf88bd70114",
        "active": True,
        "nbf": 1603761442,
        "token_type": "Bearer",
        "aud": ["nexus.api.globus.org", "21f293b0-5fa5-4ee1-9e0e-3cf88bd70114"],
        "iat": 1603761442,
        "dependent_tokens_cache_id": "af2d5979090a97536619e8fbad1ebd0afa875c880a0d8058cddf510fc288555c",
        "exp": 1603934242,
        "sub": "c0f8907a-ec78-48a7-9c85-7da995b05446",
        "email": "email@pitt.edu",
        "username": "username@pitt.edu",
        "hmscopes": ["urn:globus:auth:scope:nexus.api.globus.org:groups"],
    }
"""
def get_user_sub(token):
    # Check if the parased token is invalid or expired
    # Set the second paremeter as False to skip groups check
    user_info_dict = auth_helper_instance.getUserInfo(token, False)

    if isinstance(user_info_dict, Response):
        msg = user_info_dict.get_data().decode()
        # Log the full stack trace, prepend a line with our message
        logger.exception(msg)

        return False
    
    return user_info_dict['sub']
    
    
# Check if the user belongs to the target Globus group
def user_belongs_to_target_group(token, target_group_uuid):
    # The second argument indicates to get the groups information
    user_info_dict = auth_helper_instance.getUserInfo(token, True)

    # Validate token again in case it has become invalid or expired
    if isinstance(user_info_dict, Response):
        msg = user_info_dict.get_data().decode()
        # Log the full stack trace, prepend a line with our message
        logger.exception(msg)

        return False

    # Use the new key rather than the 'hmgroupids' which will be deprecated
    # 'group_membership_ids' is available only from test-release branch of commons
    #user_group_ids = user_info_dict['group_membership_ids']
    user_group_ids = user_info_dict['hmgroupids']
    
    for group_id in user_group_ids:
        if group_id == target_group_uuid:
            return True

    return False

#=========================================================================

# https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-lambda-authorizer-output.html
# A Lambda authorizer function's output is a dictionary-like object, which must include 
# the principal identifier (principalId) and a policy document (policyDocument) containing a list of policy statements.
class AuthPolicy(object):
    # The principal used for the policy, this should be a unique identifier for the end user
    principal_id = ""

    # The policy version used for the evaluation. This should always be '2012-10-17'
    version = "2012-10-17"
    
    effect = ""
    
    method_arn = ""

    def __init__(self, principal_id, effect, method_arn):
        self.principal_id = principal_id
        self.effect = effect
        self.method_arn = method_arn

    def build(self):
        policy = {
            'principalId' : self.principal_id,
            'policyDocument' : {
                'Version' : self.version,
                'Statement' : [
                    {
                        'Action': 'execute-api:Invoke',
                        'Effect': self.effect,
                        'Resource': self.method_arn
                    }
                ]
            }
        }

        return policy

