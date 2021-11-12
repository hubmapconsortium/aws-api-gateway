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
    principal_id = "user|a1b2c3d4"

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
        if api_access_allowed(token, HUBMAP_READ_GROUP_UUID):
            effect = 'Allow'
    except Exception:
        raise Exception('Unauthorized')
        
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
    # Check if using modified version of the globus app secret as internal token
    if is_secrect_token(token):
        return True

    try:
        if user_belongs_to_target_group(token, target_group_uuid):
            return True
    except Exception:
        raise Exception('Unauthorized')
    
    return False
    

# Always pass through the requests with using modified version of the globus app secret as internal token
def is_secrect_token(token):
    secrect_token = auth_helper_instance.getProcessSecret()

    if token == secrect_token:
        return True

    return False


# Check if the user belongs to the target Globus group
def user_belongs_to_target_group(token, target_group_uuid):
    # The second argument indicates to get the groups information
    user_info_dict = auth_helper_instance.getUserInfo(token, True)

    if isinstance(user_info_dict, Response):
        msg = "The given token is expired or invalid"
        # Log the full stack trace, prepend a line with our message
        logger.exception(msg)

        raise Exception('Unauthorized')

    # Use the new key rather than the 'hmgroupids' which will be deprecated
    # 'group_membership_ids' is available only from test-release branch of commons
    #user_group_ids = user_info_dict['group_membership_ids']
    user_group_ids = user_info_dict['hmgroupids']
    
    for group_id in user_group_ids:
        if group_id == target_group_uuid:
            return True

    return False

#=========================================================================

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

