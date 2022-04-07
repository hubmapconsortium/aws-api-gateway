import os
import logging
from flask import Response

# # HuBMAP commons
from hubmap_commons.hm_auth import AuthHelper
from hubmap_commons import globus_groups

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
HUBMAP_DATA_ADMIN_GROUP_UUID = os.environ['HUBMAP_DATA_ADMIN_GROUP_UUID']

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


# When this lambda function is invoked, it runs this handler method (we use the default name)
# The function handler name can be changed in the Lambda console, on the Runtime settings pane
def lambda_handler(event, context):
    # Default principal user identifier to be used
    principal_id = "default_user|a1b2c3d4"
    
    # Default policy effect
    effect = 'Deny'
    
    # The string value of $context.authorizer.key used by API Gateway reponse 401/403 template:
    # { "message": "$context.error.message", "hint": "$context.authorizer.key" }
    context_authorizer_key_value = ''
    
    # 'authorizationToken' and 'methodArn' are specific to the API Gateway Authorizer lambda function
    auth_header_value = event['authorizationToken']
    method_arn = event['methodArn']
    
    logger.debug("Incoming authorizationToken: " + auth_header_value)
    logger.debug("Incoming methodArn: " + method_arn)
    
    # A bit validation on the header value
    if not auth_header_value:
        context_authorizer_key_value = 'Empty value of Authorization header'
    elif not auth_header_value.upper().startswith('BEARER '):
        context_authorizer_key_value = 'Missing Bearer scheme in Authorization header value'
    else:
        # Parse the actual globus token
        token = auth_header_value[6:].strip()
        
        logger.debug("Parsed Globus token: " + token)
    
        # you can send a 401 Unauthorized response to the client by failing like so:
        #raise Exception('Unauthorized')
    
        # If the token is valid, a policy (generated on the fly) must be generated which will allow or deny access to the client
        # If access is denied, the client will recieve a 403 Forbidden response
        # if access is allowed, API Gateway will proceed with the backend integration configured on the method that was called
        # Keep in mind, the policy is cached for 5 minutes by default (TTL is configurable in API Gateway -> Authorizer)
        # and will apply to subsequent calls to any method/resource in the REST API made with the same token
        
        try:
            # Check if using modified version of the globus app secret as internal token
            if is_secrect_token(token):
                effect = 'Allow'
            else:
                user_info_dict = get_user_info(token)
                
                logger.debug(f'=======User info=======: {user_info_dict}')
                
                # The user_info_dict is a message str from commons when the token is invalid or expired
                # Otherwise it's a dict on success
                if isinstance(user_info_dict, dict):
                    principal_id = user_info_dict['sub']
                    
                    # Further check if the user belongs to the right group membership
                    user_group_ids = user_info_dict['group_membership_ids']
      
                    logger.debug(f'=======User groups=======: {user_group_ids}')
                    
                    # The HuBMAP-Data-Admin group can also create new entities
                    if user_belongs_to_target_group(user_group_ids, HUBMAP_DATA_ADMIN_GROUP_UUID):
                        effect = 'Allow'
                    else:
                        # Make sure one of the user's groups is a data provider group
                        if user_belongs_to_data_provider_group(user_group_ids):
                            effect = 'Allow'
                        else:
                            context_authorizer_key_value = 'User token is not associated with any data provider groups'
                else:
                    # We use this message in the custom 401 response template
                    context_authorizer_key_value = user_info_dict
        except Exception as e:
            logger.exception(e)
            
            raise Exception(e)
            
    # Finally, build the policy
    policy = AuthPolicy(principal_id, effect, method_arn)
    authResponse = policy.build()
    
    logger.debug(f'=======context_authorizer_key_value=======: {context_authorizer_key_value}')
    
    # Only use the context variable for authorizer when there's 401/403 response
    if context_authorizer_key_value:
        # Add additional key-value pairs associated with the authenticated principal
        # these are made available by API Gateway Responses template with custom 401 and 403 template:
        # { "message": "$context.error.message", "hint": "$context.authorizer.key" } (must be quoted to be valid json object)
        context = {
            'key': context_authorizer_key_value, # $context.authorizer.key -> value
            # numberKey and boolKey are not being used currently
            'numberKey' : 1,
            'boolKey' : True
        }

        # Add the context info to the policy
        authResponse['context'] = context
        
    logger.debug(f'=======authResponse: {authResponse}')
   
    return authResponse


"""
Always pass through the requests with using modified version of the globus app secret as internal token

Parameters
----------
token : str
    The process token based off globus app secret

Returns
-------
bool
    True if the given token is the secret internal token, otherwise False
"""
def is_secrect_token(token):
    result = False
    
    secrect_token = auth_helper_instance.getProcessSecret()

    if token == secrect_token:
        result = True

    logger.debug(f'=======is_secrect_token() result=======: {result}')
    
    return result


"""
User info introspection based on the given globus token

Parameters
----------
token : str
    The parased globus token

Returns
-------
dict or str
    A dict based on the following JSON result of user info on sucess,
    Othereise, an error message if token is invalid or expired
    
    {
       "active":true,
       "token_type":"Bearer",
       "scope":"urn:globus:auth:scope:nexus.api.globus.org:groups",
       "client_id":"21f293b0-5fa5-4ee1-9e0e-3cf88bd70114",
       "username":"zhy19@pitt.edu",
       "name":"Zhou Yuan",
       "email":"ZHY19@pitt.edu",
       "exp":1637513092,
       "iat":1637340292,
       "nbf":1637340292,
       "sub":"c0f8907a-ec78-48a7-9c85-7da995b05446",
       "aud":[
          "nexus.api.globus.org",
          "21f293b0-5fa5-4ee1-9e0e-3cf88bd70114"
       ],
       "iss":"https://auth.globus.org",
       "dependent_tokens_cache_id":"af2d5979090a97536619e8fbad1ebd0afa875c880a0d8058cddf510fc288555c",
       "hmgroupids":[
          "177f92c0-c871-11eb-9a04-a9c8d5e16226",
          "89a69625-99d7-11ea-9366-0e98982705c1",
          "5777527e-ec11-11e8-ab41-0af86edb4424",
          "5bd084c8-edc2-11e8-802f-0e368f3075e8"
       ],
       "group_membership_ids":[
          "177f92c0-c871-11eb-9a04-a9c8d5e16226",
          "89a69625-99d7-11ea-9366-0e98982705c1",
          "5777527e-ec11-11e8-ab41-0af86edb4424",
          "5bd084c8-edc2-11e8-802f-0e368f3075e8"
       ],
       "hmroleids":[],
       "hmscopes":[
          "urn:globus:auth:scope:nexus.api.globus.org:groups"
       ]
    }
"""
def get_user_info(token):
    result = None
    
    # The second argument indicates to get the groups information
    user_info_dict = auth_helper_instance.getUserInfo(token, True)
    
    logger.debug(f'=======get_user_info() user_info_dict=======: {user_info_dict}')

    # The token is invalid or expired when its type is flask.Response
    # Otherwise a dict gets returned
    if isinstance(user_info_dict, Response):
        # Return the error message instead of the dict
        result = user_info_dict.get_data().decode()
    else:
        result = user_info_dict
    
    logger.debug(f'=======get_user_info() result=======: {result}')
    
    return result
    
 
"""
Check if the user belongs to the target Globus group

Parameters
----------
user_group_ids : list
    A list of groups uuids associated with this token

target_group_uuid : str
    The uuid of target group
    
Returns
-------
bool
    True if the given token belongs to the given group, otherwise False
"""
def user_belongs_to_target_group(user_group_ids, target_group_uuid):
    result = False
    
    for group_id in user_group_ids:
        if group_id == target_group_uuid:
            result = True
            break
    
    logger.debug(f'=======user_belongs_to_target_group() result=======: {result}')

    return result
    

"""
Determine if the user is allowed to create new entity by checking if the user
belongs to one of the data provider groups

Parameters
----------
user_group_ids : list
    A list of globus group uuids that the user has access to
Returns
-------
dict
    The group info (group_uuid and group_name)
"""
def user_belongs_to_data_provider_group(user_group_ids):
    result = False

    # Get the globus groups info based on the groups json file in commons package
    globus_groups_info = globus_groups.get_globus_groups_info()
    groups_by_id_dict = globus_groups_info['by_id']

    # A list of data provider uuids
    data_provider_uuids = []
    for uuid_key in groups_by_id_dict:
        if ('data_provider' in groups_by_id_dict[uuid_key]) and groups_by_id_dict[uuid_key]['data_provider']:
            data_provider_uuids.append(uuid_key)

    user_data_provider_uuids = []
    for group_uuid in user_group_ids:
        if group_uuid in data_provider_uuids:
            user_data_provider_uuids.append(group_uuid)

    if len(user_data_provider_uuids) > 0:
        result = True

    logger.debug(f'=======user_belongs_to_data_provider_group() result=======: {result}')

    return result


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

