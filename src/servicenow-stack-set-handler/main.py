"""
Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is
furnished to do so.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

This Lambda function creates or updates CloudFormation stackset for provisioning 
AWS Accoutn in ServiceNow. The Lambda function is triggered on receiving Control Tower 
account creation event
"""

import json
import boto3
import botocore
import base64
import traceback
import os
import logging
from time import sleep
from boto3.session import Session
from botocore.exceptions import ClientError
import urllib3
from urllib3.util import parse_url
http = urllib3.PoolManager()

logger = logging.getLogger()
logger.setLevel(logging.INFO)

cloudformation = boto3.client('cloudformation')
s3 = boto3.client('s3')
lambda_client = boto3.client('lambda')
organization_client = boto3.client('organizations')

STACK_SET_ADMIN_ROLE = 'AWSControlTowerStackSetRole'
STACK_SET_EXECUTION_ROLE = 'AWSControlTowerExecution'

SUCCESS = "SUCCESS"
FAILED = "FAILED"

try:
    stack_set_name = os.environ['StackSetName']
    stack_set_regions = os.environ['StackSetRegions'].split(',')
    stack_set_description = os.environ['StackSetDescription']
    stack_template_bucket = os.environ['StackTemplateBucket']
    stack_template_file = os.environ['StackTemplatePrefix']
    servicenow_config_function = os.environ['ServiceNowConfigFunctionName']
    servicenow_role_external_id = os.environ['ServiceNowDiscoveryRoleExternalId']
    enable_servicenow_cloudwatch_intg = os.environ['ServiceNowCloudWatchAlertIntegration']
    servicenow_url = os.environ['ServiceNowEndpointUrl']
    servicenow_creds = os.environ['ServiceNowCreds']
except Exception as e:
    logger.error("Environment variables are missing required fields")
    logger.error(e)
    traceback.print_exc()

def send(event, context, responseStatus, responseData, physicalResourceId=None, noEcho=False):
    """
    Helper function to return response for CloudFormation custom resource

    :param event:
    :param context
    :param responseStatus
    :param responseData
    :param physicalResourceId
    :param noEcho
    :return:
    """

    responseUrl = event['ResponseURL']

    logger.debug(responseUrl)

    responseBody = {}
    responseBody['Status'] = responseStatus
    responseBody['Reason'] = 'See the details in CloudWatch Log Stream: ' + context.log_stream_name
    responseBody['PhysicalResourceId'] = physicalResourceId or context.log_stream_name
    responseBody['StackId'] = event['StackId']
    responseBody['RequestId'] = event['RequestId']
    responseBody['LogicalResourceId'] = event['LogicalResourceId']
    responseBody['NoEcho'] = noEcho
    responseBody['Data'] = responseData

    json_responseBody = json.dumps(responseBody)

    logger.debug("Response body:\n" + json_responseBody)

    headers = {
        'content-type' : '',
        'content-length' : str(len(json_responseBody))
    }

    try:

        response = http.request('PUT',responseUrl,body=json_responseBody.encode('utf-8'),headers=headers)
        print("Status code: " + response.reason)
    except Exception as e:
        print("send(..) failed executing requests.put(..): " + str(e))

def get_secret(secret_name):
    """
    Retrieves the specified secret from secrets manager in json string format

    :param secret_name: Secret manager secret
    :return: Return secret in json format
    """
    region_name = os.environ['StackSetRegions']

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            logger.error("Secrets Manager can't decrypt the protected secret text using the provided KMS key.")
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            logger.error("An error occurred on the server side.")
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            logger.error("Invalid value for a parameter")
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            logger.error("Provided a parameter value is not valid for the current state of the resource")
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            logger.error(f"Unable to find secret with name {secret_name}")
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            return get_secret_value_response['SecretString']
        else:
            return base64.b64decode(get_secret_value_response['SecretBinary'])

def create_stack_instances(stack_set_name, accounts, regions):
    """
    Creates stack instances for the given stack set in the specified accounts and regions

    :param stack_set_name: Name of CloudFormation StackSet to create/update
    :param stack_set_accounts: Accounts were stackset instances should be created
    :param regions: Regions in which stackset instances should be created
    :return:
    """
    resp = None

    logger.info(f'Creating stack instances for accounts: {accounts}')
    resp = cloudformation.create_stack_instances(
        StackSetName=stack_set_name,
        Accounts=accounts,
        Regions=regions,
        OperationPreferences= {
            'FailureTolerancePercentage': 100,
            'MaxConcurrentPercentage': 100
        }
    )
    logger.debug(f"Create stack instance resp: {json.dumps(resp)}")
    operation_id = resp['OperationId']

    ## wait for stack instance creation to complete
    status = 'RUNNING'
    while status == 'RUNNING' or status == 'STOPPING':
        sleep(30)
        resp = cloudformation.describe_stack_set_operation(
            StackSetName=stack_set_name,
            OperationId=operation_id
        )
        status = resp['StackSetOperation']['Status']
        logger.info(f"Stack Set Operation status: {status}")
    if status == 'FAILED':
        logger.error(f"Stack Set Operation failed. Some of the existing accounts may not be provisioned in ServiceNow")
    else:
        logger.info("Stact Set Operation was successful. Done configuring all existing accounts in ServiceNow")

def create_update_stack_set(stack_set_name, stack_set_accounts):
    """
    Creates stack set with the specified accounts

    :param stack_set_name: Name of CloudFormation StackSet to create/update
    :param stack_set_accounts: Accounts were stackset instances should be created
    :return:
    """
    try:
        logger.info("Retrieving ServiceNow API credentials from Secret Manager")
        creds = json.loads(get_secret(servicenow_creds))
    except Exception as e:
        logger.error(f"Error retrieving servicenow credentials from secret manager")
        raise e
    
    resp = None
    stack_set_exists = True
    
    ## Check if stack set exists
    try:
        logger.info(f"Checking if a Stack Set exists with name: {stack_set_name}")
        resp = cloudformation.describe_stack_set(
            StackSetName=stack_set_name
        )
        logger.debug(f"Describe stack set resp: {json.dumps(resp)}")
    except cloudformation.exceptions.StackSetNotFoundException as e:
        logger.info(f"Can't find StackSet with name {stack_set_name}")
        stack_set_exists = False
    except Exception as e:
        logger.error(f"Error while looking up StackSet with name {stack_set_name}, Error: {str(e)}")
        raise e

    if not stack_set_exists:
        client = boto3.client("sts")
        master_account_id = client.get_caller_identity()["Account"]
        stack_set_params = [
            {
                'ParameterKey': 'pMasterAccountId',
                'ParameterValue': master_account_id
            },
            {
                'ParameterKey': 'pExternalId',
                'ParameterValue': servicenow_role_external_id
            }
        ]
        if enable_servicenow_cloudwatch_intg:
            optional_params = [
                {
                    'ParameterKey': 'pEnableCloudWatchAlarmIntegration',
                    'ParameterValue': 'yes'
                },
                {
                    'ParameterKey': 'pServiceNowUrl',
                    'ParameterValue': parse_url(servicenow_url).hostname
                },
                {
                    'ParameterKey': 'pServiceNowEventUserName',
                    'ParameterValue': creds['username']
                },
                {
                    'ParameterKey': 'pServiceNowEventUserPassword',
                    'ParameterValue': creds['password']
                }
            ]
            stack_set_params.extend(optional_params)
        
        logger.info(f"Creating Stack Set {stack_set_name} ...")
        template_url = "https://{}.s3.amazonaws.com/{}".format(stack_template_bucket, stack_template_file)
        logger.info(template_url)
        try: 
            resp = cloudformation.create_stack_set(
                StackSetName=stack_set_name,
                Description=stack_set_description,
                TemplateURL=template_url,
                Parameters=stack_set_params,
                AdministrationRoleARN="arn:aws:iam::{}:role/service-role/{}".format(master_account_id, STACK_SET_ADMIN_ROLE),
                ExecutionRoleName=STACK_SET_EXECUTION_ROLE,
                Capabilities=[
                    "CAPABILITY_NAMED_IAM"
                ]
            )
        except cloudformation.exceptions.NameAlreadyExistsException as e:
            logger.info(f"StackSet creation failed as another StackSet with that name already exits")
            raise e
        except cloudformation.exceptions.LimitExceededException as e:
            logger.info(f"StackSet creation failed due to execeding cloudformation API limit")
            raise e
        except Exception as e:
            raise e
        logger.info(f"StackSet creation was successfull")
    
    logger.info(f"Creating Stack Instances for Accounts {stack_set_accounts}")
    
    if stack_set_accounts:
        try:
            create_stack_instances(stack_set_name, stack_set_accounts, stack_set_regions)
        except Exception as e:
            logger.error(f"Error creating stack instance, Error {str(e)}")
            return

def delete_stack_set(stack_set_name):
    """
    Deletes stack set and cleans up stack instance

    :param stack_set_name: Name of CloudFormation StackSet to delete
    :return: None
    """
    resp = None
    stack_set_accounts = []
    logger.info(f"Retrieving stack instances for stackset: {stack_set_name}")
    try:
        paginator = cloudformation.get_paginator('list_stack_instances')
        response_iterator = paginator.paginate(
            StackSetName=stack_set_name
        )
        #logger.debug(f"List stack instances response: {json.dumps(response_iterator)}")

        for page in response_iterator:
            stack_resources = page['Summaries']
            for stack_resource in stack_resources:
                print(json.dumps(stack_resource))
                stack_set_accounts.append(stack_resource['Account'])
    except Exception as e:
        logger.error(f"Error listing stack instances, Error: {str(e)}")
        raise e
    
    ## Delete stack instances
    try:
        if stack_set_accounts:
            logger.info(f"Deleting stack instances in accounts: {str(stack_set_accounts)}")
            resp = cloudformation.delete_stack_instances(
                StackSetName=stack_set_name,
                Accounts=stack_set_accounts,
                Regions=stack_set_regions,
                RetainStacks=False
            )
            logger.debug(f"Delete stack instances response: {json.dumps(resp)}")
            operation_id = resp['OperationId']
            # Wait for stack instances to be deleted
            status = 'RUNNING'
            while status == 'RUNNING' or status == 'STOPPING':
                sleep(10)
                resp = cloudformation.describe_stack_set_operation(
                    StackSetName=stack_set_name,
                    OperationId=operation_id
                )
                status = resp['StackSetOperation']['Status']
                logger.debug(f"Stack Set Operation status: {status}")
        
        # Delete the stack set
        logger.info(f"Deleting stack set: {str(stack_set_accounts)}")
        resp = cloudformation.delete_stack_set(
            StackSetName=stack_set_name
        )
        logger.debug(f"Delete stack set response: {json.dumps(resp)}")
    except Exception as e:
        logger.error(f"Eror deleting stack set, Error: {str(e)}")
        raise e

def update_lambda_permissions(function_name, account_id, action):
    """
    Updates permissions of lambda function to allow new accounts access to invoke the lambda function

    :param function_name: Name of the function update permissions
    :param account_id: Account Id to add/update permission for
    :param action: Permission to add
    :return:
    """
    resp = None
    logger.info(f"Updating {function_name} Lambda to allow access for account {account_id}")
    try:
        resp = lambda_client.add_permission(
                FunctionName=function_name,
                StatementId="AccessForAcct-"+account_id,
                Action=action,
                Principal=account_id
            )
        logger.debug(f"Lambda add permissions resp: {json.dumps(resp)}")
    except lambda_client.exceptions.ResourceConflictException:
        logger.info(f"Lambda function policy already has access to account: {account_id} .. skipping")

def retrieve_account_ids_for_organization_unit(ou_id):
    """
    Retrieves active accounts belonging to the specified organizations unit and returns as a list

    :param ou_id: 
    """
    account_ids = []
    paginator = organization_client.get_paginator('list_accounts_for_parent')
    page_iterator = paginator.paginate(
                        ParentId=ou_id
                    )
    for page in page_iterator:
        accounts = page['Accounts']
        for account in accounts:
            if account['Status'] == 'ACTIVE':
                account_ids.append(account['Id'])

    paginator = organization_client.get_paginator('list_children')
    page_iterator = paginator.paginate(
                        ParentId=ou_id,
                        ChildType='ORGANIZATIONAL_UNIT'
                    )
    for page in page_iterator:
        ous = page['Children']
        for ou in ous:
            account_ids = account_ids + retrieve_account_ids_for_organization_unit(ou['Id'])

    return account_ids

def retrieve_all_accounts_from_organization(master_account):
    """
    Retrieves all active accounts under the organizations (except parent account) and returns as a list

    :param master_account: Acount Id for master account
    """
    paginator = organization_client.get_paginator('list_accounts')
    page_iterator = paginator.paginate()
    account_ids = []
    for page in page_iterator:
        accounts = page['Accounts']
        for account in accounts:
            if account['Id'] != master_account and account['Status'] == 'ACTIVE':
                account_ids.append(account['Id'])
    return account_ids


def lambda_handler(event, context):
    """
    The Lambda function handler to process Control tower life cycle event and create/update stackset for ServiceNow
    for ServiceNow setup. 
   
    :param event: The event passed by Lambda
    :param context: The context passed by Lambda
    """

    logger.info(json.dumps(event))
    response_data = {}
    stack_set_accounts = []
    custom_resource_invocation = False
    ## Check if we got custom resource event for provisioning existing account or new account event
    if "RequestType" in event:
        request_type = event['RequestType']
        params = event['ResourceProperties']
        custom_resource_invocation = True
        configure_existing_accounts = params['ConfigureExistingAccounts']
        if configure_existing_accounts == 'true':
            ous_to_configure = params['OrganizationUnitsToConfigure']
            if 'ou-' in ous_to_configure:
                ou_list = ous_to_configure.split(',')
            else:
                ou_list = []
            ## retrieve current account
            sts = boto3.client('sts')
            resp = sts.get_caller_identity()
            current_account = resp['Account']
            if request_type != 'Delete':
                logger.info("Retrieving existing accounts from Organizations")
                if ou_list:
                    for ou in ou_list:
                        accounts = retrieve_account_ids_for_organization_unit(ou)
                        stack_set_accounts = stack_set_accounts + accounts
                else:
                    stack_set_accounts = retrieve_all_accounts_from_organization(current_account)
            else:
                try:
                    logger.info(f"Deleting stackset: {stack_set_name}")
                    delete_stack_set(stack_set_name)
                    send(event, context, SUCCESS, response_data, "ConfigureExistingAccounts")
                    return
                except Exception as e:
                    response_data['ERROR'] = f"StackSet deletion failed, Error {str(e)}"
                    send(event, context, FAILED, response_data, "ConfigureExistingAccounts")
                    return
    else:
        # Process new Account creation event
        try:
            ct_event_detail = event['detail']['serviceEventDetails']
            account_creation_state = ct_event_detail['createManagedAccountStatus']['state']
            if account_creation_state != "SUCCEEDED":
                logger.info(f"Control tower could not successfully create the account.. skipping event")
                return
            account = ct_event_detail['createManagedAccountStatus']['account']
            # account_info = {}
            # account_info['Id'] = account['accountId']
            # account_info['Name'] = account['accountName']
            stack_set_accounts.append(account['accountId'])
        except Exception as e:
            logger.error(f'Input event is missing required fields')
            logger.error(str(e))
            traceback.print_exc()
            return

    ## update ServiceNow config lambda permissions.
    ## TODO Remove this when Lambda Function supports sharing using aws:PrincipalOrgId in resource policy
    for account_id in stack_set_accounts:
        update_lambda_permissions(servicenow_config_function, account_id, "lambda:InvokeFunction")

    try:
        create_update_stack_set(stack_set_name, stack_set_accounts)
    except Exception as e:
        logger.error(f"StackSet creation failed, Error {str(e)}")
        if custom_resource_invocation:
            response_data['ERROR'] = f"StackSet creation failed, Error {str(e)}"
            send(event, context, FAILED, response_data, "ConfigureExistingAccounts")
            return

    if custom_resource_invocation:
        send(event, context, SUCCESS, response_data, "ConfigureExistingAccounts")
        return