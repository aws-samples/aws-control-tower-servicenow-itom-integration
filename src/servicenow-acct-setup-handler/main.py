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
"""

import json
import os
import boto3
import base64
from botocore.vendored import requests
from botocore.vendored.requests.auth import HTTPBasicAuth
from botocore.exceptions import ClientError
import urllib3
http = urllib3.PoolManager()
from time import sleep
from servicenow import *
import logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

SUCCESS = "SUCCESS"
FAILED = "FAILED"

servicenow_url = os.environ['SERVICENOW_ENDPOINT']
parent_account_id = os.environ['PARENT_ACCOUNT_ID']
discovery_schedule = os.environ['DISCOVERY_SCHEDULE']
master_acct_user_creds = os.environ['MASTER_ACCOUNT_CREDENTIALS']

def send(event, context, responseStatus, responseData, physicalResourceId=None, noEcho=False):
    responseUrl = event['ResponseURL']

    print(responseUrl)

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

    print("Response body:\n" + json_responseBody)

    headers = {
        'content-type' : '',
        'content-length' : str(len(json_responseBody))
    }

    try:

        response = http.request('PUT',responseUrl,body=json_responseBody.encode('utf-8'),headers=headers)
        print("Status code: " + response.reason)
    except Exception as e:
        print("send(..) failed executing requests.put(..): " + str(e))
                           
def lambda_handler(event, context):

    logger.info(json.dumps(event))
    response_data = {}
    master_acct_setup_request = False
    account_id = None
    try:
        request_type = event['RequestType']
        params = event['ResourceProperties']
        if 'PerformInitialSetup' in params:
            master_acct_setup_request = True
        else:
            account_id = params['AccountId']
    except Exception as e:
        logger.error(f"Error parsing event, Error: {str(e)}")
        response_data['ERROR'] = 'Missing required fields in input'
        send(event, context, FAILED, response_data, "ServiceNowInitialSetup")
        return
    
    if account_id:
        try:
            logger.info(f"Retrieving Account name from Organizations for account: {account_id}")
            client = boto3.client('organizations')
            account_info = client.describe_account(
                AccountId=account_id
            )
            account_name = account_info['Account']['Name']
        except Exception:
            logger.error("Error retrieving account info for master account from Organization")
            send(event, context, FAILED, response_data, "ServiceNowInitialSetup")
            return
    
    logger.info(f"ServiceNow Endpoint: {servicenow_url}")

    if master_acct_setup_request:
        if request_type != "Delete":
            try:
                perform_master_acct_setup(servicenow_url, parent_account_id, discovery_schedule, master_acct_user_creds)
            except Exception as e:
                logger.error(f"Failed setting up master account for discovery in ServiceNow, ERROR: {e}", exc_info=True)
                send(event, context, FAILED, response_data, str(e))
                return
        else:
            try:
                perform_master_acct_cleanup(servicenow_url, parent_account_id, discovery_schedule, master_acct_user_creds)
            except Exception as e:
                logger.error(f"Failed cleaning up master account from ServiceNow, ERROR: {e}", exc_info=True)
                send(event, context, FAILED, response_data, "ServiceNowInitialSetup")
                return
    else:
        try:
            if request_type != "Delete":
                logger.info(f"Configuring account {account_id} in ServiceNow")
                configure_account_for_snow_discovery(servicenow_url, account_id,
                            account_name, discovery_schedule, parent_account_id)
            else:
                logger.info(f"Removing account {account_id} from ServiceNow")
                deprovision_account_for_snow_discovery(servicenow_url, account_id, account_name)
        except Exception as e:
            if request_type != 'Delete':
                logger.error(f"Failed provisioning account: {account_name} for discovery in ServiceNow, ERROR: {e}", exc_info=True)
                ## Cleanup if the provisioning process failed
                deprovision_account_for_snow_discovery(servicenow_url, account_id, account_name)
            else:
                logger.error(f"Failed deleting account {account_name} from ServiceNow, ERROR: {e}", exc_info=True)
            send(event, context, FAILED, response_data, "ServiceNowInitialSetup")
            return

    send(event, context, SUCCESS, response_data, "ServiceNowInitialSetup")
    return
