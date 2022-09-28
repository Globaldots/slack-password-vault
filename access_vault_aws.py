import json
import boto3
import base64
from botocore.exceptions import ClientError
import yaml

configuration=yaml.load(open("configuration.yaml"), Loader=yaml.FullLoader)
DEFAULT_AWS_REGION = configuration.get("DEFAULT_AWS_REGION", "eu-central-1")


def get_secrets_list(prefix="", region=DEFAULT_AWS_REGION):
    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.
    full_secrets_list = []
    NextToken = None
    while True:
        parms = {"MaxResults":100}
        if NextToken:
            parms["NextToken"]=NextToken
        try:
            raw_secrets_list = client.list_secrets(**parms)
            NextToken = raw_secrets_list.get('NextToken')
        except ClientError as e:
            if e.response['Error']['Code'] == 'DecryptionFailureException':
                # Secrets Manager can't decrypt the protected private text using the provided KMS key.
                # Deal with the exception here, and/or rethrow at your discretion.
                raise e
            elif e.response['Error']['Code'] == 'InternalServiceErrorException':
                # An error occurred on the server side.
                # Deal with the exception here, and/or rethrow at your discretion.
                raise e
            elif e.response['Error']['Code'] == 'InvalidParameterException':
                # You provided an invalid value for a parameter.
                # Deal with the exception here, and/or rethrow at your discretion.
                raise e
            elif e.response['Error']['Code'] == 'InvalidRequestException':
                # You provided a parameter value that is not valid for the current state of the resource.
                # Deal with the exception here, and/or rethrow at your discretion.
                raise e
            elif e.response['Error']['Code'] == 'ResourceNotFoundException':
                # We can't find the resource that you asked for.
                # Deal with the exception here, and/or rethrow at your discretion.
                raise e

        secrets_list = [secret['Name'] for secret in raw_secrets_list['SecretList'] if secret['Name'].lower().startswith(prefix)]
        full_secrets_list += secrets_list
        if not NextToken:
            break
    return full_secrets_list

def get_secret(secret_name, region=DEFAULT_AWS_REGION):
    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected private text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts private using the associated KMS CMK.
        # Depending on whether the private is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            return secret
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            return decoded_binary_secret

def write_secret(secret_name, secret_value, region=DEFAULT_AWS_REGION):
    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region
    )

    try:
        put_secret_value_response = client.create_secret(
            Name=secret_name,
            SecretString=secret_value,
            Description=secret_name,
            Tags=[
                {
                    'Key': 'project',
                    'Value': 'slack-password-vault'
                },
            ]
        )
    except ClientError as e:
        print("failed to add", secret_name)
        print("Reason:", e)
        if e.response['Error']['Code'] == 'ResourceExistsException':
            print("Trying to update")
            result = client.put_secret_value(
                SecretId=secret_name,
                SecretString=secret_value
            )
            print("Updated Secret: \n", result)
        else:
            raise e


def lower_keys(d):
    tempdir = {key.lower():value for key,value in d.items()}
    return tempdir
