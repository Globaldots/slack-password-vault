
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
        service_name='ssm',
        region_name=region
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.
    full_secrets_list = {}
    NextToken = None
    while True:
        parms = dict(
            Path=prefix,
            Recursive=True ,
            ParameterFilters=[] ,
            WithDecryption=True ,
            MaxResults=10
        )
        if NextToken:
            parms["NextToken"]=NextToken
        try:
            raw_secrets_list = client.get_parameters_by_path(**parms)
            # raw_secrets_list = client.list_secrets(**parms)
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
            else:
                raise e

        secrets_list = {secret['Name'] : secret['Value'] for secret in raw_secrets_list['Parameters'] if secret['Name'].lower().startswith(prefix)}
        full_secrets_list.update(secrets_list)
        if not NextToken:
            break
    return full_secrets_list

def get_secret(secret_name, region=DEFAULT_AWS_REGION):
    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='ssm',
        region_name=region
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = client.get_parameter(
            Name=secret_name,
            WithDecryption=True
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
        if 'Parameter' in get_secret_value_response:
            secret = get_secret_value_response['Parameter']['Value']
            return secret
        else:
            return None

def write_secret(secret_name, secret_value, region=DEFAULT_AWS_REGION):
    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='ssm',
        region_name=region
    )

    try:
        put_secret_value_response = client.put_parameter(
            Name=secret_name,
            Value=secret_value,
            Type='SecureString',
            Overwrite=True
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
            raise e
    pass

def lower_keys(d):
    tempdir = {key.lower():value for key,value in d.items()}
    return tempdir



if __name__ == '__main__':
    otp_list_secrets_prefix = configuration.get("VAULT_SECRETS_PREFIX", "/otp/")
    otp_configuration_secrets = configuration.get("VAULT_CONFIGURATION_SECRETS", "otp-config")
    secret_list = get_secrets_list(prefix=otp_list_secrets_prefix, region=DEFAULT_AWS_REGION)
    for secret_name in secret_list:
        secret = get_secret(secret_name, region=DEFAULT_AWS_REGION)
        print(secret_name, secret)

    secret = get_secret(otp_configuration_secrets, region=DEFAULT_AWS_REGION)
    print(otp_configuration_secrets, secret)