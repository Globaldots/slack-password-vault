import json
import slack_tooling
import yaml
configuration=yaml.load(open("configuration.yaml"), Loader=yaml.FullLoader)
vault_type=configuration.get("SECRETS_STORE", "ssm")

if vault_type=="ssm":
    import access_ssm_aws as vault
elif vault_type == "secretsmanager":
    import access_vault_aws as vault
else: # ignore any other values, set default to be ssm
    import access_ssm_aws as vault

DEFAULT_AWS_REGION = configuration.get("DEFAULT_AWS_REGION", "eu-central-1")
S3_BUCKET = configuration.get("S3_BUCKET", "") # used to temporarily save QR images
otp_list_secrets_prefix = configuration.get("VAULT_SECRETS_PREFIX", "/otp/")
otp_configuration_secrets = configuration.get("VAULT_CONFIGURATION_SECRETS", "otp-config")

vault_data = json.loads(vault.get_secret(otp_configuration_secrets, region=DEFAULT_AWS_REGION))

vault_editors = vault_data.get("vault_editors",[])
vault_super_editors = vault_data.get("vault_super_editors",[])
slack_token = vault_data.get("slack-token")
slack_full_members = slack_tooling.get_slack_users(slack_token)
slack_signing_secret =  vault_data.get("slack-signing-secret")
