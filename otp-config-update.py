import json
import yaml

tool_configuration=yaml.load(open("configuration.yaml"), Loader=yaml.FullLoader)
vault_type=tool_configuration.get("SECRETS_STORE", "ssm")

if vault_type=="ssm":
    import access_ssm_aws as vault
elif vault_type == "secretsmanager":
    import access_vault_aws as vault
else: # ignore any other values, set default to be ssm
    import access_ssm_aws as vault

otp_configuration = {
    "vault_editors": ["U0AAAAAA", "U040BBBBB"],
    "vault_super_editors": ["U040CCCCC"],
    "slack-token" : "xoxb-5555555555-666666666666666-xyzxyzxyzxyzxyzxyzxyzxyz",
    "slack-signing-secret" : "7777777777777777777777777777777777"
}
otp_configuration_string = json.dumps(otp_configuration)
DEFAULT_AWS_REGION = tool_configuration.get('DEFAULT_AWS_REGION', 'eu-central-1')
VAULT_CONFIGURATION_SECRETS = tool_configuration.get('VAULT_CONFIGURATION_SECRETS', 'otp-config')
vault.write_secret(VAULT_CONFIGURATION_SECRETS, otp_configuration_string , DEFAULT_AWS_REGION)

