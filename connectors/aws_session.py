"""Build AWS sessions from saved credentials, the standard chain, or an assumed role."""

import boto3


def create_session(credentials=None, region_name=None):
    credentials = credentials or {}
    access_key = credentials.get("access_key_id")
    secret_key = credentials.get("secret_access_key")
    if bool(access_key) != bool(secret_key):
        raise ValueError("AWS access key ID and secret access key must be supplied together.")
    session_options = {"region_name": region_name or credentials.get("region") or None}
    if access_key and secret_key:
        session_options.update(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=credentials.get("session_token") or None,
        )
    else:
        session_options["profile_name"] = credentials.get("profile") or None
    session = boto3.Session(**session_options)
    role_arn = credentials.get("role_arn", "").strip()
    if not role_arn:
        return session

    assume_args = {
        "RoleArn": role_arn,
        "RoleSessionName": "MultiCloudSecurityScan",
        "DurationSeconds": 3600,
    }
    external_id = credentials.get("external_id", "").strip()
    if external_id:
        assume_args["ExternalId"] = external_id
    response = session.client("sts").assume_role(**assume_args)
    assumed = response["Credentials"]
    return boto3.Session(
        aws_access_key_id=assumed["AccessKeyId"],
        aws_secret_access_key=assumed["SecretAccessKey"],
        aws_session_token=assumed["SessionToken"],
        region_name=region_name or credentials.get("region") or None,
    )


def get_account_identity(credentials=None):
    session = create_session(credentials)
    return session.client("sts").get_caller_identity()
