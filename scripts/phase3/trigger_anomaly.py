"""Triggers a real behavioral anomaly using lab-alice's credentials."""

import json
import sys
import time

import boto3

TARGET_USER = "lab-alice"
SECRET_NAME = f"security-lab/test-users/{TARGET_USER}"


def main():
    print(f"[1/4] Fetching {TARGET_USER}'s credentials from Secrets Manager...")
    secrets = boto3.client("secretsmanager")
    resp = secrets.get_secret_value(SecretId=SECRET_NAME)
    creds = json.loads(resp["SecretString"])

    print(f"[2/4] Building boto3 session as {TARGET_USER}...")
    alice_session = boto3.Session(
        aws_access_key_id=creds["access_key_id"],
        aws_secret_access_key=creds["secret_access_key"],
        region_name="us-east-1",
    )

    print(f"[3/4] Calling iam:CreateAccessKey on self (as {TARGET_USER})...")
    alice_iam = alice_session.client("iam")
    timestamp = int(time.time())
    try:
        new_key = alice_iam.create_access_key(UserName=TARGET_USER)
        new_key_id = new_key["AccessKey"]["AccessKeyId"]
        print(f"      Created access key: {new_key_id}")
        print(f"      Anomaly fired at: {timestamp}")
    except alice_iam.exceptions.LimitExceededException:
        print("      LimitExceededException: deleting an inactive key and retrying...")
        keys = alice_iam.list_access_keys(UserName=TARGET_USER)["AccessKeyMetadata"]
        to_delete = next(
            (k for k in keys if k["AccessKeyId"] != creds["access_key_id"]),
            None,
        )
        if not to_delete:
            print("      No key safe to delete. Aborting.")
            sys.exit(1)
        # Delete via ADMIN creds — lab-alice can DeleteAccessKey on self, but
        # to be safe we use admin so this works regardless of which key it is.
        boto3.client("iam").delete_access_key(
            UserName=TARGET_USER, AccessKeyId=to_delete["AccessKeyId"]
        )
        new_key = alice_iam.create_access_key(UserName=TARGET_USER)
        new_key_id = new_key["AccessKey"]["AccessKeyId"]
        print(f"      Created access key: {new_key_id}")
        print(f"      Anomaly fired at: {timestamp}")

    # Clean up using ADMIN credentials — lab-alice lacks iam:UpdateAccessKey,
    # so we just delete the new key directly rather than deactivating first.
    print(f"[4/4] Cleaning up leaked key using admin credentials...")
    boto3.client("iam").delete_access_key(
        UserName=TARGET_USER, AccessKeyId=new_key_id
    )
    print(f"      Deleted access key: {new_key_id}")
    print()
    print("Anomaly trigger complete. Check Slack and the detector log in ~90s.")


if __name__ == "__main__":
    main()