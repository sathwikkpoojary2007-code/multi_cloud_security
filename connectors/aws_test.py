import boto3

print("Starting AWS connection...")

s3 = boto3.client("s3")

response = s3.list_buckets()

print("Buckets found:")

for bucket in response["Buckets"]:
    print("-", bucket["Name"])
