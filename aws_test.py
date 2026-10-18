"""Manual AWS connection check. Run directly to contact AWS."""


def main():
    import boto3

    print("Starting AWS connection...")
    s3 = boto3.client("s3")
    response = s3.list_buckets()
    print("Connected to S3. Buckets found:")
    for bucket in response.get("Buckets", []):
        print("-", bucket["Name"])


if __name__ == "__main__":
    main()
