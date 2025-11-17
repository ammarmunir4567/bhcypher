from __future__ import annotations

import json
import os
from datetime import datetime
from uuid import uuid4
from typing import Tuple

from app.core.config import settings

try:
    import boto3
    from botocore.exceptions import ClientError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False


def download_json(s3_path: str) -> dict:
    """
    Download JSON from S3.

    """
    if not BOTO3_AVAILABLE:
        raise RuntimeError("boto3 not available. Install with: pip install boto3")

    if not s3_path.startswith("s3://"):
        raise ValueError(f"Invalid S3 path format: {s3_path}")

    # Parse bucket and key from S3 path
    # Format: s3://bucket-name/path/to/file.json
    path_parts = s3_path.replace("s3://", "").split("/", 1)
    if len(path_parts) != 2:
        raise ValueError(f"Invalid S3 path format: {s3_path}")

    bucket = path_parts[0]
    key = path_parts[1]

    s3 = boto3.client("s3")

    try:
        response = s3.get_object(Bucket=bucket, Key=key)
        return json.loads(response["Body"].read())
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "AccessDenied":
            raise PermissionError(f"Access denied to S3 bucket '{bucket}'. Check AWS credentials and IAM permissions.")
        elif error_code == "NoSuchKey":
            raise FileNotFoundError(f"S3 object not found: {s3_path}")
        else:
            raise FileNotFoundError(f"S3 error: {str(e)}")


def upload_report(html_bytes: bytes, pdf_bytes: bytes, *, hostname: str = "unknown-host", encrypt: bool = False, public: bool = False) -> Tuple[str, str]:
    """
    Upload report to S3.
    Note: If bucket has default encryption enabled, set encrypt=False to use bucket defaults.
    """
    if not BOTO3_AVAILABLE:
        raise RuntimeError("boto3 not available. Install with: pip install boto3")

    bucket = settings.s3_bucket.strip()

    # Remove s3:// prefix if present
    if bucket.startswith("s3://"):
        bucket = bucket.replace("s3://", "").split("/")[0]

    # Remove trailing slashes and paths
    bucket = bucket.rstrip("/").split("/")[0]

    if not bucket:
        raise ValueError("s3_bucket not set or invalid")

    s3 = boto3.client("s3")
    # Build unique, host-prefixed keys
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    slug = uuid4().hex[:8]
    safe_host = (hostname or "unknown-host").strip().replace("/", "_")

    html_key = f"reports/{safe_host}/{ts}-{slug}/report.html"
    pdf_key = f"reports/{safe_host}/{ts}-{slug}/report.pdf"

    extra_args = {}

    # ACLs are disabled with bucket owner enforced setting
    # Public access must be configured via bucket policy, not ACL
    # if public:
    #     extra_args["ACL"] = "public-read"  # This will fail with AccessControlListNotSupported

    # Encryption settings
    if encrypt:
        extra_args["ServerSideEncryption"] = "AES256"  # SSE-S3

    try:
        s3.put_object(
            Bucket=bucket,
            Key=html_key,
            Body=html_bytes,
            ContentType="text/html",
            **extra_args,
        )
        s3.put_object(
            Bucket=bucket,
            Key=pdf_key,
            Body=pdf_bytes,
            ContentType="application/pdf",
            **extra_args,
        )
        return (
            f"s3://{bucket}/{html_key}",
            f"s3://{bucket}/{pdf_key}",
        )
    except ClientError as e:
        raise RuntimeError(f"S3 upload failed: {str(e)}")


def get_signed_url(s3_path: str, expires_in: int = 3600) -> str:
    """
    Generate presigned S3 URL for secure report access.

    expires_in: URL expiration in seconds (default 1 hour)
    """
    if not BOTO3_AVAILABLE:
        raise RuntimeError("boto3 not available")

    bucket = settings.s3_bucket.strip()
    if not bucket:
        raise ValueError("s3_bucket not set")

    if not s3_path.startswith("s3://"):
        raise ValueError(f"Invalid S3 path format: {s3_path}")

    s3 = boto3.client("s3")
    key = s3_path.replace(f"s3://{bucket}/", "").lstrip("/")

    try:
        url = s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket, "Key": key},
            ExpiresIn=expires_in,
        )
        return url
    except ClientError as e:
        raise RuntimeError(f"Failed to generate presigned URL: {str(e)}")

