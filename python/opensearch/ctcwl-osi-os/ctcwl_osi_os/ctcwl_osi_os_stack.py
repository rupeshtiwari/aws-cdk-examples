from aws_cdk import (
    aws_cloudtrail as cloudtrail,
    aws_iam as iam,
    aws_s3 as s3,
    aws_sqs as sqs,
    aws_secretsmanager as secretsmanager,
    Stack,
    CfnOutput,
)
import random
from constructs import Construct
import boto3
import time
import string
import json


class CtcwlOsiOsStack(Stack):
    region = "us-east-1"
    account = ""

    # Fetch the AWS account ID from STS credentials

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.account = self.get_aws_account_id()

        # Generate a unique bucket name for CloudTrail
        bucket_name = f"cloudtrail-bucket-{self.region}-{self.account}"

        # Create an S3 bucket to store CloudTrail logs
        bucket = s3.Bucket(self, "CloudTrailBucket", bucket_name=bucket_name)

        # Create an SQS queue for S3 event notifications
        queue = sqs.Queue(self, "S3EventQueue")

        # Subscribe the queue to S3 bucket notifications
        # bucket.add_event_notification(s3.EventType.OBJECT_CREATED, queue)

        # Master user for opensearch dashboard
        master_user_name = "admin"
        master_user_password = self.generate_password()

        # Create an IAM role for CloudTrail to assume
        cloudtrail_role = iam.Role(
            self,
            "CloudTrailRole",
            assumed_by=iam.ServicePrincipal("cloudtrail.amazonaws.com"),
        )

        # Grant write permissions to the S3 bucket for the CloudTrail role
        bucket.grant_write(cloudtrail_role)

        # Create a CloudTrail trail
        trail = cloudtrail.Trail(
            self,
            "CustomCloudTrail",
            bucket=bucket,
            is_multi_region_trail=True,
            include_global_service_events=True,
            send_to_cloud_watch_logs=False,
            trail_name="MyCustomTrail",
        )

        # Add a dependency on the S3 bucket for the CloudTrail trail
        trail.node.add_dependency(bucket)

        # Print the name of the CloudTrail S3 bucket
        CfnOutput(
            self,
            "CloudTrailBucketOutput",
            value=bucket.bucket_name,
            description="CloudTrail S3 Bucket",
        )

        # Create OpenSearch domain
        opensearch_client = boto3.client("opensearch")

        opensearch_domain_name = "my-opensearch-domain"
        response = opensearch_client.create_domain(
            DomainName=opensearch_domain_name,
            EBSOptions={"EBSEnabled": True, "VolumeType": "gp2", "VolumeSize": 10},
            EngineVersion="OpenSearch_1.0",
            ClusterConfig={
                "InstanceType": "t3.small.search",
                "InstanceCount": 1,
                "DedicatedMasterEnabled": False,
            },
            NodeToNodeEncryptionOptions={"Enabled": True},
            EncryptionAtRestOptions={"Enabled": True},
            DomainEndpointOptions={"EnforceHTTPS": True},
            AdvancedSecurityOptions={
                "Enabled": True,
                "InternalUserDatabaseEnabled": True,
                "MasterUserOptions": {
                    "MasterUserName": master_user_name,
                    "MasterUserPassword": master_user_password,
                },
            },
        )

        CfnOutput(self, "Username:", value=master_user_name)
        CfnOutput(self, "Password:", value=master_user_password)

        # Wait for the domain to be active
        while True:
            response = opensearch_client.describe_domains(
                DomainNames=[opensearch_domain_name]
            )
            domain_status = response["DomainStatusList"][0]
            if "Endpoint" in domain_status:
                break
            time.sleep(30)

        domain_endpoint = domain_status["Endpoint"]
        print("OpenSearch domain endpoint ready:", domain_endpoint)

        domain_arn = domain_status["ARN"]
        print("OpenSearch domain ARN:", domain_arn)

        # Create OpenSearch ingestion pipeline role if not exists
        pipeline_role_name = "PipelineRole1"
        pipeline_role = self.get_or_create_pipeline_role(pipeline_role_name, domain_arn)

        # Create OpenSearch ingestion pipeline
        pipeline_name = "my-pipeline"
        osis_client = boto3.client("osis")
        definition = f'''version: "2"
log-pipeline:
  source:
    s3:
      bucket: "{bucket.bucket_name}"
      prefix: ""
      sqs: "{queue.queue_arn}"
      notification_type: "sqs"
      codec: "json"  # Add the codec parameter with a valid value
      aws:
        region: "{self.region}"
        sts_role_arn: "{pipeline_role.role_arn}"
  processor:
    - date:
        from_time_received: true
        destination: "@timestamp"
  sink:
    - opensearch:
        hosts: ["https://{domain_endpoint}"]
        index: "cloudtrail_logs"
        aws:
          sts_role_arn: "{pipeline_role.role_arn}"
          region: "{self.region}"'''

        response = osis_client.create_pipeline(
            PipelineName=pipeline_name,
            MinUnits=4,
            MaxUnits=9,
            PipelineConfigurationBody=definition,
        )

        print("OpenSearch ingestion pipeline created:", response["PipelineId"])

        # Print the master user credentials
        CfnOutput(self, "Username:", value=master_user_name)
        CfnOutput(self, "Password:", value=master_user_password)

    def generate_password(self, length=12):
        characters = string.ascii_letters + string.digits + string.punctuation
        password = "".join(random.sample(characters, length - 4))
        password += random.choice(string.ascii_uppercase)
        password += random.choice(string.ascii_lowercase)
        password += random.choice(string.digits)
        password += random.choice(string.punctuation)
        password = "".join(random.sample(password, len(password)))
        return password

    def get_or_create_pipeline_role(self, role_name, domain_arn):
        iam_client = boto3.client("iam")

        try:
            # Check if the role already exists
            response = iam_client.get_role(RoleName=role_name)
            print("Pipeline role already exists:", response["Role"]["RoleName"])
            return iam.Role.from_role_arn(self, "PipelineRole", response["Role"]["Arn"])
        except iam_client.exceptions.NoSuchEntityException:
            # Create the role if it doesn't exist
            role = iam.Role(
                self,
                role_name,
                assumed_by=iam.ServicePrincipal("osis-pipelines.amazonaws.com"),
            )

            # Attach necessary policies to the role
            policy = iam.Policy(
                self,
                f"{role_name}Policy",
                policy_name=f"{role_name}Policy",
                statements=[
                    iam.PolicyStatement(
                        actions=["es:DescribeDomain"],
                        resources=[domain_arn],
                    ),
                    iam.PolicyStatement(
                        actions=["es:ESHttp*"],
                        resources=[f"{domain_arn}/*"],
                    ),
                ],
            )
            role.attach_inline_policy(policy)

            print('Creating pipeline role...')
            time.sleep(10)
            print('Role created: ' + role_name)
            return role

    def get_aws_account_id(self):
        sts_client = boto3.client("sts")
        response = sts_client.get_caller_identity()
        account_id = response["Account"]
        return account_id
