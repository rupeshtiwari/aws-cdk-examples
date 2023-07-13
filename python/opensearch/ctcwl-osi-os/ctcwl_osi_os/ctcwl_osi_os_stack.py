from aws_cdk import (
    aws_cloudtrail as cloudtrail,
    aws_iam as iam,
    aws_s3 as s3,
    aws_sqs as sqs,
    aws_secretsmanager as secretsmanager,
    Stack,
    CfnOutput,
    aws_osis as osis,
    Fn,
    RemovalPolicy,
    Token,
)
import random
from constructs import Construct
import boto3
import time
import string


class CtcwlOsiOsStack(Stack):
    region = "us-east-1"
    account = ""
    queue_name = "S3EventQueue"

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.account = self.get_aws_account_id()

        # Generate a unique bucket name using the current timestamp
        bucket_name = f"my-bucket-{int(time.time())}"

        # Create pipeline role
        pipeline_role_name = "PipelineRole1"
        pipeline_role = iam.Role(
            self,
            pipeline_role_name,
            assumed_by=iam.ServicePrincipal("osis-pipelines.amazonaws.com"),
            description="Role for OSIS pipeline",
        )
        CfnOutput(
            self,
            "RoleCreationComplete",
            value=Token.as_string(pipeline_role.role_name),
            export_name="RoleCreationComplete",
        )
        # Get the ARN of the role
        pipeline_role_arn = pipeline_role.role_arn

        # Create an S3 bucket to store CloudTrail logs
        bucket = s3.Bucket(
            self,
            "CloudTrailBucket",
            bucket_name=bucket_name,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # Create an SQS queue for S3 event notifications
        queue = sqs.Queue(self, self.queue_name)

        # Subscribe the queue to S3 bucket notifications
        bucket.add_event_notification(s3.EventType.OBJECT_CREATED, queue)

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

        # Update Pipeline Role with domain access
        describe_policy = iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            resources=[domain_arn],
            actions=[
                "es:DescribeDomain",
            ],
        )
        pipeline_role.add_to_policy(describe_policy)
        index_policy = iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            resources=[f"{domain_arn}/*"],
            actions=[
                "es:ESHttp*",
            ],
        )
        pipeline_role.add_to_policy(index_policy)
        trust_policy = iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=["sts:AssumeRole"],
            resources=[pipeline_role_arn],

        )
        pipeline_role.add_to_policy(trust_policy)

        print("pipeline_role_arn", pipeline_role_arn)

        # Create OpenSearch ingestion pipeline role

        pipeline_name = "my-pipeline1"
        queue_arn = f"arn:aws:sqs:{self.region}:{self.account}:{self.queue_name}"
        queue_url =  f"https://sqs.{self.region}.amazonaws.com/{self.account}/{self.queue_name}"
        pipeline_role_arn = (
            "arn:aws:iam::147228461610:role/OpenSearchIngestionFullAccessRole"
        )

        definition = f'''version: "2"
log-pipeline:
  source:
    s3:
      notification_type: "sqs"
      codec: "json"
      compression: none
      sqs:
        queue_url: "{queue_url}"
      aws:
        region: "{self.region}"
        sts_role_arn: "{pipeline_role_arn}"
  processor:
    - date:
        from_time_received: true
        destination: "@timestamp"
  sink:
    - opensearch:
        hosts: ["https://{domain_endpoint}"]
        index: "cloudtrail_logs"
        aws:
          sts_role_arn: "{pipeline_role_arn}"
          region: "{self.region}"'''

        print("Pipeline definition: ", definition)

        cfn_pipeline = osis.CfnPipeline(
            self,
            "MyCfnPipeline",
            max_units=4,
            min_units=1,
            pipeline_configuration_body=definition,
            pipeline_name=pipeline_name,
        )

        print("OpenSearch ingestion pipeline created:", cfn_pipeline)

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

    def get_aws_account_id(self):
        sts_client = boto3.client("sts")
        response = sts_client.get_caller_identity()
        account_id = response["Account"]
        return account_id
