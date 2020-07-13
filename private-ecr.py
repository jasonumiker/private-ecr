# Create a private ECR Repository that can only be accessed via a VPC Endpoint
from aws_cdk import (
    aws_ec2 as ec2,
    aws_ecr as ecr,
    aws_iam as iam,
    core
)
import os

class PrivateECRStack(core.Stack):

    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # Create a new ECR Repository
        repo = ecr.Repository(
            self, 'Repository'
        )

        # Reference the existing VPC with the name EnvironmentStack/VPC
        vpc = ec2.Vpc.from_lookup(self, 'VPC', vpc_name='EnvironmentStack/VPC')

        jsonPolicyDocument = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "ecr:*",
                        "cloudtrail:LookupEvents"
                    ],
                    "Resource": repo.repository_arn,
                    "Condition": {
                        "StringEquals": {
                            "aws:SourceVpc": vpc.vpc_id
                        }
                    }
                },
                {
                  "Effect": "Allow",
                  "Action": "ecr:GetAuthorizationToken",
                  "Resource": "*",
                  "Condition": {
                    "StringEquals": {
                      "aws:SourceVpc": "vpc-04f7508b364f824e9"
                    }
                  }
                }
            ]
        }
        policyDocument=iam.PolicyDocument.from_json(jsonPolicyDocument)

        # Create an IAM Role that has full access to this repository - but only from this VPC
        ecrAccessRole = iam.Role(
            self, "ECRAccessRole",
            assumed_by=iam.CompositePrincipal(
                iam.ServicePrincipal("codebuild.amazonaws.com"),
                iam.ServicePrincipal("ec2.amazonaws.com")
            ),
            inline_policies=[policyDocument]
        )

        instance_profile = iam.CfnInstanceProfile(
            self, "InstanceProfile",
            roles=[ecrAccessRole.role_name]            
        )

        # Create a security group for our endpoints
        security_group = ec2.SecurityGroup(
            self, "ECR-SG",
            vpc=vpc,
            allow_all_outbound=True
        )
        
        # Allow 443 inbound on our Security Group
        security_group.add_ingress_rule(
            ec2.Peer.ipv4(vpc.vpc_cidr_block),
            ec2.Port.tcp(443)
        )

        # Create VPC Endpoint for ECR API
        ecrEndpoint = ec2.InterfaceVpcEndpoint(
            self, 'ecr',
            service=ec2.InterfaceVpcEndpointAwsService.ECR,
            private_dns_enabled=True,
            vpc=vpc,
            security_groups=[security_group],
            subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE
            )
        )

        # Create VPC Endpoint for ECR Docker
        ecrEndpointDocker = ec2.InterfaceVpcEndpoint(
            self, 'ecrdkr',
            service=ec2.InterfaceVpcEndpointAwsService.ECR_DOCKER,
            private_dns_enabled=True,
            vpc=vpc,
            security_groups=[security_group],
            subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE
            )
        )

        # Create Gateway Endpoint for S3
        s3Endpoint = ec2.GatewayVpcEndpoint(
            self, 's3',
            service=ec2.GatewayVpcEndpointAwsService.S3,
            vpc=vpc,
            subnets=[ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE
            )]
        )

app = core.App()
env = core.Environment(account=os.environ.get('CDK_DEPLOY_ACCOUNT'), region=os.environ.get('AWS_DEFAULT_REGION'))
PrivateECRStack(app, 'PrivateECRStack', env=env)
app.synth()