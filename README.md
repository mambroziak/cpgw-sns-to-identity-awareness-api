# Check Point Security Gateway - SNS to Identity Awareness API
An AWS Lambda function that consumes an SNS message containing a target IP, role and session-timeout to be added/deleted into the CheckPoint Gateway Identity Awareness API
>This project has been tested on CG GW R80.20.

## **Process Summary** 
The following explains what this tool does in sequence at a high level:
1. The Lambda function is subscribed to the SNS Topic.
2. SNS messages in JSON format invoke the Lambda function and consumes the payload with an add/delete action.
3. A list of gateway IPs is parsed from the Lambda environmental variables.
4. The respective payload is built based on the intended action.
5. The results for all the gateways are built into a JSON report and returned as output along with the original message.

## Requirements
* Staging evironment running Python 3.x
* AWS Lambda, IAM, VPC, and CloudFormation permissions.
* A VPC NAT Gateway to host the lambda function with ElasticIP. ElasticIP added to the Identity Awareness API authorized clients.

## Build a lambda deployment zip file
#### Build a zip file of the python environment for AWS Lambda


1. Clone this Git repo to your local environment and change the repo directory.
2. Install package dependencies 
  ```bash
  pip install -r requirements.txt --target ./
```
3. Zip up the package
  ```bash
  zip -r ia_lambda_function.zip ./*
```
4. Upload the zip file to an S3 bucket in the same region you intend to deploy the CloudFormation template.


## Deploy CloudFormation template
#### Deploy AWS Lambda Function with CloudFormation

1. Edit `identity_awareness_function_cft.yaml` and set the CodeUri field to the S3 bucket path of the deployment zip file.
2. In AWS CloudFormation, click Create Stack.
3. Upload the CFT `identity_awareness_function_cft.yaml` and click Next
4. Populate the parameters. The to be selected VPC selected is that which hosts the Subnet.
5. Click next twice and then create the stack.
