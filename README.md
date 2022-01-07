# HuBMAP AWS API Gateway

## General workflow

- Create a Network Load Balancer (NLB) for each deployment stage (DEV/TEST/STAGE/PROD)
- For each NLB of the given stage, create a target group per REST API for that stage, define a unique TCP port number to be used to communicate to the EC2 instance
- Create a security group for each NLB, and add the primary private IPv4 of each Availability Zone (can be found under "Network interfaces" of EC2 console)
- Attach the security group to the target group's EC2 instance so the NLB is allowed to access the target EC2 instance on those defined ports
- Create a "VPC Link for REST APIs" for each deployment stage and link to the corresponding NLB
- Import target API's openapi specification yaml file to AWS API Gateway
- Enable CORS for each resource
- Choose VPC Link integration for each resource's method, check "Use Proxy Integration" and choose "Use stage variables" with value of `${stageVariables.VPCLINK}`, also use stage variable to define Endpoint URL, example:
`http://${stageVariables.VPCNLB}/ancestors/{id}`
- For each deployed stage, set the two stage variables: `VPCLINK` (the generated ID of the VPC Link created earlier) and `VPCNLB` (the DNS of NLB with the target group port, e.g., `NLB-STAGE-4fc5be9e0b9f2bd6.elb.us-east-1.amazonaws.com:3333`)
- Create a new ACM certificate for each REST API of each deploy stage via AMC console (to be used by custom domains)
- Create custom domain of each API on each stage and select the existing ACM certifiates
- Create the Route53 DNS record for each domain, use "API Gateway domain name" (generated by each API Gateway custom domain) as the CNAME value

## How to create lambda function dependencies layer

According to https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html we need to define the same folder structure in our layer .zip file archive as the ones supported: `python` or `python/lib/python3.9/site-packages`. The easies way is to just install all the dependencies to the `python` directory under this project root directory then zip it as `python.zip`:

```
pip install -r requirements.txt --target python
zip -r python.zip python
```

Next, in AWS console create a new layer in AWS Lambda and upload this zip archive with selecting `x86_64 architecture` and `Python3.9` runtime (the dependencies are installed under Python3.9.2 on my local), and then add this custom layer to each of the authorizer lambda functions.

When the dependencies get updated, recreate the .zip archive and upload to the AWS lambda layer as a new version. Will also need to specify this new layer version for each lambda function that uses it.

## Custom 401 and 403 response template

The variable `$context.authorizer.key` is made available in the authorizer lambda function to send back more detailed information. And In Gateway Responses pane, we use the following template to transform the body before returning to the client for only 401 and 403 responses:

```
{
  "message": "$context.error.message",
  "hint": "$context.authorizer.key",
  "resource_id": "$context.resourceId",
  "http_method": "$context.httpMethod"
}
```

Note: when the `Authorization` header is not present from the request, it seems AWS API Gateway just returns 401 with the `$context.error.message` being "Unauthorized" and the authorizer lambda function never gets called. Thus why `$context.authorizer.key` is not set.

## Handle undefiend endpoints with 404

By default the API Gateway returns 403 response on any undefined endpoints instead of 404. To solve this issue, we can 
- add an `ANY` method to the root API
- add a `/{proxy+}/ANY` method to the root API
- use Lambda Proxy integration with the `404.py` lambda function which simply returning a 404 response on any undefiend endpoints
