# HuBMAP AWS API Gateway

## How to create lambda function dependencies layer

According to https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html we need to define the same folder structure in our layer .zip file archive as the ones supported: `python` or `python/lib/python3.9/site-packages`. The easies way is to just install all the dependencies to the `python` directory under this project root directory then zip it as `python.zip`:

```
pip install -r requirements.txt --target python
zip -r python.zip python
```

Next, in AWS console create a new layer in AWS Lambda and upload this zip archive with selecting x86_64 architecture and Python3.9 runtime (the dependencies are installed under Python3.9.2 on my local), and then add this custom layer to each of the authorizer lambda functions.

## Custom 401 and 403 response template

The variable `$context.authorizer.key` is made available in the authorizer lambda function to send back more detailed information. And In Gateway Responses pane, we use the following template to transform the body before returning to the client for only 401 and 403 responses:

```
{ "message": "$context.error.message", "hint": "$context.authorizer.key" }
```

Note: when the `Authorization` header is not present from the request, it seems AWS API Gateway just returns 401 with the `$context.error.message` being "Unauthorized" and the authorizer lambda function never gets called. Thus why `$context.authorizer.key` is not set.

## Handle undefiend endpoints

The `404.py` lambda function simply returns 404 response on any undefiend endpoints:
- Add an `ANY` method to the root API that proxy's to this Lambda
- Add a `/{proxy+}/ANY` method to the root API that proxy's to this Lambda
