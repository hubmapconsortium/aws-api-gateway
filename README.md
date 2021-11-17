# aws-api-gateway

## How to create lambda function dependencies layer

According to https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html we need to define the same folder structure in our layer .zip file archive as the ones supported: `python` or `python/lib/python3.9/site-packages`. The easies way is to just install all the dependencies to the `python` directory under this project root directory then zip it as `python.zip`:

```
pip install -r requirements.txt --target python
zip -r python.zip python
```

Next, in AWS console create a new layer in AWS Lambda and upload this zip archive with selecting x86_64 architecture and Python3.9 runtime (the dependencies are installed under Python3.9.2 on my local), and then add this custom layer to each of the authorizer lambda functions.