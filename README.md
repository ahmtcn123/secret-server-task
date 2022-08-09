# Secret Server Coding Task

COMPLETE

## Introduction
Your task is to implement a secret server. The secret server can be used to store and share secrets
using the random generated URL. But the secret can be read only a limited number of times after that
it will expire and won’t be available. The secret may have TTL. After the expiration time the secret
won’t be available anymore. You can find the detailed API documentation in the swagger.yaml file.
We recommend to use [Swagger](https://editor.swagger.io/) or any other OpenAPI implementation to
read the documentation. 

## Task
**Implementation**: You have to implement the whole Secret Server API. If it is not specified you can choose the technology
you want to use (database, programming language, framework, etc). However it would be wise to store the data using encryption now this is not part of the task. You can use plain text to store your secrets.

**Response types**
The API must be able to response with XML or JSON too, based on the [Accept header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept). Other response types (such as YAML) might be added later so prepare your code to be extandable. 

**Hosting**: You also have to deploy and host the service. There are plenty of free solutions to do this. So this shouldn't
be an issue. If this API was used in production, then HTTPS would be a must but this is not the case now. It is allowed to use HTTP too.

**Share the code**: Upload the code to your GitHub account and share with us.

## Questions
It is totaly OK to ask if something is not clear. 

