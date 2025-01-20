# gauthlete-test-application

test authorization server code for [Gauthlete](https://github.com/kangkyu/gauthlete) library development

```sh
git clone git@github.com:kangkyu/gauthlete-test-client-app.git
cd gauthlete-test-client-app
go mod tidy

# to use gauthlete, need two environment variables
AUTHLETE_SERVICE_APIKEY='...' \
AUTHLETE_SERVICE_APISECRET='...' \
go run .

# a separate terminal, to get the following output
curl http://localhost:8080/
<html><body>
        <h1>Authlete Test App</h1>
    </body></html>
```

You should be able to get service key and secret from [Authlete](https://www.authlete.com/developers/getting_started/#signing-up-to-authlete) if you sign up.
