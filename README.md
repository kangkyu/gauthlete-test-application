# gauthlete-test-application

test authorization server code for [Gauthlete](https://github.com/kangkyu/gauthlete) library development

```sh
git clone git@github.com:kangkyu/gauthlete-test-client-app.git
cd gauthlete-test-client-app
go mod tidy
```

Need to install [dbmate](https://github.com/amacneil/dbmate) and then run this command first to get database ready
```sh
DATABASE_URL=postgresql://tester:password@localhost/test_application_development?sslmode=disable dbmate migrate
```

```sh
# to use gauthlete, need two environment variables
AUTHLETE_SERVICE_APIKEY='...' \
AUTHLETE_SERVICE_APISECRET='...' \
go run .

# a separate terminal, see if any errors
open http://localhost:8080/
```

You should be able to get service key and secret from [Authlete](https://www.authlete.com/developers/getting_started/#signing-up-to-authlete) if you sign up.
