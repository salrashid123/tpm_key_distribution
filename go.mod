module main

go 1.13

require (
	certparser v0.0.0
	github.com/aws/aws-sdk-go v1.37.5 // indirect
	github.com/coreos/go-oidc v2.2.1+incompatible // indirect
	github.com/golang-jwt/jwt v3.2.2+incompatible
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/golang/protobuf v1.4.3
	github.com/google/go-tpm v0.3.2
	github.com/google/go-tpm-tools v0.2.1
	github.com/google/uuid v1.2.0
	github.com/hashicorp/vault/api v1.0.4 // indirect
	github.com/lestrrat/go-jwx v0.0.0-20180221005942-b7d4802280ae
	github.com/lestrrat/go-pdebug v0.0.0-20180220043741-569c97477ae8 // indirect
	github.com/pquerna/cachecontrol v0.0.0-20201205024021-ac21108117ac // indirect
	github.com/salrashid123/oauth2/google v0.0.0-20201023235943-0c6294e290c3
	golang.org/x/net v0.0.0-20210119194325-5f4716e94777
	golang.org/x/oauth2 v0.0.0-20201208152858-08078c50e5b5
	golang.org/x/time v0.0.0-20200416051211-89c76fbcd5d1 // indirect
	google.golang.org/api v0.39.0
	google.golang.org/grpc v1.35.0
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 // indirect
	oid v0.0.0 // indirect
	verifier v0.0.0
)

replace (
	certparser => ./src/certparser
	oid => ./src/certparser/oid
	verifier => ./src/verifier
)
