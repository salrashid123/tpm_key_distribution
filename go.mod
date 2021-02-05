module main

go 1.13

require (
	github.com/aws/aws-sdk-go v1.37.5 // indirect
	github.com/coreos/go-oidc v2.2.1+incompatible // indirect
	github.com/google/go-tpm v0.3.2 // indirect
	github.com/google/go-tpm-tools v0.2.1 // indirect
	github.com/google/uuid v1.2.0 // indirect
	github.com/hashicorp/vault/api v1.0.4 // indirect
	github.com/lestrrat/go-jwx v0.0.0-20180221005942-b7d4802280ae // indirect
	github.com/lestrrat/go-pdebug v0.0.0-20180220043741-569c97477ae8 // indirect
	github.com/pquerna/cachecontrol v0.0.0-20201205024021-ac21108117ac // indirect
	github.com/salrashid123/oauth2/google v0.0.0-20201023235943-0c6294e290c3 // indirect
	golang.org/x/net v0.0.0-20210119194325-5f4716e94777 // indirect
	google.golang.org/api v0.39.0 // indirect
	google.golang.org/grpc v1.35.0 // indirect
	verifier v0.0.0
)

replace verifier => ./src/verifier
