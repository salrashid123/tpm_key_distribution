# TPM based Secret Sharing with Google Compute Engine

Symmetric and Asymmetric Key Distribution server using [Trusted Platform Module](https://en.wikipedia.org/wiki/Trusted_Platform_Module).

This repo contains a sample `gRPC` client server application that distributes a symmetric or asymmetric key from a server to a client.

>>> **NOTE** the code and procedure outlined here is **NOT** supported by google.  It is just something i was interested.  _caveat emptor_

There are two parts:

* `server`:  a `gRPC` server which accepts connections from a client, validates the client's TPM and system state, then securely distributes a key to that client.  The key is distributed such that it can _only_ get loaded or decoded on the client that has the TPM

* `client`: a `gRPC` client which connects to the corresponding server, proves it owns a specific TPM and then receives a sealed Key that can only be decoded by that client.


The idea is the gRPC service acts like a broker to distribute secrets to clients VM only after they prove their integrity and state using the TPM.


There are several sequences involved in this flow which uses the TPM:

* Proof that a client owns a specific TPM [Remote Attestation](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html)
* Proof that the client is in a specific TPM State [Quote-Verify](https://github.com/salrashid123/tpm2/tree/master/quote_verify)
* Secure Transfer of Key from the server to the client
* Side channel proof the client has the specific TPM using Google Cloud APIs

The basic flow as a story is like this:

1. Client wants to get a secret (eg, RSA or AES key) from a Server

2. Client asks its TPM for its `Endorsement Key` (`EK`) and to create an `Attestation Key` (`AK`).  The endorsement key is an encryption-only key tied to that specific TPM.  The attestation key is a signing key that can be used to demonstrate a the clients system state (i.,e its used to sign a [Quote](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_quote.1.md).  The client needs to first prove that its attestation key it gives to the server is associate with an endorsement key.

3. Client connects to server using TLS and provides its Google Cloud VM's [identity document](https://cloud.google.com/compute/docs/instances/verifying-instance-identity) as an authentication header.  The Identity document is an Google CA signed JWT that contains data that uniquely identifies the VM (Instance Name, instanceID, where it is running, etc).  Client sends its `EK` and `AK` _Public Key_.  The API endpoint on the server here is: `MakeCredential()`.

3. Server verifies the identity document is signed by Google and it also extracts the JWT Claims embedded in the Token.  The server will make a decision based ont the claims if its a legitimate client API request (i.,e is the VM instance or project even allowed to get a secret in the first place)

4. Server uses GCP API call using the instanceID to retrieve its version of the Endorsement Key
   `gcloud compute instances get-shielded-identity <instanceID> --format="value(encryptionKey.ekPub)"`

5. Server compares the GCP provided Endorsement Key's public part to the one provided by the client.  if they match, then the server knows the EK is atleast coming from that VM.

6. Server uses the `EK` public cert, and the "name" of the `AK` to encrypt a nonce.

7. Server sends the encrypted nonce back to the client and also asks its to provide proof about a current state of a PCR. 

8. Client uses the `EK` and `AK` to decrypt the nonce.

9. Client asks the TPM to generate a `Quote` against the PCR back requested by the server.  The Quote contains the value of the PCR bank at that moment.

10. Client makes another API call to the sever (which again includes the `id_document`).  The client sends the Quote value and the decrypted nonce. The API endpoint on the server is `ActivateCredential()`.

11. Server verifies the nonce matches what it originally encrypted.  Once that is done, it knows the `EK`, `AK` that it used to wrap a secret must be present on the client.   Server permanently associates the AK with that EK.  

12. Server verifies the Quote is singed by that AK (which is now trusted). Server checks what the attested PCR values are in the Quote.  If the PCR values are what it expects, it knows the client is in a known integrity state.


At this point, the server can distribute two types of keys Asymmetric (`RSA`) or Symmetric (eg `AES` key).  

do one of:

`RSA`:

13. Server generates `RSA` private key for this client.  It can either download a [GCP Service Account private key](https://cloud.google.com/iam/docs/creating-managing-service-account-keys#creating_service_account_keys) or ask any CA to generate a key and sign it optionally.  The server will only transfer an RSA Private key portion.

14. Server encrypts the `RSA` key using a procedure that seals it using the EK  ([CreateSigningKeyImportBlob](https://github.com/google/go-tpm-tools/blob/master/server/import.go#L38)) and optionally provides a set of PCR values.  The RSA key can only be loaded into the TPM that owns the `EK` and will load if the specific PCR hash is present on a given bank.  This ensures the key is bound to the client's state.

15. Server sends the encrypted RSA key to the client

16. Client uses its TPM to load the encrypted key into its TPM ([tpm2tools.Key.ImportSigningKey](https://godoc.org/github.com/google/go-tpm-tools/tpm2tools#Key.ImportSigningKey)).  The imported key is _not_ exportable and can only be asked to sign anything through that TPM


`AES`:

17. Server seals a symmetric key using the `EK`  ([CreateImportBlob](https://github.com/google/go-tpm-tools/blob/master/server/import.go#L57).  The key here is a static sequence that happens to be an AES256 key but  more generally, any bit of data (passphrase, symmetric key) can be sealed to the EK such that only a given TPM can decode it.  Optionally provide PCR values during sealing such that the key will only get decrypted if the PCR values exist on the TPM.

18. Server sends the encrypted key to the client

19. Client uses its TPM to decrypt the secret key using the TPM. ([tpm2tools.Key.Import](https://godoc.org/github.com/google/go-tpm-tools/tpm2tools#Key.Import))


At this point, the server transferred an RSA private key or an arbitrary key to the client in a way that ensures the client was confirmed to be in a specific state.

>> **NOTE**: The flow here generates the private key by the broker and then distributes that key to the remote TPM.  The inverse flow where the private key is generated _on the remote TPM_ and then signed by the verification service (i.,e server), is not possible at the moment.  As of 4/18/20, `go-tpm` does not support AK based signing.   This flow is superior in many ways because the private key never leaves a target TPM ever (i.,e its not generated elsewhere and transferred; it always existed on that TPM).  For more information on AK based signing feature, see:

- `Attestation Key based signing`: [go-tpm issue/101#](https://github.com/google/go-tpm/issues/101#issuecomment-613753202)

Now that the server trusts the `AK`, the client can prove its current state at anytime to the server.  Since this is a client->server flow, the client has to initiate the proof.   

20. Client needs to prove its state to the server and makes a gRPC API call to the server (`OfferQuote()`)

21. Server responds back to the client and uses the AK it now trusts with nonce and list of PCR bank to Quote.  The nonce is there just to prevent replay.

22. Client asks its TPM to generate a `Quote` using the `AK` and to include the nonce value and PCR bank state in the quote

23. Client sends the Quote and the TPM-AK signed values for the quote to the server (`ProvideQuote()`)

24. Server uses its AK public certificate to verify the Quote and inspect the PCR values.  It will also check the nonce is included in the quote.

The client has indirectly now proven its PCR state to the Server

### Flow Diagram

#### Remote Attestation with Symmetric Key import

![images/key_service_aes.png](images/key_service_aes.png)

#### Remote Attestation with Asymmetric Key import

![images/key_service_rsa.png](images/key_service_rsa.png)

#### Quote-Verify

![images/quote_verify.png](images/quote_verify.png)


### References

- [A Practical Guide to TPM 2.0](https://link.springer.com/book/10.1007/978-1-4302-6584-9)
- [tpm2-software community Remote Attestation](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html)
- [StackOverflow: Can I prove the relation between AIK and EK without asking to the TPM 2.0?](https://security.stackexchange.com/questions/197794/can-i-prove-the-relation-between-aik-and-ek-without-asking-to-the-tpm-2-0)
- [Virtual Trusted Platform Module for Shielded VMs: security in plaintext](https://cloud.google.com/blog/products/gcp/virtual-trusted-platform-module-for-shielded-vms-security-in-plaintext)

- Go Implementations/Samples:
  - Import Symmetric Key: [ek_import_blob](https://github.com/salrashid123/tpm2/tree/master/ek_import_blob)
  - Import RSA Key: [ek_import_rsa_blob](https://github.com/salrashid123/tpm2/tree/master/ek_import_rsa_blob)
  - Quote/Verify: [quote_verify](https://github.com/salrashid123/tpm2/tree/master/quote_verify)
  - MakeCredential/ActivateCredential: [tpm_make_activate](https://github.com/salrashid123/tpm2/tree/master/tpm_make_activate)


### Usage

#### Create GCE Shielded VM and Service Accounts

```bash
export PROJECT_ID=$(gcloud config list --format="value(core.project)")
export PROJECT_NUMBER=`gcloud projects describe $PROJECT_ID --format="value(projectNumber)"`
export SERVER_SERVICE_ACCOUNT=tpm-server@$PROJECT_ID.iam.gserviceaccount.com
export CLIENT_SERVICE_ACCOUNT=tpm-client@$PROJECT_ID.iam.gserviceaccount.com

gcloud iam service-accounts create tpm-client
gcloud iam service-accounts create tpm-server
```

Service Accounts:

- `tpm-client` service account will not have any IAM permissions and will only provide the gRPC Server the instance identity document.

- `tpm-server` service account will use the GCE API call to recall the clients public endorsement key

gcloud beta compute --project=mineral-minutia-820 instances create instance-4 --zone=us-central1-a --machine-type=e2-medium --subnet=aet-uscentral1-myconn-sbnt --network-tier=PREMIUM --maintenance-policy=MIGRATE --service-account=1071284184436-compute@developer.gserviceaccount.com --scopes=https://www.googleapis.com/auth/devstorage.read_only,https://www.googleapis.com/auth/logging.write,https://www.googleapis.com/auth/monitoring.write,https://www.googleapis.com/auth/servicecontrol,https://www.googleapis.com/auth/service.management.readonly,https://www.googleapis.com/auth/trace.append --image=debian-10-buster-v20210609 --image-project=debian-cloud --boot-disk-size=10GB --boot-disk-type=pd-balanced --boot-disk-device-name=instance-4 --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring --reservation-affinity=any

```bash
$ gcloud compute  instances create client \
  --service-account=$CLIENT_SERVICE_ACCOUNT \
  --scopes=email --image=debian-10-buster-v20210609 --image-project=debian-cloud  \
  --machine-type "n1-standard-1"  \
  --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring  \
  --zone us-central1-a --tags=client


$ gcloud compute  instances create server \
  --service-account=$SERVER_SERVICE_ACCOUNT \
  --scopes=compute-ro,email  --image=debian-10-buster-v20210609 --image-project=debian-cloud  \
  --machine-type "n1-standard-1" \
  --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring  \
  --zone us-central1-a --tags=server

NAME    ZONE           MACHINE_TYPE   PREEMPTIBLE  INTERNAL_IP   EXTERNAL_IP     STATUS
server  us-central1-a  n1-standard-1               10.128.0.121  104.154.44.141  RUNNING
```

Note down the internalIP for the `server`: `10.128.0.121`.  This address will be used later to make the gRPC connection

#### Allow server read access to client's metadata

Create a policy file (verify `$SERVER_SERVICE_ACCOUNT` is still active in the current shell)

```bash
cat <<EOF > policy.json
bindings:
- members:
  - serviceAccount:$SERVER_SERVICE_ACCOUNT
  role: roles/compute.viewer
version: 1
EOF

$ gcloud compute instances set-iam-policy client policy.json -q
```

#### Install go 1.14+ on client, server

- [https://golang.org/doc/install](https://golang.org/doc/install)


#### Edit /etc/hosts on client

- On the `client` VM

Add to `/etc/hosts` the _internal_ ip of the server

```bash
10.128.0.121 verify.esodemoapp2.com
```


#### Generate client, server

```bash
git clone https://github.com/salrashid123/tpm_key_distribution.git
cd tpm_key_distribution
```

### AES mode

In this mode, an simple AES key will be securely tranferred from the server to the client

#### SERVER

on the server, start the grpc service.  Instruct it to seal against `pcr=0` on the client and expect its value to be `24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f`. 

* For SEV enabled systems (confidential compute), the PCR0 value is `0f35c214608d93c7a6e68ae7359b4a8be5a0e99eea9107ece427c4dea4e439cf`

Note, that PCR value is the default PCR=0 value for a Google Compute Shielded VM


The following will start the gRPC Server and will seal and transfer an AES key to the client

```log
gcloud compute ssh server

$ go run src/grpc_server.go \
   --grpcport :50051 -pcr 0 \
   -secret bar \
   -aes256Key "G-KaPdSgUkXp2s5v8y/B?E(H+MbQeThW" \
   -expectedPCRValue 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f \
   --importMode=AES \
   --cacert  certs/CA_crt.pem  \
   --servercert certs/server_crt.pem \
   --serverkey certs/server_key.pem \
   --usemTLS \
   --v=10 -alsologtostderr 

    I0619 19:12:43.068561    2932 grpc_server.go:250] Using mTLS for initial server connection
    I0619 19:12:43.069776    2932 grpc_server.go:287] Starting gRPC server on port :50051
    I0619 19:12:52.097546    2932 grpc_server.go:156] >> authenticating inbound request
    I0619 19:12:52.098005    2932 grpc_server.go:318] OIDC doc has Audience [grpc://verify.esodemoapp2.com]   Issuer [https://accounts.google.com]
    I0619 19:12:52.098108    2932 grpc_server.go:182] HealthCheck called for Service [verifier.VerifierServer]
    I0619 19:12:52.331322    2932 grpc_server.go:156] >> authenticating inbound request
    I0619 19:12:52.331719    2932 grpc_server.go:318] OIDC doc has Audience [grpc://verify.esodemoapp2.com]   Issuer [https://accounts.google.com]
    I0619 19:12:52.331801    2932 grpc_server.go:326] ======= MakeCredential ========
    I0619 19:12:52.331862    2932 grpc_server.go:327]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
    I0619 19:12:52.331939    2932 grpc_server.go:328]      Got AKName 000b45032d89f9b80d68ed913907c87ee8a045b2a9f47e6b7fb8d73a4eb110f83a0b
    I0619 19:12:52.331994    2932 grpc_server.go:329]      Registry size 0
    I0619 19:12:52.332084    2932 grpc_server.go:332]      From InstanceID 8698503547301626160
    I0619 19:12:52.473251    2932 grpc_server.go:347]      Acquired PublickKey from GCP API: 
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzUPZU9BXAUFpmZRZXyfp
    2+bfAfqjV3KwCRjsMQUQ9r49kA4MwZUnlih9DrTejYdca7vNvbV92SAcXVebGWWC
    T9Qyk4kwXNfem1gqK+70Cfgt68OUTZm4hDIVwrpk/7OIUdhWqm3N76JDrweaBie+
    16u4OF8njLdAY3FWx9JFqIjOAk0oESxKKPKYwNOBicPiha7S1jCp+CgBEwUJ3JEa
    Pa23eWwZOn2TdT+m+VXvfPL5QIEaIVgS8uF8IgR1LmW2a6R4qsa1AKzDnHK4FRAt
    ycE+OYlGfUDqPCUfW80ldv/FdzCyHHaM7pSXN+MDK1UMGhfN3fw+Zo55gt+E+P3d
    OQIDAQAB
    -----END PUBLIC KEY-----
    I0619 19:12:52.473827    2932 grpc_server.go:349]      Decoding ekPub from client
    I0619 19:12:52.473963    2932 grpc_server.go:370]      EKPubPEM: 
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzUPZU9BXAUFpmZRZXyfp
    2+bfAfqjV3KwCRjsMQUQ9r49kA4MwZUnlih9DrTejYdca7vNvbV92SAcXVebGWWC
    T9Qyk4kwXNfem1gqK+70Cfgt68OUTZm4hDIVwrpk/7OIUdhWqm3N76JDrweaBie+
    16u4OF8njLdAY3FWx9JFqIjOAk0oESxKKPKYwNOBicPiha7S1jCp+CgBEwUJ3JEa
    Pa23eWwZOn2TdT+m+VXvfPL5QIEaIVgS8uF8IgR1LmW2a6R4qsa1AKzDnHK4FRAt
    ycE+OYlGfUDqPCUfW80ldv/FdzCyHHaM7pSXN+MDK1UMGhfN3fw+Zo55gt+E+P3d
    OQIDAQAB
    -----END PUBLIC KEY-----
    I0619 19:12:52.474380    2932 grpc_server.go:376]      Verified EkPub from GCE API matches ekPub from Client
    I0619 19:12:52.474432    2932 grpc_server.go:562]      --> Starting makeCredential()
    I0619 19:12:52.474489    2932 grpc_server.go:563]      Read (ekPub) from request
    I0619 19:12:52.488223    2932 grpc_server.go:576]      Read (akPub) from request
    I0619 19:12:52.488452    2932 grpc_server.go:598]      Decoded AkPub: 
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtJ1ORkbKCL0Mrk9NlUCM
    6IHYgD5K3ug3WzN+EuSkuVeXHRTgD2tTgkKHJ1cW3EmPjLK5Kh+K1++jFVjxkk+m
    JSPa1444KOIZ17c1wkUjzdlVFBSKaB/t1f9I+bdEVy9KP3ks7nhi3B2yTKl9Fhrx
    z7lRZeZUXNs3RUqmdRvRVQ5hb9GsIvgr/MLWoXKY8m/vw5gMCew6RaIUKv2v0Rc5
    mrk/KVZaJj+IgY+Fn8XqWd3n+KdwAamhw63IQwgjEk+BwtjZqigPhBEwgU6lvhwo
    5V7sifmYNa1cQARJejvUXrHpiMWcsxcDqTPkJOjsx020Tyfg7ThUYMn1VjF+KQPR
    oQIDAQAB
    -----END PUBLIC KEY-----
    I0619 19:12:52.488873    2932 grpc_server.go:601]      AK Default parameter match template
    I0619 19:12:52.491810    2932 grpc_server.go:610]      Loaded AK KeyName 000b45032d89f9b80d68ed913907c87ee8a045b2a9f47e6b7fb8d73a4eb110f83a0b
    I0619 19:12:52.491883    2932 grpc_server.go:612]      MakeCredential Start
    I0619 19:12:52.494891    2932 grpc_server.go:618]      credBlob 00207d9532967287c93f5afe723ecb2de032fd9e5d86cfcac28da937dba4467bc53c54d0f46144
    I0619 19:12:52.494964    2932 grpc_server.go:619]      encryptedSecret0 046888957134488dd37cf2df13ec71dc8cb128da37667b52a1ec1c2ee95eafb080a5d822e19ce2c5267f307b7b7cda1151be5eba0042107699fa2173be1405ea0f469959caceacb2e69a9b59f33612ee5e3bab2c6f8c314292681db90958a313f32996d1163451330092ceb7e69058acc59e3a857d743e31de7f7f3213034eb79b81a655a95f6d40864cff36a9737fd0de6daba4c875084f3084907d94236e17d9549763d05e21406d27e208b38a6cec0746a359ca69acc4058962399c69e342965322a38d14c5752bdda44c049efdbc870b588f9fd9ba9d3f07e17d6cee537a651e7a0bf24a6fb5a9792cb14e960e30625dc10af33423b75dbf72890d945f18
    I0619 19:12:52.495034    2932 grpc_server.go:620]      <-- End makeCredential()
    I0619 19:12:52.497623    2932 grpc_server.go:388]      Returning MakeCredentialResponse ========
    I0619 19:12:53.560241    2932 grpc_server.go:156] >> authenticating inbound request
    I0619 19:12:53.560394    2932 grpc_server.go:318] OIDC doc has Audience [grpc://verify.esodemoapp2.com]   Issuer [https://accounts.google.com]
    I0619 19:12:53.560404    2932 grpc_server.go:399] ======= ActivateCredential ========
    I0619 19:12:53.560408    2932 grpc_server.go:400]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
    I0619 19:12:53.560412    2932 grpc_server.go:401]      Secret bar
    I0619 19:12:53.560416    2932 grpc_server.go:404]      From InstanceID 8698503547301626160
    I0619 19:12:53.560422    2932 grpc_server.go:503]      --> Starting verifyQuote()
    I0619 19:12:53.560426    2932 grpc_server.go:508]      Read and Decode (attestion)
    I0619 19:12:53.560449    2932 grpc_server.go:514]      Attestation ExtraData (nonce): bar 
    I0619 19:12:53.560454    2932 grpc_server.go:515]      Attestation PCR#: [0] 
    I0619 19:12:53.560474    2932 grpc_server.go:516]      Attestation Hash: 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f 
    I0619 19:12:53.560481    2932 grpc_server.go:533]      Expected PCR Value:           --> 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f
    I0619 19:12:53.560487    2932 grpc_server.go:534]      sha256 of Expected PCR Value: --> 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
    I0619 19:12:53.560496    2932 grpc_server.go:536]      Decoding PublicKey for AK ========
    I0619 19:12:53.560581    2932 grpc_server.go:555]      Attestation Signature Verified 
    I0619 19:12:53.560589    2932 grpc_server.go:556]      <-- End verifyQuote()
    I0619 19:12:53.560593    2932 grpc_server.go:418]      Verified Quote
    I0619 19:12:53.560599    2932 grpc_server.go:719]      --> Start createImportBlob()
    I0619 19:12:53.560603    2932 grpc_server.go:720]      Load and decode ekPub from registry
    I0619 19:12:53.560614    2932 grpc_server.go:733]      Decoding sealing PCR value in hex
    I0619 19:12:53.560622    2932 grpc_server.go:769]      --> createImportBlob()
    I0619 19:12:53.560627    2932 grpc_server.go:770]      Generating to AES sealedFile
    I0619 19:12:53.560883    2932 grpc_server.go:783]      <-- End createImportBlob()
    I0619 19:12:53.560891    2932 grpc_server.go:434]      Returning ActivateCredentialResponse ========
    I0619 19:12:53.663236    2932 grpc_server.go:156] >> authenticating inbound request
    I0619 19:12:53.663597    2932 grpc_server.go:318] OIDC doc has Audience [grpc://verify.esodemoapp2.com]   Issuer [https://accounts.google.com]
    I0619 19:12:53.663676    2932 grpc_server.go:444] ======= OfferQuote ========
    I0619 19:12:53.663730    2932 grpc_server.go:445]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
    I0619 19:12:53.663798    2932 grpc_server.go:448]      From InstanceID 8698503547301626160
    I0619 19:12:53.663887    2932 grpc_server.go:457]      Returning OfferQuoteResponse ========
    I0619 19:12:53.692246    2932 grpc_server.go:156] >> authenticating inbound request
    I0619 19:12:53.692608    2932 grpc_server.go:318] OIDC doc has Audience [grpc://verify.esodemoapp2.com]   Issuer [https://accounts.google.com]
    I0619 19:12:53.692666    2932 grpc_server.go:467] ======= ProvideQuote ========
    I0619 19:12:53.692724    2932 grpc_server.go:468]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
    I0619 19:12:53.692766    2932 grpc_server.go:471]      From InstanceID 8698503547301626160
    I0619 19:12:53.692857    2932 grpc_server.go:503]      --> Starting verifyQuote()
    I0619 19:12:53.692901    2932 grpc_server.go:508]      Read and Decode (attestion)
    I0619 19:12:53.692969    2932 grpc_server.go:514]      Attestation ExtraData (nonce): 695c7576-0da8-452a-a1bd-4f5c61c38b91 
    I0619 19:12:53.693014    2932 grpc_server.go:515]      Attestation PCR#: [0] 
    I0619 19:12:53.693072    2932 grpc_server.go:516]      Attestation Hash: 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f 
    I0619 19:12:53.693129    2932 grpc_server.go:533]      Expected PCR Value:           --> 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f
    I0619 19:12:53.693172    2932 grpc_server.go:534]      sha256 of Expected PCR Value: --> 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
    I0619 19:12:53.693227    2932 grpc_server.go:536]      Decoding PublicKey for AK ========
    I0619 19:12:53.693366    2932 grpc_server.go:555]      Attestation Signature Verified 
    I0619 19:12:53.693414    2932 grpc_server.go:556]      <-- End verifyQuote()
    I0619 19:12:53.693470    2932 grpc_server.go:495]      Returning ProvideQuoteResponse ========
```

Then run the client

```log
$ go run src/grpc_client.go  \
   --uid 369c327d-ad1f-401c-aa91-d9b0e69bft67  \
   --unsealPcr=0  \
   --host verify.esodemoapp2.com:50051 \
   --importMode=AES \
   --cacert certs/CA_crt.pem  \
   --clientcert certs/client_crt.pem \
   --clientkey certs/client_key.pem \
   --usemTLS  \
   --v=10 -alsologtostderr

I0619 19:12:52.057664    3221 grpc_client.go:160] Using mTLS
I0619 19:12:52.084898    3221 grpc_client.go:189] Acquired OIDC: eyJhbGciOiJSUzI1NiIsImtpZCI6IjE5ZmUyYTdiNjc5NTIzOTYwNmNhMGE3NTA3OTRhN2JkOWZkOTU5NjEiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJncnBjOi8vdmVyaWZ5LmVzb2RlbW9hcHAyLmNvbSIsImF6cCI6IjExMzczNzQ2NjAzNDMxNDg4MDgzNyIsImVtYWlsIjoidHBtLWNsaWVudEBtaW5lcmFsLW1pbnV0aWEtODIwLmlhbS5nc2VydmljZWFjY291bnQuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImV4cCI6MTYyNDEzMzU3MiwiZ29vZ2xlIjp7ImNvbXB1dGVfZW5naW5lIjp7Imluc3RhbmNlX2NyZWF0aW9uX3RpbWVzdGFtcCI6MTYyNDEyOTUwNCwiaW5zdGFuY2VfaWQiOiI4Njk4NTAzNTQ3MzAxNjI2MTYwIiwiaW5zdGFuY2VfbmFtZSI6ImNsaWVudCIsInByb2plY3RfaWQiOiJtaW5lcmFsLW1pbnV0aWEtODIwIiwicHJvamVjdF9udW1iZXIiOjEwNzEyODQxODQ0MzYsInpvbmUiOiJ1cy1jZW50cmFsMS1hIn19LCJpYXQiOjE2MjQxMjk5NzIsImlzcyI6Imh0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbSIsInN1YiI6IjExMzczNzQ2NjAzNDMxNDg4MDgzNyJ9.rwiyu1JhEkuz-zTZgWdVRD2XtHWinzEO9skxlBykg2ivKK4lGANzCUsW9wxUKrZFEK11MXDk0LvlVnr1Qi2c3rMy5GkgE6jQE5YzPCRMUdbUF7Y7_Zv5mr59xp0PUZqlbi-LDKKaQsfRLe-r7R6OOop3fSYAy0yDEHObkkI4l4he7YS8mFgvl5KbieRnxwhN1m1XyB8lsm5i_Ratrsd6s3R7Z7-KEhYRLpOxe3T890hRmexFPRbbw6sOkugKVavG8FEGe-P-s8SvggJvZOhtRgaF6ywLh-Q5cqPEpBLFYJxi0piq4elazYfEkLRvOBO40YQvQ2N4uPBOxkGPeQPW1w
I0619 19:12:52.099257    3221 grpc_client.go:211] RPC HealthChekStatus:SERVING
I0619 19:12:52.099437    3221 grpc_client.go:215] =============== MakeCredential ===============
I0619 19:12:52.099515    3221 grpc_client.go:503]      --> CreateKeys()
I0619 19:12:52.101369    3221 grpc_client.go:510]     Current PCR 0 Value %!d(string=24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f) 
I0619 19:12:52.101564    3221 grpc_client.go:515]      createPrimary
I0619 19:12:52.168822    3221 grpc_client.go:533]      tpmEkPub: 
&{25912310074943480149737721308652377707854331362286193336728975248218541504080645993034560950975678532399513056308880417062110199079068652544142172301399725683268294732506196458137181173829606931841286764807519567032235006983873124002844906686926862393624844965800853567065877551555305788110047793379315987357891361132820525731803348160648899878161445715059780892112579551730826413790896942672502847230969215606156056838830702783927285766757803311828211918865358810151675418391724366492168693939686462882813953515060021765009342298258356048119007954374065947131929181833428757497901831343369824695032110355878755818809 65537}
I0619 19:12:52.169105    3221 grpc_client.go:546]      ekPub Name: 000b09aa66898e4a813be929f1ad9a8e7bcf8f877656a6be91fffc138a969f7e5a58
I0619 19:12:52.169178    3221 grpc_client.go:547]      ekPubPEM: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzUPZU9BXAUFpmZRZXyfp
2+bfAfqjV3KwCRjsMQUQ9r49kA4MwZUnlih9DrTejYdca7vNvbV92SAcXVebGWWC
T9Qyk4kwXNfem1gqK+70Cfgt68OUTZm4hDIVwrpk/7OIUdhWqm3N76JDrweaBie+
16u4OF8njLdAY3FWx9JFqIjOAk0oESxKKPKYwNOBicPiha7S1jCp+CgBEwUJ3JEa
Pa23eWwZOn2TdT+m+VXvfPL5QIEaIVgS8uF8IgR1LmW2a6R4qsa1AKzDnHK4FRAt
ycE+OYlGfUDqPCUfW80ldv/FdzCyHHaM7pSXN+MDK1UMGhfN3fw+Zo55gt+E+P3d
OQIDAQAB
-----END PUBLIC KEY-----
I0619 19:12:52.169616    3221 grpc_client.go:554]      CreateKeyUsingAuth
I0619 19:12:52.297713    3221 grpc_client.go:580]      akPub: 0001000b00050072000000100014000b0800000000000100b49d4e4646ca08bd0cae4f4d95408ce881d8803e4adee8375b337e12e4a4b957971d14e00f6b53824287275716dc498f8cb2b92a1f8ad7efa31558f1924fa62523dad78e3828e219d7b735c24523cdd95514148a681fedd5ff48f9b744572f4a3f792cee7862dc1db24ca97d161af1cfb95165e6545cdb37454aa6751bd1550e616fd1ac22f82bfcc2d6a17298f26fefc3980c09ec3a45a2142afdafd117399ab93f29565a263f88818f859fc5ea59dde7f8a77001a9a1c3adc8430823124f81c2d8d9aa280f841130814ea5be1c28e55eec89f99835ad5c4004497a3bd45eb1e988c59cb31703a933e424e8ecc74db44f27e0ed385460c9f556317e2903d1a1,
I0619 19:12:52.297860    3221 grpc_client.go:581]      akPriv: 00204fb500e09f2c83260672b1731cf492290144d954219c5f424f8b25fe955d612c0010e770afc7b9bbd2e0c38cac483d1e4f77014fde0bf5ba4d075c82174ae2c8e626d956d2a2ef0daddeda3a552b5a88f94510922ed27789cf896d42b5f25b903cf61176edde341c7956a0ec8864111befddede5a1e24da8817764e39e4597b66f5ac24d14b8f5c0f2127cd27a70fe20caefd2f526162aadd809bbd1a5d156daeaad64353e6a7c88631d7bfb4a06eadb47f63b03c72b62bfe3fd09d9d4766bb4242b90edd3338aa5b27a5721afc76c60618eb370451dded44cef2aad,
I0619 19:12:52.297934    3221 grpc_client.go:588]      CredentialData.ParentName.Digest.Value 09aa66898e4a813be929f1ad9a8e7bcf8f877656a6be91fffc138a969f7e5a58
I0619 19:12:52.298000    3221 grpc_client.go:589]      CredentialTicket 8fe0fb8794239b21aaec9590f64d7801dfca2dbae1da56d99dd85dbb9acecb20
I0619 19:12:52.298052    3221 grpc_client.go:590]      CredentialHash e77321cc3f6a0c1976bb73016fa0072bd8e2742f92748ec8ff124564a50f9d37
I0619 19:12:52.298125    3221 grpc_client.go:592]      ContextSave (ek)
I0619 19:12:52.307202    3221 grpc_client.go:603]      ContextLoad (ek)
I0619 19:12:52.314652    3221 grpc_client.go:613]      LoadUsingAuth
I0619 19:12:52.321520    3221 grpc_client.go:641]      AK keyName 000b45032d89f9b80d68ed913907c87ee8a045b2a9f47e6b7fb8d73a4eb110f83a0b
I0619 19:12:52.324620    3221 grpc_client.go:663]      akPubPEM: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtJ1ORkbKCL0Mrk9NlUCM
6IHYgD5K3ug3WzN+EuSkuVeXHRTgD2tTgkKHJ1cW3EmPjLK5Kh+K1++jFVjxkk+m
JSPa1444KOIZ17c1wkUjzdlVFBSKaB/t1f9I+bdEVy9KP3ks7nhi3B2yTKl9Fhrx
z7lRZeZUXNs3RUqmdRvRVQ5hb9GsIvgr/MLWoXKY8m/vw5gMCew6RaIUKv2v0Rc5
mrk/KVZaJj+IgY+Fn8XqWd3n+KdwAamhw63IQwgjEk+BwtjZqigPhBEwgU6lvhwo
5V7sifmYNa1cQARJejvUXrHpiMWcsxcDqTPkJOjsx020Tyfg7ThUYMn1VjF+KQPR
oQIDAQAB
-----END PUBLIC KEY-----
I0619 19:12:52.325110    3221 grpc_client.go:665]      Write (akPub) ========
I0619 19:12:52.325314    3221 grpc_client.go:670]      Write (akPriv) ========
I0619 19:12:52.325451    3221 grpc_client.go:676]      <-- CreateKeys()
I0619 19:12:53.498367    3221 grpc_client.go:232]      MakeCredential RPC Response with provided uid [369c327d-ad1f-401c-aa91-d9b0e69bft67]
I0619 19:12:53.498410    3221 grpc_client.go:234] =============== ActivateCredential  ===============
I0619 19:12:53.498417    3221 grpc_client.go:682]      --> activateCredential()
I0619 19:12:53.498422    3221 grpc_client.go:684]      ContextLoad (ek)
I0619 19:12:53.506021    3221 grpc_client.go:695]      Read (akPub)
I0619 19:12:53.506231    3221 grpc_client.go:700]      Read (akPriv)
I0619 19:12:53.506324    3221 grpc_client.go:706]      LoadUsingAuth
I0619 19:12:53.514014    3221 grpc_client.go:733]      keyName 000b45032d89f9b80d68ed913907c87ee8a045b2a9f47e6b7fb8d73a4eb110f83a0b
I0619 19:12:53.514181    3221 grpc_client.go:735]      ActivateCredentialUsingAuth
I0619 19:12:53.525598    3221 grpc_client.go:783]      <--  activateCredential()
I0619 19:12:53.532432    3221 grpc_client.go:428]      --> Start Quote
I0619 19:12:53.534271    3221 grpc_client.go:435]      PCR 0 Value 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f 
I0619 19:12:53.534408    3221 grpc_client.go:440]      ContextLoad (ek) ========
I0619 19:12:53.542087    3221 grpc_client.go:450]      LoadUsingAuth ========
I0619 19:12:53.545312    3221 grpc_client.go:472]      Read (akPub) ========
I0619 19:12:53.545506    3221 grpc_client.go:477]      Read (akPriv) ========
I0619 19:12:53.549847    3221 grpc_client.go:489]      AK keyName 000b45032d89f9b80d68ed913907c87ee8a045b2a9f47e6b7fb8d73a4eb110f83a0b
I0619 19:12:53.555528    3221 grpc_client.go:495]      Quote Hex ff54434780180022000b192ac22feeff9dd9a92355d5180a2b162ca4332944e31dc6a48c8f156834c23700036261720000000000070c8e000000090000000001201605110016280000000001000b0301000000202ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
I0619 19:12:53.555686    3221 grpc_client.go:496]      Quote Sig 717654f6344482db9652d1c441c27d673a2ebf0cb113bc9774b844636869650f8fa2e06e3dee55fbddd8b0de734a506f53f7772e7e1b5e472c8b27ce216759740b2149214d72cc3e545d29cc89bb27462041d01c820ff67174f12275fd46c2218d39916a22ec2fb52e57151f850ae477577fc4e481b877670cdf72b95916f58e9594805956a85e5da47fff9f6909382329c6ea4b9c8c21797bd8e7ef29f4ca775f0bcac7bcd6af907b9d78516b0b5e85c4bed356d2d32fd46cd6627ff673c5c5ccbd9a330832c140616ffb4b71a7ed9ea207e3d232b724b26311760dae1a5caa12487cb41601dab598feeafc71d564ed49f00f699a4074f3a068bbccdeb79ecb
I0619 19:12:53.555781    3221 grpc_client.go:497]      <-- End Quote
I0619 19:12:53.561174    3221 grpc_client.go:255]     Activate Credential Status true
I0619 19:12:53.561198    3221 grpc_client.go:264] ===============  Importing sealed AES Key ===============
I0619 19:12:53.561203    3221 grpc_client.go:304]      --> Starting importKey()
I0619 19:12:53.561208    3221 grpc_client.go:306]      Loading EndorsementKeyRSA
I0619 19:12:53.659489    3221 grpc_client.go:322]      <-- End importKey()
I0619 19:12:53.662270    3221 grpc_client.go:269]      Unsealed Secret G-KaPdSgUkXp2s5v8y/B?E(H+MbQeThW
I0619 19:12:53.662419    3221 grpc_client.go:274] =============== OfferQuote ===============
I0619 19:12:53.664170    3221 grpc_client.go:283]      Quote Requested with nonce 695c7576-0da8-452a-a1bd-4f5c61c38b91, pcr: 0
I0619 19:12:53.664191    3221 grpc_client.go:285] =============== Generating Quote ===============
I0619 19:12:53.664199    3221 grpc_client.go:428]      --> Start Quote
I0619 19:12:53.665823    3221 grpc_client.go:435]      PCR 0 Value 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f 
I0619 19:12:53.665837    3221 grpc_client.go:440]      ContextLoad (ek) ========
I0619 19:12:53.673250    3221 grpc_client.go:450]      LoadUsingAuth ========
I0619 19:12:53.676604    3221 grpc_client.go:472]      Read (akPub) ========
I0619 19:12:53.676797    3221 grpc_client.go:477]      Read (akPriv) ========
I0619 19:12:53.681106    3221 grpc_client.go:489]      AK keyName 000b45032d89f9b80d68ed913907c87ee8a045b2a9f47e6b7fb8d73a4eb110f83a0b
I0619 19:12:53.686947    3221 grpc_client.go:495]      Quote Hex ff54434780180022000b192ac22feeff9dd9a92355d5180a2b162ca4332944e31dc6a48c8f156834c237002436393563373537362d306461382d343532612d613162642d3466356336316333386239310000000000070d11000000090000000001201605110016280000000001000b0301000000202ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
I0619 19:12:53.687104    3221 grpc_client.go:496]      Quote Sig a5118b0d092471cc542f1a1af1d9ae28ce9dae87c94c1509bd277044145f965f716072b94b09f1039d266b06f91e4c17907e0eb16aad5f5b9f118b66bea80c4f1478dd3d0f8d3846848913a1f277be50cb1580eb2093692a34649876015495feae060b1096d3f237a31d7de21786da3a0ed49c6e9d1b07088dc2d00aab8ceda18905555d7dbf992708feea95bb210c5d2faa85098e268521398928373684c45fba36826b4fe1e6acaf40666d8bbf4223c411fdbc4ced8797275bb3796584c32a221b3682aa1c9baa4626b5dd3bab80f71b6947f813959d1b65156b7882dd9f5580c6a44971e95e1e96de0b972dc1e6f42a8490ce64e3263eaecae4d5ef2e31b9
I0619 19:12:53.687188    3221 grpc_client.go:497]      <-- End Quote
I0619 19:12:53.691335    3221 grpc_client.go:290] =============== Providing Quote ===============
I0619 19:12:53.693794    3221 grpc_client.go:300]      Provided Quote verified: true

```
Note the line on the client:

```log
    I0619 19:12:53.662270    3221 grpc_client.go:269]      Unsealed Secret G-KaPdSgUkXp2s5v8y/B?E(H+MbQeThW
```

What just happened is a symmetric key was transferred and decoded on the client using the TPM (we originally set the symmetric key to transfer on the grpc_server by setting the argument)


### RSA mode

In this mode, an RSA key that gets generated by a local CA on the server client's TPM.

This just simulates a CA cert that got created 'on demand' just for that given client TPM (the private key for this CA is `--cackey certs/CA_key.pem`)

#### Server

```log
$ go run src/grpc_server.go \
   --grpcport :50051 \
   -pcr 0 \
   -expectedPCRValue 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f \
   --secret bar \
   --importMode=RSA \
   --cacert  certs/CA_crt.pem \
   --cackey certs/CA_key.pem \
   --servercert certs/server_crt.pem \
   --serverkey certs/server_key.pem \
   --usemTLS \
   --v=10 -alsologtostderr 

    I0619 19:15:36.884741    2968 grpc_server.go:250] Using mTLS for initial server connection
    I0619 19:15:36.885785    2968 grpc_server.go:287] Starting gRPC server on port :50051
    I0619 19:15:46.793142    2968 grpc_server.go:156] >> authenticating inbound request
    I0619 19:15:46.793525    2968 grpc_server.go:318] OIDC doc has Audience [grpc://verify.esodemoapp2.com]   Issuer [https://accounts.google.com]
    I0619 19:15:46.793606    2968 grpc_server.go:182] HealthCheck called for Service [verifier.VerifierServer]
    I0619 19:15:47.103781    2968 grpc_server.go:156] >> authenticating inbound request
    I0619 19:15:47.104151    2968 grpc_server.go:318] OIDC doc has Audience [grpc://verify.esodemoapp2.com]   Issuer [https://accounts.google.com]
    I0619 19:15:47.104241    2968 grpc_server.go:326] ======= MakeCredential ========
    I0619 19:15:47.104329    2968 grpc_server.go:327]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
    I0619 19:15:47.104392    2968 grpc_server.go:328]      Got AKName 000b79cae2d62717730f9660995ef7c9ce7add71170832de1ce0637b6311330f5ec4
    I0619 19:15:47.104485    2968 grpc_server.go:329]      Registry size 0
    I0619 19:15:47.104540    2968 grpc_server.go:332]      From InstanceID 8698503547301626160
    I0619 19:15:47.226611    2968 grpc_server.go:347]      Acquired PublickKey from GCP API: 
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzUPZU9BXAUFpmZRZXyfp
    2+bfAfqjV3KwCRjsMQUQ9r49kA4MwZUnlih9DrTejYdca7vNvbV92SAcXVebGWWC
    T9Qyk4kwXNfem1gqK+70Cfgt68OUTZm4hDIVwrpk/7OIUdhWqm3N76JDrweaBie+
    16u4OF8njLdAY3FWx9JFqIjOAk0oESxKKPKYwNOBicPiha7S1jCp+CgBEwUJ3JEa
    Pa23eWwZOn2TdT+m+VXvfPL5QIEaIVgS8uF8IgR1LmW2a6R4qsa1AKzDnHK4FRAt
    ycE+OYlGfUDqPCUfW80ldv/FdzCyHHaM7pSXN+MDK1UMGhfN3fw+Zo55gt+E+P3d
    OQIDAQAB
    -----END PUBLIC KEY-----
    I0619 19:15:47.227192    2968 grpc_server.go:349]      Decoding ekPub from client
    I0619 19:15:47.227303    2968 grpc_server.go:370]      EKPubPEM: 
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzUPZU9BXAUFpmZRZXyfp
    2+bfAfqjV3KwCRjsMQUQ9r49kA4MwZUnlih9DrTejYdca7vNvbV92SAcXVebGWWC
    T9Qyk4kwXNfem1gqK+70Cfgt68OUTZm4hDIVwrpk/7OIUdhWqm3N76JDrweaBie+
    16u4OF8njLdAY3FWx9JFqIjOAk0oESxKKPKYwNOBicPiha7S1jCp+CgBEwUJ3JEa
    Pa23eWwZOn2TdT+m+VXvfPL5QIEaIVgS8uF8IgR1LmW2a6R4qsa1AKzDnHK4FRAt
    ycE+OYlGfUDqPCUfW80ldv/FdzCyHHaM7pSXN+MDK1UMGhfN3fw+Zo55gt+E+P3d
    OQIDAQAB
    -----END PUBLIC KEY-----
    I0619 19:15:47.227701    2968 grpc_server.go:376]      Verified EkPub from GCE API matches ekPub from Client
    I0619 19:15:47.227749    2968 grpc_server.go:562]      --> Starting makeCredential()
    I0619 19:15:47.227811    2968 grpc_server.go:563]      Read (ekPub) from request
    I0619 19:15:47.244017    2968 grpc_server.go:576]      Read (akPub) from request
    I0619 19:15:47.244193    2968 grpc_server.go:598]      Decoded AkPub: 
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArkaned3xqVmiRs76xOdS
    iENSXClBF6SKl5WCxCqVAdBe4aLEfqmeI6o80owgBaRLf+H+DSncPAymPSVpnzNx
    2sdxhfhamDPUwikZbuaOu7pdtPBNX4aLWyJuQSXy6F6ViAsG/mRciOnzSACfZkHo
    kgSTGLqtr5bCFvjjbEjOezWFl9yTm8AlenrrM6kcMlqnb4m4y4k2bp0ODKN8oQuY
    8AG80ZmeuI2lSmQdgD5Lgg2o0/AtuMKfdmSolcFhoHa+GOUAKIrCDqs4Vq534Uzs
    vWL54qa/S/6vHiLc2hy5/o5he4Ew1zrOm/8LrUz1yHdR1/XFIR4xm655JAj7Oicm
    PwIDAQAB
    -----END PUBLIC KEY-----
    I0619 19:15:47.244584    2968 grpc_server.go:601]      AK Default parameter match template
    I0619 19:15:47.247517    2968 grpc_server.go:610]      Loaded AK KeyName 000b79cae2d62717730f9660995ef7c9ce7add71170832de1ce0637b6311330f5ec4
    I0619 19:15:47.247592    2968 grpc_server.go:612]      MakeCredential Start
    I0619 19:15:47.250534    2968 grpc_server.go:618]      credBlob 00201821a033b3841a0ce60f2347a14ca66d9e69e9660c8a81db882166d96a0128da546420a4b7
    I0619 19:15:47.250600    2968 grpc_server.go:619]      encryptedSecret0 59ceca5c5c039005df437e773bc529b501515af0172582ddfdbc8fb31d8a48b08d6c48640f0e099703f02d1d045148d8891b3d1f2350789cc3bd7312a744667de90f0f24aeeddf371cb020b0a8fe7a61c6c961003ba0960d4936a8bb6a57a0290670ac033678b6392e0118bba84fe8c4d08ddbe5b69896bd2e1bb181356c1e3b30844d53fa46a2a9c4f3b5113afead86e9ba861eeb9f5d03817db575d9e7099ba419f0411a0a7e224b1682e88ce4daa3822729211e6da4141cec05235ffab32139a1cd70d2b61e4670d3274b8c7879ef760aa1b8937deced6b27bd29fa8f2a349be7f377af7fbcf2faff05cdada610f6ccd694fcefe09147fbca6b2f41ccffb9
    I0619 19:15:47.250658    2968 grpc_server.go:620]      <-- End makeCredential()
    I0619 19:15:47.253316    2968 grpc_server.go:388]      Returning MakeCredentialResponse ========
    I0619 19:15:48.311757    2968 grpc_server.go:156] >> authenticating inbound request
    I0619 19:15:48.311935    2968 grpc_server.go:318] OIDC doc has Audience [grpc://verify.esodemoapp2.com]   Issuer [https://accounts.google.com]
    I0619 19:15:48.311946    2968 grpc_server.go:399] ======= ActivateCredential ========
    I0619 19:15:48.311950    2968 grpc_server.go:400]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
    I0619 19:15:48.311954    2968 grpc_server.go:401]      Secret bar
    I0619 19:15:48.311959    2968 grpc_server.go:404]      From InstanceID 8698503547301626160
    I0619 19:15:48.311964    2968 grpc_server.go:503]      --> Starting verifyQuote()
    I0619 19:15:48.311969    2968 grpc_server.go:508]      Read and Decode (attestion)
    I0619 19:15:48.311989    2968 grpc_server.go:514]      Attestation ExtraData (nonce): bar 
    I0619 19:15:48.311996    2968 grpc_server.go:515]      Attestation PCR#: [0] 
    I0619 19:15:48.312017    2968 grpc_server.go:516]      Attestation Hash: 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f 
    I0619 19:15:48.312024    2968 grpc_server.go:533]      Expected PCR Value:           --> 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f
    I0619 19:15:48.312030    2968 grpc_server.go:534]      sha256 of Expected PCR Value: --> 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
    I0619 19:15:48.312038    2968 grpc_server.go:536]      Decoding PublicKey for AK ========
    I0619 19:15:48.312126    2968 grpc_server.go:555]      Attestation Signature Verified 
    I0619 19:15:48.312133    2968 grpc_server.go:556]      <-- End verifyQuote()
    I0619 19:15:48.312138    2968 grpc_server.go:418]      Verified Quote
    I0619 19:15:48.312143    2968 grpc_server.go:625]      --> Start generateCertificate()
    I0619 19:15:48.312147    2968 grpc_server.go:626]      Generating Certificate for cn=8698503547301626160
    I0619 19:15:48.312315    2968 grpc_server.go:641]      Generated cert with Serial 408254118850144987185943855269412930169279703308
    I0619 19:15:48.597722    2968 grpc_server.go:704]      Generating Test Signature with private Key
    I0619 19:15:48.600313    2968 grpc_server.go:713]      Test signature data:  GoTFPiEKfZp4GUmlom//5Zjr9oSl1pUsnLBgRK0Oed6Luv0GNa6lfhUf5MLwQy13A3Fe/xvjNHklHPPNhxyTfef3zxnfowm6iC1c4EV2bV8OB9iEWbrYB+3qODMbS0qtPOigl20HfmK4Elit0s5i2OG0LYLjFXLUumGLdzzjyXaj7CWezYzexDVjIEfPDw9ml3+Lu/mxE0fYiniQ5BLy7qk1+eNRstTkCWzZHHoAhRFm/5Agwaf9jtsdOE5FQOJhlAPeQtHMUfV4NvXCPZE9+LVwWsfqDFNhdGiedEtzROdggsb8bxW81JVJaweiYovIpJTvmkol0yJH1LF8MFu2wQ
    I0619 19:15:48.600385    2968 grpc_server.go:714]      <-- End generateCertificate()
    I0619 19:15:48.600443    2968 grpc_server.go:719]      --> Start createImportBlob()
    I0619 19:15:48.600490    2968 grpc_server.go:720]      Load and decode ekPub from registry
    I0619 19:15:48.600565    2968 grpc_server.go:733]      Decoding sealing PCR value in hex
    I0619 19:15:48.600627    2968 grpc_server.go:746]      --> createSigningKeyImportBlob()
    I0619 19:15:48.600670    2968 grpc_server.go:747]      Generating to RSA sealedFile
    I0619 19:15:48.600925    2968 grpc_server.go:761]      Returning sealed key
    I0619 19:15:48.601083    2968 grpc_server.go:783]      <-- End createImportBlob()
    I0619 19:15:48.601128    2968 grpc_server.go:434]      Returning ActivateCredentialResponse ========
    I0619 19:15:48.666236    2968 grpc_server.go:156] >> authenticating inbound request
    I0619 19:15:48.666497    2968 grpc_server.go:318] OIDC doc has Audience [grpc://verify.esodemoapp2.com]   Issuer [https://accounts.google.com]
    I0619 19:15:48.666559    2968 grpc_server.go:444] ======= OfferQuote ========
    I0619 19:15:48.666608    2968 grpc_server.go:445]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
    I0619 19:15:48.666663    2968 grpc_server.go:448]      From InstanceID 8698503547301626160
    I0619 19:15:48.666717    2968 grpc_server.go:457]      Returning OfferQuoteResponse ========
    I0619 19:15:48.694882    2968 grpc_server.go:156] >> authenticating inbound request
    I0619 19:15:48.695187    2968 grpc_server.go:318] OIDC doc has Audience [grpc://verify.esodemoapp2.com]   Issuer [https://accounts.google.com]
    I0619 19:15:48.695279    2968 grpc_server.go:467] ======= ProvideQuote ========
    I0619 19:15:48.695336    2968 grpc_server.go:468]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
    I0619 19:15:48.695387    2968 grpc_server.go:471]      From InstanceID 8698503547301626160
    I0619 19:15:48.695449    2968 grpc_server.go:503]      --> Starting verifyQuote()
    I0619 19:15:48.695488    2968 grpc_server.go:508]      Read and Decode (attestion)
    I0619 19:15:48.695553    2968 grpc_server.go:514]      Attestation ExtraData (nonce): 86386f6a-e38c-4b63-99bd-f576041233a1 
    I0619 19:15:48.695680    2968 grpc_server.go:515]      Attestation PCR#: [0] 
    I0619 19:15:48.695738    2968 grpc_server.go:516]      Attestation Hash: 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f 
    I0619 19:15:48.695817    2968 grpc_server.go:533]      Expected PCR Value:           --> 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f
    I0619 19:15:48.695877    2968 grpc_server.go:534]      sha256 of Expected PCR Value: --> 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
    I0619 19:15:48.695934    2968 grpc_server.go:536]      Decoding PublicKey for AK ========
    I0619 19:15:48.696096    2968 grpc_server.go:555]      Attestation Signature Verified 
    I0619 19:15:48.696171    2968 grpc_server.go:556]      <-- End verifyQuote()
    I0619 19:15:48.696229    2968 grpc_server.go:495]      Returning ProvideQuoteResponse ========
```


#### Client

```log
$ go run src/grpc_client.go \
  --uid 369c327d-ad1f-401c-aa91-d9b0e69bft67 \
  --unsealPcr=0 \
  --host verify.esodemoapp2.com:50051 \
  --importMode=RSA \
  --cacert certs/CA_crt.pem  \
  --clientcert certs/client_crt.pem \
  --clientkey certs/client_key.pem \
  --usemTLS \
  --v=10 -alsologtostderr 

    I0619 19:15:46.758839    3254 grpc_client.go:160] Using mTLS
    I0619 19:15:46.782238    3254 grpc_client.go:189] Acquired OIDC: eyJhbGciOiJSUzI1NiIsImtpZCI6IjE5ZmUyYTdiNjc5NTIzOTYwNmNhMGE3NTA3OTRhN2JkOWZkOTU5NjEiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJncnBjOi8vdmVyaWZ5LmVzb2RlbW9hcHAyLmNvbSIsImF6cCI6IjExMzczNzQ2NjAzNDMxNDg4MDgzNyIsImVtYWlsIjoidHBtLWNsaWVudEBtaW5lcmFsLW1pbnV0aWEtODIwLmlhbS5nc2VydmljZWFjY291bnQuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImV4cCI6MTYyNDEzMzc0NiwiZ29vZ2xlIjp7ImNvbXB1dGVfZW5naW5lIjp7Imluc3RhbmNlX2NyZWF0aW9uX3RpbWVzdGFtcCI6MTYyNDEyOTUwNCwiaW5zdGFuY2VfaWQiOiI4Njk4NTAzNTQ3MzAxNjI2MTYwIiwiaW5zdGFuY2VfbmFtZSI6ImNsaWVudCIsInByb2plY3RfaWQiOiJtaW5lcmFsLW1pbnV0aWEtODIwIiwicHJvamVjdF9udW1iZXIiOjEwNzEyODQxODQ0MzYsInpvbmUiOiJ1cy1jZW50cmFsMS1hIn19LCJpYXQiOjE2MjQxMzAxNDYsImlzcyI6Imh0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbSIsInN1YiI6IjExMzczNzQ2NjAzNDMxNDg4MDgzNyJ9.q4mJQjOMNj0ddN24D0yVv7Was3aYaSM9LX01YUdOoghYbt7_0_C3Uib20WYKCjlYM52ukP7dTim8nW05TkggcVJp5aaOg05iLsJjiuTqy7t-pGpwnrviT2YrWdK4y-lI2Hzb8QbIgOJEEgzVHTvzP3Nj-XILee8tXvoNsByIaQdCEoDEPmtrogWOwh2Afx5huPVNSkFZt1lG_cK8IwxB5JiirlBFMJNGHIo2hhcC8eCUBGxcmWJ8a9_5E4-NguE-VgpK0LrOy9-8P8MwtDU2cEKAN0r9nouX_CCVpCvDQSPA3z1tgm86PaNm28XL1JzEL-GW90aQ368ExdiviH-4ng
    I0619 19:15:46.795314    3254 grpc_client.go:211] RPC HealthChekStatus:SERVING
    I0619 19:15:46.795483    3254 grpc_client.go:215] =============== MakeCredential ===============
    I0619 19:15:46.795564    3254 grpc_client.go:503]      --> CreateKeys()
    I0619 19:15:46.797409    3254 grpc_client.go:510]     Current PCR 0 Value %!d(string=24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f) 
    I0619 19:15:46.797519    3254 grpc_client.go:515]      createPrimary
    I0619 19:15:46.863062    3254 grpc_client.go:533]      tpmEkPub: 
    &{25912310074943480149737721308652377707854331362286193336728975248218541504080645993034560950975678532399513056308880417062110199079068652544142172301399725683268294732506196458137181173829606931841286764807519567032235006983873124002844906686926862393624844965800853567065877551555305788110047793379315987357891361132820525731803348160648899878161445715059780892112579551730826413790896942672502847230969215606156056838830702783927285766757803311828211918865358810151675418391724366492168693939686462882813953515060021765009342298258356048119007954374065947131929181833428757497901831343369824695032110355878755818809 65537}
    I0619 19:15:46.863428    3254 grpc_client.go:546]      ekPub Name: 000b09aa66898e4a813be929f1ad9a8e7bcf8f877656a6be91fffc138a969f7e5a58
    I0619 19:15:46.863516    3254 grpc_client.go:547]      ekPubPEM: 
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzUPZU9BXAUFpmZRZXyfp
    2+bfAfqjV3KwCRjsMQUQ9r49kA4MwZUnlih9DrTejYdca7vNvbV92SAcXVebGWWC
    T9Qyk4kwXNfem1gqK+70Cfgt68OUTZm4hDIVwrpk/7OIUdhWqm3N76JDrweaBie+
    16u4OF8njLdAY3FWx9JFqIjOAk0oESxKKPKYwNOBicPiha7S1jCp+CgBEwUJ3JEa
    Pa23eWwZOn2TdT+m+VXvfPL5QIEaIVgS8uF8IgR1LmW2a6R4qsa1AKzDnHK4FRAt
    ycE+OYlGfUDqPCUfW80ldv/FdzCyHHaM7pSXN+MDK1UMGhfN3fw+Zo55gt+E+P3d
    OQIDAQAB
    -----END PUBLIC KEY-----
    I0619 19:15:46.864086    3254 grpc_client.go:554]      CreateKeyUsingAuth
    I0619 19:15:47.070226    3254 grpc_client.go:580]      akPub: 0001000b00050072000000100014000b0800000000000100ae46a779ddf1a959a246cefac4e7528843525c294117a48a979582c42a9501d05ee1a2c47ea99e23aa3cd28c2005a44b7fe1fe0d29dc3c0ca63d25699f3371dac77185f85a9833d4c229196ee68ebbba5db4f04d5f868b5b226e4125f2e85e95880b06fe645c88e9f348009f6641e892049318baadaf96c216f8e36c48ce7b358597dc939bc0257a7aeb33a91c325aa76f89b8cb89366e9d0e0ca37ca10b98f001bcd1999eb88da54a641d803e4b820da8d3f02db8c29f7664a895c161a076be18e500288ac20eab3856ae77e14cecbd62f9e2a6bf4bfeaf1e22dcda1cb9fe8e617b8130d73ace9bff0bad4cf5c87751d7f5c5211e319bae792408fb3a27263f,
    I0619 19:15:47.070399    3254 grpc_client.go:581]      akPriv: 00204460f811e5f40bf698f00392ec0bc356b4cf874798554488f61b2251cdbd422300108afc447124f5165742b9e5ea470adcf945abdb96f1ea4dd21f9607a8907bf48db72dc2e37508be20d9855af4ed40b52166ef768043b2c0a8c8a0f4eefb161037e267e9d3980738f8dd829913c2e2c3620a3cf097b20c2de448ce905bf76171a89b72546a9464cc8d6ea8e94ce4187874c52fd54e2b2d1a9565939d6ef0fb8a60cd9c234e8e1665deac300de8b25c59f6ebaab95c21383be1d154fe5d5603d38d879890b122304b629ede9575f03f072d274902e43393cd3709f7,
    I0619 19:15:47.070508    3254 grpc_client.go:588]      CredentialData.ParentName.Digest.Value 09aa66898e4a813be929f1ad9a8e7bcf8f877656a6be91fffc138a969f7e5a58
    I0619 19:15:47.070584    3254 grpc_client.go:589]      CredentialTicket 6a287b12dbef7c7c87660de77e1ff503d96fa4d1eb5435c5c4c65868619c9bc7
    I0619 19:15:47.070657    3254 grpc_client.go:590]      CredentialHash e77321cc3f6a0c1976bb73016fa0072bd8e2742f92748ec8ff124564a50f9d37
    I0619 19:15:47.070738    3254 grpc_client.go:592]      ContextSave (ek)
    I0619 19:15:47.079641    3254 grpc_client.go:603]      ContextLoad (ek)
    I0619 19:15:47.086921    3254 grpc_client.go:613]      LoadUsingAuth
    I0619 19:15:47.093523    3254 grpc_client.go:641]      AK keyName 000b79cae2d62717730f9660995ef7c9ce7add71170832de1ce0637b6311330f5ec4
    I0619 19:15:47.096627    3254 grpc_client.go:663]      akPubPEM: 
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArkaned3xqVmiRs76xOdS
    iENSXClBF6SKl5WCxCqVAdBe4aLEfqmeI6o80owgBaRLf+H+DSncPAymPSVpnzNx
    2sdxhfhamDPUwikZbuaOu7pdtPBNX4aLWyJuQSXy6F6ViAsG/mRciOnzSACfZkHo
    kgSTGLqtr5bCFvjjbEjOezWFl9yTm8AlenrrM6kcMlqnb4m4y4k2bp0ODKN8oQuY
    8AG80ZmeuI2lSmQdgD5Lgg2o0/AtuMKfdmSolcFhoHa+GOUAKIrCDqs4Vq534Uzs
    vWL54qa/S/6vHiLc2hy5/o5he4Ew1zrOm/8LrUz1yHdR1/XFIR4xm655JAj7Oicm
    PwIDAQAB
    -----END PUBLIC KEY-----
    I0619 19:15:47.097197    3254 grpc_client.go:665]      Write (akPub) ========
    I0619 19:15:47.097405    3254 grpc_client.go:670]      Write (akPriv) ========
    I0619 19:15:47.097552    3254 grpc_client.go:676]      <-- CreateKeys()
    I0619 19:15:48.254144    3254 grpc_client.go:232]      MakeCredential RPC Response with provided uid [369c327d-ad1f-401c-aa91-d9b0e69bft67]
    I0619 19:15:48.254192    3254 grpc_client.go:234] =============== ActivateCredential  ===============
    I0619 19:15:48.254200    3254 grpc_client.go:682]      --> activateCredential()
    I0619 19:15:48.254206    3254 grpc_client.go:684]      ContextLoad (ek)
    I0619 19:15:48.261848    3254 grpc_client.go:695]      Read (akPub)
    I0619 19:15:48.262129    3254 grpc_client.go:700]      Read (akPriv)
    I0619 19:15:48.262222    3254 grpc_client.go:706]      LoadUsingAuth
    I0619 19:15:48.269653    3254 grpc_client.go:733]      keyName 000b79cae2d62717730f9660995ef7c9ce7add71170832de1ce0637b6311330f5ec4
    I0619 19:15:48.269861    3254 grpc_client.go:735]      ActivateCredentialUsingAuth
    I0619 19:15:48.281273    3254 grpc_client.go:783]      <--  activateCredential()
    I0619 19:15:48.287025    3254 grpc_client.go:428]      --> Start Quote
    I0619 19:15:48.287832    3254 grpc_client.go:435]      PCR 0 Value 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f 
    I0619 19:15:48.287926    3254 grpc_client.go:440]      ContextLoad (ek) ========
    I0619 19:15:48.295663    3254 grpc_client.go:450]      LoadUsingAuth ========
    I0619 19:15:48.299033    3254 grpc_client.go:472]      Read (akPub) ========
    I0619 19:15:48.299233    3254 grpc_client.go:477]      Read (akPriv) ========
    I0619 19:15:48.303620    3254 grpc_client.go:489]      AK keyName 000b79cae2d62717730f9660995ef7c9ce7add71170832de1ce0637b6311330f5ec4
    I0619 19:15:48.310048    3254 grpc_client.go:495]      Quote Hex ff54434780180022000b1283470d3ca0a8cbd42d5a61adb142c7cf1dbf690d4dc4c04dd6edf88abb0d1c0003626172000000000009b72f000000090000000001201605110016280000000001000b0301000000202ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
    I0619 19:15:48.310207    3254 grpc_client.go:496]      Quote Sig 7d8e6246cef4ad0c0730dc7203063ad99ace939f6b9f471bb72c779316cd64c26caf726fbe67f5c5442698a12000488c6585487b1fe7d9f442c07bb5a2be2c6612352250546630e53c725112d2ae6e76c5fc4c5e2c31aee4fb8d18d55210f660719f52b8ffef20d5718cf16b0b0fde410d780f4415afb2be2872a9f7d2bb2e3d8d2d9b3cea14b009f74cb12d9105267af23c446b56e1cc2ae1612bb7aca78413fb9034e6a37bb2ffaa7513513b8754b8f96ee996e9983aa5b28f1ded839affc1e3912f9dfaaf3f913b65d9e48ceb68d0a89613aff3e933419665cf708c3916f14688ce696286ff2b276804d10bb1b7798adc3201f596b4cd0844526ff4589dd6
    I0619 19:15:48.310286    3254 grpc_client.go:497]      <-- End Quote
    I0619 19:15:48.601721    3254 grpc_client.go:255]     Activate Credential Status true
    I0619 19:15:48.601753    3254 grpc_client.go:258] ===============  Importing sealed RSA Key ===============
    I0619 19:15:48.601759    3254 grpc_client.go:328]      --> Starting importRSAKey()
    I0619 19:15:48.601765    3254 grpc_client.go:330]      Loading EndorsementKeyRSA
    I0619 19:15:48.607057    3254 grpc_client.go:337]      Loading sealedkey
    I0619 19:15:48.607411    3254 grpc_client.go:345]      Loading ImportSigningKey
    I0619 19:15:48.630074    3254 grpc_client.go:364]      Imported keyPublic portion: 
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtgVYudeClFrvD4fb3mSh
    VyhBJscmgfqEFr2lVwHB9JaljOBw9lOOj0T3TNgNcy5kSTmAQAPBYtz9OuXwYeVT
    t5tsOzs5cTODr73g52Zr3gLmH8asptcQYAV9XbX8bsxemheQguekrZhErdpcLFp1
    WDFJgxDvGz/MMYQ0PsVco2hbdPbqhS/khyYI62PdDlYppRl7bv/762PgJpv+9OsA
    mm3Xj3eJG4FZNQpQSybNX0ZMabNiTvesQjZ4jik/wdtEj6IHMZi2U0aL1pg2Gij0
    pDdil3U1dhgdymJSp+BIXHrIDhpvrj6sW0Jp6I7rWmmGdj3cdFJVGqsi7GNAsfJf
    cwIDAQAB
    -----END PUBLIC KEY-----
    I0619 19:15:48.630659    3254 grpc_client.go:366]      Saving Key Handle as importedKey.bin
    I0619 19:15:48.640070    3254 grpc_client.go:379]      Loading Key Handle
    I0619 19:15:48.640228    3254 grpc_client.go:381]      ContextLoad (importedKey.bin) ========
    I0619 19:15:48.647565    3254 grpc_client.go:392]     Generating Test Signature ========
    I0619 19:15:48.655930    3254 grpc_client.go:421]      Test Signature data:  GoTFPiEKfZp4GUmlom//5Zjr9oSl1pUsnLBgRK0Oed6Luv0GNa6lfhUf5MLwQy13A3Fe/xvjNHklHPPNhxyTfef3zxnfowm6iC1c4EV2bV8OB9iEWbrYB+3qODMbS0qtPOigl20HfmK4Elit0s5i2OG0LYLjFXLUumGLdzzjyXaj7CWezYzexDVjIEfPDw9ml3+Lu/mxE0fYiniQ5BLy7qk1+eNRstTkCWzZHHoAhRFm/5Agwaf9jtsdOE5FQOJhlAPeQtHMUfV4NvXCPZE9+LVwWsfqDFNhdGiedEtzROdggsb8bxW81JVJaweiYovIpJTvmkol0yJH1LF8MFu2wQ
    I0619 19:15:48.656080    3254 grpc_client.go:422]      <-- End importRSAKey()
    I0619 19:15:48.665660    3254 grpc_client.go:274] =============== OfferQuote ===============
    I0619 19:15:48.667086    3254 grpc_client.go:283]      Quote Requested with nonce 86386f6a-e38c-4b63-99bd-f576041233a1, pcr: 0
    I0619 19:15:48.667109    3254 grpc_client.go:285] =============== Generating Quote ===============
    I0619 19:15:48.667115    3254 grpc_client.go:428]      --> Start Quote
    I0619 19:15:48.668728    3254 grpc_client.go:435]      PCR 0 Value 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f 
    I0619 19:15:48.668747    3254 grpc_client.go:440]      ContextLoad (ek) ========
    I0619 19:15:48.676273    3254 grpc_client.go:450]      LoadUsingAuth ========
    I0619 19:15:48.679461    3254 grpc_client.go:472]      Read (akPub) ========
    I0619 19:15:48.679618    3254 grpc_client.go:477]      Read (akPriv) ========
    I0619 19:15:48.683904    3254 grpc_client.go:489]      AK keyName 000b79cae2d62717730f9660995ef7c9ce7add71170832de1ce0637b6311330f5ec4
    I0619 19:15:48.690096    3254 grpc_client.go:495]      Quote Hex ff54434780180022000b1283470d3ca0a8cbd42d5a61adb142c7cf1dbf690d4dc4c04dd6edf88abb0d1c002438363338366636612d653338632d346236332d393962642d663537363034313233336131000000000009b8ac000000090000000001201605110016280000000001000b0301000000202ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
    I0619 19:15:48.690263    3254 grpc_client.go:496]      Quote Sig 25f3243115b199b9f0a07fd7ecbc6ab5ceb175aac8abd1e7c2a124f1ad92dd5b8c86ae0de41741347644c6acc636a336af23cd0b7eec92cec2d3a792e7d664c834fbddd29499eb345ece8929ebc7d90cc2774b0128c11bf4c3b6dd74740acd1fd3e5c58e552863f00ed57f0481b21aba1872c6ea4880d7ba7d810b3b24cb3cde4190989dda7379ca0537174cf8f24e88ce5b0bf65629ba781bf69a3a68d70bc6d0c60f463585074530cd6ab81f00107c5d46bced9bfd4f71e2795408af9eb1bdd648d0f948aa82ee280b5843a60714eec3041f5a15dfc0fb626421b0ac2acd281841ea1b0a687ff478870198eec138f8d58651fb2cfb9a7d87fd5de0111ec32d
    I0619 19:15:48.690348    3254 grpc_client.go:497]      <-- End Quote
    I0619 19:15:48.694125    3254 grpc_client.go:290] =============== Providing Quote ===============
    I0619 19:15:48.696683    3254 grpc_client.go:300]      Provided Quote verified: true
```


Note the signatures on both the client and server match for a for the signature of a sample control string ("secret")


```log
    I0619 19:15:48.600313    2968 grpc_server.go:713]      Test signature data:  GoTFPiEKfZp4GUmlom//5Zjr9oSl1pUsnLBgRK0Oed6Luv0GNa6lfhUf5MLwQy13A3Fe/xvjNHklHPPNhxyTfef3zxnfowm6iC1c4EV2bV8OB9iEWbrYB+3qODMbS0qtPOigl20HfmK4Elit0s5i2OG0LYLjFXLUumGLdzzjyXaj7CWezYzexDVjIEfPDw9ml3+Lu/mxE0fYiniQ5BLy7qk1+eNRstTkCWzZHHoAhRFm/5Agwaf9jtsdOE5FQOJhlAPeQtHMUfV4NvXCPZE9+LVwWsfqDFNhdGiedEtzROdggsb8bxW81JVJaweiYovIpJTvmkol0yJH1LF8MFu2wQ

---

    I0619 19:15:48.655930    3254 grpc_client.go:421]      Test Signature data:  GoTFPiEKfZp4GUmlom//5Zjr9oSl1pUsnLBgRK0Oed6Luv0GNa6lfhUf5MLwQy13A3Fe/xvjNHklHPPNhxyTfef3zxnfowm6iC1c4EV2bV8OB9iEWbrYB+3qODMbS0qtPOigl20HfmK4Elit0s5i2OG0LYLjFXLUumGLdzzjyXaj7CWezYzexDVjIEfPDw9ml3+Lu/mxE0fYiniQ5BLy7qk1+eNRstTkCWzZHHoAhRFm/5Agwaf9jtsdOE5FQOJhlAPeQtHMUfV4NvXCPZE9+LVwWsfqDFNhdGiedEtzROdggsb8bxW81JVJaweiYovIpJTvmkol0yJH1LF8MFu2wQ
```

Also note that on the client, `importedKey.bin` was created.   

This file is just the TPM Handle to the embedded RSA key.  You can use `go-tpm` library to reread this file and sign for some data


```bash
$ ls
CA_crt.pem  akPriv.bin  akPub.bin  client_crt.pem  client_key.pem  ek.bin  grpc_client  importedKey.bin
```

### Applications

This is just an academic exercise (so do not use the code as is).   However, some applications of this

* RSA

- [TPM based Google Service Account Credentials](https://github.com/salrashid123/oauth2#usage-tpmtokensource)
- [TPM based mTLS](https://github.com/salrashid123/signer#usage-tls)

* AES

- [LUKS Encryption Key](https://medium.com/@salmaan.rashid/mounting-luks-encrypted-disks-using-google-secrets-manager-3eb173920a75)


#### Appendix

To  [Install tpm2_tools](https://github.com/salrashid123/tpm2#installing-tpm2_tools-golang)


To Changing PCR values, use either `go-tpm` or `tpm2_tools`:

- [tpm2_pcrextend](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_pcrextend.1.md)

