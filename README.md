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

```bash
$ gcloud compute  instances create client \
  --service-account=$CLIENT_SERVICE_ACCOUNT \
  --scopes=email  --image=ubuntu-1804-bionic-v20200317 \
  --machine-type "n1-standard-1" --image-project=gce-uefi-images \
  --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring  \
  --zone us-central1-a --tags=client


$ gcloud compute  instances create server \
  --service-account=$SERVER_SERVICE_ACCOUNT \
  --scopes=compute-ro,email  --image=ubuntu-1804-bionic-v20200317 \
  --machine-type "n1-standard-1" --image-project=gce-uefi-images \
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

on the server, start the grpc service.  Instruct it to seal against `pcr=0` on the client and expect its value to be `fcecb56acc303862b30eb342c4990beb50b5e0ab89722449c2d9a73f37b019fe`.

Note, that PCR value is the default PCR=0 value for a Google Compute Shielded VM


The following will start the gRPC Server and will seal and transfer an AES key to the client

```log
gcloud compute ssh server

$ go run src/grpc_server.go \
   --grpcport :50051 -pcr 0 \
   -secret bar \
   -aes256Key "G-KaPdSgUkXp2s5v8y/B?E(H+MbQeThW" \
   -expectedPCRValue fcecb56acc303862b30eb342c4990beb50b5e0ab89722449c2d9a73f37b019fe \
   --importMode=AES \
   --cacert  certs/CA_crt.pem  \
   --servercert certs/server_crt.pem \
   --serverkey certs/server_key.pem \
   --usemTLS \
   --v=10 -alsologtostderr 

      I0205 00:23:20.492011    3254 grpc_server.go:287] Starting gRPC server on port :50051
      I0205 00:23:25.329113    3254 grpc_server.go:156] >> authenticating inbound request
      I0205 00:23:25.329839    3254 grpc_server.go:318] OIDC doc has Audience [grpc://verify.esodemoapp2.com]   Issuer [https://accounts.google.com]
      I0205 00:23:25.329913    3254 grpc_server.go:182] HealthCheck called for Service [verifier.VerifierServer]
      I0205 00:23:25.818095    3254 grpc_server.go:156] >> authenticating inbound request
      I0205 00:23:25.818520    3254 grpc_server.go:318] OIDC doc has Audience [grpc://verify.esodemoapp2.com]   Issuer [https://accounts.google.com]
      I0205 00:23:25.818607    3254 grpc_server.go:326] ======= MakeCredential ========
      I0205 00:23:25.818666    3254 grpc_server.go:327]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
      I0205 00:23:25.818720    3254 grpc_server.go:328]      Got AKName 000beaa6d8583351a9efa5963928732d8f43f74cc1b4a1eec175b5b6ebb0b2595237
      I0205 00:23:25.818763    3254 grpc_server.go:329]      Registry size 0
      I0205 00:23:25.818818    3254 grpc_server.go:332]      From InstanceID 2219313109459351986
      I0205 00:23:25.957014    3254 grpc_server.go:347]      Acquired PublickKey from GCP API: 
      -----BEGIN PUBLIC KEY-----
      MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1/KqpvuKcaUIln6grsx9
      R0k2QD0UdU26CH24K4nCqWQaKm0ooN1kVKey9twkbk4Tw4Lem74ODwaN4bScs6OQ
      a8kJ40Oh7P4LmFvjD4o43BxFQLLE/DUUDXKujwDk/OlsTzU4doHhkniVk34mzoPM
      FtnE7cx8cWVi4a2q3X+q6351kfAmzcD+4FUtiaikTK3DyYk/V/jz1anCRw6FY0pb
      KKikTy1+mae+Ed6rex8IjqsS0Ez7nR2oktaamiTx1h4O2ANNYHO0OFklPrrtlY2Q
      0VNQ5wYd65vgZTv53QeLYrPJGw585W98WuT9d3p3hbDODdz8Zl3AHPO8Ru5Sd0NR
      AQIDAQAB
      -----END PUBLIC KEY-----
      I0205 00:23:25.957705    3254 grpc_server.go:349]      Decoding ekPub from client
      I0205 00:23:25.957831    3254 grpc_server.go:370]      EKPubPEM: 
      -----BEGIN PUBLIC KEY-----
      MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1/KqpvuKcaUIln6grsx9
      R0k2QD0UdU26CH24K4nCqWQaKm0ooN1kVKey9twkbk4Tw4Lem74ODwaN4bScs6OQ
      a8kJ40Oh7P4LmFvjD4o43BxFQLLE/DUUDXKujwDk/OlsTzU4doHhkniVk34mzoPM
      FtnE7cx8cWVi4a2q3X+q6351kfAmzcD+4FUtiaikTK3DyYk/V/jz1anCRw6FY0pb
      KKikTy1+mae+Ed6rex8IjqsS0Ez7nR2oktaamiTx1h4O2ANNYHO0OFklPrrtlY2Q
      0VNQ5wYd65vgZTv53QeLYrPJGw585W98WuT9d3p3hbDODdz8Zl3AHPO8Ru5Sd0NR
      AQIDAQAB
      -----END PUBLIC KEY-----
      I0205 00:23:25.958226    3254 grpc_server.go:376]      Verified EkPub from GCE API matches ekPub from Client
      I0205 00:23:25.958270    3254 grpc_server.go:562]      --> Starting makeCredential()
      I0205 00:23:25.958330    3254 grpc_server.go:563]      Read (ekPub) from request
      I0205 00:23:25.970948    3254 grpc_server.go:576]      Read (akPub) from request
      I0205 00:23:25.971145    3254 grpc_server.go:598]      Decoded AkPub: 
      -----BEGIN PUBLIC KEY-----
      MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5+jOtn42nQjAsS2O+NZp
      wiU4707JM3VtmVrl6l7rNZn35EwKLitPI8S3U/pUKwh6kJlkXyiii1zmTay4riNG
      3raQ0pUqRUljUQ/EB1ZlaW2Nm5+UycUaUsFU1FOuNqCapqCI6IqZVcCHCu8oXB00
      49J6ay0RF72fdI4KJZASt8cclUhO8WhrLb/1uB/6fNx7wKPhVpGWHZEGPmysqGAr
      BJQS39qvowksvLSQefvNCereLsj5Mxs7o54Qph7xZ8vD4Km6dgFU9JuNk/eZEkry
      nuvrL1Ja9xe0lvo3IDJ+uEsT0AL8YrGJc1JFzw8iCMYQkPzm55Kpfbd+U2VEdjMp
      xwIDAQAB
      -----END PUBLIC KEY-----
      I0205 00:23:25.971629    3254 grpc_server.go:601]      AK Default parameter match template
      I0205 00:23:25.974979    3254 grpc_server.go:610]      Loaded AK KeyName 000beaa6d8583351a9efa5963928732d8f43f74cc1b4a1eec175b5b6ebb0b2595237
      I0205 00:23:25.975092    3254 grpc_server.go:612]      MakeCredential Start
      I0205 00:23:25.978825    3254 grpc_server.go:618]      credBlob 00206e1fa6bbf4d18e14de1b172461bb60bf8342b759a3f4243e0a0f1813615b31fb45263f4b1d
      I0205 00:23:25.978963    3254 grpc_server.go:619]      encryptedSecret0 54fc5874fbb3175424d8d9e53617dec0b7e67c4558fc6da8d656a8cc2e26cbab890ca739aa79d45b4e0997d2c31cc172906a6b3081c4a0a81533f49925331989ace331889559f8a35ec60d435f6231af2ff1f138c621111c417250a6c0b5737418b80000eb4dcc2a273b7e9628570659f978a5957803a6e7e75ddf29ca6f372c7ba0558651dfd67dbc7131f3933ca68206dee41ea50c3c7bacc6b6a2bd4b7e4e8980598fa969af25ee75c7b52ff81aece4111eff6654bf296579523660e3a0c33f5b8ddcdec09e24527f0a130711a47f559d2f486443811cb1c37d6e1fb924637475dcfda1dc7f6cc6872775b6d86e8055055823dcc1235f0a617afa3b8e3c4f
      I0205 00:23:25.979042    3254 grpc_server.go:620]      <-- End makeCredential()
      I0205 00:23:25.981774    3254 grpc_server.go:388]      Returning MakeCredentialResponse ========
      I0205 00:23:27.070809    3254 grpc_server.go:156] >> authenticating inbound request
      I0205 00:23:27.071252    3254 grpc_server.go:318] OIDC doc has Audience [grpc://verify.esodemoapp2.com]   Issuer [https://accounts.google.com]
      I0205 00:23:27.071333    3254 grpc_server.go:399] ======= ActivateCredential ========
      I0205 00:23:27.071381    3254 grpc_server.go:400]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
      I0205 00:23:27.071430    3254 grpc_server.go:401]      Secret bar
      I0205 00:23:27.071471    3254 grpc_server.go:404]      From InstanceID 2219313109459351986
      I0205 00:23:27.071527    3254 grpc_server.go:503]      --> Starting verifyQuote()
      I0205 00:23:27.071571    3254 grpc_server.go:508]      Read and Decode (attestion)
      I0205 00:23:27.071647    3254 grpc_server.go:514]      Attestation ExtraData (nonce): bar 
      I0205 00:23:27.071699    3254 grpc_server.go:515]      Attestation PCR#: [0] 
      I0205 00:23:27.071771    3254 grpc_server.go:516]      Attestation Hash: 00e0758c418aff8b359dbcf0fb9af040ca15e973b02e5630b5dca1775c7e130a 
      I0205 00:23:27.071824    3254 grpc_server.go:533]      Expected PCR Value:           --> fcecb56acc303862b30eb342c4990beb50b5e0ab89722449c2d9a73f37b019fe
      I0205 00:23:27.071891    3254 grpc_server.go:534]      sha256 of Expected PCR Value: --> 00e0758c418aff8b359dbcf0fb9af040ca15e973b02e5630b5dca1775c7e130a
      I0205 00:23:27.071959    3254 grpc_server.go:536]      Decoding PublicKey for AK ========
      I0205 00:23:27.072128    3254 grpc_server.go:555]      Attestation Signature Verified 
      I0205 00:23:27.072182    3254 grpc_server.go:556]      <-- End verifyQuote()
      I0205 00:23:27.072222    3254 grpc_server.go:418]      Verified Quote
      I0205 00:23:27.072287    3254 grpc_server.go:719]      --> Start createImportBlob()
      I0205 00:23:27.072340    3254 grpc_server.go:720]      Load and decode ekPub from registry
      I0205 00:23:27.072395    3254 grpc_server.go:733]      Decoding sealing PCR value in hex
      I0205 00:23:27.072470    3254 grpc_server.go:769]      --> createImportBlob()
      I0205 00:23:27.072539    3254 grpc_server.go:770]      Generating to AES sealedFile
      I0205 00:23:27.072880    3254 grpc_server.go:783]      <-- End createImportBlob()
      I0205 00:23:27.072957    3254 grpc_server.go:434]      Returning ActivateCredentialResponse ========
      I0205 00:23:27.111150    3254 grpc_server.go:156] >> authenticating inbound request
      I0205 00:23:27.111563    3254 grpc_server.go:318] OIDC doc has Audience [grpc://verify.esodemoapp2.com]   Issuer [https://accounts.google.com]
      I0205 00:23:27.111650    3254 grpc_server.go:444] ======= OfferQuote ========
      I0205 00:23:27.111707    3254 grpc_server.go:445]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
      I0205 00:23:27.111776    3254 grpc_server.go:448]      From InstanceID 2219313109459351986
      I0205 00:23:27.111823    3254 grpc_server.go:457]      Returning OfferQuoteResponse ========
      I0205 00:23:27.148483    3254 grpc_server.go:156] >> authenticating inbound request
      I0205 00:23:27.148961    3254 grpc_server.go:318] OIDC doc has Audience [grpc://verify.esodemoapp2.com]   Issuer [https://accounts.google.com]
      I0205 00:23:27.149054    3254 grpc_server.go:467] ======= ProvideQuote ========
      I0205 00:23:27.149105    3254 grpc_server.go:468]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
      I0205 00:23:27.149152    3254 grpc_server.go:471]      From InstanceID 2219313109459351986
      I0205 00:23:27.149209    3254 grpc_server.go:503]      --> Starting verifyQuote()
      I0205 00:23:27.149249    3254 grpc_server.go:508]      Read and Decode (attestion)
      I0205 00:23:27.149325    3254 grpc_server.go:514]      Attestation ExtraData (nonce): 804c662b-b464-4eb5-9c67-1077f02c67c4 
      I0205 00:23:27.149380    3254 grpc_server.go:515]      Attestation PCR#: [0] 
      I0205 00:23:27.149426    3254 grpc_server.go:516]      Attestation Hash: 00e0758c418aff8b359dbcf0fb9af040ca15e973b02e5630b5dca1775c7e130a 
      I0205 00:23:27.149491    3254 grpc_server.go:533]      Expected PCR Value:           --> fcecb56acc303862b30eb342c4990beb50b5e0ab89722449c2d9a73f37b019fe
      I0205 00:23:27.149547    3254 grpc_server.go:534]      sha256 of Expected PCR Value: --> 00e0758c418aff8b359dbcf0fb9af040ca15e973b02e5630b5dca1775c7e130a
      I0205 00:23:27.149592    3254 grpc_server.go:536]      Decoding PublicKey for AK ========
      I0205 00:23:27.149782    3254 grpc_server.go:555]      Attestation Signature Verified 
      I0205 00:23:27.149832    3254 grpc_server.go:556]      <-- End verifyQuote()
      I0205 00:23:27.149885    3254 grpc_server.go:495]      Returning ProvideQuoteResponse ========
```

#### Client

Run the client. 

You can specify any `uid` value there (its just a unique self-identifier)

```log
$ go run src/grpc_client.go \
  --uid 369c327d-ad1f-401c-aa91-d9b0e69bft67 \
  --unsealPcr=0 \
  --host verify.esodemoapp2.com:50051 \
  --importMode=AES \
  --cacert certs/CA_crt.pem \
  --clientcert certs/client_crt.pem \
  --clientkey certs/client_key.pem \
  --usemTLS \
  --v=10 -alsologtostderr



    I0205 00:23:25.314590    3827 grpc_client.go:188] Acquired OIDC: eyJhbGciOiJSUzI1NiIsImtpZCI6IjAzYjJkMjJjMmZlY2Y4NzNlZDE5ZTViOGNmNzA0YWZiN2UyZWQ0YmUiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJncnBjOi8vdmVyaWZ5LmVzb2RlbW9hcHAyLmNvbSIsImF6cCI6IjExMzczNzQ2NjAzNDMxNDg4MDgzNyIsImVtYWlsIjoidHBtLWNsaWVudEBtaW5lcmFsLW1pbnV0aWEtODIwLmlhbS5nc2VydmljZWFjY291bnQuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImV4cCI6MTYxMjQ4ODIwNSwiZ29vZ2xlIjp7ImNvbXB1dGVfZW5naW5lIjp7Imluc3RhbmNlX2NyZWF0aW9uX3RpbWVzdGFtcCI6MTYxMjQ4MjM5OCwiaW5zdGFuY2VfaWQiOiIyMjE5MzEzMTA5NDU5MzUxOTg2IiwiaW5zdGFuY2VfbmFtZSI6ImNsaWVudCIsInByb2plY3RfaWQiOiJtaW5lcmFsLW1pbnV0aWEtODIwIiwicHJvamVjdF9udW1iZXIiOjEwNzEyODQxODQ0MzYsInpvbmUiOiJ1cy1jZW50cmFsMS1hIn19LCJpYXQiOjE2MTI0ODQ2MDUsImlzcyI6Imh0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbSIsInN1YiI6IjExMzczNzQ2NjAzNDMxNDg4MDgzNyJ9.F2JmaJQcDIazEM3xTp6oGyk7J4tVGenMkUpR4uD7xe5bltV7wYmvd78rzNqOVehrri6Lwny8LVp_HYox9u57aoFF6j0VcgeNem36k6Jv8QPWsc3wi6fTvX-j1xIQ5lQSDdKb_Zk3XmsLkY5Ni06f9OlY1JSKqxDclquk2k03YR2vngigsmIQQrqUiWamsBiuLHDiRzBIHEexr-fYRcTZdzphgv_DfVbGWL-QuJlGvyAiNk--PhCFn5V3D39mFxBCTtLVo7RL2nMM9PCUPDRKWRVG6ujA3KRu0BzrKXWD_KfC-lHFpkASKOBS8z10sn7jOoPj4R5aCJqe0024XeAXtw
    I0205 00:23:25.330898    3827 grpc_client.go:210] RPC HealthChekStatus:SERVING
    I0205 00:23:25.331064    3827 grpc_client.go:214] =============== MakeCredential ===============
    I0205 00:23:25.331127    3827 grpc_client.go:526]      --> CreateKeys()
    I0205 00:23:25.333116    3827 grpc_client.go:533]     Current PCR 0 Value %!d(string=fcecb56acc303862b30eb342c4990beb50b5e0ab89722449c2d9a73f37b019fe) 
    I0205 00:23:25.333255    3827 grpc_client.go:538]      createPrimary
    I0205 00:23:25.544058    3827 grpc_client.go:556]      tpmEkPub: 
    &{27260898933231187109650539769631235245098520778822151120305797390405084048932396436411612236280883853527826987913323702691938065090082778494546315846975605138899036883116018782990836591356520424709838511448389549395449112527217760390734214931218263058938629707466810467983342056321088341236168472540135713660043604927101620696186737500275421605396632004472447202557824484583826197176939758619465381136245357472284353584137607066855300619275233564239755639956395993419350286407906876999669451547900580272753943213306585464650671839489737394350371113271298222257804837471806921629630775780542040706623701170078995403009 65537}
    I0205 00:23:25.544358    3827 grpc_client.go:569]      ekPub Name: 000bd25b95af6451c03f54ebc4b9e066dfab13d1d5fc1cc7967ec456b2a93afa06f4
    I0205 00:23:25.544425    3827 grpc_client.go:570]      ekPubPEM: 
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1/KqpvuKcaUIln6grsx9
    R0k2QD0UdU26CH24K4nCqWQaKm0ooN1kVKey9twkbk4Tw4Lem74ODwaN4bScs6OQ
    a8kJ40Oh7P4LmFvjD4o43BxFQLLE/DUUDXKujwDk/OlsTzU4doHhkniVk34mzoPM
    FtnE7cx8cWVi4a2q3X+q6351kfAmzcD+4FUtiaikTK3DyYk/V/jz1anCRw6FY0pb
    KKikTy1+mae+Ed6rex8IjqsS0Ez7nR2oktaamiTx1h4O2ANNYHO0OFklPrrtlY2Q
    0VNQ5wYd65vgZTv53QeLYrPJGw585W98WuT9d3p3hbDODdz8Zl3AHPO8Ru5Sd0NR
    AQIDAQAB
    -----END PUBLIC KEY-----
    I0205 00:23:25.544858    3827 grpc_client.go:577]      CreateKeyUsingAuth
    I0205 00:23:25.762138    3827 grpc_client.go:603]      akPub: 0001000b00050072000000100014000b0800000000000100e7e8ceb67e369d08c0b12d8ef8d669c22538ef4ec933756d995ae5ea5eeb3599f7e44c0a2e2b4f23c4b753fa542b087a9099645f28a28b5ce64dacb8ae2346deb690d2952a454963510fc4075665696d8d9b9f94c9c51a52c154d453ae36a09aa6a088e88a9955c0870aef285c1d34e3d27a6b2d1117bd9f748e0a259012b7c71c95484ef1686b2dbff5b81ffa7cdc7bc0a3e15691961d91063e6caca8602b049412dfdaafa3092cbcb49079fbcd09eade2ec8f9331b3ba39e10a61ef167cbc3e0a9ba760154f49b8d93f799124af29eebeb2f525af717b496fa3720327eb84b13d002fc62b189735245cf0f2208c61090fce6e792a97db77e536544763329c7,
    I0205 00:23:25.765480    3827 grpc_client.go:604]      akPriv: 00208f52131615ad8562731a5c79880668f3b47a907bc9b3a98d8b339db422c3b6440010e8103fbac448977ace87edf443bf740680039dba83eaec94c2b2e5098261ad8cb6669219c709e6c6e0055132f2da35dac4e9d93963c5c3877e19b43c903609d8a6bf177de4f246c5beed281a89a13c955a0ed876114a439e4e5255fcc05f9df9ced7657db6abe73e63fde1675816ad69f42590bac2e9516349a38ea5581bed3c6eff62314909aa6596fdd7eb7d689988036c72bfb1e25ee90c6bfe64331bc65bd699c607baf9632b697a74db8a65275c7b1b9e7068f6afbb1628,
    I0205 00:23:25.765604    3827 grpc_client.go:611]      CredentialData.ParentName.Digest.Value d25b95af6451c03f54ebc4b9e066dfab13d1d5fc1cc7967ec456b2a93afa06f4
    I0205 00:23:25.765764    3827 grpc_client.go:612]      CredentialTicket 2fde4fef410fd16ad208ebedefe2577c14e22b8c1ef1bb1209a6bcf64561d539
    I0205 00:23:25.765843    3827 grpc_client.go:613]      CredentialHash e7f461f15412ecbcd5d6bb202703f04d0d80643481b7ff407287e084b7d3b02f
    I0205 00:23:25.765913    3827 grpc_client.go:615]      ContextSave (ek)
    I0205 00:23:25.785267    3827 grpc_client.go:626]      ContextLoad (ek)
    I0205 00:23:25.793868    3827 grpc_client.go:636]      LoadUsingAuth
    I0205 00:23:25.803132    3827 grpc_client.go:664]      AK keyName 000beaa6d8583351a9efa5963928732d8f43f74cc1b4a1eec175b5b6ebb0b2595237
    I0205 00:23:25.807129    3827 grpc_client.go:686]      akPubPEM: 
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5+jOtn42nQjAsS2O+NZp
    wiU4707JM3VtmVrl6l7rNZn35EwKLitPI8S3U/pUKwh6kJlkXyiii1zmTay4riNG
    3raQ0pUqRUljUQ/EB1ZlaW2Nm5+UycUaUsFU1FOuNqCapqCI6IqZVcCHCu8oXB00
    49J6ay0RF72fdI4KJZASt8cclUhO8WhrLb/1uB/6fNx7wKPhVpGWHZEGPmysqGAr
    BJQS39qvowksvLSQefvNCereLsj5Mxs7o54Qph7xZ8vD4Km6dgFU9JuNk/eZEkry
    nuvrL1Ja9xe0lvo3IDJ+uEsT0AL8YrGJc1JFzw8iCMYQkPzm55Kpfbd+U2VEdjMp
    xwIDAQAB
    -----END PUBLIC KEY-----
    I0205 00:23:25.807741    3827 grpc_client.go:688]      Write (akPub) ========
    I0205 00:23:25.808000    3827 grpc_client.go:693]      Write (akPriv) ========
    I0205 00:23:25.808179    3827 grpc_client.go:699]      <-- CreateKeys()
    I0205 00:23:26.982952    3827 grpc_client.go:231]      MakeCredential RPC Response with provided uid [369c327d-ad1f-401c-aa91-d9b0e69bft67]
    I0205 00:23:26.983153    3827 grpc_client.go:233] =============== ActivateCredential  ===============
    I0205 00:23:26.983166    3827 grpc_client.go:705]      --> activateCredential()
    I0205 00:23:26.983176    3827 grpc_client.go:707]      ContextLoad (ek)
    I0205 00:23:26.992744    3827 grpc_client.go:718]      Read (akPub)
    I0205 00:23:26.992977    3827 grpc_client.go:723]      Read (akPriv)
    I0205 00:23:26.993072    3827 grpc_client.go:729]      LoadUsingAuth
    I0205 00:23:27.004010    3827 grpc_client.go:756]      keyName 000beaa6d8583351a9efa5963928732d8f43f74cc1b4a1eec175b5b6ebb0b2595237
    I0205 00:23:27.004214    3827 grpc_client.go:758]      ActivateCredentialUsingAuth
    I0205 00:23:27.024045    3827 grpc_client.go:806]      <--  activateCredential()
    I0205 00:23:27.031806    3827 grpc_client.go:451]      --> Start Quote
    I0205 00:23:27.034149    3827 grpc_client.go:458]      PCR 0 Value fcecb56acc303862b30eb342c4990beb50b5e0ab89722449c2d9a73f37b019fe 
    I0205 00:23:27.034519    3827 grpc_client.go:463]      ContextLoad (ek) ========
    I0205 00:23:27.044006    3827 grpc_client.go:473]      LoadUsingAuth ========
    I0205 00:23:27.048424    3827 grpc_client.go:495]      Read (akPub) ========
    I0205 00:23:27.048609    3827 grpc_client.go:500]      Read (akPriv) ========
    I0205 00:23:27.053970    3827 grpc_client.go:512]      AK keyName 000beaa6d8583351a9efa5963928732d8f43f74cc1b4a1eec175b5b6ebb0b2595237
    I0205 00:23:27.064828    3827 grpc_client.go:518]      Quote Hex ff54434780180022000bbb569e100cb0aeea335ab47ad2bddda34fd8ecb499140c8833766991917b180900036261720000000000219536000000090000000001201605110016280000000001000b03010000002000e0758c418aff8b359dbcf0fb9af040ca15e973b02e5630b5dca1775c7e130a
    I0205 00:23:27.065015    3827 grpc_client.go:519]      Quote Sig 93ad65632b93ff0da72e96d93263270872efc829862357e839744a82217ce1d96d1f17a78da7560f0e146c35f4d89425ffcacd0f20a595ac6043fdfd7d35e33152fe59d033854bcea6cb5c75fac4b23d425b6284de0c25ea07c54c37d006f91a773763c35745d206f7ab03e31c7caa4b26ec2e3cd904fedfd608ec078504a89aff18a1594e50c2d773d1a57a0f45b58b9bb6c5338e35c439021bc5b64a2034c527ce5fb29707f3511bd0acaaa138c137574ba0bf3cfe44661c41450d7dfbe09d62661edc22d32b17363d7123781a91203064392faec78067edc960e2fce781e198f2e87706a85528b7a4e37047a695b8dd99a1f732e28f1770bd1acaccfeb533
    I0205 00:23:27.065130    3827 grpc_client.go:520]      <-- End Quote
    I0205 00:23:27.073775    3827 grpc_client.go:254]     Activate Credential Status true
    I0205 00:23:27.074305    3827 grpc_client.go:263] ===============  Importing sealed AES Key ===============
    I0205 00:23:27.074387    3827 grpc_client.go:303]      --> Starting importKey()
    I0205 00:23:27.074445    3827 grpc_client.go:305]      Loading EndorsementKeyRSA
    I0205 00:23:27.106718    3827 grpc_client.go:321]      <-- End importKey()
    I0205 00:23:27.110051    3827 grpc_client.go:268]      Unsealed Secret G-KaPdSgUkXp2s5v8y/B?E(H+MbQeThW
    I0205 00:23:27.110232    3827 grpc_client.go:273] =============== OfferQuote ===============
    I0205 00:23:27.112461    3827 grpc_client.go:282]      Quote Requested with nonce 804c662b-b464-4eb5-9c67-1077f02c67c4, pcr: 0
    I0205 00:23:27.112614    3827 grpc_client.go:284] =============== Generating Quote ===============
    I0205 00:23:27.112682    3827 grpc_client.go:451]      --> Start Quote
    I0205 00:23:27.114407    3827 grpc_client.go:458]      PCR 0 Value fcecb56acc303862b30eb342c4990beb50b5e0ab89722449c2d9a73f37b019fe 
    I0205 00:23:27.114524    3827 grpc_client.go:463]      ContextLoad (ek) ========
    I0205 00:23:27.123682    3827 grpc_client.go:473]      LoadUsingAuth ========
    I0205 00:23:27.128142    3827 grpc_client.go:495]      Read (akPub) ========
    I0205 00:23:27.128335    3827 grpc_client.go:500]      Read (akPriv) ========
    I0205 00:23:27.133273    3827 grpc_client.go:512]      AK keyName 000beaa6d8583351a9efa5963928732d8f43f74cc1b4a1eec175b5b6ebb0b2595237
    I0205 00:23:27.142305    3827 grpc_client.go:518]      Quote Hex ff54434780180022000bbb569e100cb0aeea335ab47ad2bddda34fd8ecb499140c8833766991917b1809002438303463363632622d623436342d346562352d396336372d3130373766303263363763340000000000219586000000090000000001201605110016280000000001000b03010000002000e0758c418aff8b359dbcf0fb9af040ca15e973b02e5630b5dca1775c7e130a
    I0205 00:23:27.142456    3827 grpc_client.go:519]      Quote Sig 6529762da6069bb466f8abda91029d2ad93ea5e69484ff084b12f4788bf3c886d26607e662af76cdaae4c4824d7c6aca018178fc3080c76229951d72855cb48d74b1d0c63eba477a500fddf93b3f894d5c7041fa0cd2bf7a9c8cef65c0dd2a70e65a333c715fa6cdbeb15e904265427770db9650b19581259ea52192866e7485efe2afb6c1319cce9ae9ba622a32f63b5121e721cbbe6261d27d5bf5d8e727fbc5a3fde71f403c4649f0f938486b5534cdcfae07fcad4e2c8b020359c6294a37e618b8d00d09d2c33a0f9598eeeac323f7ae96a3a0a7ef3bac36ebb2af4448d70bc46bce61df98a5b8e4d84a7d632095aeaa9489ce8b613a501e068c50950622
    I0205 00:23:27.142541    3827 grpc_client.go:520]      <-- End Quote
    I0205 00:23:27.147438    3827 grpc_client.go:289] =============== Providing Quote ===============
    I0205 00:23:27.150630    3827 grpc_client.go:299]      Provided Quote verified: true
```


Note the line on the client:

```bash
    I0205 00:23:27.110051    3827 grpc_client.go:268]      Unsealed Secret G-KaPdSgUkXp2s5v8y/B?E(H+MbQeThW
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
   -expectedPCRValue fcecb56acc303862b30eb342c4990beb50b5e0ab89722449c2d9a73f37b019fe \
   --secret bar \
   --importMode=RSA \
   --cacert  certs/CA_crt.pem \
   --cackey certs/CA_key.pem \
   --servercert certs/server_crt.pem \
   --serverkey certs/server_key.pem \
   --usemTLS \
   --v=10 -alsologtostderr 


    I0205 01:09:46.300848    3944 grpc_server.go:287] Starting gRPC server on port :50051
    I0205 01:09:54.117608    3944 grpc_server.go:156] >> authenticating inbound request
    I0205 01:09:54.118126    3944 grpc_server.go:318] OIDC doc has Audience [grpc://verify.esodemoapp2.com]   Issuer [https://accounts.google.com]
    I0205 01:09:54.118214    3944 grpc_server.go:182] HealthCheck called for Service [verifier.VerifierServer]
    I0205 01:09:54.578241    3944 grpc_server.go:156] >> authenticating inbound request
    I0205 01:09:54.578738    3944 grpc_server.go:318] OIDC doc has Audience [grpc://verify.esodemoapp2.com]   Issuer [https://accounts.google.com]
    I0205 01:09:54.578824    3944 grpc_server.go:326] ======= MakeCredential ========
    I0205 01:09:54.578882    3944 grpc_server.go:327]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
    I0205 01:09:54.578934    3944 grpc_server.go:328]      Got AKName 000b4098f26fd3539ffac59d5410b4b85190a14bf14f91f0af2fb24c49504e2995c4
    I0205 01:09:54.578989    3944 grpc_server.go:329]      Registry size 0
    I0205 01:09:54.579031    3944 grpc_server.go:332]      From InstanceID 2219313109459351986
    I0205 01:09:54.704423    3944 grpc_server.go:347]      Acquired PublickKey from GCP API: 
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1/KqpvuKcaUIln6grsx9
    R0k2QD0UdU26CH24K4nCqWQaKm0ooN1kVKey9twkbk4Tw4Lem74ODwaN4bScs6OQ
    a8kJ40Oh7P4LmFvjD4o43BxFQLLE/DUUDXKujwDk/OlsTzU4doHhkniVk34mzoPM
    FtnE7cx8cWVi4a2q3X+q6351kfAmzcD+4FUtiaikTK3DyYk/V/jz1anCRw6FY0pb
    KKikTy1+mae+Ed6rex8IjqsS0Ez7nR2oktaamiTx1h4O2ANNYHO0OFklPrrtlY2Q
    0VNQ5wYd65vgZTv53QeLYrPJGw585W98WuT9d3p3hbDODdz8Zl3AHPO8Ru5Sd0NR
    AQIDAQAB
    -----END PUBLIC KEY-----
    I0205 01:09:54.704977    3944 grpc_server.go:349]      Decoding ekPub from client
    I0205 01:09:54.705099    3944 grpc_server.go:370]      EKPubPEM: 
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1/KqpvuKcaUIln6grsx9
    R0k2QD0UdU26CH24K4nCqWQaKm0ooN1kVKey9twkbk4Tw4Lem74ODwaN4bScs6OQ
    a8kJ40Oh7P4LmFvjD4o43BxFQLLE/DUUDXKujwDk/OlsTzU4doHhkniVk34mzoPM
    FtnE7cx8cWVi4a2q3X+q6351kfAmzcD+4FUtiaikTK3DyYk/V/jz1anCRw6FY0pb
    KKikTy1+mae+Ed6rex8IjqsS0Ez7nR2oktaamiTx1h4O2ANNYHO0OFklPrrtlY2Q
    0VNQ5wYd65vgZTv53QeLYrPJGw585W98WuT9d3p3hbDODdz8Zl3AHPO8Ru5Sd0NR
    AQIDAQAB
    -----END PUBLIC KEY-----
    I0205 01:09:54.705601    3944 grpc_server.go:376]      Verified EkPub from GCE API matches ekPub from Client
    I0205 01:09:54.705662    3944 grpc_server.go:562]      --> Starting makeCredential()
    I0205 01:09:54.705718    3944 grpc_server.go:563]      Read (ekPub) from request
    I0205 01:09:54.718195    3944 grpc_server.go:576]      Read (akPub) from request
    I0205 01:09:54.718408    3944 grpc_server.go:598]      Decoded AkPub: 
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2Pt0XAgRwaA/tMhS7eQl
    Ke1cEwl/t2Ofyjwlw2hKAHEI2UUA1EmOgNI5p36EhGvoBXWS3E8UCO2FuLCIMaqk
    AOt47SfT7808fSLZENyHmOW1+ljfdxRm98HNPvdQPlE1HZ5q/C0Hc3yzanoMofFN
    O8+R8i/Nlz46NEbJakHzFsWKQeZIoMIHp0HmwpbJF/N8jXvGSlnyKwDt9RVG9SYh
    lZ4vpr4m/o+0S2EJKYkdXEsg/SSUqojM6XV0Q8ge+zLNweQ47vFxU2YBKs+66fg2
    wXCRmNSHKWTxFEJgBEmaQPF5fWBR0GXE0scsry5amq/AJzIerE42m2M6BEcef4zE
    PQIDAQAB
    -----END PUBLIC KEY-----
    I0205 01:09:54.719007    3944 grpc_server.go:601]      AK Default parameter match template
    I0205 01:09:54.722344    3944 grpc_server.go:610]      Loaded AK KeyName 000b4098f26fd3539ffac59d5410b4b85190a14bf14f91f0af2fb24c49504e2995c4
    I0205 01:09:54.722571    3944 grpc_server.go:612]      MakeCredential Start
    I0205 01:09:54.725991    3944 grpc_server.go:618]      credBlob 0020d07a077ce53aefee3ff0f7179517e94db28e4b7c4044bbda5c71469e0e61db9562d9fad5a7
    I0205 01:09:54.726098    3944 grpc_server.go:619]      encryptedSecret0 8ed429930a38bb07b4a306ce8ddab855000909937305ef57231e7153812905efb583ce4c23e8f1a953e378edf82bf347508e1247621ee9e454d87c28b7bcb83e1484e7bbe91fb1fb3b53977e7d079eccf51a5aedaf9dcda72e5fbabde81ead2640a92286304a438dd6a6e56f80694924cde465e07b6e5c72773fac252ba299df898f9f154d7f988adc5062df2c70faa7dd2b8be054b5deb44faf109c4d33c97f4c16a8931f3cfaf203a94ab007af3b25d91c07247587c76edc5165e485746446b6f3a94cc8755019ba368f625e23db9087a815b2594b50ee5a50436d74ce5a081f79e17792ef55b37623aba3d8185f2fd69acdeafd06d52a9154f0d5b92bc8bd
    I0205 01:09:54.726162    3944 grpc_server.go:620]      <-- End makeCredential()
    I0205 01:09:54.728636    3944 grpc_server.go:388]      Returning MakeCredentialResponse ========
    I0205 01:09:55.810706    3944 grpc_server.go:156] >> authenticating inbound request
    I0205 01:09:55.811051    3944 grpc_server.go:318] OIDC doc has Audience [grpc://verify.esodemoapp2.com]   Issuer [https://accounts.google.com]
    I0205 01:09:55.811120    3944 grpc_server.go:399] ======= ActivateCredential ========
    I0205 01:09:55.811167    3944 grpc_server.go:400]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
    I0205 01:09:55.811207    3944 grpc_server.go:401]      Secret bar
    I0205 01:09:55.811250    3944 grpc_server.go:404]      From InstanceID 2219313109459351986
    I0205 01:09:55.811473    3944 grpc_server.go:503]      --> Starting verifyQuote()
    I0205 01:09:55.811515    3944 grpc_server.go:508]      Read and Decode (attestion)
    I0205 01:09:55.811574    3944 grpc_server.go:514]      Attestation ExtraData (nonce): bar 
    I0205 01:09:55.811616    3944 grpc_server.go:515]      Attestation PCR#: [0] 
    I0205 01:09:55.811661    3944 grpc_server.go:516]      Attestation Hash: 00e0758c418aff8b359dbcf0fb9af040ca15e973b02e5630b5dca1775c7e130a 
    I0205 01:09:55.811712    3944 grpc_server.go:533]      Expected PCR Value:           --> fcecb56acc303862b30eb342c4990beb50b5e0ab89722449c2d9a73f37b019fe
    I0205 01:09:55.811776    3944 grpc_server.go:534]      sha256 of Expected PCR Value: --> 00e0758c418aff8b359dbcf0fb9af040ca15e973b02e5630b5dca1775c7e130a
    I0205 01:09:55.811820    3944 grpc_server.go:536]      Decoding PublicKey for AK ========
    I0205 01:09:55.811973    3944 grpc_server.go:555]      Attestation Signature Verified 
    I0205 01:09:55.812036    3944 grpc_server.go:556]      <-- End verifyQuote()
    I0205 01:09:55.812077    3944 grpc_server.go:418]      Verified Quote
    I0205 01:09:55.812117    3944 grpc_server.go:625]      --> Start generateCertificate()
    I0205 01:09:55.812162    3944 grpc_server.go:626]      Generating Certificate for cn=2219313109459351986
    I0205 01:09:55.812384    3944 grpc_server.go:641]      Generated cert with Serial 408254118850144987185943855269412930169279703308
    I0205 01:09:56.052342    3944 grpc_server.go:704]      Generating Test Signature with private Key
    I0205 01:09:56.055133    3944 grpc_server.go:713]      Test signature data:  jJ4bcxBnRmHKWdo7T5x3gGqtAZBdS4axPOdpoS0hBQbVDXY2Bnn5RVilm7oqy+9p/W0FXx/aZxifv/4xySSqShjTnkDR32QLx2eLywoftbfh8zv99po1XKfTw2Nq3cgIOVe9rNEYTkV2bfNyKWlpEJnm1U1b2lPrpaLMWJ6HBsrb3/Y7n5hF9EfQwSx7BK1n3rFZSchlblTs+JBIAaTGYbRnskYIWJCZihhh1661ignJAOw+WQDulGwrxMtJqsnKW2ctnCw2S41Hfu+YoFZi4T/6cHFk/o0I3oqXu0jQW/mdqN1bWkp0Rr2bi6WWJhAmPdibcBni+MiH6hNJl1ww2g
    I0205 01:09:56.055211    3944 grpc_server.go:714]      <-- End generateCertificate()
    I0205 01:09:56.055264    3944 grpc_server.go:719]      --> Start createImportBlob()
    I0205 01:09:56.055306    3944 grpc_server.go:720]      Load and decode ekPub from registry
    I0205 01:09:56.055380    3944 grpc_server.go:733]      Decoding sealing PCR value in hex
    I0205 01:09:56.055433    3944 grpc_server.go:746]      --> createSigningKeyImportBlob()
    I0205 01:09:56.055474    3944 grpc_server.go:747]      Generating to RSA sealedFile
    I0205 01:09:56.055847    3944 grpc_server.go:761]      Returning sealed key
    I0205 01:09:56.056039    3944 grpc_server.go:783]      <-- End createImportBlob()
    I0205 01:09:56.056086    3944 grpc_server.go:434]      Returning ActivateCredentialResponse ========
    I0205 01:09:56.133820    3944 grpc_server.go:156] >> authenticating inbound request
    I0205 01:09:56.134181    3944 grpc_server.go:318] OIDC doc has Audience [grpc://verify.esodemoapp2.com]   Issuer [https://accounts.google.com]
    I0205 01:09:56.134253    3944 grpc_server.go:444] ======= OfferQuote ========
    I0205 01:09:56.134489    3944 grpc_server.go:445]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
    I0205 01:09:56.134548    3944 grpc_server.go:448]      From InstanceID 2219313109459351986
    I0205 01:09:56.134605    3944 grpc_server.go:457]      Returning OfferQuoteResponse ========
    I0205 01:09:56.168893    3944 grpc_server.go:156] >> authenticating inbound request
    I0205 01:09:56.169278    3944 grpc_server.go:318] OIDC doc has Audience [grpc://verify.esodemoapp2.com]   Issuer [https://accounts.google.com]
    I0205 01:09:56.169368    3944 grpc_server.go:467] ======= ProvideQuote ========
    I0205 01:09:56.169411    3944 grpc_server.go:468]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
    I0205 01:09:56.169465    3944 grpc_server.go:471]      From InstanceID 2219313109459351986
    I0205 01:09:56.169507    3944 grpc_server.go:503]      --> Starting verifyQuote()
    I0205 01:09:56.169564    3944 grpc_server.go:508]      Read and Decode (attestion)
    I0205 01:09:56.169635    3944 grpc_server.go:514]      Attestation ExtraData (nonce): 59269f78-ac2a-422b-8577-d70e32dcd11c 
    I0205 01:09:56.169679    3944 grpc_server.go:515]      Attestation PCR#: [0] 
    I0205 01:09:56.169743    3944 grpc_server.go:516]      Attestation Hash: 00e0758c418aff8b359dbcf0fb9af040ca15e973b02e5630b5dca1775c7e130a 
    I0205 01:09:56.169800    3944 grpc_server.go:533]      Expected PCR Value:           --> fcecb56acc303862b30eb342c4990beb50b5e0ab89722449c2d9a73f37b019fe
    I0205 01:09:56.169847    3944 grpc_server.go:534]      sha256 of Expected PCR Value: --> 00e0758c418aff8b359dbcf0fb9af040ca15e973b02e5630b5dca1775c7e130a
    I0205 01:09:56.169904    3944 grpc_server.go:536]      Decoding PublicKey for AK ========
    I0205 01:09:56.170070    3944 grpc_server.go:555]      Attestation Signature Verified 
    I0205 01:09:56.170128    3944 grpc_server.go:556]      <-- End verifyQuote()
    I0205 01:09:56.170169    3944 grpc_server.go:495]      Returning ProvideQuoteResponse ========   

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


    I0205 01:09:54.107088    5182 grpc_client.go:189] Acquired OIDC: eyJhbGciOiJSUzI1NiIsImtpZCI6IjAzYjJkMjJjMmZlY2Y4NzNlZDE5ZTViOGNmNzA0YWZiN2UyZWQ0YmUiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJncnBjOi8vdmVyaWZ5LmVzb2RlbW9hcHAyLmNvbSIsImF6cCI6IjExMzczNzQ2NjAzNDMxNDg4MDgzNyIsImVtYWlsIjoidHBtLWNsaWVudEBtaW5lcmFsLW1pbnV0aWEtODIwLmlhbS5nc2VydmljZWFjY291bnQuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImV4cCI6MTYxMjQ5MDk5NCwiZ29vZ2xlIjp7ImNvbXB1dGVfZW5naW5lIjp7Imluc3RhbmNlX2NyZWF0aW9uX3RpbWVzdGFtcCI6MTYxMjQ4MjM5OCwiaW5zdGFuY2VfaWQiOiIyMjE5MzEzMTA5NDU5MzUxOTg2IiwiaW5zdGFuY2VfbmFtZSI6ImNsaWVudCIsInByb2plY3RfaWQiOiJtaW5lcmFsLW1pbnV0aWEtODIwIiwicHJvamVjdF9udW1iZXIiOjEwNzEyODQxODQ0MzYsInpvbmUiOiJ1cy1jZW50cmFsMS1hIn19LCJpYXQiOjE2MTI0ODczOTQsImlzcyI6Imh0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbSIsInN1YiI6IjExMzczNzQ2NjAzNDMxNDg4MDgzNyJ9.kchcyvDIam-0t7JJPEqtWckwaIwp5E9tCJwn5PdrGlQLbJ6EgdfDyRFSPU6ZticNpD9jDiJ4Syj0_d75oQ3OWQUXVbbYreP62T2uk-LDLkRGwYklmN8wNQY348vEA2rCsUAmKZts6vaKPHzpOAZSYI9td4ky82eVwFiVaFUTQJQXrtWf2DWJPu4jepf9tM8_0m4LQIz-eFrJu52fEM6HIluxG7SQ_KXTLi_3RG47gikJMCY-BzitIJoSBAv2YqLV1znB5CETGgLGybH6bVdKpjLrs7PO-hX_1Ph2o9qVECER-ti1N1gIxw2F2OQ2pveiL957FQEmJQ5AJAOnF7uXAw
    I0205 01:09:54.119306    5182 grpc_client.go:211] RPC HealthChekStatus:SERVING
    I0205 01:09:54.119522    5182 grpc_client.go:215] =============== MakeCredential ===============
    I0205 01:09:54.119570    5182 grpc_client.go:503]      --> CreateKeys()
    I0205 01:09:54.121634    5182 grpc_client.go:510]     Current PCR 0 Value %!d(string=fcecb56acc303862b30eb342c4990beb50b5e0ab89722449c2d9a73f37b019fe) 
    I0205 01:09:54.121757    5182 grpc_client.go:515]      createPrimary
    I0205 01:09:54.339720    5182 grpc_client.go:533]      tpmEkPub: 
    &{27260898933231187109650539769631235245098520778822151120305797390405084048932396436411612236280883853527826987913323702691938065090082778494546315846975605138899036883116018782990836591356520424709838511448389549395449112527217760390734214931218263058938629707466810467983342056321088341236168472540135713660043604927101620696186737500275421605396632004472447202557824484583826197176939758619465381136245357472284353584137607066855300619275233564239755639956395993419350286407906876999669451547900580272753943213306585464650671839489737394350371113271298222257804837471806921629630775780542040706623701170078995403009 65537}
    I0205 01:09:54.340026    5182 grpc_client.go:546]      ekPub Name: 000bd25b95af6451c03f54ebc4b9e066dfab13d1d5fc1cc7967ec456b2a93afa06f4
    I0205 01:09:54.340104    5182 grpc_client.go:547]      ekPubPEM: 
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1/KqpvuKcaUIln6grsx9
    R0k2QD0UdU26CH24K4nCqWQaKm0ooN1kVKey9twkbk4Tw4Lem74ODwaN4bScs6OQ
    a8kJ40Oh7P4LmFvjD4o43BxFQLLE/DUUDXKujwDk/OlsTzU4doHhkniVk34mzoPM
    FtnE7cx8cWVi4a2q3X+q6351kfAmzcD+4FUtiaikTK3DyYk/V/jz1anCRw6FY0pb
    KKikTy1+mae+Ed6rex8IjqsS0Ez7nR2oktaamiTx1h4O2ANNYHO0OFklPrrtlY2Q
    0VNQ5wYd65vgZTv53QeLYrPJGw585W98WuT9d3p3hbDODdz8Zl3AHPO8Ru5Sd0NR
    AQIDAQAB
    -----END PUBLIC KEY-----
    I0205 01:09:54.340526    5182 grpc_client.go:554]      CreateKeyUsingAuth
    I0205 01:09:54.535262    5182 grpc_client.go:580]      akPub: 0001000b00050072000000100014000b0800000000000100d8fb745c0811c1a03fb4c852ede42529ed5c13097fb7639fca3c25c3684a007108d94500d4498e80d239a77e84846be8057592dc4f1408ed85b8b08831aaa400eb78ed27d3efcd3c7d22d910dc8798e5b5fa58df771466f7c1cd3ef7503e51351d9e6afc2d07737cb36a7a0ca1f14d3bcf91f22fcd973e3a3446c96a41f316c58a41e648a0c207a741e6c296c917f37c8d7bc64a59f22b00edf51546f52621959e2fa6be26fe8fb44b610929891d5c4b20fd2494aa88cce9757443c81efb32cdc1e438eef1715366012acfbae9f836c1709198d4872964f114426004499a40f1797d6051d065c4d2c72caf2e5a9aafc027321eac4e369b633a04471e7f8cc43d,
    I0205 01:09:54.535412    5182 grpc_client.go:581]      akPriv: 0020bfb91212d7c3b1d54b72e9b8bb08727e45bd657d533d98cd1de1050833715a460010e6d953d7dad7772820d5197ed3da2627099cfbdb6486761c53fbeca326dda2f1da42d6817c7e791703f73c482eae6e82e87aa21ecd5e3cfa7bc0e40a06026acef940aa6ebd452848de387a526238da19cdbcf3d6136a9dbba79ee47601b3b1ed0cfcfa729d05e7e1749e99181e79d70b59c6a06377cb5704670338a67f60ca636445dd3c6f8cea59d284624c1d7f94d7e228fb6b5fbac049de96f71fbe8065506f74c028859c4b63088a3a05e150ce2edea8982290bf4f6a834a,
    I0205 01:09:54.535490    5182 grpc_client.go:588]      CredentialData.ParentName.Digest.Value d25b95af6451c03f54ebc4b9e066dfab13d1d5fc1cc7967ec456b2a93afa06f4
    I0205 01:09:54.535881    5182 grpc_client.go:589]      CredentialTicket 41c6f12363f4e410f8c89e12f26f2ec08274333c9f690e696a1275112bcb5c6b
    I0205 01:09:54.535961    5182 grpc_client.go:590]      CredentialHash e7f461f15412ecbcd5d6bb202703f04d0d80643481b7ff407287e084b7d3b02f
    I0205 01:09:54.536010    5182 grpc_client.go:592]      ContextSave (ek)
    I0205 01:09:54.548686    5182 grpc_client.go:603]      ContextLoad (ek)
    I0205 01:09:54.557674    5182 grpc_client.go:613]      LoadUsingAuth
    I0205 01:09:54.565816    5182 grpc_client.go:641]      AK keyName 000b4098f26fd3539ffac59d5410b4b85190a14bf14f91f0af2fb24c49504e2995c4
    I0205 01:09:54.569633    5182 grpc_client.go:663]      akPubPEM: 
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2Pt0XAgRwaA/tMhS7eQl
    Ke1cEwl/t2Ofyjwlw2hKAHEI2UUA1EmOgNI5p36EhGvoBXWS3E8UCO2FuLCIMaqk
    AOt47SfT7808fSLZENyHmOW1+ljfdxRm98HNPvdQPlE1HZ5q/C0Hc3yzanoMofFN
    O8+R8i/Nlz46NEbJakHzFsWKQeZIoMIHp0HmwpbJF/N8jXvGSlnyKwDt9RVG9SYh
    lZ4vpr4m/o+0S2EJKYkdXEsg/SSUqojM6XV0Q8ge+zLNweQ47vFxU2YBKs+66fg2
    wXCRmNSHKWTxFEJgBEmaQPF5fWBR0GXE0scsry5amq/AJzIerE42m2M6BEcef4zE
    PQIDAQAB
    -----END PUBLIC KEY-----
    I0205 01:09:54.570106    5182 grpc_client.go:665]      Write (akPub) ========
    I0205 01:09:54.570308    5182 grpc_client.go:670]      Write (akPriv) ========
    I0205 01:09:54.570530    5182 grpc_client.go:676]      <-- CreateKeys()
    I0205 01:09:55.729542    5182 grpc_client.go:232]      MakeCredential RPC Response with provided uid [369c327d-ad1f-401c-aa91-d9b0e69bft67]
    I0205 01:09:55.729742    5182 grpc_client.go:234] =============== ActivateCredential  ===============
    I0205 01:09:55.729755    5182 grpc_client.go:682]      --> activateCredential()
    I0205 01:09:55.729765    5182 grpc_client.go:684]      ContextLoad (ek)
    I0205 01:09:55.747657    5182 grpc_client.go:695]      Read (akPub)
    I0205 01:09:55.748083    5182 grpc_client.go:700]      Read (akPriv)
    I0205 01:09:55.748193    5182 grpc_client.go:706]      LoadUsingAuth
    I0205 01:09:55.757070    5182 grpc_client.go:733]      keyName 000b4098f26fd3539ffac59d5410b4b85190a14bf14f91f0af2fb24c49504e2995c4
    I0205 01:09:55.757226    5182 grpc_client.go:735]      ActivateCredentialUsingAuth
    I0205 01:09:55.771713    5182 grpc_client.go:783]      <--  activateCredential()
    I0205 01:09:55.779307    5182 grpc_client.go:428]      --> Start Quote
    I0205 01:09:55.781503    5182 grpc_client.go:435]      PCR 0 Value fcecb56acc303862b30eb342c4990beb50b5e0ab89722449c2d9a73f37b019fe 
    I0205 01:09:55.781626    5182 grpc_client.go:440]      ContextLoad (ek) ========
    I0205 01:09:55.790300    5182 grpc_client.go:450]      LoadUsingAuth ========
    I0205 01:09:55.793252    5182 grpc_client.go:472]      Read (akPub) ========
    I0205 01:09:55.793432    5182 grpc_client.go:477]      Read (akPriv) ========
    I0205 01:09:55.798325    5182 grpc_client.go:489]      AK keyName 000b4098f26fd3539ffac59d5410b4b85190a14bf14f91f0af2fb24c49504e2995c4
    I0205 01:09:55.805249    5182 grpc_client.go:495]      Quote Hex ff54434780180022000bfcef3e9eb0e69b41b90c0979b34c68ef89530d0f78858e55f4c2b1aac5c40d78000362617200000000004c22be000000090000000001201605110016280000000001000b03010000002000e0758c418aff8b359dbcf0fb9af040ca15e973b02e5630b5dca1775c7e130a
    I0205 01:09:55.805435    5182 grpc_client.go:496]      Quote Sig 0755016b1603b21f7a6fe8d684df9b9bc01ffa78021b601fd1552b9b307a381eee52dcd352c1a0f78e7c1a87289e30cd34da65e509baef3d2dcf3b264fb3b63b03c77f728a2033c4b74fc1a97e43b29d672ffdb9e1995faf4ceac23b9368a726aac7a14a58954ba07c17f4325b0b7b4d53772661233baa49fff8f113ad62a9331d36ea5e22ba95926531d85dfe87399100fc4cfbc88495e7cb791b44e402d0b4a23c74a57d5f65a8a5220fbfee15ccb213e7ea1899cfb11cd65b859e839d58424133ea2800f0b2b5085ebc063498c53c072ec78530d48f7c32ac2fb2198e06c02292b5408c2876b934c5cd2074356d082ca33714ac6c2c4257055cde6f6bbc77
    I0205 01:09:55.805525    5182 grpc_client.go:497]      <-- End Quote
    I0205 01:09:56.056691    5182 grpc_client.go:255]     Activate Credential Status true
    I0205 01:09:56.057095    5182 grpc_client.go:258] ===============  Importing sealed RSA Key ===============
    I0205 01:09:56.057151    5182 grpc_client.go:328]      --> Starting importRSAKey()
    I0205 01:09:56.057205    5182 grpc_client.go:330]      Loading EndorsementKeyRSA
    I0205 01:09:56.063115    5182 grpc_client.go:337]      Loading sealedkey
    I0205 01:09:56.063512    5182 grpc_client.go:345]      Loading ImportSigningKey
    I0205 01:09:56.090786    5182 grpc_client.go:364]      Imported keyPublic portion: 
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2CdzwNGy2Kc8uuzzdhuP
    6Y9sucOkKkBbS4hxcZyT1m7ZK/OZctM8r6wZ19OqO6saJRCmP4gTeM/Api3xY0JI
    FARVAAQ/KTFOuF/rpWjeyVHYq7z1pEjAiLZybxmoD3zLY6fK4Wk9VQU6iiuCnfu/
    qZUFxa6Wo1ri41bO8IZ/LjFnFo03X3V50x1t3Q7Yq8zPM/aqR8k7etPZ70sFsqVg
    KFHlaDHrBKAJbpcvsln0/ASyy/JY83Y/3OA2vwL58MetqMLy+EtvXGu9eF7/DWUi
    YsCmnT07qPMMxB3cqs1V3HOe29x66aBgBPydoPvm2oEU32e/QEkflVuTQ1idRmOJ
    GQIDAQAB
    -----END PUBLIC KEY-----
    I0205 01:09:56.091260    5182 grpc_client.go:366]      Saving Key Handle as importedKey.bin
    I0205 01:09:56.101974    5182 grpc_client.go:379]      Loading Key Handle
    I0205 01:09:56.102114    5182 grpc_client.go:381]      ContextLoad (importedKey.bin) ========
    I0205 01:09:56.110877    5182 grpc_client.go:392]     Generating Test Signature ========
    I0205 01:09:56.121236    5182 grpc_client.go:421]      Test Signature data:  jJ4bcxBnRmHKWdo7T5x3gGqtAZBdS4axPOdpoS0hBQbVDXY2Bnn5RVilm7oqy+9p/W0FXx/aZxifv/4xySSqShjTnkDR32QLx2eLywoftbfh8zv99po1XKfTw2Nq3cgIOVe9rNEYTkV2bfNyKWlpEJnm1U1b2lPrpaLMWJ6HBsrb3/Y7n5hF9EfQwSx7BK1n3rFZSchlblTs+JBIAaTGYbRnskYIWJCZihhh1661ignJAOw+WQDulGwrxMtJqsnKW2ctnCw2S41Hfu+YoFZi4T/6cHFk/o0I3oqXu0jQW/mdqN1bWkp0Rr2bi6WWJhAmPdibcBni+MiH6hNJl1ww2g
    I0205 01:09:56.121423    5182 grpc_client.go:422]      <-- End importRSAKey()
    I0205 01:09:56.133132    5182 grpc_client.go:274] =============== OfferQuote ===============
    I0205 01:09:56.135199    5182 grpc_client.go:283]      Quote Requested with nonce 59269f78-ac2a-422b-8577-d70e32dcd11c, pcr: 0
    I0205 01:09:56.135329    5182 grpc_client.go:285] =============== Generating Quote ===============
    I0205 01:09:56.135394    5182 grpc_client.go:428]      --> Start Quote
    I0205 01:09:56.137081    5182 grpc_client.go:435]      PCR 0 Value fcecb56acc303862b30eb342c4990beb50b5e0ab89722449c2d9a73f37b019fe 
    I0205 01:09:56.137170    5182 grpc_client.go:440]      ContextLoad (ek) ========
    I0205 01:09:56.145766    5182 grpc_client.go:450]      LoadUsingAuth ========
    I0205 01:09:56.149792    5182 grpc_client.go:472]      Read (akPub) ========
    I0205 01:09:56.150171    5182 grpc_client.go:477]      Read (akPriv) ========
    I0205 01:09:56.155412    5182 grpc_client.go:489]      AK keyName 000b4098f26fd3539ffac59d5410b4b85190a14bf14f91f0af2fb24c49504e2995c4
    I0205 01:09:56.162876    5182 grpc_client.go:495]      Quote Hex ff54434780180022000bfcef3e9eb0e69b41b90c0979b34c68ef89530d0f78858e55f4c2b1aac5c40d78002435393236396637382d616332612d343232622d383537372d64373065333264636431316300000000004c2424000000090000000001201605110016280000000001000b03010000002000e0758c418aff8b359dbcf0fb9af040ca15e973b02e5630b5dca1775c7e130a
    I0205 01:09:56.163047    5182 grpc_client.go:496]      Quote Sig d8c616e27672e63190bbfa7ad7d1fad2f5e964cd8094a12dcb773b004461a070d496ae7c4bdaea416319295b777983f81b8ed0c8e9c896ec3cdf6035f3294abcf76cb04fbf242a6953c5df050a20b0db4e91f8f51e8f7cc656c71681cdd0f85b8b836ffd46b171b6b5dc0e1f7b29a750a76a354ef2a11bb1d62c6b196cdf8bef71ee5858771cfdae39418e719c8fa4b27d49b9c4db1a70b4eaa23079de3cd2c4241ccc9de0e63fa76dd1975e219c0800661bd8513938637ee609c4fa6cde0c2ec7212ca4c6ffe2a93987631c56fa963b9da4f1d9b28066c18e528ac537e09fccea3492e448ad200f05ab5f588b2db9edf8532019272220c73f58ff6809526521
    I0205 01:09:56.163115    5182 grpc_client.go:497]      <-- End Quote
    I0205 01:09:56.167595    5182 grpc_client.go:290] =============== Providing Quote ===============
    I0205 01:09:56.171081    5182 grpc_client.go:300]      Provided Quote verified: true
```


Note the signatures on both the client and server match for a for the signature of a sample control string ("secret")


```log
    I0205 01:09:56.055133    3944 grpc_server.go:713]      Test signature data:  jJ4bcxBnRmHKWdo7T5x3gGqtAZBdS4axPOdpoS0hBQbVDXY2Bnn5RVilm7oqy+9p/W0FXx/aZxifv/4xySSqShjTnkDR32QLx2eLywoftbfh8zv99po1XKfTw2Nq3cgIOVe9rNEYTkV2bfNyKWlpEJnm1U1b2lPrpaLMWJ6HBsrb3/Y7n5hF9EfQwSx7BK1n3rFZSchlblTs+JBIAaTGYbRnskYIWJCZihhh1661ignJAOw+WQDulGwrxMtJqsnKW2ctnCw2S41Hfu+YoFZi4T/6cHFk/o0I3oqXu0jQW/mdqN1bWkp0Rr2bi6WWJhAmPdibcBni+MiH6hNJl1ww2g

---

    I0205 01:09:56.121236    5182 grpc_client.go:421]      Test Signature data:  jJ4bcxBnRmHKWdo7T5x3gGqtAZBdS4axPOdpoS0hBQbVDXY2Bnn5RVilm7oqy+9p/W0FXx/aZxifv/4xySSqShjTnkDR32QLx2eLywoftbfh8zv99po1XKfTw2Nq3cgIOVe9rNEYTkV2bfNyKWlpEJnm1U1b2lPrpaLMWJ6HBsrb3/Y7n5hF9EfQwSx7BK1n3rFZSchlblTs+JBIAaTGYbRnskYIWJCZihhh1661ignJAOw+WQDulGwrxMtJqsnKW2ctnCw2S41Hfu+YoFZi4T/6cHFk/o0I3oqXu0jQW/mdqN1bWkp0Rr2bi6WWJhAmPdibcBni+MiH6hNJl1ww2g
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

```bash
apt-get update

apt -y install   autoconf-archive   libcmocka0   libcmocka-dev   procps   iproute2   build-essential   git   pkg-config   gcc   libtool   automake   libssl-dev   uthash-dev   autoconf   doxygen  libcurl4-openssl-dev dbus-x11 libglib2.0-dev

cd
git clone https://github.com/tpm2-software/tpm2-tss.git
  cd tpm2-tss
  git fetch && git fetch --tags && git checkout 2.3.1
  ./bootstrap
  ./configure --with-udevrulesdir=/etc/udev/rules.d
  make -j$(nproc)
  make install
  udevadm control --reload-rules && sudo udevadm trigger
  ldconfig
cd
git clone https://github.com/tpm2-software/tpm2-tools.git
  cd tpm2-tools
  git fetch && git fetch --tags && git checkout 4.0-rc2
  ./bootstrap
  ./configure
  make check
  make install
```

To Changing PCR values, use either `go-tpm` or `tpm2_tools`:

- [tpm2_pcrextend](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_pcrextend.1.md)

