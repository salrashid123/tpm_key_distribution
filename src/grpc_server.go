// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"sync"
	"verifier"

	"github.com/golang/glog"
	"golang.org/x/net/context"
	"google.golang.org/api/compute/v1"
	"google.golang.org/grpc"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/lestrrat/go-jwx/jwk"
	"google.golang.org/grpc/status"

	"github.com/golang/protobuf/proto"
	gotpmserver "github.com/google/go-tpm-tools/server"
	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"

	pb "github.com/google/go-tpm-tools/proto"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
)

var (
	grpcport         = flag.String("grpcport", "", "grpcport")
	secret           = flag.String("secret", "foo", "secret")
	expectedPCRValue = flag.String("expectedPCRValue", "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b", "expectedPCRValue")
	pcr              = flag.Int("pcr", 23, "PCR Value to use")
	caCert           = flag.String("cacert", "CA_crt.pem", "CA Certificate to issue certs")
	caKey            = flag.String("cackey", "CA_key.pem", "CA PrivateKey to issue certs")
	serverCert       = flag.String("servercert", "server_crt.pem", "Server SSL Certificate")
	serverKey        = flag.String("serverkey", "server_key.pem", "Server SSL PrivateKey")
	usemTLS          = flag.Bool("usemTLS", false, "Validate original client request with mTLS")
	registry         = make(map[string]verifier.MakeCredentialRequest)
	nonces           = make(map[string]string)
	rwc              io.ReadWriteCloser
	jwtSet           *jwk.Set
	importMode       = flag.String("importMode", "AES", "RSA|AES")
	aes256Key        = flag.String("aes256Key", "G-KaPdSgUkXp2s5v8y/B?E(H+MbQeThW", "AES Symmetric key for client")
	handleNames      = map[string][]tpm2.HandleType{
		"all":       []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    []tpm2.HandleType{tpm2.HandleTypeLoadedSession},
		"saved":     []tpm2.HandleType{tpm2.HandleTypeSavedSession},
		"transient": []tpm2.HandleType{tpm2.HandleTypeTransient},
	}

	defaultKeyParams = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagSign,
		AuthPolicy: []byte{},
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}
)

const (
	targetAudience = "grpc://verify.esodemoapp2.com"
	jwksURL        = "https://www.googleapis.com/oauth2/v3/certs"
	tpmDevice      = "/dev/tpm0"

	// bool that defines if the client's instanceIdentity should be used as
	// the primary key that saves AK-EK.   if set to false, the primary key
	// is whatever the UID value the client sent over.  If set to true, he insanceID
	// is used.  If true, then only one AK-EK can exist at one tiem for a given VM
	// (since the instanceID is the same)
	useInstanceIDAsKey = true
)

type server struct {
}

type hserver struct {
	mu sync.Mutex
	// statusMap stores the serving status of the services this Server monitors.
	statusMap map[string]healthpb.HealthCheckResponse_ServingStatus
}

// struct to hold the GCP instance Identity Document.
// its an OIDC document with google extensions that shows more detailed specs of
// the origin machine (instanceID, name, project, etc).  THis data is used in side-channel
// verification.
type gcpIdentityDoc struct {
	Google struct {
		ComputeEngine struct {
			InstanceCreationTimestamp int64  `json:"instance_creation_timestamp,omitempty"`
			InstanceID                string `json:"instance_id,omitempty"`
			InstanceName              string `json:"instance_name,omitempty"`
			ProjectID                 string `json:"project_id,omitempty"`
			ProjectNumber             int64  `json:"project_number,omitempty"`
			Zone                      string `json:"zone,omitempty"`
		} `json:"compute_engine"`
	} `json:"google"`
	Email           string `json:"email,omitempty"`
	EmailVerified   bool   `json:"email_verified,omitempty"`
	AuthorizedParty string `json:"azp,omitempty"`
	jwt.StandardClaims
}

type contextKey string

// gRPC middleware which validates the OIDC token sent in every request.
// This check verifies the id token is valid and then extracts the google specific annotations.
func authUnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	glog.V(2).Infof(">> authenticating inbound request")
	md, _ := metadata.FromIncomingContext(ctx)
	if len(md["authorization"]) > 0 {
		reqToken := md["authorization"][0]
		splitToken := strings.Split(reqToken, "Bearer")
		tok := strings.TrimSpace(splitToken[1])
		idDoc, err := verifyGoogleIDToken(ctx, targetAudience, tok)
		if err != nil {
			return nil, grpc.Errorf(codes.Unauthenticated, fmt.Sprintf("Request Token verification failed: %v", err))
		}
		newCtx := context.WithValue(ctx, contextKey("idtoken"), idDoc)
		return handler(newCtx, req)
	}
	return nil, grpc.Errorf(codes.Unauthenticated, "Authorization header not provided")
}

// Check() and Watch() are for gRPC healthcheck protocols.
// currently it always returns healthy status.
func (s *hserver) Check(ctx context.Context, in *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if in.Service == "" {
		// return overall status
		return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
	}
	glog.V(10).Infof("HealthCheck called for Service [%s]", in.Service)
	s.statusMap["verifier.VerifierServer"] = healthpb.HealthCheckResponse_SERVING
	status, ok := s.statusMap[in.Service]
	if !ok {
		return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_UNKNOWN}, grpc.Errorf(codes.NotFound, "unknown service")
	}
	return &healthpb.HealthCheckResponse{Status: status}, nil
}

func (s *hserver) Watch(in *healthpb.HealthCheckRequest, srv healthpb.Health_WatchServer) error {
	return status.Error(codes.Unimplemented, "Watch is not implemented")
}

func main() {

	flag.Parse()

	if *grpcport == "" {
		fmt.Fprintln(os.Stderr, "missing -grpcport flag (:50051)")
		flag.Usage()
		os.Exit(2)
	}

	var err error
	rwc, err = tpm2.OpenTPM(tpmDevice)
	if err != nil {
		glog.Fatalf("can't open TPM %q: %v", tpmDevice, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			glog.Fatalf("can't close TPM %q: %v", tpmDevice, err)
		}
	}()

	totalHandles := 0
	for _, handleType := range handleNames["transient"] {
		handles, err := tpm2tools.Handles(rwc, handleType)
		if err != nil {
			glog.Fatalf("getting handles: %v", err)
		}
		for _, handle := range handles {
			if err = tpm2.FlushContext(rwc, handle); err != nil {
				glog.Fatalf("flushing handle 0x%x: %v", handle, err)
			}
			glog.V(10).Infof("Handle 0x%x flushed\n", handle)
			totalHandles++
		}
	}

	jwtSet, err = jwk.FetchHTTP(jwksURL)
	if err != nil {
		glog.Fatal("Unable to load JWK Set: ", err)
	}

	var tlsConfig *tls.Config
	ca, err := ioutil.ReadFile(*caCert)
	if err != nil {
		glog.Fatalf("Faild to read CA Certificate file %s: %v", *caCert, err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(ca)

	serverCerts, err := tls.LoadX509KeyPair(*serverCert, *serverKey)
	if err != nil {
		glog.Fatalf("Failed to read Server Certificate files %s  %s: %v", *serverCert, *serverKey, err)
	}

	if *usemTLS {
		glog.V(5).Infoln("Using mTLS for initial server connection")

		clientCaCert, err := ioutil.ReadFile(*caCert)
		if err != nil {
			glog.Fatalf("Failed to read CA Certificate file %s: %v", *caCert, err)
		}
		clientCaCertPool := x509.NewCertPool()
		clientCaCertPool.AppendCertsFromPEM(clientCaCert)

		tlsConfig = &tls.Config{
			RootCAs:      caCertPool,
			ClientCAs:    clientCaCertPool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			Certificates: []tls.Certificate{serverCerts},
		}
	} else {
		tlsConfig = &tls.Config{
			RootCAs:      caCertPool,
			Certificates: []tls.Certificate{serverCerts},
		}
	}
	ce := credentials.NewTLS(tlsConfig)

	lis, err := net.Listen("tcp", *grpcport)
	if err != nil {
		glog.Fatalf("failed to listen: %v", err)
	}

	sopts := []grpc.ServerOption{grpc.MaxConcurrentStreams(10)}
	sopts = append(sopts, grpc.Creds(ce), grpc.UnaryInterceptor(authUnaryInterceptor))
	s := grpc.NewServer(sopts...)

	verifier.RegisterVerifierServer(s, &server{})
	healthpb.RegisterHealthServer(s, &hserver{
		statusMap: make(map[string]healthpb.HealthCheckResponse_ServingStatus),
	})

	glog.V(2).Infof("Starting gRPC server on port %v", *grpcport)

	s.Serve(lis)
}

// Downloads the JWK for OIDC doc verification
func getKey(token *jwt.Token) (interface{}, error) {

	keyID, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("expecting JWT header to have string kid")
	}

	if key := jwtSet.LookupKeyID(keyID); len(key) == 1 {
		return key[0].Materialize()
	}

	return nil, errors.New("unable to find key")
}

// Verifies the token with the intended audience.  Returns the parsed OIDC doc
func verifyGoogleIDToken(ctx context.Context, aud string, rawToken string) (gcpIdentityDoc, error) {

	token, err := jwt.ParseWithClaims(rawToken, &gcpIdentityDoc{}, getKey)

	if err != nil {
		glog.V(2).Infof("Error parsing JWT %v", err)
		return gcpIdentityDoc{}, err
	}

	if claims, ok := token.Claims.(*gcpIdentityDoc); ok && token.Valid {
		glog.V(5).Infof("OIDC doc has Audience [%s]   Issuer [%v]", claims.Audience, claims.StandardClaims.Issuer)
		return *claims, nil
	}
	return gcpIdentityDoc{}, errors.New("Error parsing JWT Claims")
}

func (s *server) MakeCredential(ctx context.Context, in *verifier.MakeCredentialRequest) (*verifier.MakeCredentialResponse, error) {

	glog.V(2).Infof("======= MakeCredential ========")
	glog.V(5).Infof("     client provided uid: %s", in.Uid)
	glog.V(10).Infof("     Got AKName %s", in.AkName)
	glog.V(10).Infof("     Registry size %d\n", len(registry))

	idToken := ctx.Value(contextKey("idtoken")).(gcpIdentityDoc)
	glog.V(5).Infof("     From InstanceID %s", idToken.Google.ComputeEngine.InstanceID)

	newCtx := context.Background()

	computService, err := compute.NewService(newCtx)
	if err != nil {
		return &verifier.MakeCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to Verify EK with GCP APIs %v", err))
	}

	req := computService.Instances.GetShieldedInstanceIdentity(idToken.Google.ComputeEngine.ProjectID, idToken.Google.ComputeEngine.Zone, idToken.Google.ComputeEngine.InstanceName)
	r, err := req.Do()
	if err != nil {
		return &verifier.MakeCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to Recall Shielded Identity %v", err))
	}

	glog.V(10).Infof("     Acquired PublickKey from GCP API: \n%s", r.EncryptionKey.EkPub)

	glog.V(10).Infof("     Decoding ekPub from client")
	ekPub, err := tpm2.DecodePublic(in.EkPub)
	if err != nil {
		return &verifier.MakeCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Error DecodePublic EK %v", err))
	}

	ekPubKey, err := ekPub.Key()
	if err != nil {
		return &verifier.MakeCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Error extracting ekPubKey: %s", err))
	}
	ekBytes, err := x509.MarshalPKIXPublicKey(ekPubKey)
	if err != nil {
		return &verifier.MakeCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to convert ekPub: %v", err))
	}

	ekPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: ekBytes,
		},
	)
	glog.V(10).Infof("     EKPubPEM: \n%v", string(ekPubPEM))

	if string(ekPubPEM) != r.EncryptionKey.EkPub {
		return &verifier.MakeCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("EkPub mismatchKey"))
	}

	glog.V(2).Infof("     Verified EkPub from GCE API matches ekPub from Client")

	if useInstanceIDAsKey {
		registry[idToken.Google.ComputeEngine.InstanceID] = *in
	} else {
		registry[in.Uid] = *in
	}

	credBlob, encryptedSecret, err := makeCredential(*secret, in.EkPub, in.AkPub)
	if err != nil {
		return &verifier.MakeCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to makeCredential"))
	}
	glog.V(2).Infof("     Returning MakeCredentialResponse ========")
	return &verifier.MakeCredentialResponse{
		Uid:             in.Uid,
		CredBlob:        credBlob,
		EncryptedSecret: encryptedSecret,
		Pcr:             int32(*pcr),
	}, nil
}

func (s *server) ActivateCredential(ctx context.Context, in *verifier.ActivateCredentialRequest) (*verifier.ActivateCredentialResponse, error) {

	glog.V(2).Infof("======= ActivateCredential ========")
	glog.V(5).Infof("     client provided uid: %s", in.Uid)
	glog.V(10).Infof("     Secret %s", in.Secret)

	idToken := ctx.Value(contextKey("idtoken")).(gcpIdentityDoc)
	glog.V(5).Infof("     From InstanceID %s", idToken.Google.ComputeEngine.InstanceID)

	verified := false
	var id string
	if useInstanceIDAsKey {
		id = idToken.Google.ComputeEngine.InstanceID
	} else {
		id = in.Uid
	}
	err := verifyQuote(id, *secret, in.Attestation, in.Signature)
	if err != nil {
		glog.Errorf("     Quote Verification Failed Quote: %v", err)
		return &verifier.ActivateCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Quote Verification Failed Quote: %v", err))
	} else {
		glog.V(2).Infof("     Verified Quote")
		verified = true
	}

	var key []byte
	if *importMode == "RSA" {
		_, key, err = generateCertificate(id)
		if err != nil {
			return &verifier.ActivateCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to gernate certificate %v", err))
		}
	}

	importBLob, err := createImportBlob(id, key)
	if err != nil {
		return &verifier.ActivateCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create Import Blob %v", err))
	}
	glog.V(2).Infof("     Returning ActivateCredentialResponse ========")

	return &verifier.ActivateCredentialResponse{
		Uid:        in.Uid,
		Verified:   verified,
		ImportBlob: importBLob,
	}, nil
}

func (s *server) OfferQuote(ctx context.Context, in *verifier.OfferQuoteRequest) (*verifier.OfferQuoteResponse, error) {
	glog.V(2).Infof("======= OfferQuote ========")
	glog.V(5).Infof("     client provided uid: %s", in.Uid)

	idToken := ctx.Value(contextKey("idtoken")).(gcpIdentityDoc)
	glog.V(5).Infof("     From InstanceID %s", idToken.Google.ComputeEngine.InstanceID)

	nonce := uuid.New().String()
	var id string
	if useInstanceIDAsKey {
		id = idToken.Google.ComputeEngine.InstanceID
	} else {
		id = in.Uid
	}
	glog.V(2).Infof("     Returning OfferQuoteResponse ========")
	nonces[id] = nonce
	return &verifier.OfferQuoteResponse{
		Uid:   in.Uid,
		Pcr:   int32(*pcr),
		Nonce: nonce,
	}, nil
}

func (s *server) ProvideQuote(ctx context.Context, in *verifier.ProvideQuoteRequest) (*verifier.ProvideQuoteResponse, error) {
	glog.V(2).Infof("======= ProvideQuote ========")
	glog.V(5).Infof("     client provided uid: %s", in.Uid)

	idToken := ctx.Value(contextKey("idtoken")).(gcpIdentityDoc)
	glog.V(5).Infof("     From InstanceID %s", idToken.Google.ComputeEngine.InstanceID)

	ver := false
	var id string

	if useInstanceIDAsKey {
		id = idToken.Google.ComputeEngine.InstanceID
	} else {
		id = in.Uid
	}

	val, ok := nonces[id]
	if !ok {
		glog.V(2).Infof("Unable to find nonce request for uid")
	} else {
		delete(nonces, id)
		err := verifyQuote(id, val, in.Attestation, in.Signature)
		if err == nil {
			ver = true
		} else {
			return &verifier.ProvideQuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to Verify Quote %v", err))
		}
	}

	glog.V(2).Infof("     Returning ProvideQuoteResponse ========")
	return &verifier.ProvideQuoteResponse{
		Uid:      in.Uid,
		Verified: ver,
	}, nil
}

func verifyQuote(uid string, nonce string, attestation []byte, sigBytes []byte) (retErr error) {
	glog.V(2).Infof("     --> Starting verifyQuote()")

	nn := registry[uid]
	akPub := nn.AkPub

	glog.V(10).Infof("     Read and Decode (attestion)")
	att, err := tpm2.DecodeAttestationData(attestation)
	if err != nil {
		return fmt.Errorf("DecodeAttestationData(%v) failed: %v", attestation, err)
	}

	glog.V(5).Infof("     Attestation ExtraData (nonce): %s ", string(att.ExtraData))
	glog.V(5).Infof("     Attestation PCR#: %v ", att.AttestedQuoteInfo.PCRSelection.PCRs)
	glog.V(5).Infof("     Attestation Hash: %v ", hex.EncodeToString(att.AttestedQuoteInfo.PCRDigest))

	if nonce != string(att.ExtraData) {
		glog.Errorf("     Nonce Value mismatch Got: (%s) Expected: (%v)", string(att.ExtraData), nonce)
		return fmt.Errorf("Nonce Value mismatch Got: (%s) Expected: (%v)", string(att.ExtraData), nonce)
	}

	sigL := tpm2.SignatureRSA{
		HashAlg:   tpm2.AlgSHA256,
		Signature: sigBytes,
	}
	decoded, err := hex.DecodeString(*expectedPCRValue)
	if err != nil {
		return fmt.Errorf("DecodeAttestationData(%v) failed: %v", attestation, err)
	}
	hash := sha256.Sum256(decoded)

	glog.V(5).Infof("     Expected PCR Value:           --> %s", *expectedPCRValue)
	glog.V(5).Infof("     sha256 of Expected PCR Value: --> %x", hash)

	glog.V(2).Infof("     Decoding PublicKey for AK ========")
	p, err := tpm2.DecodePublic(akPub)
	if err != nil {
		return fmt.Errorf("DecodePublic failed: %v", err)
	}
	rsaPub := rsa.PublicKey{E: int(p.RSAParameters.Exponent()), N: p.RSAParameters.Modulus()}
	hsh := crypto.SHA256.New()
	hsh.Write(attestation)
	if err := rsa.VerifyPKCS1v15(&rsaPub, crypto.SHA256, hsh.Sum(nil), sigL.Signature); err != nil {
		return fmt.Errorf("VerifyPKCS1v15 failed: %v", err)
	}

	if fmt.Sprintf("%x", hash) != hex.EncodeToString(att.AttestedQuoteInfo.PCRDigest) {
		return fmt.Errorf("Unexpected PCR hash Value expected: %s  Got %s", fmt.Sprintf("%x", hash), hex.EncodeToString(att.AttestedQuoteInfo.PCRDigest))
	}

	if nonce != string(att.ExtraData) {
		return fmt.Errorf("Unexpected secret Value expected: %v  Got %v", nonce, string(att.ExtraData))
	}
	glog.V(2).Infof("     Attestation Signature Verified ")
	glog.V(2).Infof("     <-- End verifyQuote()")
	return nil
}

func makeCredential(sec string, ekPubBytes []byte, akPubBytes []byte) (credBlob []byte, encryptedSecret []byte, retErr error) {

	glog.V(2).Infof("     --> Starting makeCredential()")
	glog.V(10).Infof("     Read (ekPub) from request")

	ekPub, err := tpm2.DecodePublic(ekPubBytes)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Error DecodePublic AK %v", err)
	}

	ekh, keyName, err := tpm2.LoadExternal(rwc, ekPub, tpm2.Private{}, tpm2.HandleNull)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Error loadingExternal EK %v", err)
	}
	defer tpm2.FlushContext(rwc, ekh)

	glog.V(10).Infof("     Read (akPub) from request")

	tPub, err := tpm2.DecodePublic(akPubBytes)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Error DecodePublic AK %v", tPub)
	}

	ap, err := tPub.Key()
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("akPub.Key() failed: %s", err)
	}
	akBytes, err := x509.MarshalPKIXPublicKey(ap)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Unable to convert akPub: %v", err)
	}

	akPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: akBytes,
		},
	)
	glog.V(10).Infof("     Decoded AkPub: \n%v", string(akPubPEM))

	if tPub.MatchesTemplate(defaultKeyParams) {
		glog.V(10).Infof("     AK Default parameter match template")
	} else {
		return []byte(""), []byte(""), fmt.Errorf("AK does not have correct defaultParameters")
	}
	h, keyName, err := tpm2.LoadExternal(rwc, tPub, tpm2.Private{}, tpm2.HandleNull)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Error loadingExternal AK %v", err)
	}
	defer tpm2.FlushContext(rwc, h)
	glog.V(10).Infof("     Loaded AK KeyName %s", hex.EncodeToString(keyName))

	glog.V(5).Infof("     MakeCredential Start")
	credential := []byte(sec)
	credBlob, encryptedSecret0, err := tpm2.MakeCredential(rwc, ekh, credential, keyName)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("MakeCredential failed: %v", err)
	}
	glog.V(10).Infof("     credBlob %s", hex.EncodeToString(credBlob))
	glog.V(10).Infof("     encryptedSecret0 %s", hex.EncodeToString(encryptedSecret0))
	glog.V(2).Infof("     <-- End makeCredential()")
	return credBlob, encryptedSecret0, nil
}

func generateCertificate(cn string) (cert []byte, key []byte, retErr error) {
	glog.V(2).Infof("     --> Start generateCertificate()")
	glog.V(5).Infof("     Generating Certificate for cn=%s", cn)

	certPEMBytes, err := ioutil.ReadFile(*caCert)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Unable to read %s %v", *caCert, err)
	}
	block, _ := pem.Decode(certPEMBytes)
	if block == nil {
		return []byte(""), []byte(""), fmt.Errorf("Unable to decode %s %v", *caCert, err)
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Unable to parse %s %v", *caCert, err)
	}

	glog.V(10).Infof("     Generated cert with Serial %s", ca.SerialNumber.String())

	keyPEMBytes, err := ioutil.ReadFile(*caKey)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Unable to read %s  %v", *caKey, err)
	}
	privPem, _ := pem.Decode(keyPEMBytes)
	parsedKey, err := x509.ParsePKCS1PrivateKey(privPem.Bytes)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Unable to parse %s %v", *caKey, err)
	}

	var notBefore time.Time
	notBefore = time.Now()

	notAfter := notBefore.Add(time.Hour * 24 * 365)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Failed to generate serial number: %v", err)
	}

	cc := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"Acme Co"},
			OrganizationalUnit: []string{"Enterprise"},
			Locality:           []string{"Mountain View"},
			Province:           []string{"California"},
			Country:            []string{"US"},
			CommonName:         cn,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              []string{cn},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &priv.PublicKey

	cert_b, err := x509.CreateCertificate(rand.Reader, cc, ca, pub, parsedKey)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Failed to createCertificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert_b,
		},
	)
	privPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)

	glog.V(10).Infof("     Generating Test Signature with private Key")
	dataToSign := []byte("secret")
	digest := sha256.Sum256(dataToSign)
	signature, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from signing: %s\n", err)
		return
	}

	glog.V(10).Infof("     Test signature data:  %s", base64.RawStdEncoding.EncodeToString(signature))
	glog.V(2).Infof("     <-- End generateCertificate()")
	return certPEM, privPEM, nil
}

func createImportBlob(uid string, saKey []byte) (blob []byte, retErr error) {
	glog.V(2).Infof("     --> Start createImportBlob()")
	glog.V(10).Infof("     Load and decode ekPub from registry")
	nn := registry[uid]

	tPub, err := tpm2.DecodePublic(nn.EkPub)
	if err != nil {
		return []byte(""), fmt.Errorf("Error DecodePublic K %v", tPub)
	}

	ap, err := tPub.Key()
	if err != nil {
		return []byte(""), fmt.Errorf("akPub.Key() failed: %s", err)
	}

	glog.V(5).Infof("     Decoding sealing PCR value in hex")
	hv, err := hex.DecodeString(*expectedPCRValue)
	if err != nil {
		return []byte(""), fmt.Errorf("Error parsing uint64->32: %v\n", err)
	}

	pcrMap := map[uint32][]byte{uint32(*pcr): hv}
	var pcrs *pb.Pcrs

	pcrs = &pb.Pcrs{Hash: pb.HashAlgo_SHA256, Pcrs: pcrMap}

	var sealedOutput []byte
	if *importMode == "RSA" {
		glog.V(2).Infof("     --> createSigningKeyImportBlob()")
		glog.V(5).Infof("     Generating to RSA sealedFile")

		privBlock, _ := pem.Decode(saKey)

		signingKey, err := x509.ParsePKCS1PrivateKey(privBlock.Bytes)
		if err != nil {
			return []byte(""), fmt.Errorf("Unable to read read rsa PrivateKey: %v", err)
		}

		importBlob, err := gotpmserver.CreateSigningKeyImportBlob(ap, signingKey, pcrs)
		if err != nil {
			return []byte(""), fmt.Errorf("Unable to CreateSigningKeyImportBlob: %v", err)
		}

		glog.V(5).Infof("     Returning sealed key")

		sealedOutput, err = proto.Marshal(importBlob)
		if err != nil {
			return []byte(""), fmt.Errorf("marshaling error: ", err)
		}

	} else if *importMode == "AES" {
		glog.V(2).Infof("     --> createImportBlob()")
		glog.V(5).Infof("     Generating to AES sealedFile")
		importBlob, err := gotpmserver.CreateImportBlob(ap, []byte(*aes256Key), pcrs)
		if err != nil {
			glog.Fatalf("Unable to CreateImportBlob : %v", err)
		}
		sealedOutput, err = proto.Marshal(importBlob)
		if err != nil {
			glog.Fatalf("Unable to marshall ImportBlob: ", err)
		}
	} else {
		glog.Fatalln("Import mode must be RSA or AES")
	}

	glog.V(2).Infof("     <-- End createImportBlob()")

	return sealedOutput, nil
}
