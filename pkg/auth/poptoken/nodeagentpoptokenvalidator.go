package poptoken

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pkg/errors"
)

const (
	TokenVersion1         = "1.0"
	TokenVersion2         = "2.0"
	PopTokenValidInterval = 1 * time.Hour //TODO: should we make this smaller?
)

type nodeAgentPopTokenBody struct {
	ShrPopTokenBody
	// target resource Id. Expected to match ShrPopTokenValidator.TargetResourceId
	ResourceId string `json:"resourceid"`
}

// contains a subset of custom claims in Entra/AzureAD access tokens we want to validate.
// See https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference#payload-claims
type AccessTokenCustomClaims struct {
	// contains the public key kid use to sign the pop token. Verify this matches the kid in the poptoken body.
	ReqCnf ReqCnf `json:"cnf"`
	// requester Id, i.e. CMP 1P. Expected to match ShrPopTokenValidator.ClientId. Only valid for token v2
	Azp string `json:"azp"`
	// requester Id, i.e. CMP 1P/identifuerUri. Expected to match ShrPopTokenValidator.ClientId. Only valid for token v1
	AppId string `json:"appid"`
	// Tenant Id. Expected to match ShrPopTokenValidator.TenantId
	Tid string `json:"tid"`
	// token version.
	TokenVersion string `json:"ver"`
	jwt.RegisteredClaims
}

type ShrPopTokenValidator struct {
	// A4S agent resourceId
	TargetResourceId string
	// Tenant Id of  CMP 1P
	TenantId string
	// The target Id. In this case,  client Id or one of its identifierUri, depending on the token version.
	Audience map[string]bool
	// CMP 1P client Id
	ClientId string
	// Issuer url, e.g. https://login.microsoftonline.com/<tenanId>
	IssuerUrl string
	// component use to query Entra JWK endpoint.
	jwk JwkInterface
}

// handle situation where url may or may not have a backslash
func appendUrl(url string, postfix string) string {
	sep := "/"
	if strings.HasSuffix(url, "/") {
		sep = ""
	}
	return fmt.Sprintf("%s%s%s", url, sep, postfix)
}

func isTokenExpire(timestamp int64, now time.Time) error {
	var issuedTime time.Time
	convertTime(timestamp, &issuedTime)
	expireat := issuedTime.Add(PopTokenValidInterval)
	if expireat.Before(now) {
		return fmt.Errorf("pop token has expired. Time when validated: %v, issued At: %v, valid duration: %v", now, issuedTime, PopTokenValidInterval)
	}
	return nil
}

func isHeaderValid(header *ShrPopHeader) error {
	if header.Typ != TokenType {
		return fmt.Errorf("expected token type %s, got %s", TokenType, header.Typ)
	}
	if header.Alg != Alg {
		return fmt.Errorf("expected alg %s, got %s", Alg, header.Alg)
	}

	return nil
}

func isSignatureValid(signingStr *string, signature []byte, cnf *Cnf) error {
	publicKey, err := publicRSA256KeyFromCnf(cnf)
	if err != nil {
		return err
	}
	return verifyPayload(signingStr, []byte(signature), publicKey)
}

func verifyPayload(signingStr *string, sig []byte, pubKey *rsa.PublicKey) error {
	hash := sha256.New()
	hash.Write([]byte(*signingStr))
	err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash.Sum(nil), sig)
	if err != nil {
		return errors.Wrapf(err, "failed to validate signature of poptoken using cnf")
	}
	return nil
}

func publicRSA256KeyFromCnf(cnf *Cnf) (*rsa.PublicKey, error) {
	modulus, err := base64.URLEncoding.DecodeString(cnf.Jwk.N)
	if err != nil {
		err := errors.Wrapf(err, "error while parsing poptoken cnf: failed to decode modulus")
		return nil, err
	}
	n := big.NewInt(0)
	n.SetString(string(modulus), 10)

	e, err := base64ToExponential(string(cnf.Jwk.E))
	if err != nil {
		err := errors.Wrapf(err, "error while parsing poptoken cnf: failed to parse exponent")
		return nil, err
	}
	pKey := rsa.PublicKey{N: n, E: int(e)}

	return &pKey, nil
}

func base64ToExponential(encodedE string) (int, error) {
	decE, err := base64.URLEncoding.DecodeString(encodedE)
	if err != nil {
		return 0, err
	}

	var eBytes []byte
	if len(decE) < 8 {
		eBytes = make([]byte, 8-len(decE), 8)
		eBytes = append(eBytes, decE...)
	} else {
		eBytes = decE
	}
	eReader := bytes.NewReader(eBytes)
	var ee uint64
	err = binary.Read(eReader, binary.BigEndian, &ee)
	if err != nil {
		return 0, err
	}

	return int(ee), nil
}

func decodeFromBase64[T any](jsonData string) (T, error) {
	var t T
	var err error

	bytes, err := base64.RawURLEncoding.DecodeString(jsonData)
	if err != nil {
		return t, err
	}

	err = json.Unmarshal(bytes, &t)
	if err != nil {
		return t, err
	}

	return t, nil
}

func convertTime(i any, tm *time.Time) {
	switch iat := i.(type) {
	case float64:
		*tm = time.Unix(int64(iat), 0)
	case int64:
		*tm = time.Unix(iat, 0)
	case string:
		v, _ := strconv.ParseInt(iat, 10, 64)
		*tm = time.Unix(v, 0)
	}
}

func (s *ShrPopTokenValidator) parseAndValidateAccessToken(tokenStr string, popTokenKid string) error {
	// ParseWithClaims() will validate the token expiry date and signing.
	at, err := jwt.ParseWithClaims(tokenStr, &AccessTokenCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("failed to find kid in access token header")
		}

		pKey, err := s.jwk.GetPublicKey(kid)
		if err != nil {
			return nil, err
		}

		return pKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))

	if err != nil {
		return errors.Wrapf(err, "failed to parse access token")
	}

	err = s.validateAccessTokenClaims(at, popTokenKid)
	return err
}

func (s *ShrPopTokenValidator) validateAccessTokenClaims(token *jwt.Token, popTokenKid string) error {
	if token == nil {
		return fmt.Errorf("empty token in validateAccessTokenClaims!")
	}

	// now read in Entra access token's specific claims and validate them
	claims, ok := token.Claims.(*AccessTokenCustomClaims)
	if !ok {
		return fmt.Errorf("failed to retrieve expected claims in access token")
	}

	// Handle claims that are specifc to token versions
	switch claims.TokenVersion {
	case TokenVersion1:
		if claims.AppId != s.ClientId {
			return fmt.Errorf("invalid appId claim")
		}
		if claims.Issuer != s.IssuerUrl {
			return fmt.Errorf("invalid issuer")
		}
	case TokenVersion2:
		if claims.Azp != s.ClientId {
			return fmt.Errorf("invalid azp claim")
		}
		// for v2, issuer ends with v2.0
		if claims.Issuer != appendUrl(s.IssuerUrl, "v2.0") {
			return fmt.Errorf("invalid issuer for v2 token")
		}

	default:
		return fmt.Errorf("unknown token version %s. expected either %sor %s", claims.TokenVersion, TokenVersion1, TokenVersion2)
	}

	if claims.ReqCnf.Kid != popTokenKid {
		return fmt.Errorf("kid in pop token did not match kid in access token. expected kid: %s, got kid: %s", claims.ReqCnf.Kid, popTokenKid)
	}

	foundAud := false
	for _, aud := range claims.Audience {
		if _, ok := s.Audience[aud]; ok {
			foundAud = true
			break
		}
	}
	if !foundAud {
		return fmt.Errorf("aud claim was not expected")
	}

	return nil
}

func (s *ShrPopTokenValidator) isCustomClaimsValid(body *nodeAgentPopTokenBody) error {
	if body.ResourceId != s.TargetResourceId {
		return fmt.Errorf("invalid resourceId")
	}

	return nil
}

func (s *ShrPopTokenValidator) Validate(popToken string) error {
	toks := strings.Split(popToken, ".")
	if len(toks) != 3 {
		return fmt.Errorf("invalid pop tokens expected 3 segments, got %d", len(toks))
	}

	header, err := decodeFromBase64[ShrPopHeader](toks[0])
	if err != nil {
		return err
	}

	if err := isHeaderValid(&header); err != nil {
		return err
	}

	body, err := decodeFromBase64[nodeAgentPopTokenBody](toks[1])
	if err != nil {
		return err
	}

	if err := isTokenExpire(body.Ts, time.Now()); err != nil {
		return err
	}

	if err := s.isCustomClaimsValid(&body); err != nil {
		return err
	}

	signature, err := base64.RawURLEncoding.DecodeString(toks[2])
	if err != nil {
		return err
	}
	signingStr := strings.Join([]string{toks[0], toks[1]}, ".")
	err = isSignatureValid(&signingStr, signature, &body.Cnf)
	if err != nil {
		return err
	}

	// now retrieve the inner access token
	err = s.parseAndValidateAccessToken(body.At, body.Cnf.Jwk.Kid)
	if err != nil {
		return err
	}

	return nil
}

func NewPopTokenValidator(targetResourceId string, tenantId string, audiences []string, clientId string, authorityUrl string, jwk JwkInterface) (*ShrPopTokenValidator, error) {
	audienceMap := make(map[string]bool)
	for _, aud := range audiences {
		audienceMap[aud] = true
	}

	return &ShrPopTokenValidator{
		TargetResourceId: targetResourceId,
		TenantId:         tenantId,
		Audience:         audienceMap,
		ClientId:         clientId,
		IssuerUrl:        appendUrl(authorityUrl, tenantId),
		jwk:              jwk,
	}, nil
}
