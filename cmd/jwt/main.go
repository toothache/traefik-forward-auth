package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/coreos/go-oidc"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/palantir/stacktrace"
	"github.com/s12v/go-jwks"
	"github.com/square/go-jose"
)

const (
	// Key in the Headers hashmap of the token that points to the key ID
	keyIdTokenHeaderKey = "kid"

	// Header and footer to attach to base64-encoded key data that we receive from Auth0
	pubKeyHeader = "-----BEGIN CERTIFICATE-----"
	pubKeyFooter = "-----END CERTIFICATE-----"
)

func getKey(keyId string) (*jose.JSONWebKey, bool) {
	jwksSource := jwks.NewWebSource("https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/discovery/v2.0/keys")
	jwksClient := jwks.NewDefaultClient(
		jwksSource,
		time.Hour,    // Refresh keys every 1 hour
		12*time.Hour, // Expire keys after 12 hours
	)

	var jwk *jose.JSONWebKey
	jwk, err := jwksClient.GetEncryptionKey(keyId)
	if err != nil {
		log.Fatal(err)
		return nil, false
	}

	return jwk, true
}

func validate() {
	// sample token string taken from the New example
	tokenString := "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6ImtnMkxZczJUMENUaklmajRydDZKSXluZW4zOCIsImtpZCI6ImtnMkxZczJUMENUaklmajRydDZKSXluZW4zOCJ9.eyJhdWQiOiJhcGk6Ly8yYmRkMTE4Yi1kMDI3LTRiNmYtYmMyMy02OTM2MGE1Yzk1NmQiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC83MmY5ODhiZi04NmYxLTQxYWYtOTFhYi0yZDdjZDAxMWRiNDcvIiwiaWF0IjoxNjA1MTA3MzMyLCJuYmYiOjE2MDUxMDczMzIsImV4cCI6MTYwNTExMTIzMiwiYWNyIjoiMSIsImFpbyI6IkFWUUFxLzhSQUFBQUVsbFZQSDJKamV1TWZHQ2F4ZEtwRlQxalJPVDZRZFZSbzltZG1ZNmQrUW4zTktnM210cjFyNXpsREdHdC9RTlBCZUR1aDg5ckFjZnlyZ1VYSm8reEZPUlVvSENFU3IvNmt1OUJNd1owWTJNPSIsImFtciI6WyJwd2QiLCJyc2EiLCJtZmEiXSwiYXBwaWQiOiIzZGQyMWY2Mi1jODM2LTQ2ODktODRmNi02NzgwOTU4Y2YwMDIiLCJhcHBpZGFjciI6IjAiLCJkZXZpY2VpZCI6ImU2ODM5OTlmLTY5MTYtNDk4OS1iODJhLTI0NTNmODgxOGJkZCIsImZhbWlseV9uYW1lIjoiSG9uZyIsImdpdmVuX25hbWUiOiJZYXRlbmciLCJpcGFkZHIiOiIxMTQuMjUzLjg3LjEyNiIsIm5hbWUiOiJZYXRlbmcgSG9uZyIsIm9pZCI6ImM4ZmMzNGE2LWQzMTQtNDBkNy1iMjg0LThkYzJkOTE2OTdhNyIsIm9ucHJlbV9zaWQiOiJTLTEtNS0yMS0yMTQ2NzczMDg1LTkwMzM2MzI4NS03MTkzNDQ3MDctMTkzMjA0NSIsInJoIjoiMC5BUm9BdjRqNWN2R0dyMEdScXkxODBCSGJSMklmMGowMnlJbEdoUFpuZ0pXTThBSWFBSFkuIiwic2NwIjoiYWNjZXNzX2FzX3VzZXIiLCJzdWIiOiJYRHVWNjRQOFl0d2Flek1rbld1Rm5HY0xJR3BWejFOM3RUREFKdG1za2lvIiwidGlkIjoiNzJmOTg4YmYtODZmMS00MWFmLTkxYWItMmQ3Y2QwMTFkYjQ3IiwidW5pcXVlX25hbWUiOiJ5YXRlbmdoQG1pY3Jvc29mdC5jb20iLCJ1cG4iOiJ5YXRlbmdoQG1pY3Jvc29mdC5jb20iLCJ1dGkiOiJaeU1Tdm1DUnRFeWlRNlYyc0pSSUFnIiwidmVyIjoiMS4wIn0.InY5GwT_8-PDxXmyrV7XAa68JnJh0WN_oLK83-fNYstVCe-dLehQihCMYv_4ansEdP2vWQY9t91CK8yH6EE3jHvgdfZItjesY9BiUzLG2sPCJ_JPkyLUXysno8cLC2bCyzaMgP1SUrG1hUR3olYPMtB6_8esZiZ_MfZXJfffxaNHgu9pNGCJ7blWGIhXBeXEU9yGH7f13Whq_pLlvBOZ2tZ9RLsEmxp8Z3GMXMjY8nYLadxLHPsuxN-UexgDVVsWr74rcWFFXwduGV8W26X5sDvKs7EflByVkptbExC3t8qhETr7A5cQu5ZSCNZNcv9azrwXsDiZuGn7asCtQFnpdQ"

	// Parse takes the token string and a function for looking up the key. The latter is especially
	// useful if you use multiple keys for your application.  The standard is to use 'kid' in the
	// head of the token to identify which key to use, but the parsed token (head and claims) is provided
	// to the callback, providing flexibility.
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		fmt.Println(token.Header)

		// IMPORTANT: Validating the algorithm per https://godoc.org/github.com/dgrijalva/jwt-go#example-Parse--Hmac
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, stacktrace.NewError(
				"Expected token algorithm '%v' but got '%v'",
				jwt.SigningMethodRS256.Name,
				token.Header)
		}

		untypedKeyId, found := token.Header[keyIdTokenHeaderKey]
		if !found {
			return nil, stacktrace.NewError("No key ID key '%v' found in token header", keyIdTokenHeaderKey)
		}
		keyId, ok := untypedKeyId.(string)
		if !ok {
			return nil, stacktrace.NewError("Found key ID, but value was not a string")
		}

		webKey, found := getKey(keyId)
		if !found {
			return nil, stacktrace.NewError("No public RSA key found corresponding to key ID from token '%v'", keyId)
		}

		return webKey.Public().Key, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		fmt.Println(claims)
	} else {
		fmt.Println(err)
	}
}

func main() {
	ctx := context.Background()
	p, err := oidc.NewProvider(ctx, "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0")
	if err == nil {
		cfg := &oidc.Config{
			ClientID:             "3dd21f62-c836-4689-84f6-6780958cf002",
			SupportedSigningAlgs: []string{"RS256"},
			SkipClientIDCheck:    false,
			SkipExpiryCheck:      false,
			SkipIssuerCheck:      false,
		}
		verifier := p.Verifier(cfg)

		var token *oidc.IDToken
		token, err = verifier.Verify(ctx, "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImtnMkxZczJUMENUaklmajRydDZKSXluZW4zOCJ9.eyJhdWQiOiIzZGQyMWY2Mi1jODM2LTQ2ODktODRmNi02NzgwOTU4Y2YwMDIiLCJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vNzJmOTg4YmYtODZmMS00MWFmLTkxYWItMmQ3Y2QwMTFkYjQ3L3YyLjAiLCJpYXQiOjE2MDUxMzU4NTcsIm5iZiI6MTYwNTEzNTg1NywiZXhwIjoxNjA1MTM5NzU3LCJhaW8iOiJBWFFBaS84UkFBQUE2eUw3VXVmMzVkeHJ4WEU0K1FDZ3lQcXdLMzZHaFdUK0ZlM3BZZnl4ZlRrUEZTQ1k1amVuMCtBTDVHRVYvcVNnQnNNNStRb3o2MzBERjl2YXdOdVpzK1NkVjAydGZENUxzN1dyZGdpRkVrMW9nQktreTgzNEVoZ3crYzBaZkJZZ0dIZVExMGR3YlpJUTVsY2Qyek9PUnc9PSIsImF6cCI6IjNkZDIxZjYyLWM4MzYtNDY4OS04NGY2LTY3ODA5NThjZjAwMiIsImF6cGFjciI6IjAiLCJuYW1lIjoiWWF0ZW5nIEhvbmciLCJvaWQiOiJjOGZjMzRhNi1kMzE0LTQwZDctYjI4NC04ZGMyZDkxNjk3YTciLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJ5YXRlbmdoQG1pY3Jvc29mdC5jb20iLCJyaCI6IjAuQVJvQXY0ajVjdkdHcjBHUnF5MTgwQkhiUjJJZjBqMDJ5SWxHaFBabmdKV004QUlhQUhZLiIsInNjcCI6ImFjY2Vzc19hc191c2VyIiwic3ViIjoiZFZ1dE1KRUhKQVA1c3ZNQmdHOUFZanZTejc0REZLU0hEMEZ0ZWdnWkFwWSIsInRpZCI6IjcyZjk4OGJmLTg2ZjEtNDFhZi05MWFiLTJkN2NkMDExZGI0NyIsInV0aSI6IjZqbXhBTWRvSDA2ckpaZy1USnBDQWciLCJ2ZXIiOiIyLjAifQ.hIStHDTmvwOqsmJRIREWWXoo8MDhoIzOKHuvx_-MdspeWqmJ6Y1-aTyECmSBvkEeKjdou3RQZ5cREkPIhzT-WFwHbFF3e2WNORwlGLDMXOu6psCoXk_HnozL536MQ4F4mMK18vDs4OJWNB2FyRarfcGcV4Q89x1JPPdPFa2nAt0NFRc1uQqMWJYEyi0uwUiGHLn6c1iTH35SVbZva18SOtlJE9z_IqpicxWvwj6V7JgWOmY7rBwXcklAl-2q5HS1INEe_mPm5j2iOGeaDL3beYGaMGaNZJFpwWTsg4rJG9RR-S_rmmzVdTx5wu8C36kEBuOD4hXNthA3M4KNEvBrIg")
		if err == nil {
			var claims struct {
				Name string `json:"name"`

				Email string `json:"preferred_username"`
			}
			err = token.Claims(&claims)
			fmt.Println(claims, err)
		}
	}

}
