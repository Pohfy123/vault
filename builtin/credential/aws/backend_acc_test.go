package awsauth

/*
	The AWS auth method backend acceptance tests are for testing high-level
	use cases the AWS auth engine has.
*/

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/hashicorp/go-hclog"

	logicaltest "github.com/hashicorp/vault/helper/testhelpers/logical"
	"github.com/hashicorp/vault/sdk/logical"
)

// This is directly based on our docs here:
// https://www.vaultproject.io/docs/auth/aws
func TestEC2LoginRenewDefaultSettings(t *testing.T) {
	if os.Getenv(logicaltest.TestEnvVar) == "" {
		t.Skip(fmt.Sprintf("Acceptance tests skipped unless env '%s' set", logicaltest.TestEnvVar))
	}
	testEnv, err := newTestEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	{
		// This is the fake key and secret in our docs.
		// vault write auth/aws/config/client secret_key=vCtSM8ZUEQ3mOFVlYPBQkf2sO6F/W7a5TVzrl3Oj access_key=VKIAJBRHKH6EVTTNXDHA
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "config/client",
			Storage:   testEnv.conf.StorageView,
			Data: map[string]interface{}{
				"secret_key": "vCtSM8ZUEQ3mOFVlYPBQkf2sO6F/W7a5TVzrl3Oj",
				"access_key": "VKIAJBRHKH6EVTTNXDHA",
			},
		}
		resp, err := testEnv.backend.HandleRequest(testEnv.ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if resp != nil {
			t.Fatalf("expected nil response but received %+v", resp)
		}
	}
	{
		// vault write auth/aws/role/dev-role auth_type=ec2 bound_ami_id=ami-fce3c696 policies=prod,dev max_ttl=500h
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "role/dev-role",
			Storage:   testEnv.conf.StorageView,
			Data: map[string]interface{}{
				"auth_type":    "ec2",
				"bound_ami_id": "ami-fce3c696",
				"policies":     []string{"prod", "dev"},
				"max_ttl":      "500h",
			},
		}
		resp, err := testEnv.backend.HandleRequest(testEnv.ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if resp != nil {
			t.Fatalf("expected nil response but received %+v", resp)
		}
	}
	{
		// vault write auth/aws/config/client iam_server_id_header_value=vault.example.com
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "config/client",
			Storage:   testEnv.conf.StorageView,
			Data: map[string]interface{}{
				"iam_server_id_header_value": "vault.example.com",
			},
		}
		resp, err := testEnv.backend.HandleRequest(testEnv.ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if resp != nil {
			t.Fatalf("expected nil response but received %+v", resp)
		}
	}
	renewalReq := &logical.Request{}
	{
		// vault write auth/aws/login role=dev-role \
		//		pkcs7=MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEHAaCAJIAEggGmewogICJkZXZwYXlQcm9kdWN0Q29kZXMiIDogbnVsbCwKICAicHJpdmF0ZUlwIiA6ICIxNzIuMzEuNjMuNjAiLAogICJhdmFpbGFiaWxpdHlab25lIiA6ICJ1cy1lYXN0LTFjIiwKICAidmVyc2lvbiIgOiAiMjAxMC0wOC0zMSIsCiAgImluc3RhbmNlSWQiIDogImktZGUwZjEzNDQiLAogICJiaWxsaW5nUHJvZHVjdHMiIDogbnVsbCwKICAiaW5zdGFuY2VUeXBlIiA6ICJ0Mi5taWNybyIsCiAgImFjY291bnRJZCIgOiAiMjQxNjU2NjE1ODU5IiwKICAiaW1hZ2VJZCIgOiAiYW1pLWZjZTNjNjk2IiwKICAicGVuZGluZ1RpbWUiIDogIjIwMTYtMDQtMDVUMTY6MjY6NTVaIiwKICAiYXJjaGl0ZWN0dXJlIiA6ICJ4ODZfNjQiLAogICJrZXJuZWxJZCIgOiBudWxsLAogICJyYW1kaXNrSWQiIDogbnVsbCwKICAicmVnaW9uIiA6ICJ1cy1lYXN0LTEiCn0AAAAAAAAxggEXMIIBEwIBATBpMFwxCzAJBgNVBAYTAlVTMRkwFwYDVQQIExBXYXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYDVQQKExdBbWF6b24gV2ViIFNlcnZpY2VzIExMQwIJAJa6SNnlXhpnMAkGBSsOAwIaBQCgXTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0xNjA0MDUxNjI3MDBaMCMGCSqGSIb3DQEJBDEWBBRtiynzMTNfTw1TV/d8NvfgVw+XfTAJBgcqhkjOOAQDBC4wLAIUVfpVcNYoOKzN1c+h1Vsm/c5U0tQCFAK/K72idWrONIqMOVJ8Uen0wYg4AAAAAAAA \
		//		nonce=5defbf9e-a8f9-3063-bdfc-54b7a42a1f95
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "login",
			Storage:   testEnv.conf.StorageView,
			Data: map[string]interface{}{
				"role":  "dev-role",
				"pkcs7": "MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEHAaCAJIAEggGmewogICJkZXZwYXlQcm9kdWN0Q29kZXMiIDogbnVsbCwKICAicHJpdmF0ZUlwIiA6ICIxNzIuMzEuNjMuNjAiLAogICJhdmFpbGFiaWxpdHlab25lIiA6ICJ1cy1lYXN0LTFjIiwKICAidmVyc2lvbiIgOiAiMjAxMC0wOC0zMSIsCiAgImluc3RhbmNlSWQiIDogImktZGUwZjEzNDQiLAogICJiaWxsaW5nUHJvZHVjdHMiIDogbnVsbCwKICAiaW5zdGFuY2VUeXBlIiA6ICJ0Mi5taWNybyIsCiAgImFjY291bnRJZCIgOiAiMjQxNjU2NjE1ODU5IiwKICAiaW1hZ2VJZCIgOiAiYW1pLWZjZTNjNjk2IiwKICAicGVuZGluZ1RpbWUiIDogIjIwMTYtMDQtMDVUMTY6MjY6NTVaIiwKICAiYXJjaGl0ZWN0dXJlIiA6ICJ4ODZfNjQiLAogICJrZXJuZWxJZCIgOiBudWxsLAogICJyYW1kaXNrSWQiIDogbnVsbCwKICAicmVnaW9uIiA6ICJ1cy1lYXN0LTEiCn0AAAAAAAAxggEXMIIBEwIBATBpMFwxCzAJBgNVBAYTAlVTMRkwFwYDVQQIExBXYXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYDVQQKExdBbWF6b24gV2ViIFNlcnZpY2VzIExMQwIJAJa6SNnlXhpnMAkGBSsOAwIaBQCgXTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0xNjA0MDUxNjI3MDBaMCMGCSqGSIb3DQEJBDEWBBRtiynzMTNfTw1TV/d8NvfgVw+XfTAJBgcqhkjOOAQDBC4wLAIUVfpVcNYoOKzN1c+h1Vsm/c5U0tQCFAK/K72idWrONIqMOVJ8Uen0wYg4AAAAAAAA",
				"nonce": "5defbf9e-a8f9-3063-bdfc-54b7a42a1f95",
			},
		}
		resp, err := testEnv.backend.HandleRequest(testEnv.ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response but received")
		}
		if resp.Auth == nil {
			t.Fatal("expected to receive auth")
		}
		renewalReq.Auth = resp.Auth
	}
	{
		// Test renewal.
		renewalReq.Storage = testEnv.conf.StorageView
		resp, err := testEnv.backend.pathLoginRenew(testEnv.ctx, renewalReq, nil)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response but received")
		}
		if resp.Auth == nil {
			t.Fatal("expected to receive auth")
		}
	}
}

func TestIAMLoginRenewDefaultSettings(t *testing.T) {
	if os.Getenv(logicaltest.TestEnvVar) == "" {
		t.Skip(fmt.Sprintf("Acceptance tests skipped unless env '%s' set", logicaltest.TestEnvVar))
	}
}

func newTestEnvironment() (*testEnvironment, error) {
	fakeEC2 := &fakeEC2Client{}
	mockEC2Client = fakeEC2
	fakeSTS := &fakeSTSClient{}
	mockSTSClient = fakeSTS
	ctx := context.Background()
	conf := &logical.BackendConfig{
		StorageView: &logical.InmemStorage{},
		Logger:      hclog.Default(),
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: 24 * time.Hour * 32,
			MaxLeaseTTLVal:     24 * time.Hour * 32,
		},
		BackendUUID: "1234-5678-9012-3456",
	}
	b, err := Factory(ctx, conf)
	if err != nil {
		return nil, err
	}
	return &testEnvironment{
		ctx:     ctx,
		conf:    conf,
		backend: b.(*backend),
		fakeEC2: fakeEC2,
		fakeSTS: fakeSTS,
	}, nil
}

type testEnvironment struct {
	ctx     context.Context
	conf    *logical.BackendConfig
	backend *backend
	fakeEC2 *fakeEC2Client
	fakeSTS *fakeSTSClient
}

type fakeSTSClient struct{}

func (f *fakeSTSClient) GetCallerIdentity(*sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
	return &sts.GetCallerIdentityOutput{
		Account: aws.String("241656615859"),
		Arn:     aws.String("arn:aws:iam::241656615859:tester/tester"),
		UserId:  aws.String("5678"),
	}, nil
}
func (f *fakeSTSClient) GetCallerIdentityRequest(*sts.GetCallerIdentityInput) (req *request.Request, output *sts.GetCallerIdentityOutput) {
	return &request.Request{}, nil
}

type fakeEC2Client struct{}

func (f *fakeEC2Client) DescribeInstances(*ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
	return &ec2.DescribeInstancesOutput{
		NextToken: nil,
		Reservations: []*ec2.Reservation{
			{
				Instances: []*ec2.Instance{
					{
						InstanceId: aws.String("i-de0f1344"),
						State: &ec2.InstanceState{
							Name: aws.String("running"),
						},
						ImageId: aws.String("ami-fce3c696"),
					},
				},
			},
		},
	}, nil
}
