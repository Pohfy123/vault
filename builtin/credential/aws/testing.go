package awsauth

import (
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/sts"
)

var (
	mockEC2Client ec2Client = nil
	mockSTSClient stsClient = nil
)

// If all STS clients are instantiated through here, they can easily become
// testable by simply supplying a mock client.
func newSTSClient(sess *session.Session) stsClient {
	if mockSTSClient != nil {
		return &testableSTSClient{
			stsClient: mockSTSClient,
		}
	}
	return &testableSTSClient{
		stsClient: sts.New(sess),
	}
}

type stsClient interface {
	GetCallerIdentity(*sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error)
	GetCallerIdentityRequest(*sts.GetCallerIdentityInput) (req *request.Request, output *sts.GetCallerIdentityOutput)
}

type testableSTSClient struct {
	stsClient
}

func newEC2Client(sess *session.Session) ec2Client {
	if mockEC2Client != nil {
		return &testableEC2Client{
			ec2Client: mockEC2Client,
		}
	}
	return &testableEC2Client{
		ec2Client: ec2.New(sess),
	}
}

type ec2Client interface {
	DescribeInstances(*ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error)
}

type testableEC2Client struct {
	ec2Client
}
