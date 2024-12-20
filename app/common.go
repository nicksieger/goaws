package app

/*** config ***/
type EnvSubsciption struct {
	Protocol     string
	EndPoint     string
	TopicArn     string
	QueueName    string
	Raw          bool
	FilterPolicy string
}

type EnvTopic struct {
	Name          string
	Subscriptions []EnvSubsciption
}

type EnvQueue struct {
	Name                          string
	ReceiveMessageWaitTimeSeconds int
	RedrivePolicy                 string
	MaximumMessageSize            int
	VisibilityTimeout             int
}

type EnvQueueAttributes struct {
	VisibilityTimeout             int
	ReceiveMessageWaitTimeSeconds int
	MaximumMessageSize            int
}

type Credentials struct {
	AccessKeyId, SecretAccessKey string
}

type Environment struct {
	Host                   string
	Port                   string
	SqsPort                string
	SnsPort                string
	Region                 string
	AccountID              string
	Credentials            Credentials
	LogToFile              bool
	LogFile                string
	EnableDuplicates       bool
	TopicStorage           string
	Topics                 []EnvTopic
	Queues                 []EnvQueue
	QueueAttributeDefaults EnvQueueAttributes
	RandomLatency          RandomLatency
	SkipConfirmSubs        bool
	SubscriptionsDir       string
}

var CurrentEnvironment Environment

/*** Common ***/
type ResponseMetadata struct {
	RequestId string `xml:"RequestId"`
}

/*** Error Responses ***/
type ErrorResult struct {
	Type    string `xml:"Type,omitempty"`
	Code    string `xml:"Code,omitempty"`
	Message string `xml:"Message,omitempty"`
}

type ErrorResponse struct {
	Result    ErrorResult `xml:"Error"`
	RequestId string      `xml:"RequestId"`
}

type RandomLatency struct {
	Min int
	Max int
}
