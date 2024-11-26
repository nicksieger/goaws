package app

import (
	"fmt"
	"slices"
	"sync"
)

type SnsErrorType struct {
	HttpError int
	Type      string
	Code      string
	Message   string
}

var SnsErrors map[string]SnsErrorType

type MsgAttr struct {
	Type  string
	Value string
}
type SNSMessage struct {
	Type              string
	Token             string `json:"Token,omitempty"`
	MessageId         string
	TopicArn          string
	Subject           string
	Message           string
	Timestamp         string
	SignatureVersion  string
	Signature         string `json:"Signature,omitempty"`
	SigningCertURL    string
	UnsubscribeURL    string
	SubscribeURL      string             `json:"SubscribeURL,omitempty"`
	MessageAttributes map[string]MsgAttr `json:"MessageAttributes,omitempty"`
}

type Subscription struct {
	TopicArn        string
	Protocol        string
	SubscriptionArn string
	EndPoint        string
	Raw             bool
	FilterPolicy    FilterPolicy `json:"FilterPolicy,omitempty"`
}

// only simple "ExactMatch" string policy is supported at the moment
type FilterPolicy map[string][]string

// Function checks if MessageAttributes passed to Topic satisfy FilterPolicy set by subscription
func (fp FilterPolicy) IsSatisfiedBy(msgAttrs map[string]MessageAttributeValue) bool {
	for policyAttrName, policyAttrValues := range fp {
		attrValue, ok := msgAttrs[policyAttrName]
		if !ok {
			return false // the attribute has to be present in the message
		}

		// String, String.Array, Number data-types are allowed by SNS filter policies
		// however go-AWS currently only supports String filter policies. That feature can be added here
		// ref: https://docs.aws.amazon.com/sns/latest/dg/message-filtering.html
		if attrValue.DataType != "String" {
			return false
		}

		if !stringInSlice(attrValue.Value, policyAttrValues) {
			return false // the attribute value has to be among filtered ones
		}
	}

	return true
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

type Topic struct {
	Name          string
	Arn           string
	Subscriptions []*Subscription
}

type (
	Protocol         string
	MessageStructure string
)

const (
	ProtocolHTTP    Protocol = "http"
	ProtocolHTTPS   Protocol = "https"
	ProtocolSQS     Protocol = "sqs"
	ProtocolDefault Protocol = "default"
)

const (
	MessageStructureJSON MessageStructure = "json"
)

// Predefined errors
const (
	ErrNoDefaultElementInJSON = "Invalid parameter: Message Structure - No default entry in JSON message body"
)

type Topics struct {
	sync.RWMutex
	Topics map[string]*Topic
}

func (ts *Topics) Add(t *Topic) {
	ts.Lock()
	defer ts.Unlock()
	ts.Topics[t.Name] = t
}

func (ts *Topics) Remove(t *Topic) bool {
	ts.Lock()
	defer ts.Unlock()
	if _, res := ts.Topics[t.Name]; res {
		delete(ts.Topics, t.Name)
		return true
	}
	return false
}

func (ts *Topics) Get(name string) (*Topic, bool) {
	ts.RLock()
	defer ts.RUnlock()
	t, ok := ts.Topics[name]
	return t, ok
}

func (ts *Topics) List() []*Topic {
	ts.RLock()
	defer ts.RUnlock()

	var res []*Topic

	for _, t := range ts.Topics {
		res = append(res, t)
	}
	return res
}

func (ts *Topics) Count() int {
	ts.RLock()
	defer ts.RUnlock()
	return len(ts.Topics)
}

func (ts *Topics) Clear() {
	ts.Lock()
	defer ts.Unlock()
	ts.Topics = make(map[string]*Topic)
}

func (ts *Topics) Subscriptions(t *Topic) []*Subscription {
	ts.RLock()
	defer ts.RUnlock()
	if t != ts.Topics[t.Name] {
		panic(fmt.Errorf("unregistered topic %s", t.Name))
	}
	return t.Subscriptions[:]
}

func (ts *Topics) Subscribe(t *Topic, s *Subscription) {
	ts.Lock()
	defer ts.Unlock()
	if t != ts.Topics[t.Name] {
		panic(fmt.Errorf("unregistered topic %s", t.Name))
	}
	t.Subscriptions = append(t.Subscriptions, s)
}

func (ts *Topics) Unsubscribe(t *Topic, s *Subscription) {
	ts.Lock()
	defer ts.Unlock()
	if t != ts.Topics[t.Name] {
		panic(fmt.Errorf("unregistered topic %s", t.Name))
	}
	t.Subscriptions = slices.DeleteFunc(t.Subscriptions, func(sub *Subscription) bool {
		return sub.SubscriptionArn == s.SubscriptionArn
	})
}

func (ts *Topics) GetSubscription(arn string) (*Subscription, bool) {
	ts.RLock()
	defer ts.RUnlock()
	for _, t := range ts.Topics {
		for _, sub := range t.Subscriptions {
			if arn == sub.SubscriptionArn {
				return sub, true
			}
		}
	}
	return nil, false
}

func (ts *Topics) UpdateSubscription(t *Topic, arn string, update func(s *Subscription)) {
	ts.Lock()
	defer ts.Unlock()
	for _, sub := range t.Subscriptions {
		if sub.SubscriptionArn == arn {
			update(sub)
			break
		}
	}
}

var AllTopics = &Topics{Topics: make(map[string]*Topic)}
