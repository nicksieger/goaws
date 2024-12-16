package app

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/ghodss/yaml"
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

		var values []string

		// String, String.Array, Number data-types are allowed by SNS filter policies
		// however go-AWS currently only supports String/String.Array attribute types.
		// ref: https://docs.aws.amazon.com/sns/latest/dg/message-filtering.html
		switch attrValue.DataType {
		case "String":
			values = []string{attrValue.Value}

		case "String.Array":
			if err := json.Unmarshal([]byte(attrValue.Value), &values); err != nil {
				return false
			}

		default:
			return false
		}

		if !valuesInPolicy(values, policyAttrValues) {
			return false // the attribute value has to be among filtered ones
		}
	}

	return true
}

func valuesInPolicy(values []string, list []string) bool {
	for _, b := range values {
		if !slices.Contains(list, b) {
			return false
		}
	}
	return true
}

type Topic struct {
	Name          string
	Arn           string
	Subscriptions []*Subscription
}

func (t *Topic) EnsureArn() string {
	if t.Arn == "" {
		t.Arn = "arn:aws:sns:" + CurrentEnvironment.Region + ":" + CurrentEnvironment.AccountID + ":" + t.Name
	}
	return t.Arn
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

type TopicChanges interface {
	OnUpdate(t *Topic)
	OnRemove(t *Topic)
	OnClear()
}

type Topics struct {
	sync.RWMutex
	TopicChanges
	Topics map[string]*Topic
}

func (ts *Topics) Add(t *Topic) {
	ts.Lock()
	defer ts.Unlock()
	ts.Topics[t.Name] = t
	ts.TopicChanges.OnUpdate(t)
}

func (ts *Topics) Remove(t *Topic) bool {
	ts.Lock()
	defer ts.Unlock()
	ts.TopicChanges.OnRemove(t)
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
	ts.TopicChanges.OnClear()
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
	ts.TopicChanges.OnUpdate(t)
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
	ts.TopicChanges.OnUpdate(t)
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
	ts.TopicChanges.OnUpdate(t)
}

var AllTopics = &Topics{
	TopicChanges: &NoTopicStorage{},
	Topics:       make(map[string]*Topic),
}

type TopicStorage struct {
	Directory string
}

func (ts *TopicStorage) TopicsDir() string {
	return filepath.Join(ts.Directory, "goaws_topics")
}

func (ts *TopicStorage) writeTopic(t *Topic) error {
	b, err := yaml.Marshal(t)
	if err != nil {
		return err
	}
	d := ts.TopicsDir()
	err = os.MkdirAll(d, 0o0700)
	if err != nil {
		return err
	}
	return os.WriteFile(fmt.Sprintf("%s.yaml", filepath.Join(d, t.Name)), b, 0o0644)
}

func (ts *TopicStorage) Load() map[string]*Topic {
	topics := make(map[string]*Topic)
	_ = filepath.WalkDir(ts.TopicsDir(), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		ext := filepath.Ext(path)
		if ext != ".yaml" {
			return nil
		}
		var contents []byte
		contents, err = os.ReadFile(path)
		if err != nil {
			return err
		}
		t := &Topic{}
		err = yaml.Unmarshal(contents, t)
		if err != nil {
			return err
		}
		if t.Name == "" {
			t.Name = strings.TrimSuffix(filepath.Base(path), ext)
		}
		_ = t.EnsureArn()
		topics[t.Name] = t
		return nil
	})
	return topics
}

// OnClear implements TopicChanges.
func (ts *TopicStorage) OnClear() {
	_ = os.RemoveAll(ts.TopicsDir())
}

// OnRemove implements TopicChanges.
func (ts *TopicStorage) OnRemove(t *Topic) {
	f := fmt.Sprintf("%s.yaml", filepath.Join(ts.TopicsDir(), t.Name))
	_ = os.Remove(f)
}

// OnUpdate implements TopicChanges.
func (ts *TopicStorage) OnUpdate(t *Topic) {
	_ = ts.writeTopic(t)
}

var _ TopicChanges = (*TopicStorage)(nil)

type NoTopicStorage struct{}

// OnClear implements TopicChanges.
func (n *NoTopicStorage) OnClear() {
}

// OnRemove implements TopicChanges.
func (n *NoTopicStorage) OnRemove(t *Topic) {
}

// OnUpdate implements TopicChanges.
func (n *NoTopicStorage) OnUpdate(t *Topic) {
}

var _ TopicChanges = (*NoTopicStorage)(nil)
