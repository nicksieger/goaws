package gosns

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"math/big"

	"github.com/Admiral-Piett/goaws/app"
	"github.com/Admiral-Piett/goaws/app/common"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	log "github.com/sirupsen/logrus"
)

type pendingConfirm struct {
	subArn string
	token  string
}

var PemKEY []byte
var PrivateKEY *rsa.PrivateKey
var TOPIC_DATA map[string]*pendingConfirm

func init() {
	TOPIC_DATA = make(map[string]*pendingConfirm)

	app.SnsErrors = make(map[string]app.SnsErrorType)
	err1 := app.SnsErrorType{HttpError: http.StatusBadRequest, Type: "Not Found", Code: "AWS.SimpleNotificationService.NonExistentTopic", Message: "The specified topic does not exist for this wsdl version."}
	app.SnsErrors["TopicNotFound"] = err1
	err2 := app.SnsErrorType{HttpError: http.StatusBadRequest, Type: "Not Found", Code: "AWS.SimpleNotificationService.NonExistentSubscription", Message: "The specified subscription does not exist for this wsdl version."}
	app.SnsErrors["SubscriptionNotFound"] = err2
	err3 := app.SnsErrorType{HttpError: http.StatusBadRequest, Type: "Duplicate", Code: "AWS.SimpleNotificationService.TopicAlreadyExists", Message: "The specified topic already exists."}
	app.SnsErrors["TopicExists"] = err3
	err4 := app.SnsErrorType{HttpError: http.StatusBadRequest, Type: "InvalidParameter", Code: "AWS.SimpleNotificationService.ValidationError", Message: "The input fails to satisfy the constraints specified by an AWS service."}
	app.SnsErrors["ValidationError"] = err4
	app.SnsErrors["InternalFailure"] = app.SnsErrorType{HttpError: http.StatusInternalServerError, Type: "InternalFailure", Code: "AWS.SimpleNotificationService.InternalFailure", Message: "The request processing has failed because of an unknown error, exception or failure."}
	PrivateKEY, PemKEY, _ = createPemFile()
}

func createPemFile() (privkey *rsa.PrivateKey, pemkey []byte, err error) {
	template := &x509.Certificate{
		IsCA:                  true,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{11, 22, 33},
		SerialNumber:          big.NewInt(1111),
		Subject: pkix.Name{
			Country:      []string{"USA"},
			Organization: []string{"Amazon"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Duration(5) * time.Second),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	// generate private key
	privkey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}

	// create a self-signed certificate
	parent := template
	cert, err := x509.CreateCertificate(rand.Reader, template, parent, &privkey.PublicKey, privkey)
	if err != nil {
		return
	}

	pemkey = pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert,
		},
	)
	return
}

func ListTopics(w http.ResponseWriter, req *http.Request) {
	content := req.FormValue("ContentType")

	respStruct := app.ListTopicsResponse{}
	respStruct.Xmlns = "http://queue.amazonaws.com/doc/2012-11-05/"
	uuid, _ := common.NewUUID()
	respStruct.Metadata = app.ResponseMetadata{RequestId: uuid}

	respStruct.Result.Topics.Member = make([]app.TopicArnResult, 0)
	log.Println("Listing Topics")
	for _, topic := range app.AllTopics.List() {
		ta := app.TopicArnResult{TopicArn: topic.Arn}
		respStruct.Result.Topics.Member = append(respStruct.Result.Topics.Member, ta)
	}

	SendResponseBack(w, req, respStruct, content)
}

func CreateTopic(w http.ResponseWriter, req *http.Request) {
	content := req.FormValue("ContentType")
	topicName := req.FormValue("Name")
	topicArn := ""
	if t, ok := app.AllTopics.Get(topicName); ok {
		topicArn = t.Arn
	} else {
		log.Println("Creating Topic:", topicName)
		topic := &app.Topic{Name: topicName}
		topicArn = topic.EnsureArn()
		topic.Subscriptions = make([]*app.Subscription, 0)
		app.AllTopics.Add(topic)
	}
	uuid, _ := common.NewUUID()
	respStruct := app.CreateTopicResponse{"http://queue.amazonaws.com/doc/2012-11-05/", app.CreateTopicResult{TopicArn: topicArn}, app.ResponseMetadata{RequestId: uuid}}
	SendResponseBack(w, req, respStruct, content)
}

// aws --endpoint-url http://localhost:47194 sns subscribe --topic-arn arn:aws:sns:us-west-2:0123456789012:my-topic --protocol email --notification-endpoint my-email@example.com
func Subscribe(w http.ResponseWriter, req *http.Request) {
	content := req.FormValue("ContentType")
	topicArn := req.FormValue("TopicArn")
	protocol := req.FormValue("Protocol")
	endpoint := req.FormValue("Endpoint")
	filterPolicy := app.FilterPolicy{}
	raw := false

	_, err := url.Parse(endpoint)
	if err != nil {
		createErrorResponse(w, req, "ValidationError")
		return
	}

	for attrIndex := 1; req.FormValue("Attributes.entry."+strconv.Itoa(attrIndex)+".key") != ""; attrIndex++ {
		value := req.FormValue("Attributes.entry." + strconv.Itoa(attrIndex) + ".value")
		switch key := req.FormValue("Attributes.entry." + strconv.Itoa(attrIndex) + ".key"); key {
		case "FilterPolicy":
			json.Unmarshal([]byte(value), &filterPolicy)
		case "RawMessageDelivery":
			raw = (value == "true")
		}
	}

	uriSegments := strings.Split(topicArn, ":")
	topicName := uriSegments[len(uriSegments)-1]
	log.WithFields(log.Fields{
		"content":      content,
		"topicArn":     topicArn,
		"topicName":    topicName,
		"protocol":     protocol,
		"endpoint":     endpoint,
		"filterPolicy": filterPolicy,
		"raw":          raw,
	}).Info("Creating Subscription")

	subscription := &app.Subscription{EndPoint: endpoint, Protocol: protocol, TopicArn: topicArn, Raw: raw, FilterPolicy: filterPolicy}
	subArn, _ := common.NewUUID()
	subArn = topicArn + ":" + subArn
	subscription.SubscriptionArn = subArn

	if t, ok := app.AllTopics.Get(topicName); ok {
		isDuplicate := false
		// Duplicate check
		for _, subscription := range app.AllTopics.Subscriptions(t) {
			if subscription.EndPoint == endpoint && subscription.TopicArn == topicArn {
				isDuplicate = true
				subArn = subscription.SubscriptionArn
			}
		}
		if !isDuplicate {
			app.AllTopics.Subscribe(t, subscription)
			log.WithFields(log.Fields{
				"topic":    topicName,
				"endpoint": endpoint,
				"topicArn": topicArn,
			}).Debug("Created subscription")
		}

		//Create the response
		uuid, _ := common.NewUUID()
		respStruct := app.SubscribeResponse{"http://queue.amazonaws.com/doc/2012-11-05/", app.SubscribeResult{SubscriptionArn: subArn}, app.ResponseMetadata{RequestId: uuid}}
		if !app.CurrentEnvironment.SkipConfirmSubs &&
			(app.Protocol(subscription.Protocol) == app.ProtocolHTTP ||
				app.Protocol(subscription.Protocol) == app.ProtocolHTTPS) {
			id, _ := common.NewUUID()
			token, _ := common.NewUUID()

			TOPIC_DATA[topicArn] = &pendingConfirm{
				subArn: subArn,
				token:  token,
			}

			SendResponseBack(w, req, respStruct, content)
			time.Sleep(time.Second)

			snsMSG := &app.SNSMessage{
				Type:             "SubscriptionConfirmation",
				MessageId:        id,
				Token:            token,
				TopicArn:         topicArn,
				Message:          "You have chosen to subscribe to the topic " + topicArn + ".\nTo confirm the subscription, visit the SubscribeURL included in this message.",
				SigningCertURL:   "http://" + app.CurrentEnvironment.Host + ":" + app.CurrentEnvironment.Port + "/SimpleNotificationService/" + uuid + ".pem",
				SignatureVersion: "1",
				SubscribeURL:     "http://" + app.CurrentEnvironment.Host + ":" + app.CurrentEnvironment.Port + "/?Action=ConfirmSubscription&TopicArn=" + topicArn + "&Token=" + token,
				Timestamp:        time.Now().UTC().Format(time.RFC3339),
			}
			signature, err := signMessage(PrivateKEY, snsMSG)
			if err != nil {
				log.Error("Error signing message")
			} else {
				snsMSG.Signature = signature
			}
			err = callEndpoint(subscription.EndPoint, uuid, *snsMSG, subscription.Raw)
			if err != nil {
				log.Error("Error posting to url ", err)
			}
		} else {
			SendResponseBack(w, req, respStruct, content)
		}

	} else {
		createErrorResponse(w, req, "TopicNotFound")
	}
}

func signMessage(privkey *rsa.PrivateKey, snsMsg *app.SNSMessage) (string, error) {
	fs, err := formatSignature(snsMsg)
	if err != nil {
		return "", nil
	}

	h := sha1.Sum([]byte(fs))
	signature_b, err := rsa.SignPKCS1v15(rand.Reader, privkey, crypto.SHA1, h[:])

	return base64.StdEncoding.EncodeToString(signature_b), err
}

func formatSignature(msg *app.SNSMessage) (formated string, err error) {
	if msg.Type == "Notification" && msg.Subject != "" {
		formated = fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n",
			"Message", msg.Message,
			"MessageId", msg.MessageId,
			"Subject", msg.Subject,
			"Timestamp", msg.Timestamp,
			"TopicArn", msg.TopicArn,
			"Type", msg.Type,
		)
	} else if msg.Type == "Notification" && msg.Subject == "" {
		formated = fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n",
			"Message", msg.Message,
			"MessageId", msg.MessageId,
			"Timestamp", msg.Timestamp,
			"TopicArn", msg.TopicArn,
			"Type", msg.Type,
		)
	} else if msg.Type == "SubscriptionConfirmation" || msg.Type == "UnsubscribeConfirmation" {
		formated = fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n",
			"Message", msg.Message,
			"MessageId", msg.MessageId,
			"SubscribeURL", msg.SubscribeURL,
			"Timestamp", msg.Timestamp,
			"Token", msg.Token,
			"TopicArn", msg.TopicArn,
			"Type", msg.Type,
		)
	} else {
		return formated, errors.New("Unable to determine SNSMessage type")
	}

	return
}

func ConfirmSubscription(w http.ResponseWriter, req *http.Request) {
	topicArn := req.Form.Get("TopicArn")
	confirmToken := req.Form.Get("Token")
	pendingConfirm := TOPIC_DATA[topicArn]
	if pendingConfirm.token == confirmToken {
		uuid, _ := common.NewUUID()
		respStruct := app.ConfirmSubscriptionResponse{"http://queue.amazonaws.com/doc/2012-11-05/", app.SubscribeResult{SubscriptionArn: pendingConfirm.subArn}, app.ResponseMetadata{RequestId: uuid}}

		SendResponseBack(w, req, respStruct, "application/xml")
	} else {
		createErrorResponse(w, req, "SubArnNotFound")
	}

}

func ListSubscriptions(w http.ResponseWriter, req *http.Request) {
	content := req.FormValue("ContentType")

	uuid, _ := common.NewUUID()
	respStruct := app.ListSubscriptionsResponse{}
	respStruct.Xmlns = "http://queue.amazonaws.com/doc/2012-11-05/"
	respStruct.Metadata.RequestId = uuid
	respStruct.Result.Subscriptions.Member = make([]app.TopicMemberResult, 0)

	for _, topic := range app.AllTopics.List() {
		for _, sub := range app.AllTopics.Subscriptions(topic) {
			tar := app.TopicMemberResult{TopicArn: topic.Arn, Protocol: sub.Protocol,
				SubscriptionArn: sub.SubscriptionArn, Endpoint: sub.EndPoint, Owner: app.CurrentEnvironment.AccountID}
			respStruct.Result.Subscriptions.Member = append(respStruct.Result.Subscriptions.Member, tar)
		}
	}

	SendResponseBack(w, req, respStruct, content)
}

func ListSubscriptionsByTopic(w http.ResponseWriter, req *http.Request) {
	content := req.FormValue("ContentType")
	topicArn := req.FormValue("TopicArn")

	uriSegments := strings.Split(topicArn, ":")
	topicName := uriSegments[len(uriSegments)-1]

	if topic, ok := app.AllTopics.Get(topicName); ok {
		uuid, _ := common.NewUUID()
		respStruct := app.ListSubscriptionsByTopicResponse{}
		respStruct.Xmlns = "http://queue.amazonaws.com/doc/2012-11-05/"
		respStruct.Metadata.RequestId = uuid
		respStruct.Result.Subscriptions.Member = make([]app.TopicMemberResult, 0)

		for _, sub := range app.AllTopics.Subscriptions(topic) {
			tar := app.TopicMemberResult{TopicArn: topic.Arn, Protocol: sub.Protocol,
				SubscriptionArn: sub.SubscriptionArn, Endpoint: sub.EndPoint, Owner: app.CurrentEnvironment.AccountID}
			respStruct.Result.Subscriptions.Member = append(respStruct.Result.Subscriptions.Member, tar)
		}
		SendResponseBack(w, req, respStruct, content)
	} else {
		createErrorResponse(w, req, "TopicNotFound")
	}
}

func SetSubscriptionAttributes(w http.ResponseWriter, req *http.Request) {
	content := req.FormValue("ContentType")
	subsArn := req.FormValue("SubscriptionArn")
	Attribute := req.FormValue("AttributeName")
	Value := req.FormValue("AttributeValue")

	for _, topic := range app.AllTopics.List() {
		app.AllTopics.UpdateSubscription(topic, subsArn, func(sub *app.Subscription) {
			if Attribute == "RawMessageDelivery" {
				if Value == "true" {
					sub.Raw = true
				} else {
					sub.Raw = false
				}
				//Good Response == return
				uuid, _ := common.NewUUID()
				respStruct := app.SetSubscriptionAttributesResponse{"http://queue.amazonaws.com/doc/2012-11-05/", app.ResponseMetadata{RequestId: uuid}}
				SendResponseBack(w, req, respStruct, content)
				return
			}

			if Attribute == "FilterPolicy" {
				filterPolicy := app.FilterPolicy{}
				err := json.Unmarshal([]byte(Value), &filterPolicy)
				if err != nil {
					createErrorResponse(w, req, "ValidationError")
					return
				}

				sub.FilterPolicy = filterPolicy

				//Good Response == return
				uuid, _ := common.NewUUID()
				respStruct := app.SetSubscriptionAttributesResponse{"http://queue.amazonaws.com/doc/2012-11-05/", app.ResponseMetadata{RequestId: uuid}}
				SendResponseBack(w, req, respStruct, content)
				return
			}
		})
	}
	createErrorResponse(w, req, "SubscriptionNotFound")
}

func GetSubscriptionAttributes(w http.ResponseWriter, req *http.Request) {

	content := req.FormValue("ContentType")
	subsArn := req.FormValue("SubscriptionArn")

	if sub, ok := app.AllTopics.GetSubscription(subsArn); ok {
		entries := make([]app.SubscriptionAttributeEntry, 0)
		entry := app.SubscriptionAttributeEntry{Key: "Owner", Value: app.CurrentEnvironment.AccountID}
		entries = append(entries, entry)
		entry = app.SubscriptionAttributeEntry{Key: "RawMessageDelivery", Value: strconv.FormatBool(sub.Raw)}
		entries = append(entries, entry)
		entry = app.SubscriptionAttributeEntry{Key: "TopicArn", Value: sub.TopicArn}
		entries = append(entries, entry)
		entry = app.SubscriptionAttributeEntry{Key: "Endpoint", Value: sub.EndPoint}
		entries = append(entries, entry)
		entry = app.SubscriptionAttributeEntry{Key: "PendingConfirmation", Value: "false"}
		entries = append(entries, entry)
		entry = app.SubscriptionAttributeEntry{Key: "ConfirmationWasAuthenticated", Value: "true"}
		entries = append(entries, entry)
		entry = app.SubscriptionAttributeEntry{Key: "SubscriptionArn", Value: sub.SubscriptionArn}
		entries = append(entries, entry)
		entry = app.SubscriptionAttributeEntry{Key: "Protocol", Value: sub.Protocol}
		entries = append(entries, entry)
		entry = app.SubscriptionAttributeEntry{Key: "Endpoint", Value: sub.EndPoint}
		entries = append(entries, entry)

		if sub.FilterPolicy != nil {
			filterPolicyBytes, _ := json.Marshal(sub.FilterPolicy)
			entry = app.SubscriptionAttributeEntry{Key: "FilterPolicy", Value: string(filterPolicyBytes)}
			entries = append(entries, entry)
		}

		result := app.GetSubscriptionAttributesResult{SubscriptionAttributes: app.SubscriptionAttributes{Entries: entries}}
		uuid, _ := common.NewUUID()
		respStruct := app.GetSubscriptionAttributesResponse{"http://sns.amazonaws.com/doc/2010-03-31", result, app.ResponseMetadata{RequestId: uuid}}

		SendResponseBack(w, req, respStruct, content)
		return
	}
	createErrorResponse(w, req, "SubscriptionNotFound")
}

func Unsubscribe(w http.ResponseWriter, req *http.Request) {
	content := req.FormValue("ContentType")
	subArn := req.FormValue("SubscriptionArn")

	log.Println("Unsubscribe:", subArn)
	for _, topic := range app.AllTopics.List() {
		for _, sub := range app.AllTopics.Subscriptions(topic) {
			if sub.SubscriptionArn == subArn {
				app.AllTopics.Unsubscribe(topic, sub)

				uuid, _ := common.NewUUID()
				respStruct := app.UnsubscribeResponse{"http://queue.amazonaws.com/doc/2012-11-05/", app.ResponseMetadata{RequestId: uuid}}
				SendResponseBack(w, req, respStruct, content)
				return
			}
		}
	}
	createErrorResponse(w, req, "SubscriptionNotFound")
}

func DeleteTopic(w http.ResponseWriter, req *http.Request) {
	content := req.FormValue("ContentType")
	topicArn := req.FormValue("TopicArn")

	uriSegments := strings.Split(topicArn, ":")
	topicName := uriSegments[len(uriSegments)-1]

	log.Println("Delete Topic - TopicName:", topicName)

	if t, ok := app.AllTopics.Get(topicName); ok {
		app.AllTopics.Remove(t)

		uuid, _ := common.NewUUID()
		respStruct := app.DeleteTopicResponse{"http://queue.amazonaws.com/doc/2012-11-05/", app.ResponseMetadata{RequestId: uuid}}
		SendResponseBack(w, req, respStruct, content)
	} else {
		createErrorResponse(w, req, "TopicNotFound")
	}

}

// aws --endpoint-url http://localhost:47194 sns publish --topic-arn arn:aws:sns:yopa-local:000000000000:test1 --message "This is a test"
func Publish(w http.ResponseWriter, req *http.Request) {
	content := req.FormValue("ContentType")
	topicArn := req.FormValue("TopicArn")
	subject := req.FormValue("Subject")
	messageBody := req.FormValue("Message")
	messageStructure := req.FormValue("MessageStructure")
	messageAttributes := getMessageAttributesFromRequest(req)

	arnSegments := strings.Split(topicArn, ":")
	topicName := arnSegments[len(arnSegments)-1]

	t, ok := app.AllTopics.Get(topicName)
	if ok {
		log.WithFields(log.Fields{
			"topic":    topicName,
			"topicArn": topicArn,
			"subject":  subject,
		}).Debug("Publish to Topic")
		for _, subs := range app.AllTopics.Subscriptions(t) {
			switch app.Protocol(subs.Protocol) {
			case app.ProtocolSQS:
				if err := publishSQS(req, subs, messageBody, messageAttributes, subject, topicName, messageStructure); err != nil {
					createErrorResponse(w, req, err.Error())
					return
				}
			case app.ProtocolHTTP:
				fallthrough
			case app.ProtocolHTTPS:
				publishHTTP(subs, messageBody, messageAttributes, subject, topicArn)
			}
		}
	} else {
		createErrorResponse(w, req, "TopicNotFound")
		return
	}

	//Create the response
	msgId, _ := common.NewUUID()
	uuid, _ := common.NewUUID()
	respStruct := app.PublishResponse{"http://queue.amazonaws.com/doc/2012-11-05/", app.PublishResult{MessageId: msgId}, app.ResponseMetadata{RequestId: uuid}}
	SendResponseBack(w, req, respStruct, content)
}

func publishSQS(req *http.Request,
	subs *app.Subscription, messageBody string, messageAttributes map[string]app.MessageAttributeValue,
	subject string, topicName string, messageStructure string) error {
	if subs.FilterPolicy != nil && !subs.FilterPolicy.IsSatisfiedBy(messageAttributes) {
		log.Debugf("message to %q with attributes %v filtered out by filter policy %v", subs.EndPoint, messageAttributes, subs.FilterPolicy)
		return nil
	}

	endPoint, err := url.Parse(subs.EndPoint)
	if err != nil {
		log.Errorf("error parsing endpoint: %v", err)
		return errors.New("ValidationError")
	}

	ourHost := url.URL{
		Scheme: req.URL.Scheme,
		Host:   req.Host,
	}

	msg, err := newMessage(subs, messageBody, subject, messageStructure, messageAttributes)
	if err != nil {
		log.Errorf("error creating message: %v", err)
		return errors.New("InternalFailure")
	}

	log.Infof("publishSQS %s (host %s)", endPoint.String(), ourHost.String())
	if (endPoint.Scheme == "http" || endPoint.Scheme == "https") && !strings.HasPrefix(endPoint.String(), ourHost.String()) {
		// external sqs service
		sess, err := session.NewSession(aws.NewConfig().
			WithRegion(app.CurrentEnvironment.Region).
			WithEndpoint(endPoint.String()).
			WithCredentials(credentials.NewStaticCredentials(
				app.CurrentEnvironment.Credentials.AccessKeyId,
				app.CurrentEnvironment.Credentials.SecretAccessKey,
				"",
			)))
		if err != nil {
			log.Errorf("creating sqs session: %v", err)
			return errors.New("InternalFailure")
		}
		svc := sqs.New(sess)
		body := string(msg.MessageBody)
		output, err := svc.SendMessage(&sqs.SendMessageInput{
			QueueUrl:          &subs.EndPoint,
			MessageAttributes: convertMessageAttributes(msg.MessageAttributes),
			MessageBody:       &body,
		})
		if err != nil {
			log.Errorf("delivering sqs message: %v", err)
		} else {
			log.Infof("delivered sqs message, MessageId: %s", *output.MessageId)
		}
		return nil
	}

	uriSegments := strings.Split(endPoint.String(), "/")
	queueName := uriSegments[len(uriSegments)-1]
	arnSegments := strings.Split(queueName, ":")
	queueName = arnSegments[len(arnSegments)-1]

	if _, ok := app.AllQueues.Queues[queueName]; ok {
		app.AllQueues.Lock()
		app.AllQueues.Queues[queueName].Messages = append(app.AllQueues.Queues[queueName].Messages, msg)
		app.AllQueues.Unlock()

		log.Infof("%s: Topic: %s(%s), Message: %s\n", time.Now().Format("2006-01-02 15:04:05"), topicName, queueName, msg.MessageBody)
	} else {
		log.Infof("%s: Queue %s does not exist, message discarded\n", time.Now().Format("2006-01-02 15:04:05"), queueName)
	}

	return nil
}

func convertMessageAttributes(values map[string]app.MessageAttributeValue) map[string]*sqs.MessageAttributeValue {
	result := make(map[string]*sqs.MessageAttributeValue)
	for k, v := range values {
		result[k] = &sqs.MessageAttributeValue{
			DataType:    &v.DataType,
			StringValue: &v.Value,
		}
	}
	return result
}

func newMessage(subs *app.Subscription, messageBody string, subject string, messageStructure string, messageAttributes map[string]app.MessageAttributeValue) (app.Message, error) {
	msg := app.Message{}

	if !subs.Raw {
		m, err := CreateMessageBody(subs, messageBody, subject, messageStructure, messageAttributes)
		if err != nil {
			return msg, err
		}

		msg.MessageBody = m
	} else {
		msg.MessageAttributes = messageAttributes
		msg.MD5OfMessageAttributes = common.HashAttributes(messageAttributes)
		msg.MessageBody = []byte(extractMessageFromJSON(messageBody, subs.Protocol))
	}

	msg.MD5OfMessageBody = common.GetMD5Hash(messageBody)
	msg.Uuid, _ = common.NewUUID()
	return msg, nil
}

func publishHTTP(subs *app.Subscription, messageBody string, messageAttributes map[string]app.MessageAttributeValue,
	subject string, topicArn string) {
	id, _ := common.NewUUID()
	msg := app.SNSMessage{
		Type:              "Notification",
		MessageId:         id,
		TopicArn:          topicArn,
		Subject:           subject,
		Message:           messageBody,
		Timestamp:         time.Now().UTC().Format(time.RFC3339),
		SignatureVersion:  "1",
		SigningCertURL:    "http://" + app.CurrentEnvironment.Host + ":" + app.CurrentEnvironment.Port + "/SimpleNotificationService/" + id + ".pem",
		UnsubscribeURL:    "http://" + app.CurrentEnvironment.Host + ":" + app.CurrentEnvironment.Port + "/?Action=Unsubscribe&SubscriptionArn=" + subs.SubscriptionArn,
		MessageAttributes: formatAttributes(messageAttributes),
	}

	signature, err := signMessage(PrivateKEY, &msg)
	if err != nil {
		log.Error(err)
	} else {
		msg.Signature = signature
	}
	err = callEndpoint(subs.EndPoint, subs.SubscriptionArn, msg, subs.Raw)
	if err != nil {
		log.WithFields(log.Fields{
			"EndPoint": subs.EndPoint,
			"ARN":      subs.SubscriptionArn,
			"error":    err.Error(),
		}).Error("Error calling endpoint")
	}
}

func formatAttributes(values map[string]app.MessageAttributeValue) map[string]app.MsgAttr {
	attr := make(map[string]app.MsgAttr)
	for k, v := range values {
		attr[k] = app.MsgAttr{
			Type:  v.DataType,
			Value: v.Value,
		}
	}
	return attr
}

func callEndpoint(endpoint string, subArn string, msg app.SNSMessage, raw bool) error {
	log.WithFields(log.Fields{
		"sns":      msg,
		"subArn":   subArn,
		"endpoint": endpoint,
	}).Debug("Calling endpoint")
	var err error
	var byteData []byte

	if raw {
		byteData, err = json.Marshal(msg.Message)
	} else {
		byteData, err = json.Marshal(msg)
	}
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(byteData))
	if err != nil {
		return err
	}

	//req.Header.Add("Authorization", "Basic YXV0aEhlYWRlcg==")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("x-amz-sns-message-type", msg.Type)
	req.Header.Add("x-amz-sns-message-id", msg.MessageId)
	req.Header.Add("x-amz-sns-topic-arn", msg.TopicArn)
	req.Header.Add("x-amz-sns-subscription-arn", subArn)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	if res == nil {
		return errors.New("response is nil")
	}

	//Amazon considers a Notification delivery attempt successful if the endpoint
	//responds in the range of 200-499. Response codes outside that range will
	//trigger the Subscription's retry policy.
	//https://docs.aws.amazon.com/sns/latest/dg/SendMessageToHttp.prepare.html
	if res.StatusCode < 200 || res.StatusCode > 499 {
		log.WithFields(log.Fields{
			"statusCode": res.StatusCode,
			"status":     res.Status,
			"header":     res.Header,
			"endpoint":   endpoint,
		}).Error("Response outside of acceptable (200-499) range")
		return errors.New("Response outside of acceptable (200-499) range")
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	log.WithFields(log.Fields{
		"body": string(body),
		"res":  res,
	}).Debug("Received successful response")

	return nil
}

func getMessageAttributesFromRequest(req *http.Request) map[string]app.MessageAttributeValue {
	attributes := make(map[string]app.MessageAttributeValue)

	for i := 1; true; i++ {
		name := req.FormValue(fmt.Sprintf("MessageAttributes.entry.%d.Name", i))
		if name == "" {
			break
		}

		dataType := req.FormValue(fmt.Sprintf("MessageAttributes.entry.%d.Value.DataType", i))
		if dataType == "" {
			log.Warnf("DataType of MessageAttribute %s is missing, MD5 checksum will most probably be wrong!\n", name)
			continue
		}

		// StringListValue and BinaryListValue is currently not implemented
		for _, valueKey := range [...]string{"StringValue", "BinaryValue"} {
			value := req.FormValue(fmt.Sprintf("MessageAttributes.entry.%d.Value.%s", i, valueKey))
			if value != "" {
				attributes[name] = app.MessageAttributeValue{name, dataType, value, valueKey}
			}
		}

		if _, ok := attributes[name]; !ok {
			log.Warnf("StringValue or BinaryValue of MessageAttribute %s is missing, MD5 checksum will most probably be wrong!\n", name)
		}
	}

	return attributes
}

func CreateMessageBody(subs *app.Subscription, msg string, subject string, messageStructure string,
	messageAttributes map[string]app.MessageAttributeValue) ([]byte, error) {

	msgId, _ := common.NewUUID()

	message := app.SNSMessage{
		Type:              "Notification",
		MessageId:         msgId,
		TopicArn:          subs.TopicArn,
		Subject:           subject,
		Timestamp:         time.Now().UTC().Format(time.RFC3339),
		SignatureVersion:  "1",
		SigningCertURL:    "http://" + app.CurrentEnvironment.Host + ":" + app.CurrentEnvironment.Port + "/SimpleNotificationService/" + msgId + ".pem",
		UnsubscribeURL:    "http://" + app.CurrentEnvironment.Host + ":" + app.CurrentEnvironment.Port + "/?Action=Unsubscribe&SubscriptionArn=" + subs.SubscriptionArn,
		MessageAttributes: formatAttributes(messageAttributes),
	}

	if app.MessageStructure(messageStructure) == app.MessageStructureJSON {
		message.Message = extractMessageFromJSON(msg, subs.Protocol)
	} else {
		message.Message = msg
	}

	signature, err := signMessage(PrivateKEY, &message)
	if err != nil {
		log.Error(err)
	} else {
		message.Signature = signature
	}

	byteMsg, _ := json.Marshal(message)
	return byteMsg, nil
}

func extractMessageFromJSON(msg string, protocol string) string {
	var msgWithProtocols map[string]string
	if err := json.Unmarshal([]byte(msg), &msgWithProtocols); err != nil {
		return msg
	}

	defaultMsg, ok := msgWithProtocols[string(app.ProtocolDefault)]
	if !ok {
		defaultMsg = msg
	}

	if m, ok := msgWithProtocols[protocol]; ok {
		return m
	}

	return defaultMsg
}

func createErrorResponse(w http.ResponseWriter, req *http.Request, err string) {
	er := app.SnsErrors[err]
	respStruct := app.ErrorResponse{
		Result:    app.ErrorResult{Type: er.Type, Code: er.Code, Message: er.Message},
		RequestId: "00000000-0000-0000-0000-000000000000",
	}

	w.WriteHeader(er.HttpError)
	enc := xml.NewEncoder(w)
	enc.Indent("  ", "    ")
	if err := enc.Encode(respStruct); err != nil {
		log.Printf("error: %v\n", err)
	}
}

func SendResponseBack(w http.ResponseWriter, req *http.Request, respStruct interface{}, content string) {
	if content == "JSON" {
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		if err := enc.Encode(respStruct); err != nil {
			log.Printf("error: %v\n", err)
		}
	} else {
		w.Header().Set("Content-Type", "application/xml")
		enc := xml.NewEncoder(w)
		enc.Indent("  ", "    ")
		if err := enc.Encode(respStruct); err != nil {
			log.Printf("error: %v\n", err)
		}
	}
}
