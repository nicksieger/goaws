package gosns

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"github.com/Admiral-Piett/goaws/app"
	"github.com/Admiral-Piett/goaws/app/common"
)

func TestListTopicshandler_POST_NoTopics(t *testing.T) {
	clearTopics(t)

	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, err := http.NewRequest("POST", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(ListTopics)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the response body is what we expect.
	expected := "<Topics></Topics>"
	if !strings.Contains(rr.Body.String(), expected) {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}

func TestCreateTopicshandler_POST_CreateTopics(t *testing.T) {
	clearTopics(t)

	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, err := http.NewRequest("POST", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	form := url.Values{}
	form.Add("Action", "CreateTopic")
	form.Add("Name", "UnitTestTopic1")
	req.PostForm = form

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(CreateTopic)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the response body is what we expect.
	expected := "UnitTestTopic1"
	if !strings.Contains(rr.Body.String(), expected) {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}

func TestPublishhandler_POST_SendMessage(t *testing.T) {
	setTopics(t, "UnitTestTopic1")

	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, err := http.NewRequest("POST", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	form := url.Values{}
	form.Add("TopicArn", "arn:aws:sns:local:000000000000:UnitTestTopic1")
	form.Add("Message", "TestMessage1")
	req.PostForm = form

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(Publish)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the response body is what we expect.
	expected := "<MessageId>"
	if !strings.Contains(rr.Body.String(), expected) {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}

func TestPublishHandler_POST_FilterPolicyRejectsTheMessage(t *testing.T) {
	clearTopics(t)

	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, err := http.NewRequest("POST", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	// We set up queue so later we can check if anything was posted there
	queueName := "testingQueue"
	queueUrl := "http://" + app.CurrentEnvironment.Host + ":" + app.CurrentEnvironment.Port + "/queue/" + queueName
	queueArn := "arn:aws:sqs:" + app.CurrentEnvironment.Region + ":000000000000:" + queueName
	app.AllQueues.Queues[queueName] = &app.Queue{
		Name:        queueName,
		TimeoutSecs: 30,
		Arn:         queueArn,
		URL:         queueUrl,
		IsFIFO:      app.HasFIFOQueueName(queueName),
	}

	// We set up a topic with the corresponding Subscription including FilterPolicy
	topicName := "testingTopic"
	topicArn := "arn:aws:sns:" + app.CurrentEnvironment.Region + ":000000000000:" + topicName
	subArn, _ := common.NewUUID()
	subArn = topicArn + ":" + subArn
	app.AllTopics.Topics[topicName] = &app.Topic{Name: topicName, Arn: topicArn, Subscriptions: []*app.Subscription{
		{
			EndPoint:        app.AllQueues.Queues[queueName].Arn,
			Protocol:        "sqs",
			SubscriptionArn: subArn,
			FilterPolicy: app.FilterPolicy{
				"foo": {"bar"}, // set up FilterPolicy for attribute `foo` to be equal `bar`
			},
		},
	}}

	form := url.Values{}
	form.Add("TopicArn", topicArn)
	form.Add("Message", "TestMessage1")
	form.Add("MessageAttributes.entry.1.Name", "foo")              // special format of parameter for MessageAttribute
	form.Add("MessageAttributes.entry.1.Value.StringValue", "baz") // we actually sent attribute `foo` to be equal `baz`
	req.PostForm = form

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(Publish)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the response body is what we expect.
	expected := "<MessageId>"
	if !strings.Contains(rr.Body.String(), expected) {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}

	// check of the queue is empty
	if len(app.AllQueues.Queues[queueName].Messages) != 0 {
		t.Errorf("queue contains unexpected messages: got %v want %v",
			len(app.AllQueues.Queues[queueName].Messages), 0)
	}
}

var testHost = "http://localhost:4002/"

func TestPublishHandler_POST_FilterPolicyPassesTheMessage(t *testing.T) {
	clearTopics(t)

	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, err := http.NewRequest("POST", testHost, nil)
	if err != nil {
		t.Fatal(err)
	}

	// We set up queue so later we can check if anything was posted there
	queueName := "testingQueue"
	queueUrl := testHost + "queue/" + queueName
	queueArn := "arn:aws:sqs:" + app.CurrentEnvironment.Region + ":000000000000:" + queueName
	app.AllQueues.Queues[queueName] = &app.Queue{
		Name:        queueName,
		TimeoutSecs: 30,
		Arn:         queueArn,
		URL:         queueUrl,
		IsFIFO:      app.HasFIFOQueueName(queueName),
	}

	// We set up a topic with the corresponding Subscription including FilterPolicy
	topicName := "testingTopic"
	topicArn := "arn:aws:sns:" + app.CurrentEnvironment.Region + ":000000000000:" + topicName
	subArn, _ := common.NewUUID()
	subArn = topicArn + ":" + subArn
	app.AllTopics.Topics[topicName] = &app.Topic{Name: topicName, Arn: topicArn, Subscriptions: []*app.Subscription{
		{
			EndPoint:        app.AllQueues.Queues[queueName].Arn,
			Protocol:        "sqs",
			SubscriptionArn: subArn,
			FilterPolicy: app.FilterPolicy{
				"foo": {"bar"}, // set up FilterPolicy for attribute `foo` to be equal `bar`
			},
		},
	}}

	form := url.Values{}
	form.Add("TopicArn", topicArn)
	form.Add("Message", "TestMessage1")
	form.Add("MessageAttributes.entry.1.Name", "foo")              // special format of parameter for MessageAttribute
	form.Add("MessageAttributes.entry.1.Value.DataType", "String") // Datatype must be specified for proper parsing by aws
	form.Add("MessageAttributes.entry.1.Value.StringValue", "bar") // we actually sent attribute `foo` to be equal `baz`
	req.PostForm = form

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(Publish)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the response body is what we expect.
	expected := "<MessageId>"
	if !strings.Contains(rr.Body.String(), expected) {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}

	// check of the queue is empty
	if len(app.AllQueues.Queues[queueName].Messages) != 1 {
		t.Errorf("queue contains unexpected messages: got %v want %v",
			len(app.AllQueues.Queues[queueName].Messages), 1)
	}
}

func TestPublishHandler_POST_FilterPolicyMultiplesPassesTheMessage(t *testing.T) {
	clearTopics(t)

	// We set up queue so later we can check if anything was posted there
	queueName := "testingQueue"
	queueUrl := "http://" + app.CurrentEnvironment.Host + ":" + app.CurrentEnvironment.Port + "/queue/" + queueName
	queueArn := "arn:aws:sqs:" + app.CurrentEnvironment.Region + ":000000000000:" + queueName
	app.AllQueues.Queues[queueName] = &app.Queue{
		Name:        queueName,
		TimeoutSecs: 30,
		Arn:         queueArn,
		URL:         queueUrl,
		IsFIFO:      app.HasFIFOQueueName(queueName),
	}

	// We set up a topic with the corresponding Subscription including FilterPolicy
	topicName := "testingTopic"
	topicArn := "arn:aws:sns:" + app.CurrentEnvironment.Region + ":000000000000:" + topicName
	subArn, _ := common.NewUUID()
	subArn = topicArn + ":" + subArn
	app.AllTopics.Topics[topicName] = &app.Topic{Name: topicName, Arn: topicArn, Subscriptions: []*app.Subscription{
		{
			EndPoint:        app.AllQueues.Queues[queueName].Arn,
			Protocol:        "sqs",
			SubscriptionArn: subArn,
			FilterPolicy: app.FilterPolicy{
				"foo":   {"bar", "baz", "quux"}, // set up FilterPolicy for attribute `foo` to be equal to one of `bar`, `baz`, or `quux`
				"fruit": {"apple", "orange", "mango"},
			},
		},
	}}

	tt := []struct {
		fooValue, fruitValue, fruitType string
		expected                        int
	}{
		{"baz", "apple", "String", 1},
		{"fred", "apple", "String", 0},
		{"baz", "tomato", "String", 0},
		{"baz", "[\"apple\"]", "String.Array", 1},
		{"baz", "apple", "String.Array", 0},
	}

	for _, test := range tt {
		t.Run(test.fooValue+"-"+test.fruitValue, func(t *testing.T) {
			app.AllQueues.Queues[queueName].Messages = nil

			// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
			// pass 'nil' as the third parameter.
			req, err := http.NewRequest("POST", "/", nil)
			if err != nil {
				t.Fatal(err)
			}

			form := url.Values{}
			form.Add("TopicArn", topicArn)
			form.Add("Message", "TestMessage1")
			form.Add("MessageAttributes.entry.1.Name", "foo")                      // special format of parameter for MessageAttribute
			form.Add("MessageAttributes.entry.1.Value.DataType", "String")         // Datatype must be specified for proper parsing by aws
			form.Add("MessageAttributes.entry.1.Value.StringValue", test.fooValue) // we actually sent attribute `foo`
			form.Add("MessageAttributes.entry.2.Name", "fruit")
			form.Add("MessageAttributes.entry.2.Value.DataType", test.fruitType)
			form.Add("MessageAttributes.entry.2.Value.StringValue", test.fruitValue)
			req.PostForm = form

			// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
			rr := httptest.NewRecorder()
			handler := http.HandlerFunc(Publish)

			// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
			// directly and pass in our Request and ResponseRecorder.
			handler.ServeHTTP(rr, req)

			// Check the status code is what we expect.
			if status := rr.Code; status != http.StatusOK {
				t.Errorf("handler returned wrong status code: got %v want %v",
					status, http.StatusOK)
			}

			// Check the response body is what we expect.
			expected := "<MessageId>"
			if !strings.Contains(rr.Body.String(), expected) {
				t.Errorf("handler returned unexpected body: got %v want %v",
					rr.Body.String(), expected)
			}

			// check of the queue is empty
			if len(app.AllQueues.Queues[queueName].Messages) != test.expected {
				t.Errorf("queue contains unexpected messages: got %v want %v",
					len(app.AllQueues.Queues[queueName].Messages), test.expected)
			}
		})
	}
}

func TestSubscribehandler_POST_Success(t *testing.T) {
	setTopics(t, "UnitTestTopic1")

	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, err := http.NewRequest("POST", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	form := url.Values{}
	form.Add("TopicArn", "arn:aws:sns:local:000000000000:UnitTestTopic1")
	form.Add("Protocol", "sqs")
	form.Add("Endpoint", "http://localhost:4100/queue/noqueue1")
	req.PostForm = form

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(Subscribe)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the response body is what we expect.
	expected := "</SubscriptionArn>"
	if !strings.Contains(rr.Body.String(), expected) {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}

func TestSubscribehandler_HTTP_POST_Success(t *testing.T) {
	setTopics(t, "UnitTestTopic1")

	done := make(chan bool)

	r := mux.NewRouter()
	r.HandleFunc("/sns_post", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		close(done)

	}))

	ts := httptest.NewServer(r)
	defer ts.Close()

	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, err := http.NewRequest("POST", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	form := url.Values{}
	form.Add("TopicArn", "arn:aws:sns:local:000000000000:UnitTestTopic1")
	form.Add("Protocol", "http")
	form.Add("Endpoint", ts.URL+"/sns_post")
	req.PostForm = form

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()

	handler := http.HandlerFunc(Subscribe)

	// Create ResponseRecorder for http side

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the response body is what we expect.
	expected := "</SubscribeResponse>"
	if !strings.Contains(rr.Body.String(), expected) {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("http sns handler must be called")
	}
}

func TestPublish_No_Queue_Error_handler_POST_Success(t *testing.T) {
	setTopics(t, "UnitTestTopic1")

	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, err := http.NewRequest("POST", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	form := url.Values{}
	form.Add("TopicArn", "arn:aws:sns:local:000000000000:UnitTestTopic1")
	form.Add("Message", "TestMessage1")
	req.PostForm = form

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(Publish)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the response body is what we expect.
	expected := "<MessageId>"
	if !strings.Contains(rr.Body.String(), expected) {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}

func TestListSubscriptionByTopicResponse_No_Owner(t *testing.T) {
	setTopics(t, "UnitTestTopic1")

	// set accountID to test value so it can be populated in response
	app.CurrentEnvironment.AccountID = "100010001000"

	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, err := http.NewRequest("POST", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	form := url.Values{}
	form.Add("TopicArn", "arn:aws:sns:local:000000000000:UnitTestTopic1")
	req.PostForm = form

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(ListSubscriptionsByTopic)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the response body is what we expect.
	expected := `<Owner>` + app.CurrentEnvironment.AccountID + `</Owner>`
	if !strings.Contains(rr.Body.String(), expected) {
		t.Errorf("handler returned empty owner for subscription member: got %v want %v",
			rr.Body.String(), expected)
	}
}

func TestListSubscriptionsResponse_No_Owner(t *testing.T) {
	setTopics(t, "UnitTestTopic1")

	// set accountID to test value so it can be populated in response
	app.CurrentEnvironment.AccountID = "100010001000"

	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, err := http.NewRequest("POST", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	form := url.Values{}
	form.Add("TopicArn", "arn:aws:sns:local:000000000000:UnitTestTopic1")
	req.PostForm = form

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(ListSubscriptions)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the response body is what we expect.
	expected := `<Owner>` + app.CurrentEnvironment.AccountID + `</Owner>`
	if !strings.Contains(rr.Body.String(), expected) {
		t.Errorf("handler returned empty owner for subscription member: got %v want %v",
			rr.Body.String(), expected)
	}
}

func TestDeleteTopichandler_POST_Success(t *testing.T) {
	setTopics(t, "UnitTestTopic1")

	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, err := http.NewRequest("POST", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	form := url.Values{}
	form.Add("TopicArn", "arn:aws:sns:local:000000000000:UnitTestTopic1")
	form.Add("Message", "TestMessage1")
	req.PostForm = form

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(DeleteTopic)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the response body is what we expect.
	expected := "</DeleteTopicResponse>"
	if !strings.Contains(rr.Body.String(), expected) {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
	// Check the response body is what we expect.
	expected = "</ResponseMetadata>"
	if !strings.Contains(rr.Body.String(), expected) {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}

func TestGetSubscriptionAttributesHandler_POST_Success(t *testing.T) {
	clearTopics(t)

	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, err := http.NewRequest("POST", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	topicName := "testing"
	topicArn := "arn:aws:sns:" + app.CurrentEnvironment.Region + ":000000000000:" + topicName
	subArn, _ := common.NewUUID()
	subArn = topicArn + ":" + subArn
	app.AllTopics.Topics[topicName] = &app.Topic{Name: topicName, Arn: topicArn, Subscriptions: []*app.Subscription{
		{
			SubscriptionArn: subArn,
			FilterPolicy: app.FilterPolicy{
				"foo": {"bar"},
			},
		},
	}}

	form := url.Values{}
	form.Add("SubscriptionArn", subArn)
	req.PostForm = form

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(GetSubscriptionAttributes)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the response body is what we expect.
	expected := "</GetSubscriptionAttributesResult>"
	if !strings.Contains(rr.Body.String(), expected) {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}

	expectedElements := []string{"Owner", "RawMessageDelivery", "TopicArn", "Endpoint", "PendingConfirmation",
		"ConfirmationWasAuthenticated", "SubscriptionArn", "Protocol", "FilterPolicy"}
	for _, element := range expectedElements {
		expected := "<key>" + element + "</key>"
		if !strings.Contains(rr.Body.String(), expected) {
			t.Errorf("handler returned unexpected body: got %v want %v",
				rr.Body.String(), expected)
		}
	}

	// Check the response body is what we expect.
	expected = "{&#34;foo&#34;:[&#34;bar&#34;]}"
	if !strings.Contains(rr.Body.String(), expected) {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}

func TestSetSubscriptionAttributesHandler_FilterPolicy_POST_Success(t *testing.T) {
	clearTopics(t)

	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, err := http.NewRequest("POST", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	topicName := "testing"
	topicArn := "arn:aws:sns:" + app.CurrentEnvironment.Region + ":000000000000:" + topicName
	subArn, _ := common.NewUUID()
	subArn = topicArn + ":" + subArn
	app.AllTopics.Topics[topicName] = &app.Topic{Name: topicName, Arn: topicArn, Subscriptions: []*app.Subscription{
		{
			SubscriptionArn: subArn,
		},
	}}

	form := url.Values{}
	form.Add("SubscriptionArn", subArn)
	form.Add("AttributeName", "FilterPolicy")
	form.Add("AttributeValue", "{\"foo\": [\"bar\"]}")
	req.PostForm = form

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(SetSubscriptionAttributes)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the response body is what we expect.
	expected := "</SetSubscriptionAttributesResponse>"
	if !strings.Contains(rr.Body.String(), expected) {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}

	actualFilterPolicy := app.AllTopics.Topics[topicName].Subscriptions[0].FilterPolicy
	if actualFilterPolicy["foo"][0] != "bar" {
		t.Errorf("filter policy has not need applied")
	}
}

func setTopics(t *testing.T, names ...string) {
	clearTopics(t)
	for _, n := range names {
		t := &app.Topic{
			Name: n,
			Arn:  fmt.Sprintf("arn:aws:sns:%s:%s:%s", app.CurrentEnvironment.Region, app.CurrentEnvironment.AccountID, n),
		}
		t.Subscriptions = append(t.Subscriptions, &app.Subscription{
			TopicArn: t.Arn,
			EndPoint: "http://localhost",
			Protocol: "http",
		})
		app.AllTopics.Topics[n] = t
	}
}

func clearTopics(t *testing.T) {
	t.Cleanup(func() {
		app.AllTopics.Topics = make(map[string]*app.Topic)
	})
}
