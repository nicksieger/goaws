package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFilterPolicy_IsSatisfiedBy(t *testing.T) {
	var tests = []struct {
		filterPolicy      *FilterPolicy
		messageAttributes map[string]MessageAttributeValue
		expected          bool
	}{
		{
			&FilterPolicy{"foo": {"bar"}},
			map[string]MessageAttributeValue{"foo": {DataType: "String", Value: "bar"}},
			true,
		},
		{
			&FilterPolicy{"foo": {"bar", "xyz"}},
			map[string]MessageAttributeValue{"foo": {DataType: "String", Value: "xyz"}},
			true,
		},
		{
			&FilterPolicy{"foo": {"bar", "xyz"}, "abc": {"def"}},
			map[string]MessageAttributeValue{"foo": {DataType: "String", Value: "xyz"},
				"abc": {DataType: "String", Value: "def"}},
			true,
		},
		{
			&FilterPolicy{"foo": {"bar"}},
			map[string]MessageAttributeValue{"foo": {DataType: "String", Value: "baz"}},
			false,
		},
		{
			&FilterPolicy{"foo": {"bar"}},
			map[string]MessageAttributeValue{},
			false,
		},
		{
			&FilterPolicy{"foo": {"bar"}, "abc": {"def"}},
			map[string]MessageAttributeValue{"foo": {DataType: "String", Value: "bar"}},
			false,
		},
		{
			&FilterPolicy{"foo": {"bar"}},
			map[string]MessageAttributeValue{"foo": {DataType: "Binary", Value: "bar"}},
			false,
		},
	}

	for i, tt := range tests {
		actual := tt.filterPolicy.IsSatisfiedBy(tt.messageAttributes)
		if tt.filterPolicy.IsSatisfiedBy(tt.messageAttributes) != tt.expected {
			t.Errorf("#%d FilterPolicy: expected %t, actual %t", i, tt.expected, actual)
		}
	}

}

func TestTopicStorage(t *testing.T) {
	ts := &TopicStorage{Directory: t.TempDir()}
	dir := ts.TopicsDir()

	assert.Equal(t, 0, len(ts.Load()))

	assert.NoError(t, os.MkdirAll(dir, 0o0700))

	assert.Equal(t, 0, len(ts.Load()))

	assert.NoError(t, os.WriteFile(filepath.Join(dir, "file.txt"), []byte("hello"), 0o0600))

	assert.Equal(t, 0, len(ts.Load()))

	topic := &Topic{Name: "hello-topic"}
	assert.NoError(t, ts.writeTopic(topic))

	topics := ts.Load()
	assert.Equal(t, 1, len(topics))

	assert.NotNil(t, topics[topic.Name])

	ts.OnRemove(topic)

	assert.Equal(t, 0, len(ts.Load()))
}
