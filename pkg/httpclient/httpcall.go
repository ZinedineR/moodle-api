package httpclient

import (
	rdis "moodle-api/internal/base/service/redisser"
)

// New creates client Factory
func New() ClientFactory {
	return *&clientFactory{}
}

// ClientFactory creates specific client implementation
type ClientFactory interface {
	CreateClient(redisClient rdis.RedisClient) Client
}

type clientFactory struct{}

func (c clientFactory) CreateClient(redisClient rdis.RedisClient) Client {
	return client{
		RedisClient: redisClient,
	}
}

// Client abstracts third party request client
type Client interface {
}

type client struct {
	RedisClient rdis.RedisClient
}
