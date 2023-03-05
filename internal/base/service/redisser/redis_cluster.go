package redisser

import (
	"context"
	"github.com/go-redis/redis/v8"
	"time"
)

type redisClusterClient struct {
	Redis *redis.ClusterClient
}

func (r redisClusterClient) Get(ctx context.Context, key string) (string, error) {
	stringCmd := r.Redis.Get(ctx, key)
	return stringCmd.Result()
}

func (r redisClusterClient) SetWithExpire(ctx context.Context, key string, value interface{}, second time.Duration) (string, error) {
	statusCmd := r.Redis.Set(ctx, key, value, second)
	return statusCmd.Result()
}

func (r redisClusterClient) GetTTL(ctx context.Context, key string) int {
	stringCmd := r.Redis.TTL(ctx, key)
	return int(stringCmd.Val().Seconds())
}

func (r redisClusterClient) Set(ctx context.Context, key string, value interface{}) (string, error) {
	statusCmd := r.Redis.Set(ctx, key, value, 0)
	return statusCmd.Result()
}

func (r redisClusterClient) Del(ctx context.Context, key string) (int64, error) {
	intCmd := r.Redis.Del(ctx, key)
	return intCmd.Result()
}

func (r redisClusterClient) GetRedis() *redis.ClusterClient {
	return r.Redis
}

func (r redisClusterClient) SetBit(ctx context.Context, key string, offset int64, value int) (int64, error) {
	intCmd := r.Redis.SetBit(ctx, key, offset, value)
	return intCmd.Result()
}

func (r redisClusterClient) GetAllBits(ctx context.Context, key string) ([]bool, error) {
	re, err := r.Get(ctx, key)
	return bitStringToBool(re), err
}

func NewRedisClusterClient(redis *redis.ClusterClient) RedisClient {
	return &redisClusterClient{Redis: redis}
}
