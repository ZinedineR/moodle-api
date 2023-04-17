package redisser

import (
	"context"
	"time"

	"github.com/go-redis/redis/v8"
)

type redisClient struct {
	Redis *redis.Client
}

func (r redisClient) Get(ctx context.Context, key string) (string, error) {
	stringCmd := r.Redis.Get(ctx, key)
	return stringCmd.Result()
}

func (r redisClient) HGet(ctx context.Context, key, field string) (string, error) {
	stringCmd := r.Redis.HGet(ctx, key, field)
	return stringCmd.Result()

}

func (r redisClient) HSet(ctx context.Context, key, field, value string) error {
	if err := r.Redis.HSet(ctx, key, field, value).Err(); err != nil {
		return err
	}
	return nil
}

func (r redisClient) SetHashesExpire(ctx context.Context, key string, timeopen, timeclose int64) error {
	convertedTimeOpen := time.Unix(timeopen, 0)
	convertedTimeClose := time.Unix(timeclose, 0)
	duration := convertedTimeClose.Sub(convertedTimeOpen)
	if err := r.Redis.Expire(ctx, key, duration).Err(); err != nil {
		return err
	}
	return nil
}

func (r redisClient) SetWithExpire(ctx context.Context, key string, value interface{}, second time.Duration) (string, error) {
	statusCmd := r.Redis.Set(ctx, key, value, second)
	return statusCmd.Result()
}

func (r redisClient) GetTTL(ctx context.Context, key string) int {
	stringCmd := r.Redis.TTL(ctx, key)
	return int(stringCmd.Val().Seconds())
}

func (r redisClient) Set(ctx context.Context, key string, value interface{}) (string, error) {
	statusCmd := r.Redis.Set(ctx, key, value, 0)
	return statusCmd.Result()
}

func (r redisClient) Del(ctx context.Context, key string) (int64, error) {
	intCmd := r.Redis.Del(ctx, key)
	return intCmd.Result()
}

func (r redisClient) GetRedis() *redis.Client {
	return r.Redis
}

func (r redisClient) SetBit(ctx context.Context, key string, offset int64, value int) (int64, error) {
	intCmd := r.Redis.SetBit(ctx, key, offset, value)
	return intCmd.Result()
}

func (r redisClient) GetAllBits(ctx context.Context, key string) ([]bool, error) {
	re, err := r.Get(ctx, key)
	return bitStringToBool(re), err
}

func bitStringToBool(str string) []bool {
	s := make([]bool, len(str)*8)
	for i := 0; i < len(str); i++ {
		for bit := 7; bit >= 0; bit++ {
			bitN := uint(i*8 + (7 - bit))
			s[bitN] = (str[i]>>uint(bit))&1 == 1
		}
	}

	return s
}

func NewRedisClient(redis *redis.Client) RedisClient {
	return &redisClient{Redis: redis}
}
