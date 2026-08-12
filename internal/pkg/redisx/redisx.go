package redisx

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type Client struct {
	rdb *redis.Client
}

func New(addr, password string, db int) *Client {
	return &Client{rdb: redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})}
}

func NewWithRedis(rdb *redis.Client) *Client {
	return &Client{rdb: rdb}
}

func (c *Client) Ping(ctx context.Context) error {
	return c.rdb.Ping(ctx).Err()
}

func (c *Client) Raw() *redis.Client { return c.rdb }

// Allow 简单固定窗口限流，返回是否允许以及剩余等待秒数。
func (c *Client) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, int, error) {
	pipe := c.rdb.TxPipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, window)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return false, 0, err
	}
	n := int(incr.Val())
	if n > limit {
		ttl, err := c.rdb.TTL(ctx, key).Result()
		if err != nil {
			return false, int(window.Seconds()), nil
		}
		return false, int(ttl.Seconds()), nil
	}
	return true, 0, nil
}

// SetNX 用于重发间隔控制。
func (c *Client) SetNX(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	return c.rdb.SetNX(ctx, key, "1", ttl).Result()
}

func (c *Client) BlacklistAccess(ctx context.Context, jti string, ttl time.Duration) error {
	return c.rdb.Set(ctx, fmt.Sprintf("uac:bl:at:%s", jti), "1", ttl).Err()
}

func (c *Client) IsAccessBlacklisted(ctx context.Context, jti string) (bool, error) {
	n, err := c.rdb.Exists(ctx, fmt.Sprintf("uac:bl:at:%s", jti)).Result()
	return n > 0, err
}

func (c *Client) Close() error {
	return c.rdb.Close()
}
