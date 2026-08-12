package redisx

import (
	"context"
	"encoding/json"
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

// Allow 固定窗口限流（Lua 保证 Incr+Expire 原子）。
func (c *Client) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, int, error) {
	script := redis.NewScript(`
local n = redis.call("INCR", KEYS[1])
if n == 1 then
  redis.call("PEXPIRE", KEYS[1], ARGV[1])
end
local ttl = redis.call("PTTL", KEYS[1])
return {n, ttl}
`)
	res, err := script.Run(ctx, c.rdb, []string{key}, window.Milliseconds()).Slice()
	if err != nil {
		return false, 0, err
	}
	n, _ := res[0].(int64)
	ttlMs, _ := res[1].(int64)
	if int(n) > limit {
		wait := int(ttlMs / 1000)
		if wait < 1 {
			wait = int(window.Seconds())
		}
		return false, wait, nil
	}
	return true, 0, nil
}

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

func (c *Client) SetJSON(ctx context.Context, key string, v interface{}, ttl time.Duration) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.rdb.Set(ctx, key, b, ttl).Err()
}

// GetDelJSON 读取并删除（一次性消费）。
func (c *Client) GetDelJSON(ctx context.Context, key string, dest interface{}) (bool, error) {
	val, err := c.rdb.GetDel(ctx, key).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		// Redis < 6.2 无 GetDel 时回退
		val, err = c.rdb.Get(ctx, key).Result()
		if err == redis.Nil {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		_ = c.rdb.Del(ctx, key).Err()
	}
	if err := json.Unmarshal([]byte(val), dest); err != nil {
		return false, err
	}
	return true, nil
}

func (c *Client) Close() error {
	return c.rdb.Close()
}
