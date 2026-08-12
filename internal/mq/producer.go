package mq

import (
	"context"
	"encoding/json"
	"log"
	"sync"
)

// Producer 消息发送抽象；生产环境可切换为 RocketMQ。
type Producer interface {
	SendJSON(ctx context.Context, topic, tag string, payload interface{}) error
	Close() error
}

// LogProducer 本地开发用：打印消息到日志。
type LogProducer struct {
	mu   sync.Mutex
	msgs []LoggedMessage
}

type LoggedMessage struct {
	Topic   string
	Tag     string
	Payload string
}

func NewLogProducer() *LogProducer { return &LogProducer{} }

func (p *LogProducer) SendJSON(ctx context.Context, topic, tag string, payload interface{}) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.msgs = append(p.msgs, LoggedMessage{Topic: topic, Tag: tag, Payload: string(b)})
	p.mu.Unlock()
	log.Printf("[mq-log] topic=%s tag=%s body=%s", topic, tag, string(b))
	return nil
}

func (p *LogProducer) Messages() []LoggedMessage {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]LoggedMessage, len(p.msgs))
	copy(out, p.msgs)
	return out
}

func (p *LogProducer) Close() error { return nil }
