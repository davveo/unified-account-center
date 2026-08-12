package mq

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/apache/rocketmq-client-go/v2"
	"github.com/apache/rocketmq-client-go/v2/primitive"
	"github.com/apache/rocketmq-client-go/v2/producer"
	"github.com/davveo/unified-account-center/internal/config"
)

type rocketProducer struct {
	p rocketmq.Producer
}

func NewRocketMQProducer(cfg config.MQConfig) (Producer, error) {
	p, err := rocketmq.NewProducer(
		producer.WithNameServer([]string{cfg.NameServer}),
		producer.WithGroupName(cfg.ProducerGroup),
		producer.WithRetry(2),
	)
	if err != nil {
		return nil, err
	}
	if err := p.Start(); err != nil {
		return nil, err
	}
	return &rocketProducer{p: p}, nil
}

func (r *rocketProducer) SendJSON(ctx context.Context, topic, tag string, payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	msg := &primitive.Message{Topic: topic, Body: body}
	msg.WithTag(tag)
	res, err := r.p.SendSync(ctx, msg)
	if err != nil {
		return err
	}
	if res.Status != primitive.SendOK {
		return fmt.Errorf("rocketmq send status=%v", res.Status)
	}
	return nil
}

func (r *rocketProducer) Close() error {
	return r.p.Shutdown()
}
