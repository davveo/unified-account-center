package sms

import (
	"context"
	"log"

	"github.com/davveo/unified-account-center/internal/mq"
)

type MockSender struct{}

func NewMock() *MockSender { return &MockSender{} }

func (m *MockSender) SendOTP(ctx context.Context, phone, code, scene string) error {
	log.Printf("[mock-sms] phone=%s scene=%s code=%s", phone, scene, code)
	return nil
}

type MQSender struct {
	producer mq.Producer
	topic    string
}

func NewMQ(producer mq.Producer, topic string) *MQSender {
	return &MQSender{producer: producer, topic: topic}
}

func (s *MQSender) SendOTP(ctx context.Context, phone, code, scene string) error {
	body := map[string]string{
		"phone": phone,
		"code":  code,
		"scene": scene,
		"type":  "otp",
	}
	return s.producer.SendJSON(ctx, s.topic, "sms_otp", body)
}
