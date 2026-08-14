package service

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/davveo/unified-account-center/internal/adapter"
	"github.com/davveo/unified-account-center/internal/adapter/sms"
	"github.com/davveo/unified-account-center/internal/model"
	"github.com/davveo/unified-account-center/internal/mq"
	"github.com/davveo/unified-account-center/internal/pkg/errcode"
	"github.com/davveo/unified-account-center/internal/pkg/idgen"
	"github.com/davveo/unified-account-center/internal/pkg/observability"
	"github.com/davveo/unified-account-center/internal/repository"
)

const settingKeySMSProvider = "sms.provider"

type DashboardSummary struct {
	Process     observability.Snapshot `json:"process"`
	Audit24h    DashboardAuditStats    `json:"audit_24h"`
	SMSAlerts   []DashboardAlert       `json:"sms_alerts"`
	SMSProvider string                 `json:"sms_provider"`
	Quota       DashboardQuota         `json:"quota"`
	GeneratedAt string                 `json:"generated_at"`
}

type DashboardQuota struct {
	TenantID      string `json:"tenant_id,omitempty"`
	AppsUsed      int64  `json:"apps_used"`
	AppsMax       int    `json:"apps_max"`
	OTPToday      int64  `json:"otp_today"`
	OTPDailyLimit int    `json:"otp_daily_limit"`
}

type DashboardAuditStats struct {
	LoginOK    int64 `json:"login_ok"`
	LoginFail  int64 `json:"login_fail"`
	Challenge  int64 `json:"challenge"`
	OTPLimit   int64 `json:"otp_limit_related"`
	SuccessRate float64 `json:"login_success_rate"`
}

type DashboardAlert struct {
	ID        uint64 `json:"id"`
	Action    string `json:"action"`
	Detail    string `json:"detail"`
	IP        string `json:"ip"`
	CreatedAt string `json:"created_at"`
}

func (s *AdminService) Dashboard(ctx context.Context) (*DashboardSummary, error) {
	snap := observability.MetricsSnapshot()
	since := time.Now().Add(-24 * time.Hour)
	stats, err := s.auditStatsSince(ctx, since)
	if err != nil {
		return nil, err
	}
	alerts, _ := s.recentSMSAlerts(ctx, since, 20)
	provider := s.currentSMSProvider()
	quota := s.dashboardQuota(ctx, "default")
	return &DashboardSummary{
		Process:     snap,
		Audit24h:    stats,
		SMSAlerts:   alerts,
		SMSProvider: provider,
		Quota:       quota,
		GeneratedAt: time.Now().Format(time.RFC3339),
	}, nil
}

func (s *AdminService) dashboardQuota(ctx context.Context, tenantID string) DashboardQuota {
	q := DashboardQuota{TenantID: tenantID, AppsMax: 20, OTPDailyLimit: 5000}
	if t, _ := s.repos.Tenant.FindByTenantID(ctx, tenantID); t != nil {
		q.AppsMax = t.MaxApps
		q.OTPDailyLimit = t.DailyOTPLimit
	}
	_, total, _ := s.repos.App.List(ctx, tenantID, 1, 0)
	q.AppsUsed = total
	dayStart := time.Now().Truncate(24 * time.Hour)
	_ = s.repos.DB.WithContext(ctx).Model(&model.AuditLog{}).
		Where("created_at >= ? AND action = ? AND success = ?", dayStart, "challenge", true).
		Count(&q.OTPToday)
	return q
}

func (s *AdminService) auditStatsSince(ctx context.Context, since time.Time) (DashboardAuditStats, error) {
	var out DashboardAuditStats
	_ = s.repos.DB.WithContext(ctx).Model(&model.AuditLog{}).
		Where("created_at >= ? AND action = ? AND success = ?", since, "login_ok", true).
		Count(&out.LoginOK)
	_ = s.repos.DB.WithContext(ctx).Model(&model.AuditLog{}).
		Where("created_at >= ? AND action = ?", since, "login_fail").
		Count(&out.LoginFail)
	_ = s.repos.DB.WithContext(ctx).Model(&model.AuditLog{}).
		Where("created_at >= ? AND action = ? AND success = ?", since, "challenge", true).
		Count(&out.Challenge)
	_ = s.repos.DB.WithContext(ctx).Model(&model.AuditLog{}).
		Where("created_at >= ? AND action IN ?", since, []string{"otp_limit_alert", "risk_alert"}).
		Count(&out.OTPLimit)
	total := out.LoginOK + out.LoginFail
	if total > 0 {
		out.SuccessRate = float64(out.LoginOK) / float64(total)
	}
	return out, nil
}

func (s *AdminService) recentSMSAlerts(ctx context.Context, since time.Time, limit int) ([]DashboardAlert, error) {
	var list []model.AuditLog
	err := s.repos.DB.WithContext(ctx).
		Where("created_at >= ? AND (action LIKE ? OR detail LIKE ? OR action = ?)",
			since, "%otp%", "%otp%", "risk_alert").
		Order("id desc").Limit(limit).Find(&list).Error
	if err != nil {
		return nil, err
	}
	out := make([]DashboardAlert, 0, len(list))
	for _, a := range list {
		out = append(out, DashboardAlert{
			ID: a.ID, Action: a.Action, Detail: a.Detail, IP: a.IP,
			CreatedAt: a.CreatedAt.Format("2006-01-02 15:04:05"),
		})
	}
	return out, nil
}

type ExportAuditsResult struct {
	Filename   string `json:"filename"`
	Path       string `json:"path,omitempty"`
	URL        string `json:"url,omitempty"`
	Count      int    `json:"count"`
	Persisted  bool   `json:"persisted"`
	DownloadHint string `json:"download_hint,omitempty"`
}

// ExportAuditsCSV 导出审计日志；persist=true 时写入本地对象存储目录。
func (s *AdminService) ExportAuditsCSV(ctx context.Context, filter repository.AuditFilter, persist bool, actor string) (*ExportAuditsResult, []byte, error) {
	filter.Limit = 10000
	filter.Offset = 0
	list, _, err := s.repos.Audit.List(ctx, filter)
	if err != nil {
		return nil, nil, errcode.Wrap(errcode.Internal, "查询审计失败", err)
	}

	var b strings.Builder
	w := csv.NewWriter(&b)
	_ = w.Write([]string{"id", "tenant_id", "client_id", "user_id", "action", "success", "detail", "ip", "ua", "created_at"})
	for _, a := range list {
		_ = w.Write([]string{
			strconv.FormatUint(a.ID, 10),
			a.TenantID, a.ClientID, a.UserID, a.Action,
			strconv.FormatBool(a.Success), a.Detail, a.IP, a.UA,
			a.CreatedAt.Format(time.RFC3339),
		})
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, nil, errcode.Wrap(errcode.Internal, "生成 CSV 失败", err)
	}
	data := []byte(b.String())
	filename := fmt.Sprintf("audits_%s.csv", time.Now().Format("20060102_150405"))

	_ = s.repos.Audit.Create(ctx, &model.AuditLog{
		TenantID: filter.TenantID, UserID: actor, Action: "admin_export_audits", Success: true,
		Detail: fmt.Sprintf("count=%d persist=%v", len(list), persist), CreatedAt: time.Now(),
	})

	res := &ExportAuditsResult{Filename: filename, Count: len(list)}
	if persist {
		dir := "data/exports"
		if s.cfg != nil && s.cfg.Export.Dir != "" {
			dir = s.cfg.Export.Dir
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, nil, errcode.Wrap(errcode.Internal, "创建导出目录失败", err)
		}
		path := filepath.Join(dir, filename)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return nil, nil, errcode.Wrap(errcode.Internal, "写入导出文件失败", err)
		}
		res.Persisted = true
		res.Path = path
		res.URL = "/api/v1/admin/exports/" + filename
		res.DownloadHint = "可通过管理 API GET " + res.URL + " 下载"
	}
	return res, data, nil
}

type SMSChannelView struct {
	Provider    string `json:"provider"` // mock | mq
	MQTopic     string `json:"mq_topic,omitempty"`
	MQEnabled   bool   `json:"mq_enabled"`
	HotReload   bool   `json:"hot_reload"`
	UpdatedAt   string `json:"updated_at,omitempty"`
}

func (s *AdminService) GetSMSChannel(ctx context.Context) (*SMSChannelView, error) {
	provider := s.currentSMSProvider()
	view := &SMSChannelView{
		Provider:  provider,
		HotReload: s.smsHot != nil,
		MQEnabled: s.cfg != nil && s.cfg.MQ.Enabled,
	}
	if s.cfg != nil {
		view.MQTopic = s.cfg.MQ.SMSTopic
	}
	var row model.PlatformSetting
	if err := s.repos.DB.WithContext(ctx).Where("setting_key = ?", settingKeySMSProvider).First(&row).Error; err == nil {
		view.UpdatedAt = row.UpdatedAt.Format(time.RFC3339)
	}
	return view, nil
}

type UpdateSMSChannelRequest struct {
	Provider string `json:"provider" binding:"required"` // mock | mq
}

func (s *AdminService) UpdateSMSChannel(ctx context.Context, req UpdateSMSChannelRequest, actor string) (*SMSChannelView, error) {
	provider := strings.ToLower(strings.TrimSpace(req.Provider))
	if provider != "mock" && provider != "mq" {
		return nil, errcode.New(errcode.BadRequest, "provider 仅支持 mock/mq")
	}
	if provider == "mq" && (s.cfg == nil || !s.cfg.MQ.Enabled || s.mqProducer == nil) {
		return nil, errcode.New(errcode.BadRequest, "MQ 未启用，无法切换到 mq 通道")
	}
	if s.smsHot == nil {
		return nil, errcode.New(errcode.Internal, "短信热更新未初始化")
	}

	var next adapter.SMSSender
	if provider == "mq" {
		topic := s.cfg.MQ.SMSTopic
		if topic == "" {
			topic = "uac_sms"
		}
		next = sms.NewMQ(s.mqProducer, topic)
	} else {
		next = sms.NewMock()
	}
	s.smsHot.Swap(next)

	now := time.Now()
	var row model.PlatformSetting
	err := s.repos.DB.WithContext(ctx).Where("setting_key = ?", settingKeySMSProvider).First(&row).Error
	if err != nil {
		row = model.PlatformSetting{Key: settingKeySMSProvider, Value: provider, UpdatedAt: now}
		if err := s.repos.DB.WithContext(ctx).Create(&row).Error; err != nil {
			return nil, errcode.Wrap(errcode.Internal, "保存短信配置失败", err)
		}
	} else {
		row.Value = provider
		row.UpdatedAt = now
		if err := s.repos.DB.WithContext(ctx).Save(&row).Error; err != nil {
			return nil, errcode.Wrap(errcode.Internal, "更新短信配置失败", err)
		}
	}

	_ = s.repos.Audit.Create(ctx, &model.AuditLog{
		UserID: actor, Action: "admin_sms_hot_reload", Success: true,
		Detail: "provider=" + provider, CreatedAt: now,
	})
	return s.GetSMSChannel(ctx)
}

func (s *AdminService) currentSMSProvider() string {
	var row model.PlatformSetting
	if err := s.repos.DB.Where("setting_key = ?", settingKeySMSProvider).First(&row).Error; err == nil && row.Value != "" {
		return row.Value
	}
	if s.cfg != nil && s.cfg.SMS.Provider != "" {
		return s.cfg.SMS.Provider
	}
	return "mock"
}

func (s *AdminService) SetSMSHot(h *sms.HotSender) { s.smsHot = h }
func (s *AdminService) SetMQProducer(p mq.Producer) { s.mqProducer = p }

// RestoreSMSChannel 启动时按 DB 配置恢复热通道。
func (s *AdminService) RestoreSMSChannel(ctx context.Context) {
	if s.smsHot == nil {
		return
	}
	provider := s.currentSMSProvider()
	if provider == "mq" && s.cfg != nil && s.cfg.MQ.Enabled && s.mqProducer != nil {
		topic := s.cfg.MQ.SMSTopic
		if topic == "" {
			topic = "uac_sms"
		}
		s.smsHot.Swap(sms.NewMQ(s.mqProducer, topic))
		return
	}
	s.smsHot.Swap(sms.NewMock())
}

// ReadExportFile 读取已持久化的导出文件（防路径穿越）。
func (s *AdminService) ReadExportFile(name string) (string, []byte, error) {
	name = filepath.Base(strings.TrimSpace(name))
	if name == "" || name != filepath.Clean(name) || strings.Contains(name, "..") {
		return "", nil, errcode.New(errcode.BadRequest, "非法文件名")
	}
	if !strings.HasSuffix(name, ".csv") {
		return "", nil, errcode.New(errcode.BadRequest, "仅支持 csv")
	}
	dir := "data/exports"
	if s.cfg != nil && s.cfg.Export.Dir != "" {
		dir = s.cfg.Export.Dir
	}
	path := filepath.Join(dir, name)
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, errcode.New(errcode.NotFound, "导出文件不存在")
	}
	return name, data, nil
}

// NewExportID 供测试/调用方生成文件名。
func NewExportID() string { return idgen.New("exp") }
