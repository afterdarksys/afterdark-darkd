package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	pb "github.com/afterdarksys/afterdark-darkd/api/proto/plugin"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
	"time"
)

// FirewallPluginImpl is the host-side firewall protocol adapter.
type FirewallPluginImpl struct{ plugin.Plugin }

func (*FirewallPluginImpl) GRPCServer(*plugin.GRPCBroker, *grpc.Server) error {
	return fmt.Errorf("use pluginsdk.ServeFirewallPlugin to serve a firewall")
}
func (*FirewallPluginImpl) GRPCClient(_ context.Context, _ *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &firewallGRPCClient{client: pb.NewFirewallPluginClient(c)}, nil
}

type firewallGRPCClient struct{ client pb.FirewallPluginClient }

var _ FirewallPlugin = (*firewallGRPCClient)(nil)

func firewallError(response interface {
	GetSuccess() bool
	GetError() string
}, err error) error {
	if err != nil {
		return err
	}
	if !response.GetSuccess() {
		return fmt.Errorf("firewall operation failed: %s", response.GetError())
	}
	return nil
}
func (c *firewallGRPCClient) Info() PluginInfo {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r, err := c.client.Info(ctx, &pb.Empty{})
	if err != nil {
		return PluginInfo{}
	}
	return PluginInfo{Name: r.Name, Version: r.Version, Type: PluginType(r.Type), Description: r.Description, Author: r.Author, License: r.License, Capabilities: r.Capabilities}
}
func (c *firewallGRPCClient) Configure(config map[string]interface{}) error {
	b, err := json.Marshal(config)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r, err := c.client.Configure(ctx, &pb.ConfigureRequest{ConfigJson: b})
	return firewallError(r, err)
}
func (c *firewallGRPCClient) Health() PluginHealth {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r, err := c.client.Health(ctx, &pb.HealthRequest{})
	if err != nil {
		return PluginHealth{State: PluginStateError, Message: err.Error(), LastCheck: time.Now()}
	}
	if r.Health == nil {
		return PluginHealth{State: PluginStateError, Message: "missing firewall health", LastCheck: time.Now()}
	}
	metrics := map[string]interface{}{}
	for k, v := range r.Health.Metrics {
		metrics[k] = v
	}
	return PluginHealth{State: parsePluginState(r.Health.State), Message: r.Health.Message, LastCheck: time.Unix(r.Health.LastCheckUnix, 0), Metrics: metrics}
}
func statusFromPB(r *pb.FirewallStatus) *FirewallStatus {
	if r == nil {
		return nil
	}
	return &FirewallStatus{Enabled: r.Enabled, Backend: r.Backend, Version: r.Version, TotalRules: int(r.TotalRules), ActiveRules: int(r.ActiveRules), BlockedIPs: int(r.BlockedIps), DefaultDenyInbound: r.DefaultDenyInbound, DefaultDenyOutbound: r.DefaultDenyOutbound, LastUpdated: time.Unix(r.LastUpdated, 0), Capabilities: r.Capabilities}
}
func convertStatusToPB(status *FirewallStatus) *pb.FirewallStatus {
	if status == nil {
		return nil
	}
	return &pb.FirewallStatus{
		Enabled:             status.Enabled,
		Backend:             status.Backend,
		Version:             status.Version,
		TotalRules:          int32(status.TotalRules),
		ActiveRules:         int32(status.ActiveRules),
		BlockedIps:          int32(status.BlockedIPs),
		DefaultDenyInbound:  status.DefaultDenyInbound,
		DefaultDenyOutbound: status.DefaultDenyOutbound,
		LastUpdated:         status.LastUpdated.Unix(),
		Capabilities:        status.Capabilities,
	}
}

func convertBlockedIPToPB(blocked *BlockedIP) *pb.BlockedIP {
	if blocked == nil {
		return nil
	}
	var expiresAt int64
	if !blocked.ExpiresAt.IsZero() {
		expiresAt = blocked.ExpiresAt.Unix()
	}
	return &pb.BlockedIP{
		Ip:            blocked.IP,
		Reason:        blocked.Reason,
		SourceService: blocked.SourceService,
		BlockedAt:     blocked.BlockedAt.Unix(),
		ExpiresAt:     expiresAt,
		ThreatScore:   int32(blocked.ThreatScore),
		Categories:    blocked.Categories,
	}
}

func convertBlockedIPFromPB(pb *pb.BlockedIP) *BlockedIP {
	if pb == nil {
		return nil
	}
	blocked := &BlockedIP{
		IP:            pb.Ip,
		Reason:        pb.Reason,
		SourceService: pb.SourceService,
		BlockedAt:     time.Unix(pb.BlockedAt, 0),
		ThreatScore:   int(pb.ThreatScore),
		Categories:    pb.Categories,
	}
	if pb.ExpiresAt > 0 {
		blocked.ExpiresAt = time.Unix(pb.ExpiresAt, 0)
	}
	return blocked
}

func convertRuleToPB(rule *FirewallRule) *pb.FirewallRule {
	if rule == nil {
		return nil
	}
	var expiresAt, lastHitAt int64
	if !rule.ExpiresAt.IsZero() {
		expiresAt = rule.ExpiresAt.Unix()
	}
	if !rule.LastHitAt.IsZero() {
		lastHitAt = rule.LastHitAt.Unix()
	}
	return &pb.FirewallRule{
		Id:            rule.ID,
		Name:          rule.Name,
		Description:   rule.Description,
		Direction:     rule.Direction,
		Action:        rule.Action,
		Protocol:      rule.Protocol,
		SourceIp:      rule.SourceIP,
		SourcePort:    rule.SourcePort,
		DestIp:        rule.DestIP,
		DestPort:      rule.DestPort,
		Interface:     rule.Interface,
		Priority:      int32(rule.Priority),
		Enabled:       rule.Enabled,
		CreatedAt:     rule.CreatedAt.Unix(),
		ExpiresAt:     expiresAt,
		Reason:        rule.Reason,
		SourceService: rule.SourceService,
		HitCount:      rule.HitCount,
		LastHitAt:     lastHitAt,
	}
}

func convertRuleFromPB(pb *pb.FirewallRule) *FirewallRule {
	if pb == nil {
		return nil
	}
	rule := &FirewallRule{
		ID:            pb.Id,
		Name:          pb.Name,
		Description:   pb.Description,
		Direction:     pb.Direction,
		Action:        pb.Action,
		Protocol:      pb.Protocol,
		SourceIP:      pb.SourceIp,
		SourcePort:    pb.SourcePort,
		DestIP:        pb.DestIp,
		DestPort:      pb.DestPort,
		Interface:     pb.Interface,
		Priority:      int(pb.Priority),
		Enabled:       pb.Enabled,
		CreatedAt:     time.Unix(pb.CreatedAt, 0),
		Reason:        pb.Reason,
		SourceService: pb.SourceService,
		HitCount:      pb.HitCount,
	}
	if pb.ExpiresAt > 0 {
		rule.ExpiresAt = time.Unix(pb.ExpiresAt, 0)
	}
	if pb.LastHitAt > 0 {
		rule.LastHitAt = time.Unix(pb.LastHitAt, 0)
	}
	return rule
}

func (c *firewallGRPCClient) Enable(ctx context.Context, enable, defaultDenyInbound, defaultDenyOutbound bool) (*FirewallStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if defaultDenyInbound || defaultDenyOutbound {
		return nil, fmt.Errorf("default-deny requires a verified rollback policy; unsupported")
	}
	r, err := c.client.Enable(ctx, &pb.FirewallEnableRequest{Enable: enable, DefaultDenyInbound: defaultDenyInbound, DefaultDenyOutbound: defaultDenyOutbound})
	if err = firewallError(r, err); err != nil {
		return nil, err
	}
	if r.Status == nil {
		return nil, fmt.Errorf("missing firewall status")
	}
	return statusFromPB(r.Status), nil
}

func (c *firewallGRPCClient) Status(ctx context.Context) (*FirewallStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	r, err := c.client.Status(ctx, &pb.FirewallStatusRequest{})
	if err = firewallError(r, err); err != nil {
		return nil, err
	}
	if r.Status == nil {
		return nil, fmt.Errorf("missing firewall status")
	}
	return statusFromPB(r.Status), nil
}

func (c *firewallGRPCClient) BlockIP(ctx context.Context, ip, reason, source string, durationSeconds int64, score int, categories []string) (*BlockedIP, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	r, err := c.client.BlockIP(ctx, &pb.BlockIPRequest{Ip: ip, Reason: reason, SourceService: source, DurationSeconds: durationSeconds, ThreatScore: int32(score), Categories: categories})
	if err = firewallError(r, err); err != nil {
		return nil, err
	}
	if r.BlockedIp == nil {
		return nil, fmt.Errorf("missing blocked IP")
	}
	return convertBlockedIPFromPB(r.BlockedIp), nil
}

func (c *firewallGRPCClient) UnblockIP(ctx context.Context, ip string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	r, err := c.client.UnblockIP(ctx, &pb.UnblockIPRequest{Ip: ip})
	if err = firewallError(r, err); err != nil {
		return err
	}
	return nil
}

func (c *firewallGRPCClient) ListBlockedIPs(ctx context.Context, limit, offset int, source string) ([]BlockedIP, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	r, err := c.client.ListBlockedIPs(ctx, &pb.ListBlockedIPsRequest{Limit: int32(limit), Offset: int32(offset), SourceService: source})
	if err = firewallError(r, err); err != nil {
		return nil, 0, err
	}
	items := make([]BlockedIP, 0, len(r.BlockedIps))
	for _, v := range r.BlockedIps {
		if v == nil {
			return nil, 0, fmt.Errorf("missing blocked IP")
		}
		items = append(items, *convertBlockedIPFromPB(v))
	}
	return items, int(r.TotalCount), nil
}

func (c *firewallGRPCClient) IsIPBlocked(ctx context.Context, ip string) (bool, *BlockedIP, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	r, err := c.client.IsIPBlocked(ctx, &pb.IsIPBlockedRequest{Ip: ip})
	if err = firewallError(r, err); err != nil {
		return false, nil, err
	}
	return r.Blocked, convertBlockedIPFromPB(r.BlockedIp), nil
}

func (c *firewallGRPCClient) AddRule(ctx context.Context, rule *FirewallRule) (*FirewallRule, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	r, err := c.client.AddRule(ctx, &pb.AddRuleRequest{Rule: convertRuleToPB(rule)})
	if err = firewallError(r, err); err != nil {
		return nil, err
	}
	if r.Rule == nil {
		return nil, fmt.Errorf("missing firewall rule")
	}
	return convertRuleFromPB(r.Rule), nil
}

func (c *firewallGRPCClient) RemoveRule(ctx context.Context, ruleID string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	r, err := c.client.RemoveRule(ctx, &pb.RemoveRuleRequest{RuleId: ruleID})
	if err = firewallError(r, err); err != nil {
		return err
	}
	return nil
}

func (c *firewallGRPCClient) UpdateRule(ctx context.Context, rule *FirewallRule) (*FirewallRule, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	r, err := c.client.UpdateRule(ctx, &pb.UpdateRuleRequest{Rule: convertRuleToPB(rule)})
	if err = firewallError(r, err); err != nil {
		return nil, err
	}
	if r.Rule == nil {
		return nil, fmt.Errorf("missing firewall rule")
	}
	return convertRuleFromPB(r.Rule), nil
}

func (c *firewallGRPCClient) ListRules(ctx context.Context, limit, offset int, direction string, enabledOnly bool) ([]FirewallRule, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	r, err := c.client.ListRules(ctx, &pb.ListRulesRequest{Limit: int32(limit), Offset: int32(offset), Direction: direction, EnabledOnly: enabledOnly})
	if err = firewallError(r, err); err != nil {
		return nil, 0, err
	}
	items := make([]FirewallRule, 0, len(r.Rules))
	for _, v := range r.Rules {
		if v == nil {
			return nil, 0, fmt.Errorf("missing firewall rule")
		}
		items = append(items, *convertRuleFromPB(v))
	}
	return items, int(r.TotalCount), nil
}

func (c *firewallGRPCClient) GetRule(ctx context.Context, ruleID string) (*FirewallRule, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	r, err := c.client.GetRule(ctx, &pb.GetRuleRequest{RuleId: ruleID})
	if err = firewallError(r, err); err != nil {
		return nil, err
	}
	if r.Rule == nil {
		return nil, fmt.Errorf("missing firewall rule")
	}
	return convertRuleFromPB(r.Rule), nil
}

func (c *firewallGRPCClient) FlushRules(ctx context.Context, flushBlocks, flushRules, keepEssential bool) (int, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	r, err := c.client.FlushRules(ctx, &pb.FlushRulesRequest{FlushBlocks: flushBlocks, FlushRules: flushRules, KeepEssential: keepEssential})
	if err = firewallError(r, err); err != nil {
		return 0, 0, err
	}
	return int(r.RulesFlushed), int(r.BlocksFlushed), nil
}

func (c *firewallGRPCClient) OpenPort(ctx context.Context, port int, protocol, direction, sourceIP, description string) (*FirewallRule, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	r, err := c.client.OpenPort(ctx, &pb.OpenPortRequest{Port: int32(port), Protocol: protocol, Direction: direction, SourceIp: sourceIP, Description: description})
	if err = firewallError(r, err); err != nil {
		return nil, err
	}
	if r.Rule == nil {
		return nil, fmt.Errorf("missing firewall rule")
	}
	return convertRuleFromPB(r.Rule), nil
}

func (c *firewallGRPCClient) ClosePort(ctx context.Context, port int, protocol, direction string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	r, err := c.client.ClosePort(ctx, &pb.ClosePortRequest{Port: int32(port), Protocol: protocol, Direction: direction})
	if err = firewallError(r, err); err != nil {
		return err
	}
	return nil
}

func (c *firewallGRPCClient) SyncBlocklist(ctx context.Context, items []BlockedIP, replace bool) (int, int, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	values := make([]*pb.BlockedIP, len(items))
	for i := range items {
		values[i] = convertBlockedIPToPB(&items[i])
	}
	r, err := c.client.SyncBlocklist(ctx, &pb.SyncBlocklistRequest{BlockedIps: values, Replace: replace})
	if err = firewallError(r, err); err != nil {
		return 0, 0, 0, err
	}
	return int(r.Added), int(r.Removed), int(r.Unchanged), nil
}
