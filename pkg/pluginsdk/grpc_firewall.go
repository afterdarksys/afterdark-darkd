package pluginsdk

import (
	"context"
	"encoding/json"
	"time"

	pb "github.com/afterdarksys/afterdark-darkd/api/proto/plugin"
)

// firewallGRPCServer is the gRPC server for FirewallPlugin (plugin side)
type firewallGRPCServer struct {
	pb.UnimplementedFirewallPluginServer
	Impl FirewallPlugin
}

func (s *firewallGRPCServer) Info(ctx context.Context, req *pb.Empty) (*pb.PluginInfo, error) {
	info := s.Impl.Info()
	return &pb.PluginInfo{
		Name:         info.Name,
		Version:      info.Version,
		Type:         string(info.Type),
		Description:  info.Description,
		Author:       info.Author,
		License:      info.License,
		Capabilities: info.Capabilities,
	}, nil
}

func (s *firewallGRPCServer) Configure(ctx context.Context, req *pb.ConfigureRequest) (*pb.ConfigureResponse, error) {
	config := make(map[string]interface{})
	for k, v := range req.Config {
		config[k] = v
	}
	if len(req.ConfigJson) > 0 {
		var jsonConfig map[string]interface{}
		if err := json.Unmarshal(req.ConfigJson, &jsonConfig); err == nil {
			for k, v := range jsonConfig {
				config[k] = v
			}
		}
	}

	err := s.Impl.Configure(config)
	if err != nil {
		return &pb.ConfigureResponse{Success: false, Error: err.Error()}, nil
	}
	return &pb.ConfigureResponse{Success: true}, nil
}

func (s *firewallGRPCServer) Health(ctx context.Context, req *pb.HealthRequest) (*pb.HealthResponse, error) {
	health := s.Impl.Health()
	metrics := make(map[string]string)
	for k, v := range health.Metrics {
		if str, ok := v.(string); ok {
			metrics[k] = str
		} else {
			b, _ := json.Marshal(v)
			metrics[k] = string(b)
		}
	}
	return &pb.HealthResponse{
		Health: &pb.PluginHealth{
			State:         health.State.String(),
			Message:       health.Message,
			LastCheckUnix: health.LastCheck.Unix(),
			Metrics:       metrics,
		},
	}, nil
}

func (s *firewallGRPCServer) Enable(ctx context.Context, req *pb.FirewallEnableRequest) (*pb.FirewallEnableResponse, error) {
	status, err := s.Impl.Enable(ctx, req.Enable, req.DefaultDenyInbound, req.DefaultDenyOutbound)
	if err != nil {
		return &pb.FirewallEnableResponse{Success: false, Error: err.Error()}, nil
	}
	return &pb.FirewallEnableResponse{
		Success: true,
		Status:  convertStatusToPB(status),
	}, nil
}

func (s *firewallGRPCServer) Status(ctx context.Context, req *pb.FirewallStatusRequest) (*pb.FirewallStatusResponse, error) {
	status, err := s.Impl.Status(ctx)
	if err != nil {
		return &pb.FirewallStatusResponse{Success: false, Error: err.Error()}, nil
	}
	return &pb.FirewallStatusResponse{
		Success: true,
		Status:  convertStatusToPB(status),
	}, nil
}

func (s *firewallGRPCServer) BlockIP(ctx context.Context, req *pb.BlockIPRequest) (*pb.BlockIPResponse, error) {
	blocked, err := s.Impl.BlockIP(ctx, req.Ip, req.Reason, req.SourceService, req.DurationSeconds, int(req.ThreatScore), req.Categories)
	if err != nil {
		return &pb.BlockIPResponse{Success: false, Error: err.Error()}, nil
	}
	return &pb.BlockIPResponse{
		Success:   true,
		BlockedIp: convertBlockedIPToPB(blocked),
	}, nil
}

func (s *firewallGRPCServer) UnblockIP(ctx context.Context, req *pb.UnblockIPRequest) (*pb.UnblockIPResponse, error) {
	err := s.Impl.UnblockIP(ctx, req.Ip)
	if err != nil {
		return &pb.UnblockIPResponse{Success: false, Error: err.Error()}, nil
	}
	return &pb.UnblockIPResponse{Success: true}, nil
}

func (s *firewallGRPCServer) ListBlockedIPs(ctx context.Context, req *pb.ListBlockedIPsRequest) (*pb.ListBlockedIPsResponse, error) {
	blockedIPs, total, err := s.Impl.ListBlockedIPs(ctx, int(req.Limit), int(req.Offset), req.SourceService)
	if err != nil {
		return &pb.ListBlockedIPsResponse{Success: false, Error: err.Error()}, nil
	}

	pbBlocked := make([]*pb.BlockedIP, len(blockedIPs))
	for i, b := range blockedIPs {
		pbBlocked[i] = convertBlockedIPToPB(&b)
	}

	return &pb.ListBlockedIPsResponse{
		Success:    true,
		BlockedIps: pbBlocked,
		TotalCount: int32(total),
	}, nil
}

func (s *firewallGRPCServer) IsIPBlocked(ctx context.Context, req *pb.IsIPBlockedRequest) (*pb.IsIPBlockedResponse, error) {
	blocked, blockedIP, err := s.Impl.IsIPBlocked(ctx, req.Ip)
	if err != nil {
		return &pb.IsIPBlockedResponse{Success: false, Error: err.Error()}, nil
	}
	resp := &pb.IsIPBlockedResponse{
		Success: true,
		Blocked: blocked,
	}
	if blockedIP != nil {
		resp.BlockedIp = convertBlockedIPToPB(blockedIP)
	}
	return resp, nil
}

func (s *firewallGRPCServer) AddRule(ctx context.Context, req *pb.AddRuleRequest) (*pb.AddRuleResponse, error) {
	rule := convertRuleFromPB(req.Rule)
	result, err := s.Impl.AddRule(ctx, rule)
	if err != nil {
		return &pb.AddRuleResponse{Success: false, Error: err.Error()}, nil
	}
	return &pb.AddRuleResponse{
		Success: true,
		Rule:    convertRuleToPB(result),
	}, nil
}

func (s *firewallGRPCServer) RemoveRule(ctx context.Context, req *pb.RemoveRuleRequest) (*pb.RemoveRuleResponse, error) {
	err := s.Impl.RemoveRule(ctx, req.RuleId)
	if err != nil {
		return &pb.RemoveRuleResponse{Success: false, Error: err.Error()}, nil
	}
	return &pb.RemoveRuleResponse{Success: true}, nil
}

func (s *firewallGRPCServer) UpdateRule(ctx context.Context, req *pb.UpdateRuleRequest) (*pb.UpdateRuleResponse, error) {
	rule := convertRuleFromPB(req.Rule)
	result, err := s.Impl.UpdateRule(ctx, rule)
	if err != nil {
		return &pb.UpdateRuleResponse{Success: false, Error: err.Error()}, nil
	}
	return &pb.UpdateRuleResponse{
		Success: true,
		Rule:    convertRuleToPB(result),
	}, nil
}

func (s *firewallGRPCServer) ListRules(ctx context.Context, req *pb.ListRulesRequest) (*pb.ListRulesResponse, error) {
	rules, total, err := s.Impl.ListRules(ctx, int(req.Limit), int(req.Offset), req.Direction, req.EnabledOnly)
	if err != nil {
		return &pb.ListRulesResponse{Success: false, Error: err.Error()}, nil
	}

	pbRules := make([]*pb.FirewallRule, len(rules))
	for i, r := range rules {
		pbRules[i] = convertRuleToPB(&r)
	}

	return &pb.ListRulesResponse{
		Success:    true,
		Rules:      pbRules,
		TotalCount: int32(total),
	}, nil
}

func (s *firewallGRPCServer) GetRule(ctx context.Context, req *pb.GetRuleRequest) (*pb.GetRuleResponse, error) {
	rule, err := s.Impl.GetRule(ctx, req.RuleId)
	if err != nil {
		return &pb.GetRuleResponse{Success: false, Error: err.Error()}, nil
	}
	return &pb.GetRuleResponse{
		Success: true,
		Rule:    convertRuleToPB(rule),
	}, nil
}

func (s *firewallGRPCServer) SyncBlocklist(ctx context.Context, req *pb.SyncBlocklistRequest) (*pb.SyncBlocklistResponse, error) {
	blockedIPs := make([]BlockedIP, len(req.BlockedIps))
	for i, b := range req.BlockedIps {
		blockedIPs[i] = *convertBlockedIPFromPB(b)
	}

	added, removed, unchanged, err := s.Impl.SyncBlocklist(ctx, blockedIPs, req.Replace)
	if err != nil {
		return &pb.SyncBlocklistResponse{Success: false, Error: err.Error()}, nil
	}
	return &pb.SyncBlocklistResponse{
		Success:   true,
		Added:     int32(added),
		Removed:   int32(removed),
		Unchanged: int32(unchanged),
	}, nil
}

func (s *firewallGRPCServer) FlushRules(ctx context.Context, req *pb.FlushRulesRequest) (*pb.FlushRulesResponse, error) {
	rulesFlushed, blocksFlushed, err := s.Impl.FlushRules(ctx, req.FlushBlocks, req.FlushRules, req.KeepEssential)
	if err != nil {
		return &pb.FlushRulesResponse{Success: false, Error: err.Error()}, nil
	}
	return &pb.FlushRulesResponse{
		Success:       true,
		RulesFlushed:  int32(rulesFlushed),
		BlocksFlushed: int32(blocksFlushed),
	}, nil
}

func (s *firewallGRPCServer) OpenPort(ctx context.Context, req *pb.OpenPortRequest) (*pb.OpenPortResponse, error) {
	rule, err := s.Impl.OpenPort(ctx, int(req.Port), req.Protocol, req.Direction, req.SourceIp, req.Description)
	if err != nil {
		return &pb.OpenPortResponse{Success: false, Error: err.Error()}, nil
	}
	return &pb.OpenPortResponse{
		Success: true,
		Rule:    convertRuleToPB(rule),
	}, nil
}

func (s *firewallGRPCServer) ClosePort(ctx context.Context, req *pb.ClosePortRequest) (*pb.ClosePortResponse, error) {
	err := s.Impl.ClosePort(ctx, int(req.Port), req.Protocol, req.Direction)
	if err != nil {
		return &pb.ClosePortResponse{Success: false, Error: err.Error()}, nil
	}
	return &pb.ClosePortResponse{Success: true}, nil
}

// Helper functions for converting between SDK and protobuf types

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
