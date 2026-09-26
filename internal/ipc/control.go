package ipc

import (
	"context"
	"errors"
	"time"

	pb "github.com/afterdarksys/afterdark-darkd/api/proto/ipc"
	"github.com/afterdarksys/afterdark-darkd/internal/control"
	"github.com/afterdarksys/afterdark-darkd/internal/events"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// controlPeerUID is the only local peer uid allowed to present a control
// token. Tests substitute their own uid to reach the token checks.
var controlPeerUID uint32 = 0

const controlEventSource = "control"

// controlServer implements ControlService. It is separate from Server because
// Server.Stop already names the IPC lifecycle method.
type controlServer struct {
	pb.UnimplementedControlServiceServer
	s *Server
}

// Stop verifies a signed token and opens the maintenance window. Every step
// fails closed: the bearer token and allowlisted uid are checked by the
// interceptors, then this requires a uid 0 Unix peer, then the token.
func (c *controlServer) Stop(ctx context.Context, req *pb.ControlStopRequest) (*pb.ControlStopResponse, error) {
	s := c.s
	uid, err := controlPeer(ctx)
	if err != nil {
		s.journalControlDenied(-1, err)
		return nil, err
	}
	ctl := s.config.Control
	if ctl == nil {
		err := status.Error(codes.FailedPrecondition, control.ErrNoKeys.Error())
		s.journalControlDenied(int64(uid), err)
		return nil, err
	}
	grant, err := ctl.Authorize(req.GetToken(), func(g control.Grant) error {
		return events.Emit(s.registry, controlEventSource, "agent.control", "warning", controlPayload(g, int64(uid), "accepted", ""))
	})
	if err != nil {
		s.logger.Warn("control token rejected", zap.Uint32("peer_uid", uid), zap.Error(err))
		s.journalControlDenied(int64(uid), err)
		if errors.Is(err, control.ErrNoKeys) {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
		return nil, status.Error(codes.PermissionDenied, "control token rejected: "+err.Error())
	}
	s.logger.Warn("control token accepted; maintenance window open",
		zap.String("action", grant.Action),
		zap.String("key_fingerprint", grant.KeyFingerprint),
		zap.String("nonce_sha256", grant.NonceHash),
		zap.Duration("window", grant.Window),
	)
	message := "maintenance window open; darkd may be unloaded and replaced"
	if grant.Action == control.ActionStop {
		message = "maintenance window open; darkd is shutting down"
		if s.config.OnControlStop != nil {
			go s.config.OnControlStop()
		}
	}
	return &pb.ControlStopResponse{
		Action:         grant.Action,
		KeyFingerprint: grant.KeyFingerprint,
		WindowSeconds:  int64(grant.Window / time.Second),
		Message:        message,
	}, nil
}

// controlPeer requires a Unix socket peer whose uid is controlPeerUID. TCP and
// named-pipe connections carry no peer uid and are rejected.
func controlPeer(ctx context.Context) (uint32, error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return 0, status.Error(codes.PermissionDenied, "control requires a local Unix socket peer")
	}
	info, ok := p.AuthInfo.(*localAuthInfo)
	if !ok {
		return 0, status.Error(codes.PermissionDenied, "control requires a local Unix socket peer")
	}
	if info.UID != controlPeerUID {
		return info.UID, status.Error(codes.PermissionDenied, "control requires a root (uid 0) peer")
	}
	return info.UID, nil
}

func controlPayload(g control.Grant, uid int64, outcome, reason string) map[string]interface{} {
	facts := map[string]interface{}{
		"control.outcome":  outcome,
		"control.peer_uid": uid,
	}
	if g.Action != "" {
		facts["control.action"] = g.Action
		facts["control.key_fingerprint"] = g.KeyFingerprint
		facts["control.nonce_sha256"] = g.NonceHash
		facts["control.not_after"] = g.NotAfter.Format(time.RFC3339)
		facts["control.window_seconds"] = int64(g.Window / time.Second)
	}
	if reason != "" {
		facts["control.reason"] = reason
	}
	return map[string]interface{}{"collection_status": "observed", "facts": facts}
}

// journalControlDenied records a rejected attempt. The token is never
// included; a journal failure is logged because the request is already denied.
func (s *Server) journalControlDenied(uid int64, cause error) {
	if err := events.Emit(s.registry, controlEventSource, "agent.control", "warning", controlPayload(control.Grant{}, uid, "denied", cause.Error())); err != nil {
		s.logger.Warn("control denial was not journaled", zap.Error(err))
	}
}

// NewControlClientWithToken dials the daemon's ControlService.
func NewControlClientWithToken(ctx context.Context, socketPath, token string) (pb.ControlServiceClient, error) {
	conn, err := DialWithToken(ctx, socketPath, token)
	if err != nil {
		return nil, err
	}
	return pb.NewControlServiceClient(conn), nil
}
