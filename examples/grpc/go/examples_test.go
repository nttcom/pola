// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package go_test

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	pb "github.com/nttcom/pola/api/pola/v1"
)

var errFake = errors.New("fake server failure")

// fakeServer records requests and can inject RPC failures.
type fakeServer struct {
	pb.UnimplementedPCEServiceServer

	fail bool

	sessions         []*pb.Session
	srPolicySessions []*pb.SRPolicySession
	ted              *pb.GetTEDResponse

	mu         sync.Mutex
	createReq  *pb.CreateSRPolicyRequest
	deleteReq  *pb.DeleteSRPolicyRequest
	sessionReq *pb.DeleteSessionRequest
}

func (f *fakeServer) CreateSRPolicy(_ context.Context, req *pb.CreateSRPolicyRequest) (*pb.CreateSRPolicyResponse, error) {
	f.mu.Lock()
	f.createReq = req
	f.mu.Unlock()

	if f.fail {
		return nil, errFake
	}

	return &pb.CreateSRPolicyResponse{}, nil
}

func (f *fakeServer) DeleteSRPolicy(_ context.Context, req *pb.DeleteSRPolicyRequest) (*pb.DeleteSRPolicyResponse, error) {
	f.mu.Lock()
	f.deleteReq = req
	f.mu.Unlock()

	if f.fail {
		return nil, errFake
	}

	return &pb.DeleteSRPolicyResponse{}, nil
}

func (f *fakeServer) DeleteSession(_ context.Context, req *pb.DeleteSessionRequest) (*pb.DeleteSessionResponse, error) {
	f.mu.Lock()
	f.sessionReq = req
	f.mu.Unlock()

	if f.fail {
		return nil, errFake
	}

	return &pb.DeleteSessionResponse{}, nil
}

func (f *fakeServer) GetSessionList(_ context.Context, _ *pb.GetSessionListRequest) (*pb.GetSessionListResponse, error) {
	if f.fail {
		return nil, errFake
	}

	return &pb.GetSessionListResponse{Sessions: f.sessions}, nil
}

func (f *fakeServer) GetSRPolicyList(_ context.Context, _ *pb.GetSRPolicyListRequest) (*pb.GetSRPolicyListResponse, error) {
	if f.fail {
		return nil, errFake
	}

	return &pb.GetSRPolicyListResponse{Sessions: f.srPolicySessions}, nil
}

func (f *fakeServer) GetTED(_ context.Context, _ *pb.GetTEDRequest) (*pb.GetTEDResponse, error) {
	if f.fail {
		return nil, errFake
	}

	return f.ted, nil
}

func serve(t *testing.T, f *fakeServer) string {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	s := grpc.NewServer()

	pb.RegisterPCEServiceServer(s, f)
	go func() {
		_ = s.Serve(lis) //nolint:errcheck // expected error when the test server stops.
	}()

	t.Cleanup(s.Stop)

	return lis.Addr().String()
}

const modulePath = "github.com/nttcom/pola/examples/grpc/go"

var (
	binDir string
	covDir string
	// Populated from the tree to detect untested examples.
	exampleDirs []string
)

func TestMain(m *testing.M) {
	_, err := setupAndRun(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1) //nolint:forbidigo // required for TestMain setup failure.
	}
}

func setupAndRun(m *testing.M) (int, error) {
	mains, err := filepath.Glob("*/main.go")
	if err != nil {
		return 0, err
	}

	if len(mains) == 0 {
		return 0, errors.New("no examples found next to this test")
	}

	for _, p := range mains {
		exampleDirs = append(exampleDirs, filepath.Dir(p))
	}

	binDir, err = os.MkdirTemp("", "pola-examples-bin")
	if err != nil {
		return 0, err
	}
	defer func() { _ = os.RemoveAll(binDir) }() //nolint:errcheck // best-effort cleanup.

	if covDir = os.Getenv("EXAMPLES_COVERDIR"); covDir == "" {
		if covDir, err = os.MkdirTemp("", "pola-examples-cov"); err != nil {
			return 0, err
		}
		defer func() { _ = os.RemoveAll(covDir) }() //nolint:errcheck // best-effort cleanup.
	} else if err := os.MkdirAll(covDir, 0o755); err != nil {
		return 0, err
	}

	if err := buildExamples(); err != nil {
		return 0, err
	}

	code := m.Run()
	if code == 0 {
		if err := reportCoverage(); err != nil {
			return 1, err
		}
	}

	return code, nil
}

// reportCoverage verifies that every example is covered.
// The check is skipped when running a subset of tests (-run).
func reportCoverage() error {
	out, err := exec.Command("go", "tool", "covdata", "percent", "-i="+covDir).CombinedOutput()
	if err != nil {
		return fmt.Errorf("go tool covdata: %w\n%s", err, out)
	}

	pcts := map[string]float64{}

	for line := range strings.Lines(string(out)) {
		// e.g. "<pkg> coverage: 92.3% of statements"
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[1] != "coverage:" {
			continue
		}

		if pct, err := strconv.ParseFloat(strings.TrimSuffix(fields[2], "%"), 64); err == nil {
			pcts[fields[0]] = pct
		}
	}

	filtered := flag.Lookup("test.run").Value.String() != ""

	var missing []string

	for _, dir := range exampleDirs {
		pct := pcts[modulePath+"/"+dir]
		fmt.Fprintf(os.Stderr, "coverage: %-34s %5.1f%%\n", dir, pct)

		if pct == 0 && !filtered {
			missing = append(missing, dir)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("no test drives these examples: %s", strings.Join(missing, ", "))
	}

	return nil
}

func buildExamples() error {
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
	for _, dir := range exampleDirs {
		wg.Go(func() {
			pkg := modulePath + "/" + dir

			out, err := exec.Command("go", "build",
				"-cover", "-coverpkg="+pkg,
				"-o", filepath.Join(binDir, dir), pkg).CombinedOutput()
			if err != nil {
				mu.Lock()

				errs = append(errs, fmt.Errorf("build %s: %w\n%s", dir, err, out))
				mu.Unlock()
			}
		})
	}

	wg.Wait()

	return errors.Join(errs...)
}

func run(t *testing.T, name, addr string) (output string, exitCode int) {
	t.Helper()

	cmd := exec.Command(filepath.Join(binDir, name), "-server", addr)

	cmd.Env = append(os.Environ(), "GOCOVERDIR="+covDir)

	out, err := cmd.CombinedOutput()

	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return string(out), 0
	case errors.As(err, &exitErr):
		return string(out), exitErr.ExitCode()
	default:
		t.Fatalf("run %s: %v", name, err)
		return "", 0
	}
}

func wantOutput(t *testing.T, out string, code int, want ...string) {
	t.Helper()

	assert.Equal(t, 0, code, "output:\n%s", out)

	for _, w := range want {
		assert.Contains(t, out, w)
	}
}

func wantFailure(t *testing.T, out string, code int, wantPrefix string) {
	t.Helper()

	assert.NotEqual(t, 0, code, "output:\n%s", out)
	assert.Contains(t, out, wantPrefix)
	assert.Contains(t, out, errFake.Error(), "output does not surface the server error")
}

func addrBytes(t *testing.T, s string) []byte {
	t.Helper()

	ip := net.ParseIP(s)
	require.NotNil(t, ip, "bad test address %q", s)

	if v4 := ip.To4(); v4 != nil {
		return v4
	}

	return ip
}

// grpc.NewClient resolves targets lazily, so "%%" is rejected immediately,
// exercising the dial-time failure path.
func TestInvalidServerAddress(t *testing.T) {
	t.Parallel()

	for _, dir := range exampleDirs {
		t.Run(dir, func(t *testing.T) {
			t.Parallel()

			out, code := run(t, dir, "%%")
			assert.NotEqual(t, 0, code, "output:\n%s", out)
			assert.Contains(t, out, "unable to connect to %%")
		})
	}
}

func TestSRPolicyCreateDynamic(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		f := &fakeServer{}
		out, code := run(t, "sr-policy-create-dynamic", serve(t, f))
		wantOutput(t, out, code, "success")

		req := f.createReq
		require.NotNil(t, req, "server received no request")
		// Dynamic policies require TED-based path computation.
		assert.False(t, req.GetDisablePathCompute())
		assert.Equal(t, pb.SRPolicyType_SR_POLICY_TYPE_DYNAMIC, req.GetSrPolicy().GetType())
		assert.NotZero(t, req.GetAsn(), "want the TED ASN")
		assert.NotEmpty(t, req.GetSrPolicy().GetSrcRouterId())
		assert.Len(t, req.GetSrPolicy().GetWaypoints(), 1)
		assert.Equal(t, pb.MetricType_METRIC_TYPE_TE, req.GetSrPolicy().GetMetric())
		assert.False(t, req.GetNoSidValidate())
	})

	t.Run("rpc error", func(t *testing.T) {
		t.Parallel()

		out, code := run(t, "sr-policy-create-dynamic", serve(t, &fakeServer{fail: true}))
		wantFailure(t, out, code, "c.CreateSRPolicy error")
	})
}

func TestSRPolicyCreateExplicit(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		f := &fakeServer{}
		out, code := run(t, "sr-policy-create-explicit", serve(t, f))
		wantOutput(t, out, code, "success")

		req := f.createReq
		require.NotNil(t, req, "server received no request")
		assert.False(t, req.GetDisablePathCompute())
		assert.Equal(t, pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT, req.GetSrPolicy().GetType())
		assert.NotEmpty(t, req.GetSrPolicy().GetSegmentList())
		assert.False(t, req.GetNoSidValidate())
	})

	t.Run("rpc error", func(t *testing.T) {
		t.Parallel()

		out, code := run(t, "sr-policy-create-explicit", serve(t, &fakeServer{fail: true}))
		wantFailure(t, out, code, "c.CreateSRPolicy error")
	})
}

func TestSRPolicyCreateNoSIDValidate(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		f := &fakeServer{}
		out, code := run(t, "sr-policy-create-no-sid-validate", serve(t, f))
		wantOutput(t, out, code, "success")

		req := f.createReq
		require.NotNil(t, req, "server received no request")
		assert.True(t, req.GetDisablePathCompute())
		assert.Equal(t, pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT, req.GetSrPolicy().GetType())
		assert.NotEmpty(t, req.GetSrPolicy().GetSrcAddr())
		assert.NotEmpty(t, req.GetSrPolicy().GetDstAddr())
		assert.NotEmpty(t, req.GetSrPolicy().GetSegmentList())
		assert.True(t, req.GetNoSidValidate())
	})

	t.Run("rpc error", func(t *testing.T) {
		t.Parallel()

		out, code := run(t, "sr-policy-create-no-sid-validate", serve(t, &fakeServer{fail: true}))
		wantFailure(t, out, code, "c.CreateSRPolicy error")
	})
}

func TestSRPolicyCreateSRv6(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		f := &fakeServer{}
		out, code := run(t, "sr-policy-create-srv6", serve(t, f))
		wantOutput(t, out, code, "success")

		req := f.createReq
		require.NotNil(t, req, "server received no request")
		// SRv6 segments require LocalAddr and SidStructure.
		for _, seg := range req.GetSrPolicy().GetSegmentList() {
			assert.NotEmpty(t, seg.GetLocalAddr(), "segment %s", seg.GetSid())
			assert.NotEmpty(t, seg.GetSidStructure(), "segment %s", seg.GetSid())
		}

		assert.True(t, req.GetNoSidValidate())
	})

	t.Run("rpc error", func(t *testing.T) {
		t.Parallel()

		out, code := run(t, "sr-policy-create-srv6", serve(t, &fakeServer{fail: true}))
		wantFailure(t, out, code, "c.CreateSRPolicy error")
	})
}

func TestSRPolicyDelete(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		f := &fakeServer{}
		out, code := run(t, "sr-policy-delete", serve(t, f))
		wantOutput(t, out, code, "success")

		req := f.deleteReq
		require.NotNil(t, req, "server received no request")
		// polad identifies the policy by these four fields, so all must be set.
		assert.NotEmpty(t, req.GetSrPolicy().GetPeerAddr())
		assert.NotEmpty(t, req.GetSrPolicy().GetDstAddr())
		assert.NotZero(t, req.GetSrPolicy().GetColor())
		assert.NotEmpty(t, req.GetSrPolicy().GetPolicyName())
	})

	t.Run("rpc error", func(t *testing.T) {
		t.Parallel()

		out, code := run(t, "sr-policy-delete", serve(t, &fakeServer{fail: true}))
		wantFailure(t, out, code, "c.DeleteSRPolicy error")
	})
}

func TestSessionDelete(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		f := &fakeServer{}
		out, code := run(t, "session-delete", serve(t, f))
		wantOutput(t, out, code, "success")

		require.NotNil(t, f.sessionReq, "server received no request")
		assert.Equal(t, addrBytes(t, "192.0.2.1"), f.sessionReq.GetPeerAddr())
	})

	t.Run("rpc error", func(t *testing.T) {
		t.Parallel()

		out, code := run(t, "session-delete", serve(t, &fakeServer{fail: true}))
		wantFailure(t, out, code, "c.DeleteSession error")
	})
}

func TestSessionList(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		f := &fakeServer{sessions: []*pb.Session{
			{
				PeerAddr: addrBytes(t, "192.0.2.1"),
				State:    pb.SessionState_SESSION_STATE_UP,
				LocalCapabilities: []*pb.Capability{
					{Type: pb.CapabilityType_CAPABILITY_TYPE_STATEFUL},
					{Type: pb.CapabilityType_CAPABILITY_TYPE_SR, Detail: &pb.Capability_Sr{Sr: &pb.SrCapability{Msd: proto.Uint32(10)}}},
				},
				SyncState: pb.LspDbSyncState_LSP_DB_SYNC_STATE_FINISHED,
			},
			// Invalid peer address: the example should warn and skip the session.
			{PeerAddr: []byte{1, 2, 3}},
		}}
		out, code := run(t, "session-list", serve(t, f))
		wantOutput(t, out, code,
			"peerAddr(0): 192.0.2.1",
			"state: SESSION_STATE_UP",
			"capabilities (Pola): STATEFUL, SR(msd=10, unlimitedMsd=false, naiSupported=false)",
			"syncState: FINISHED",
			"invalid address for session 1",
		)
		assert.NotContains(t, out, "peerAddr(1)", "the invalid session was printed anyway")
	})

	t.Run("rpc error", func(t *testing.T) {
		t.Parallel()

		out, code := run(t, "session-list", serve(t, &fakeServer{fail: true}))
		wantFailure(t, out, code, "unable to get session list from server")
	})
}

func TestSRPolicyList(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		f := &fakeServer{srPolicySessions: []*pb.SRPolicySession{
			{
				PeerAddr: addrBytes(t, "192.0.2.1"),
				SrPolicies: []*pb.SRPolicy{{
					SrcAddr:     addrBytes(t, "192.0.2.1"),
					DstAddr:     addrBytes(t, "192.0.2.2"),
					PolicyName:  "with-segments",
					Color:       100,
					Preference:  200,
					SegmentList: []*pb.Segment{{Sid: "16002"}, {Sid: "16003"}},
				}},
			},
			{
				PeerAddr: []byte{1, 2, 3},
				SrPolicies: []*pb.SRPolicy{{
					PolicyName: "no-segments",
				}},
			},
		}}
		out, code := run(t, "sr-policy-list", serve(t, f))
		wantOutput(t, out, code,
			"srPolicy(0):",
			"policyName: with-segments",
			"srcAddr: 192.0.2.1",
			"dstAddr: 192.0.2.2",
			"color: 100",
			"preference: 200",
			"path: 16002 -> 16003",
			"srPolicy(1):",
			"peerAddr: invalid",
			"path: None",
		)
	})

	t.Run("rpc error", func(t *testing.T) {
		t.Parallel()

		out, code := run(t, "sr-policy-list", serve(t, &fakeServer{fail: true}))
		wantFailure(t, out, code, "unable to get SR policy list from server")
	})
}

func TestTEDGet(t *testing.T) {
	t.Parallel()

	t.Run("enabled", func(t *testing.T) {
		t.Parallel()

		f := &fakeServer{ted: &pb.GetTEDResponse{
			Enabled: true,
			Nodes: []*pb.LsNode{{
				Asn:      65000,
				RouterId: "0000.0aff.0001",
				Hostname: "node1",
				Prefixes: []*pb.LsPrefix{{Prefix: "10.0.0.1/32"}},
				Links:    []*pb.LsLink{{LocalRouterId: "0000.0aff.0001"}},
			}},
		}}
		out, code := run(t, "ted-get", serve(t, f))
		// protojson may vary whitespace, so match only stable values.
		wantOutput(t, out, code, "routerId", "0000.0aff.0001", "node1", "10.0.0.1/32")
	})

	t.Run("disabled", func(t *testing.T) {
		t.Parallel()

		f := &fakeServer{ted: &pb.GetTEDResponse{Enabled: false}}
		out, code := run(t, "ted-get", serve(t, f))
		wantOutput(t, out, code, "TED is disabled")
	})

	t.Run("rpc error", func(t *testing.T) {
		t.Parallel()

		out, code := run(t, "ted-get", serve(t, &fakeServer{fail: true}))
		wantFailure(t, out, code, "unable to get TED info")
	})
}
