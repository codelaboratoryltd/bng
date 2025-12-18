package radius_test

import (
	"context"
	"net"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/codelaboratoryltd/bng/pkg/radius"
	"go.uber.org/zap"
)

func TestRADIUSCoA(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "RADIUS CoA Suite")
}

var _ = Describe("RADIUS CoA Server", func() {
	var (
		logger *zap.Logger
	)

	BeforeEach(func() {
		logger = zap.NewNop()
	})

	Describe("NewCoAServer", func() {
		Context("when creating a CoA server with valid config", func() {
			It("should create successfully", func() {
				cfg := radius.CoAServerConfig{
					Address: ":3799",
					Secret:  "testing123",
				}

				server, err := radius.NewCoAServer(cfg, logger)

				Expect(err).NotTo(HaveOccurred())
				Expect(server).NotTo(BeNil())
			})

			It("should use default port when address is empty", func() {
				cfg := radius.CoAServerConfig{
					Secret: "testing123",
				}

				server, err := radius.NewCoAServer(cfg, logger)

				Expect(err).NotTo(HaveOccurred())
				Expect(server).NotTo(BeNil())
			})
		})

		Context("when creating a CoA server with invalid config", func() {
			It("should return error when secret is empty", func() {
				cfg := radius.CoAServerConfig{
					Address: ":3799",
					Secret:  "",
				}

				server, err := radius.NewCoAServer(cfg, logger)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("secret required"))
				Expect(server).To(BeNil())
			})
		})
	})

	Describe("CoA Request Handling", func() {
		var (
			server *radius.CoAServer
			cancel context.CancelFunc
		)

		BeforeEach(func() {
			cfg := radius.CoAServerConfig{
				Address: "127.0.0.1:0", // Random available port
				Secret:  "testing123",
			}
			var err error
			server, err = radius.NewCoAServer(cfg, logger)
			Expect(err).NotTo(HaveOccurred())

			_, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		})

		AfterEach(func() {
			cancel()
			if server != nil {
				server.Stop()
			}
		})

		Context("when setting handlers", func() {
			It("should accept CoA handler", func() {
				handler := func(ctx context.Context, req *radius.CoARequest) *radius.CoAResponse {
					_ = ctx // Use ctx to avoid unused warning
					_ = req
					return &radius.CoAResponse{Success: true}
				}

				Expect(func() {
					server.SetCoAHandler(handler)
				}).NotTo(Panic())
			})

			It("should accept Disconnect handler", func() {
				handler := func(ctx context.Context, req *radius.DisconnectRequest) *radius.DisconnectResponse {
					_ = ctx // Use ctx to avoid unused warning
					_ = req
					return &radius.DisconnectResponse{Success: true}
				}

				Expect(func() {
					server.SetDisconnectHandler(handler)
				}).NotTo(Panic())
			})

			It("should accept session lookup function", func() {
				lookup := func(sessionID string) bool {
					return sessionID == "valid-session"
				}

				Expect(func() {
					server.SetSessionLookup(lookup)
				}).NotTo(Panic())
			})
		})

		Context("when getting statistics", func() {
			It("should return initial zero statistics", func() {
				stats := server.GetStats()

				Expect(stats["coa_requests_received"]).To(Equal(uint64(0)))
				Expect(stats["coa_acks_sent"]).To(Equal(uint64(0)))
				Expect(stats["coa_naks_sent"]).To(Equal(uint64(0)))
				Expect(stats["disconnect_requests_received"]).To(Equal(uint64(0)))
				Expect(stats["disconnect_acks_sent"]).To(Equal(uint64(0)))
				Expect(stats["disconnect_naks_sent"]).To(Equal(uint64(0)))
			})
		})
	})

	Describe("CoARequest", func() {
		Context("when examining request fields", func() {
			It("should have all expected fields", func() {
				req := &radius.CoARequest{
					SessionID:      "session-123",
					Username:       "user@example.com",
					NASIPAddress:   net.ParseIP("192.168.1.1"),
					FramedIP:       net.ParseIP("10.0.1.100"),
					CallingStation: "AA:BB:CC:DD:EE:FF",
					FramedPool:     "pool-1",
					SessionTimeout: 3600,
					IdleTimeout:    300,
					FilterID:       "gold-plan",
					QoSDownload:    100000,
					QoSUpload:      50000,
				}

				Expect(req.SessionID).To(Equal("session-123"))
				Expect(req.Username).To(Equal("user@example.com"))
				Expect(req.NASIPAddress.String()).To(Equal("192.168.1.1"))
				Expect(req.FramedIP.String()).To(Equal("10.0.1.100"))
				Expect(req.CallingStation).To(Equal("AA:BB:CC:DD:EE:FF"))
				Expect(req.FramedPool).To(Equal("pool-1"))
				Expect(req.SessionTimeout).To(Equal(uint32(3600)))
				Expect(req.IdleTimeout).To(Equal(uint32(300)))
				Expect(req.FilterID).To(Equal("gold-plan"))
				Expect(req.QoSDownload).To(Equal(uint32(100000)))
				Expect(req.QoSUpload).To(Equal(uint32(50000)))
			})
		})
	})

	Describe("CoAResponse", func() {
		Context("when creating responses", func() {
			It("should create success response", func() {
				resp := &radius.CoAResponse{
					Success: true,
					Message: "OK",
				}

				Expect(resp.Success).To(BeTrue())
				Expect(resp.ErrorCause).To(Equal(uint32(0)))
			})

			It("should create failure response with error cause", func() {
				resp := &radius.CoAResponse{
					Success:    false,
					ErrorCause: radius.ErrorCauseSessionContextNotFound,
					Message:    "Session not found",
				}

				Expect(resp.Success).To(BeFalse())
				Expect(resp.ErrorCause).To(Equal(uint32(radius.ErrorCauseSessionContextNotFound)))
			})
		})
	})

	Describe("DisconnectRequest", func() {
		Context("when examining request fields", func() {
			It("should have all expected fields", func() {
				req := &radius.DisconnectRequest{
					SessionID:      "session-456",
					Username:       "disconnect-user",
					NASIPAddress:   net.ParseIP("192.168.1.2"),
					FramedIP:       net.ParseIP("10.0.2.100"),
					CallingStation: "11:22:33:44:55:66",
					AcctSessionID:  "acct-session-789",
				}

				Expect(req.SessionID).To(Equal("session-456"))
				Expect(req.AcctSessionID).To(Equal("acct-session-789"))
			})
		})
	})

	Describe("DisconnectResponse", func() {
		Context("when creating responses", func() {
			It("should create success response", func() {
				resp := &radius.DisconnectResponse{
					Success: true,
					Message: "Disconnected",
				}

				Expect(resp.Success).To(BeTrue())
			})

			It("should create failure response", func() {
				resp := &radius.DisconnectResponse{
					Success:    false,
					ErrorCause: radius.ErrorCauseSessionContextNotRemovable,
					Message:    "Cannot remove session",
				}

				Expect(resp.Success).To(BeFalse())
				Expect(resp.ErrorCause).To(Equal(uint32(radius.ErrorCauseSessionContextNotRemovable)))
			})
		})
	})

	Describe("Error Cause Constants", func() {
		DescribeTable("should have correct values",
			func(constant uint32, expected uint32) {
				Expect(constant).To(Equal(expected))
			},
			Entry("ResidualSessionContextRemoved", uint32(radius.ErrorCauseResidualSessionContextRemoved), uint32(201)),
			Entry("MissingAttribute", uint32(radius.ErrorCauseMissingAttribute), uint32(402)),
			Entry("NASIdentificationMismatch", uint32(radius.ErrorCauseNASIdentificationMismatch), uint32(403)),
			Entry("InvalidRequest", uint32(radius.ErrorCauseInvalidRequest), uint32(404)),
			Entry("UnsupportedService", uint32(radius.ErrorCauseUnsupportedService), uint32(405)),
			Entry("AdministrativelyProhibited", uint32(radius.ErrorCauseAdministrativelyProhibited), uint32(501)),
			Entry("SessionContextNotFound", uint32(radius.ErrorCauseSessionContextNotFound), uint32(503)),
			Entry("SessionContextNotRemovable", uint32(radius.ErrorCauseSessionContextNotRemovable), uint32(504)),
			Entry("ResourcesUnavailable", uint32(radius.ErrorCauseResourcesUnavailable), uint32(506)),
		)
	})

	Describe("RADIUS Attribute Constants", func() {
		DescribeTable("should have correct RFC 2865 values",
			func(constant uint8, expected uint8) {
				Expect(constant).To(Equal(expected))
			},
			Entry("User-Name", uint8(radius.AttrUserName), uint8(1)),
			Entry("User-Password", uint8(radius.AttrUserPassword), uint8(2)),
			Entry("NAS-IP-Address", uint8(radius.AttrNASIPAddress), uint8(4)),
			Entry("NAS-Port", uint8(radius.AttrNASPort), uint8(5)),
			Entry("Framed-IP-Address", uint8(radius.AttrFramedIPAddress), uint8(8)),
			Entry("Filter-Id", uint8(radius.AttrFilterID), uint8(11)),
			Entry("Session-Timeout", uint8(radius.AttrSessionTimeout), uint8(27)),
			Entry("Idle-Timeout", uint8(radius.AttrIdleTimeout), uint8(28)),
			Entry("Calling-Station-Id", uint8(radius.AttrCallingStationID), uint8(31)),
			Entry("Acct-Session-Id", uint8(radius.AttrAcctSessionID), uint8(44)),
		)
	})

	Describe("Attribute", func() {
		It("should hold type and value", func() {
			attr := radius.Attribute{
				Type:  radius.AttrUserName,
				Value: []byte("testuser"),
			}

			Expect(attr.Type).To(Equal(uint8(radius.AttrUserName)))
			Expect(string(attr.Value)).To(Equal("testuser"))
		})
	})
})
