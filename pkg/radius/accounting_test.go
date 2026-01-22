package radius_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/codelaboratoryltd/bng/pkg/radius"
	"go.uber.org/zap"
)

// Note: TestRADIUSCoA in coa_test.go serves as the test runner for all RADIUS tests

var _ = Describe("RADIUS Accounting Manager", func() {
	var (
		tempDir string
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "bng-accounting-test")
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		os.RemoveAll(tempDir)
	})

	Describe("AccountingConfig", func() {
		Context("DefaultAccountingConfig", func() {
			It("should return sensible defaults", func() {
				cfg := radius.DefaultAccountingConfig()

				Expect(cfg.DefaultInterimInterval).To(Equal(5 * time.Minute))
				Expect(cfg.InterimEnabled).To(BeTrue())
				Expect(cfg.BatchSize).To(Equal(100))
				Expect(cfg.MaxRetries).To(Equal(10))
				Expect(cfg.RetryBaseDelay).To(Equal(1 * time.Second))
				Expect(cfg.RetryMaxDelay).To(Equal(60 * time.Second))
				Expect(cfg.QueueSize).To(Equal(10000))
				Expect(cfg.ShutdownTimeout).To(Equal(30 * time.Second))
				Expect(cfg.DrainOnShutdown).To(BeTrue())
			})
		})
	})

	Describe("AccountingSession", func() {
		It("should hold all expected fields", func() {
			mac, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
			session := &radius.AccountingSession{
				SessionID:       "session-123",
				Username:        "user@example.com",
				MAC:             mac,
				FramedIP:        net.ParseIP("10.0.1.100"),
				NASPort:         1001,
				CircuitID:       "circuit-1",
				RemoteID:        "nte-001",
				Class:           []byte("class-data"),
				InterimInterval: 5 * time.Minute,
				StartTime:       time.Now(),
				LastInterimTime: time.Now(),
			}

			Expect(session.SessionID).To(Equal("session-123"))
			Expect(session.Username).To(Equal("user@example.com"))
			Expect(session.MAC.String()).To(Equal("aa:bb:cc:dd:ee:ff"))
			Expect(session.FramedIP.String()).To(Equal("10.0.1.100"))
			Expect(session.NASPort).To(Equal(uint32(1001)))
			Expect(session.CircuitID).To(Equal("circuit-1"))
			Expect(session.RemoteID).To(Equal("nte-001"))
			Expect(session.Class).To(Equal([]byte("class-data")))
			Expect(session.InterimInterval).To(Equal(5 * time.Minute))
		})
	})

	Describe("SessionCounters", func() {
		It("should hold traffic counters", func() {
			counters := &radius.SessionCounters{
				InputOctets:   1000000,
				OutputOctets:  2000000,
				InputPackets:  1000,
				OutputPackets: 2000,
			}

			Expect(counters.InputOctets).To(Equal(uint64(1000000)))
			Expect(counters.OutputOctets).To(Equal(uint64(2000000)))
			Expect(counters.InputPackets).To(Equal(uint64(1000)))
			Expect(counters.OutputPackets).To(Equal(uint64(2000)))
		})
	})

	Describe("AccountingStats", func() {
		It("should hold all statistics fields", func() {
			stats := radius.AccountingStats{
				ActiveSessions:    100,
				InterimTotal:      5000,
				InterimFailed:     10,
				StopTotal:         4500,
				StopFailed:        5,
				StopAbandoned:     2,
				StopRetries:       15,
				OrphanedRecovered: 3,
				PendingQueueDepth: 0,
			}

			Expect(stats.ActiveSessions).To(Equal(100))
			Expect(stats.InterimTotal).To(Equal(uint64(5000)))
			Expect(stats.InterimFailed).To(Equal(uint64(10)))
			Expect(stats.StopTotal).To(Equal(uint64(4500)))
			Expect(stats.StopFailed).To(Equal(uint64(5)))
			Expect(stats.StopAbandoned).To(Equal(uint64(2)))
			Expect(stats.StopRetries).To(Equal(uint64(15)))
			Expect(stats.OrphanedRecovered).To(Equal(uint64(3)))
			Expect(stats.PendingQueueDepth).To(Equal(uint64(0)))
		})
	})

	Describe("PendingAcctRecord", func() {
		It("should track retry state", func() {
			mac, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
			record := &radius.PendingAcctRecord{
				ID: "record-123",
				Request: &radius.AcctRequest{
					SessionID:  "session-456",
					Username:   "user@test.com",
					MAC:        mac,
					StatusType: radius.AcctStatusStop,
				},
				CreatedAt:  time.Now(),
				RetryCount: 3,
				NextRetry:  time.Now().Add(8 * time.Second), // exponential backoff
				LastError:  "connection refused",
			}

			Expect(record.ID).To(Equal("record-123"))
			Expect(record.Request.SessionID).To(Equal("session-456"))
			Expect(record.RetryCount).To(Equal(3))
			Expect(record.LastError).To(Equal("connection refused"))
		})
	})

	Describe("Terminate Cause Constants", func() {
		It("should have correct RFC 2866 values", func() {
			Expect(radius.TerminateCauseUserRequest).To(Equal(1))
			Expect(radius.TerminateCauseLostCarrier).To(Equal(2))
			Expect(radius.TerminateCauseIdleTimeout).To(Equal(4))
			Expect(radius.TerminateCauseSessionTimeout).To(Equal(5))
			Expect(radius.TerminateCauseAdminReset).To(Equal(6))
			Expect(radius.TerminateCauseAdminReboot).To(Equal(7))
			Expect(radius.TerminateCauseNASError).To(Equal(9))
			Expect(radius.TerminateCauseNASRequest).To(Equal(10))
			Expect(radius.TerminateCauseNASReboot).To(Equal(11))
		})
	})

	Describe("Acct Status Type Constants", func() {
		DescribeTable("should have correct RFC 2866 values",
			func(constant radius.AcctStatusType, expected uint32) {
				Expect(uint32(constant)).To(Equal(expected))
			},
			Entry("Start", radius.AcctStatusStart, uint32(1)),
			Entry("Stop", radius.AcctStatusStop, uint32(2)),
			Entry("Interim-Update", radius.AcctStatusInterimUpdate, uint32(3)),
			Entry("Accounting-On", radius.AcctStatusAccountingOn, uint32(7)),
			Entry("Accounting-Off", radius.AcctStatusAccountingOff, uint32(8)),
		)
	})
})

var _ = Describe("RADIUS Accounting Manager Integration", func() {
	var (
		tempDir string
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "bng-accounting-test")
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		os.RemoveAll(tempDir)
	})

	// Note: Full integration tests with actual RADIUS server would go here
	// These would require mocking the RADIUS client or using a test server

	Describe("Persistence Directory", func() {
		It("should create persistence directory structure", func() {
			sessionsDir := filepath.Join(tempDir, "sessions")
			err := os.MkdirAll(sessionsDir, 0755)
			Expect(err).NotTo(HaveOccurred())

			// Verify directory exists
			info, err := os.Stat(sessionsDir)
			Expect(err).NotTo(HaveOccurred())
			Expect(info.IsDir()).To(BeTrue())
		})
	})
})

var _ = Describe("RADIUS CoA Processor", func() {
	var (
		logger    *zap.Logger
		processor *radius.CoAProcessor
	)

	BeforeEach(func() {
		logger = zap.NewNop()
		processor = radius.NewCoAProcessor(logger)
	})

	Describe("NewCoAProcessor", func() {
		It("should create a processor successfully", func() {
			Expect(processor).NotTo(BeNil())
		})
	})

	Describe("Session Lookup Configuration", func() {
		It("should accept session lookup by ID", func() {
			lookup := func(sessionID string) (*radius.SessionInfo, bool) {
				if sessionID == "test-session" {
					return &radius.SessionInfo{
						SessionID: sessionID,
						Username:  "testuser",
					}, true
				}
				return nil, false
			}

			Expect(func() {
				processor.SetSessionLookup(lookup)
			}).NotTo(Panic())
		})

		It("should accept session lookup by IP", func() {
			lookup := func(ip net.IP) (*radius.SessionInfo, bool) {
				if ip.Equal(net.ParseIP("10.0.1.100")) {
					return &radius.SessionInfo{
						SessionID: "session-by-ip",
						FramedIP:  ip,
					}, true
				}
				return nil, false
			}

			Expect(func() {
				processor.SetSessionLookupByIP(lookup)
			}).NotTo(Panic())
		})

		It("should accept session lookup by MAC", func() {
			lookup := func(mac string) (*radius.SessionInfo, bool) {
				if mac == "AA:BB:CC:DD:EE:FF" {
					return &radius.SessionInfo{
						SessionID: "session-by-mac",
					}, true
				}
				return nil, false
			}

			Expect(func() {
				processor.SetSessionLookupByMAC(lookup)
			}).NotTo(Panic())
		})
	})

	Describe("Handler Configuration", func() {
		It("should accept session terminator", func() {
			terminator := func(ctx context.Context, sessionID string, reason uint32) error {
				_ = ctx
				_ = sessionID
				_ = reason
				return nil
			}

			Expect(func() {
				processor.SetSessionTerminator(terminator)
			}).NotTo(Panic())
		})

		It("should accept session policy updater", func() {
			updater := func(ctx context.Context, sessionID string, update *radius.PolicyUpdate) error {
				_ = ctx
				_ = sessionID
				_ = update
				return nil
			}

			Expect(func() {
				processor.SetSessionPolicyUpdater(updater)
			}).NotTo(Panic())
		})

		It("should accept eBPF QoS updater", func() {
			updater := func(sessionID string, downloadBPS, uploadBPS uint64) error {
				_ = sessionID
				_ = downloadBPS
				_ = uploadBPS
				return nil
			}

			Expect(func() {
				processor.SetEBPFQoSUpdater(updater)
			}).NotTo(Panic())
		})

		It("should accept audit logger", func() {
			auditLogger := radius.NewDefaultAuditLogger(logger)

			Expect(func() {
				processor.SetAuditLogger(auditLogger)
			}).NotTo(Panic())
		})
	})

	Describe("HandleCoA", func() {
		BeforeEach(func() {
			// Set up a session lookup that finds sessions
			processor.SetSessionLookup(func(sessionID string) (*radius.SessionInfo, bool) {
				if sessionID == "existing-session" {
					return &radius.SessionInfo{
						SessionID:       sessionID,
						Username:        "testuser",
						FramedIP:        net.ParseIP("10.0.1.100"),
						DownloadRateBPS: 100_000_000,
						UploadRateBPS:   50_000_000,
					}, true
				}
				return nil, false
			})

			// Set up policy updater
			processor.SetSessionPolicyUpdater(func(ctx context.Context, sessionID string, update *radius.PolicyUpdate) error {
				_ = ctx
				_ = sessionID
				_ = update
				return nil
			})
		})

		Context("when session is found and policy is valid", func() {
			It("should return success for filter ID change", func() {
				req := &radius.CoARequest{
					SessionID: "existing-session",
					FilterID:  "gold-plan",
				}

				resp := processor.HandleCoA(context.Background(), req)

				Expect(resp.Success).To(BeTrue())
				Expect(resp.ErrorCause).To(Equal(uint32(0)))
			})

			It("should return success for QoS change", func() {
				req := &radius.CoARequest{
					SessionID:   "existing-session",
					QoSDownload: 200000, // 200 Mbps in kbps
					QoSUpload:   100000, // 100 Mbps in kbps
				}

				resp := processor.HandleCoA(context.Background(), req)

				Expect(resp.Success).To(BeTrue())
			})

			It("should return success for timeout change", func() {
				req := &radius.CoARequest{
					SessionID:      "existing-session",
					SessionTimeout: 7200, // 2 hours
					IdleTimeout:    600,  // 10 minutes
				}

				resp := processor.HandleCoA(context.Background(), req)

				Expect(resp.Success).To(BeTrue())
			})
		})

		Context("when session is not found", func() {
			It("should return session not found error", func() {
				req := &radius.CoARequest{
					SessionID: "non-existent-session",
					FilterID:  "gold-plan",
				}

				resp := processor.HandleCoA(context.Background(), req)

				Expect(resp.Success).To(BeFalse())
				Expect(resp.ErrorCause).To(Equal(uint32(radius.ErrorCauseSessionContextNotFound)))
			})
		})

		Context("when no policy changes specified", func() {
			It("should return missing attribute error", func() {
				req := &radius.CoARequest{
					SessionID: "existing-session",
					// No policy changes
				}

				resp := processor.HandleCoA(context.Background(), req)

				Expect(resp.Success).To(BeFalse())
				Expect(resp.ErrorCause).To(Equal(uint32(radius.ErrorCauseMissingAttribute)))
			})
		})
	})

	Describe("HandleDisconnect", func() {
		BeforeEach(func() {
			// Set up a session lookup
			processor.SetSessionLookup(func(sessionID string) (*radius.SessionInfo, bool) {
				if sessionID == "existing-session" {
					return &radius.SessionInfo{
						SessionID: sessionID,
						Username:  "testuser",
						FramedIP:  net.ParseIP("10.0.1.100"),
					}, true
				}
				return nil, false
			})

			// Set up terminator
			processor.SetSessionTerminator(func(ctx context.Context, sessionID string, reason uint32) error {
				_ = ctx
				_ = sessionID
				_ = reason
				return nil
			})
		})

		Context("when session is found", func() {
			It("should return success", func() {
				req := &radius.DisconnectRequest{
					SessionID: "existing-session",
					Username:  "testuser",
				}

				resp := processor.HandleDisconnect(context.Background(), req)

				Expect(resp.Success).To(BeTrue())
			})
		})

		Context("when session is not found", func() {
			It("should return session not found error", func() {
				req := &radius.DisconnectRequest{
					SessionID: "non-existent-session",
				}

				resp := processor.HandleDisconnect(context.Background(), req)

				Expect(resp.Success).To(BeFalse())
				Expect(resp.ErrorCause).To(Equal(uint32(radius.ErrorCauseSessionContextNotFound)))
			})
		})
	})

	Describe("Statistics", func() {
		BeforeEach(func() {
			processor.SetSessionLookup(func(sessionID string) (*radius.SessionInfo, bool) {
				if sessionID == "existing-session" {
					return &radius.SessionInfo{SessionID: sessionID}, true
				}
				return nil, false
			})
			processor.SetSessionPolicyUpdater(func(ctx context.Context, sessionID string, update *radius.PolicyUpdate) error {
				return nil
			})
			processor.SetSessionTerminator(func(ctx context.Context, sessionID string, reason uint32) error {
				return nil
			})
		})

		It("should track CoA statistics", func() {
			// Process a successful CoA
			req := &radius.CoARequest{
				SessionID: "existing-session",
				FilterID:  "test-policy",
			}
			processor.HandleCoA(context.Background(), req)

			// Process a failed CoA
			req2 := &radius.CoARequest{
				SessionID: "non-existent",
				FilterID:  "test-policy",
			}
			processor.HandleCoA(context.Background(), req2)

			stats := processor.GetStats()
			Expect(stats.CoAProcessed).To(Equal(uint64(2)))
			Expect(stats.CoASucceeded).To(Equal(uint64(1)))
			Expect(stats.CoAFailed).To(Equal(uint64(1)))
		})

		It("should track Disconnect statistics", func() {
			// Process a successful disconnect
			req := &radius.DisconnectRequest{
				SessionID: "existing-session",
			}
			processor.HandleDisconnect(context.Background(), req)

			// Process a failed disconnect
			req2 := &radius.DisconnectRequest{
				SessionID: "non-existent",
			}
			processor.HandleDisconnect(context.Background(), req2)

			stats := processor.GetStats()
			Expect(stats.DisconnectProcessed).To(Equal(uint64(2)))
			Expect(stats.DisconnectSucceeded).To(Equal(uint64(1)))
			Expect(stats.DisconnectFailed).To(Equal(uint64(1)))
		})

		It("should track policy updates", func() {
			req := &radius.CoARequest{
				SessionID: "existing-session",
				FilterID:  "new-policy",
			}
			processor.HandleCoA(context.Background(), req)

			stats := processor.GetStats()
			Expect(stats.PolicyUpdates).To(Equal(uint64(1)))
		})
	})
})

var _ = Describe("SessionInfo", func() {
	It("should hold all session information", func() {
		mac, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
		info := &radius.SessionInfo{
			SessionID:       "session-123",
			Username:        "user@example.com",
			MAC:             mac,
			FramedIP:        net.ParseIP("10.0.1.100"),
			State:           "active",
			QoSPolicyID:     "gold-plan",
			DownloadRateBPS: 100_000_000,
			UploadRateBPS:   50_000_000,
			SessionTimeout:  24 * time.Hour,
			IdleTimeout:     30 * time.Minute,
		}

		Expect(info.SessionID).To(Equal("session-123"))
		Expect(info.Username).To(Equal("user@example.com"))
		Expect(info.MAC.String()).To(Equal("aa:bb:cc:dd:ee:ff"))
		Expect(info.FramedIP.String()).To(Equal("10.0.1.100"))
		Expect(info.State).To(Equal("active"))
		Expect(info.QoSPolicyID).To(Equal("gold-plan"))
		Expect(info.DownloadRateBPS).To(Equal(uint64(100_000_000)))
		Expect(info.UploadRateBPS).To(Equal(uint64(50_000_000)))
		Expect(info.SessionTimeout).To(Equal(24 * time.Hour))
		Expect(info.IdleTimeout).To(Equal(30 * time.Minute))
	})
})

var _ = Describe("PolicyUpdate", func() {
	It("should hold policy changes", func() {
		update := &radius.PolicyUpdate{
			FilterID:        "gold-plan",
			DownloadRateBPS: 200_000_000,
			UploadRateBPS:   100_000_000,
			SessionTimeout:  48 * time.Hour,
			IdleTimeout:     1 * time.Hour,
		}

		Expect(update.FilterID).To(Equal("gold-plan"))
		Expect(update.DownloadRateBPS).To(Equal(uint64(200_000_000)))
		Expect(update.UploadRateBPS).To(Equal(uint64(100_000_000)))
		Expect(update.SessionTimeout).To(Equal(48 * time.Hour))
		Expect(update.IdleTimeout).To(Equal(1 * time.Hour))
	})
})

var _ = Describe("DefaultAuditLogger", func() {
	var (
		logger      *zap.Logger
		auditLogger *radius.DefaultAuditLogger
	)

	BeforeEach(func() {
		logger = zap.NewNop()
		auditLogger = radius.NewDefaultAuditLogger(logger)
	})

	It("should create successfully", func() {
		Expect(auditLogger).NotTo(BeNil())
	})

	It("should log CoA request without panic", func() {
		req := &radius.CoARequest{
			SessionID: "session-123",
			Username:  "testuser",
			FramedIP:  net.ParseIP("10.0.1.100"),
			FilterID:  "gold-plan",
		}
		resp := &radius.CoAResponse{
			Success: true,
			Message: "OK",
		}

		Expect(func() {
			auditLogger.LogCoARequest(req, resp, 100*time.Millisecond)
		}).NotTo(Panic())
	})

	It("should log Disconnect request without panic", func() {
		req := &radius.DisconnectRequest{
			SessionID: "session-123",
			Username:  "testuser",
			FramedIP:  net.ParseIP("10.0.1.100"),
		}
		resp := &radius.DisconnectResponse{
			Success: true,
			Message: "Disconnected",
		}

		Expect(func() {
			auditLogger.LogDisconnectRequest(req, resp, 50*time.Millisecond)
		}).NotTo(Panic())
	})
})

var _ = Describe("CoAProcessorStats", func() {
	It("should hold all statistics", func() {
		stats := radius.CoAProcessorStats{
			CoAProcessed:        100,
			CoASucceeded:        95,
			CoAFailed:           5,
			DisconnectProcessed: 50,
			DisconnectSucceeded: 48,
			DisconnectFailed:    2,
			PolicyUpdates:       95,
			AvgProcessingMs:     2.5,
		}

		Expect(stats.CoAProcessed).To(Equal(uint64(100)))
		Expect(stats.CoASucceeded).To(Equal(uint64(95)))
		Expect(stats.CoAFailed).To(Equal(uint64(5)))
		Expect(stats.DisconnectProcessed).To(Equal(uint64(50)))
		Expect(stats.DisconnectSucceeded).To(Equal(uint64(48)))
		Expect(stats.DisconnectFailed).To(Equal(uint64(2)))
		Expect(stats.PolicyUpdates).To(Equal(uint64(95)))
		Expect(stats.AvgProcessingMs).To(Equal(2.5))
	})
})

var _ = Describe("CoAProcessorConfig", func() {
	Context("DefaultCoAProcessorConfig", func() {
		It("should return sensible defaults", func() {
			cfg := radius.DefaultCoAProcessorConfig()

			Expect(cfg.PolicyUpdateTimeout).To(Equal(5 * time.Second))
			Expect(cfg.AllowSessionLookupByIP).To(BeTrue())
			Expect(cfg.AllowSessionLookupByMAC).To(BeTrue())
		})
	})
})
