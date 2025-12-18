package dhcpv6_test

import (
	"encoding/binary"
	"net"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/codelaboratoryltd/bng/pkg/dhcpv6"
)

func TestDHCPv6Protocol(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "DHCPv6 Protocol Suite")
}

var _ = Describe("DHCPv6 Protocol", func() {

	Describe("Message", func() {

		Context("when parsing messages", func() {
			It("should parse a Solicit message", func() {
				// Given a DHCPv6 Solicit message
				data := []byte{
					0x01,             // Type: Solicit
					0xAB, 0xCD, 0xEF, // Transaction ID
					// Client ID option
					0x00, 0x01, // Option: Client ID
					0x00, 0x0E, // Length: 14
					0x00, 0x01, // DUID-LLT
					0x00, 0x01, // Hardware type: Ethernet
					0x00, 0x00, 0x00, 0x00, // Time
					0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // MAC
				}

				// When parsing
				msg, err := dhcpv6.ParseMessage(data)

				// Then it should succeed
				Expect(err).NotTo(HaveOccurred())
				Expect(msg.Type).To(Equal(uint8(dhcpv6.MsgTypeSolicit)))
				Expect(msg.TransactionID).To(Equal([3]byte{0xAB, 0xCD, 0xEF}))
				Expect(msg.Options).To(HaveLen(1))
			})

			DescribeTable("parsing different message types",
				func(msgType uint8, expectedType uint8) {
					data := []byte{msgType, 0x00, 0x00, 0x01}
					msg, err := dhcpv6.ParseMessage(data)
					Expect(err).NotTo(HaveOccurred())
					Expect(msg.Type).To(Equal(expectedType))
				},
				Entry("Solicit", uint8(1), uint8(dhcpv6.MsgTypeSolicit)),
				Entry("Advertise", uint8(2), uint8(dhcpv6.MsgTypeAdvertise)),
				Entry("Request", uint8(3), uint8(dhcpv6.MsgTypeRequest)),
				Entry("Confirm", uint8(4), uint8(dhcpv6.MsgTypeConfirm)),
				Entry("Renew", uint8(5), uint8(dhcpv6.MsgTypeRenew)),
				Entry("Rebind", uint8(6), uint8(dhcpv6.MsgTypeRebind)),
				Entry("Reply", uint8(7), uint8(dhcpv6.MsgTypeReply)),
				Entry("Release", uint8(8), uint8(dhcpv6.MsgTypeRelease)),
				Entry("Decline", uint8(9), uint8(dhcpv6.MsgTypeDecline)),
				Entry("Information-Request", uint8(11), uint8(dhcpv6.MsgTypeInformationRequest)),
			)

			It("should return error for message that is too short", func() {
				data := []byte{0x01, 0x02}
				msg, err := dhcpv6.ParseMessage(data)
				Expect(err).To(HaveOccurred())
				Expect(msg).To(BeNil())
			})
		})

		Context("when serializing messages", func() {
			It("should serialize correctly", func() {
				msg := &dhcpv6.Message{
					Type:          dhcpv6.MsgTypeAdvertise,
					TransactionID: [3]byte{0x11, 0x22, 0x33},
					Options: []dhcpv6.Option{
						{Code: dhcpv6.OptServerID, Data: []byte{0x00, 0x01}},
					},
				}

				data := msg.Serialize()

				Expect(data[0]).To(Equal(uint8(dhcpv6.MsgTypeAdvertise)))
				Expect(data[1:4]).To(Equal([]byte{0x11, 0x22, 0x33}))
			})

			It("should round-trip correctly", func() {
				original := &dhcpv6.Message{
					Type:          dhcpv6.MsgTypeRequest,
					TransactionID: [3]byte{0xAA, 0xBB, 0xCC},
					Options: []dhcpv6.Option{
						{Code: dhcpv6.OptClientID, Data: []byte{0x00, 0x03, 0x00, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66}},
					},
				}

				data := original.Serialize()
				parsed, err := dhcpv6.ParseMessage(data)

				Expect(err).NotTo(HaveOccurred())
				Expect(parsed.Type).To(Equal(original.Type))
				Expect(parsed.TransactionID).To(Equal(original.TransactionID))
				Expect(parsed.Options).To(HaveLen(1))
			})
		})

		Context("when getting options", func() {
			var msg *dhcpv6.Message

			BeforeEach(func() {
				msg = &dhcpv6.Message{
					Type:          dhcpv6.MsgTypeSolicit,
					TransactionID: [3]byte{0x00, 0x00, 0x01},
					Options: []dhcpv6.Option{
						{Code: dhcpv6.OptClientID, Data: []byte{0x01}},
						{Code: dhcpv6.OptORO, Data: []byte{0x02}},
						{Code: dhcpv6.OptIANA, Data: []byte{0x03}},
						{Code: dhcpv6.OptIANA, Data: []byte{0x04}}, // Duplicate
					},
				}
			})

			It("should find first option by code", func() {
				opt := msg.GetOption(dhcpv6.OptClientID)
				Expect(opt).NotTo(BeNil())
				Expect(opt.Data).To(Equal([]byte{0x01}))
			})

			It("should return nil for non-existent option", func() {
				opt := msg.GetOption(dhcpv6.OptServerID)
				Expect(opt).To(BeNil())
			})

			It("should find all options by code", func() {
				opts := msg.GetAllOptions(dhcpv6.OptIANA)
				Expect(opts).To(HaveLen(2))
				Expect(opts[0].Data).To(Equal([]byte{0x03}))
				Expect(opts[1].Data).To(Equal([]byte{0x04}))
			})
		})
	})

	Describe("Options", func() {

		Context("when parsing options", func() {
			It("should parse multiple options", func() {
				data := []byte{
					0x00, 0x01, 0x00, 0x02, 0xAA, 0xBB, // Client ID
					0x00, 0x02, 0x00, 0x03, 0xCC, 0xDD, 0xEE, // Server ID
				}

				opts, err := dhcpv6.ParseOptions(data)

				Expect(err).NotTo(HaveOccurred())
				Expect(opts).To(HaveLen(2))
				Expect(opts[0].Code).To(Equal(uint16(dhcpv6.OptClientID)))
				Expect(opts[0].Data).To(Equal([]byte{0xAA, 0xBB}))
				Expect(opts[1].Code).To(Equal(uint16(dhcpv6.OptServerID)))
			})

			It("should return error for truncated option", func() {
				data := []byte{0x00, 0x01, 0x00, 0x10, 0xAA} // Length says 16, only 1 byte
				opts, err := dhcpv6.ParseOptions(data)
				Expect(err).To(HaveOccurred())
				Expect(opts).To(BeNil())
			})
		})

		Context("when serializing options", func() {
			It("should serialize correctly", func() {
				opts := []dhcpv6.Option{
					{Code: 1, Data: []byte{0x11, 0x22}},
					{Code: 2, Data: []byte{0x33}},
				}

				data := dhcpv6.SerializeOptions(opts)

				Expect(data).To(HaveLen(4 + 2 + 4 + 1)) // Two headers + data
				Expect(binary.BigEndian.Uint16(data[0:2])).To(Equal(uint16(1)))
				Expect(binary.BigEndian.Uint16(data[2:4])).To(Equal(uint16(2)))
			})
		})
	})

	Describe("DUID", func() {

		Context("when parsing DUID", func() {
			It("should parse DUID-LL", func() {
				data := []byte{
					0x00, 0x03, // Type: DUID-LL
					0x00, 0x01, // Hardware type: Ethernet
					0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // MAC
				}

				duid, err := dhcpv6.ParseDUID(data)

				Expect(err).NotTo(HaveOccurred())
				Expect(duid.Type).To(Equal(uint16(dhcpv6.DUIDTypeLL)))
			})

			It("should return error for short DUID", func() {
				data := []byte{0x00}
				duid, err := dhcpv6.ParseDUID(data)
				Expect(err).To(HaveOccurred())
				Expect(duid).To(BeNil())
			})
		})

		Context("when serializing DUID", func() {
			It("should round-trip correctly", func() {
				original := &dhcpv6.DUID{
					Type: dhcpv6.DUIDTypeLL,
					Data: []byte{0x00, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
				}

				data := original.Serialize()
				parsed, err := dhcpv6.ParseDUID(data)

				Expect(err).NotTo(HaveOccurred())
				Expect(parsed.Type).To(Equal(original.Type))
				Expect(parsed.Data).To(Equal(original.Data))
			})
		})
	})

	Describe("IA_NA", func() {

		Context("when parsing IA_NA", func() {
			It("should parse IA_NA with address option", func() {
				data := []byte{
					0x00, 0x00, 0x00, 0x01, // IAID: 1
					0x00, 0x00, 0x0E, 0x10, // T1: 3600
					0x00, 0x00, 0x1C, 0x20, // T2: 7200
					// IA Address option would follow
				}

				iana, err := dhcpv6.ParseIANA(data)

				Expect(err).NotTo(HaveOccurred())
				Expect(iana.IAID).To(Equal(uint32(1)))
				Expect(iana.T1).To(Equal(uint32(3600)))
				Expect(iana.T2).To(Equal(uint32(7200)))
			})

			It("should return error for short data", func() {
				data := []byte{0x00, 0x00, 0x00, 0x01}
				iana, err := dhcpv6.ParseIANA(data)
				Expect(err).To(HaveOccurred())
				Expect(iana).To(BeNil())
			})
		})

		Context("when serializing IA_NA", func() {
			It("should round-trip correctly", func() {
				original := &dhcpv6.IANA{
					IAID: 42,
					T1:   1800,
					T2:   3600,
				}

				data := original.Serialize()
				parsed, err := dhcpv6.ParseIANA(data)

				Expect(err).NotTo(HaveOccurred())
				Expect(parsed.IAID).To(Equal(original.IAID))
				Expect(parsed.T1).To(Equal(original.T1))
				Expect(parsed.T2).To(Equal(original.T2))
			})
		})
	})

	Describe("IA_PD", func() {

		Context("when parsing IA_PD", func() {
			It("should parse IA_PD", func() {
				data := []byte{
					0x00, 0x00, 0x00, 0x02, // IAID: 2
					0x00, 0x00, 0x07, 0x08, // T1: 1800
					0x00, 0x00, 0x0E, 0x10, // T2: 3600
				}

				iapd, err := dhcpv6.ParseIAPD(data)

				Expect(err).NotTo(HaveOccurred())
				Expect(iapd.IAID).To(Equal(uint32(2)))
				Expect(iapd.T1).To(Equal(uint32(1800)))
				Expect(iapd.T2).To(Equal(uint32(3600)))
			})
		})
	})

	Describe("IAAddress", func() {

		Context("when parsing IAAddress", func() {
			It("should parse address with lifetimes", func() {
				ip := net.ParseIP("2001:db8::1")
				data := make([]byte, 24)
				copy(data[0:16], ip.To16())
				binary.BigEndian.PutUint32(data[16:20], 3600) // Preferred
				binary.BigEndian.PutUint32(data[20:24], 7200) // Valid

				addr, err := dhcpv6.ParseIAAddress(data)

				Expect(err).NotTo(HaveOccurred())
				Expect(addr.Address.String()).To(Equal("2001:db8::1"))
				Expect(addr.PreferredLifetime).To(Equal(uint32(3600)))
				Expect(addr.ValidLifetime).To(Equal(uint32(7200)))
			})
		})

		Context("when serializing IAAddress", func() {
			It("should round-trip correctly", func() {
				original := &dhcpv6.IAAddress{
					Address:           net.ParseIP("2001:db8:cafe::1"),
					PreferredLifetime: 1800,
					ValidLifetime:     3600,
				}

				data := original.Serialize()
				parsed, err := dhcpv6.ParseIAAddress(data)

				Expect(err).NotTo(HaveOccurred())
				Expect(parsed.Address.String()).To(Equal(original.Address.String()))
				Expect(parsed.PreferredLifetime).To(Equal(original.PreferredLifetime))
				Expect(parsed.ValidLifetime).To(Equal(original.ValidLifetime))
			})
		})
	})

	Describe("IAPrefix", func() {

		Context("when parsing IAPrefix", func() {
			It("should parse prefix delegation", func() {
				prefix := net.ParseIP("2001:db8:1234::")
				data := make([]byte, 25)
				binary.BigEndian.PutUint32(data[0:4], 3600) // Preferred
				binary.BigEndian.PutUint32(data[4:8], 7200) // Valid
				data[8] = 56                                // Prefix length
				copy(data[9:25], prefix.To16())

				iaPrefix, err := dhcpv6.ParseIAPrefix(data)

				Expect(err).NotTo(HaveOccurred())
				Expect(iaPrefix.PreferredLifetime).To(Equal(uint32(3600)))
				Expect(iaPrefix.ValidLifetime).To(Equal(uint32(7200)))
				Expect(iaPrefix.PrefixLength).To(Equal(uint8(56)))
			})
		})

		Context("when serializing IAPrefix", func() {
			It("should round-trip correctly", func() {
				original := &dhcpv6.IAPrefix{
					PreferredLifetime: 1800,
					ValidLifetime:     3600,
					PrefixLength:      60,
					Prefix:            net.ParseIP("2001:db8:abcd::"),
				}

				data := original.Serialize()
				parsed, err := dhcpv6.ParseIAPrefix(data)

				Expect(err).NotTo(HaveOccurred())
				Expect(parsed.PreferredLifetime).To(Equal(original.PreferredLifetime))
				Expect(parsed.ValidLifetime).To(Equal(original.ValidLifetime))
				Expect(parsed.PrefixLength).To(Equal(original.PrefixLength))
			})
		})
	})

	Describe("Option Builders", func() {

		It("should build StatusCode option", func() {
			opt := dhcpv6.MakeStatusCodeOption(dhcpv6.StatusSuccess, "OK")

			Expect(opt.Code).To(Equal(uint16(dhcpv6.OptStatusCode)))
			Expect(binary.BigEndian.Uint16(opt.Data[0:2])).To(Equal(uint16(dhcpv6.StatusSuccess)))
			Expect(string(opt.Data[2:])).To(Equal("OK"))
		})

		It("should build DNS Servers option", func() {
			servers := []net.IP{
				net.ParseIP("2001:4860:4860::8888"),
				net.ParseIP("2001:4860:4860::8844"),
			}

			opt := dhcpv6.MakeDNSServersOption(servers)

			Expect(opt.Code).To(Equal(uint16(dhcpv6.OptDNSServers)))
			Expect(opt.Data).To(HaveLen(32)) // 2 x 16 bytes
		})

		It("should build Server ID option", func() {
			duid := &dhcpv6.DUID{
				Type: dhcpv6.DUIDTypeLL,
				Data: []byte{0x00, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
			}

			opt := dhcpv6.MakeServerIDOption(duid)

			Expect(opt.Code).To(Equal(uint16(dhcpv6.OptServerID)))
		})

		It("should build IA_NA option", func() {
			iana := &dhcpv6.IANA{
				IAID: 1,
				T1:   1800,
				T2:   3600,
			}

			opt := dhcpv6.MakeIANAOption(iana)

			Expect(opt.Code).To(Equal(uint16(dhcpv6.OptIANA)))
			Expect(opt.Data).To(HaveLen(12))
		})

		It("should build IA_PD option", func() {
			iapd := &dhcpv6.IAPD{
				IAID: 2,
				T1:   1800,
				T2:   3600,
			}

			opt := dhcpv6.MakeIAPDOption(iapd)

			Expect(opt.Code).To(Equal(uint16(dhcpv6.OptIAPD)))
		})
	})
})
