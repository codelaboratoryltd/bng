package pppoe_test

import (
	"encoding/binary"
	"net"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/codelaboratoryltd/bng/pkg/pppoe"
)

func TestPPPoEProtocol(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "PPPoE Protocol Suite")
}

var _ = Describe("PPPoE Protocol", func() {

	Describe("PPPoE Header", func() {

		Context("when parsing a valid PPPoE header", func() {
			It("should correctly parse all fields", func() {
				// Given a valid PPPoE header
				data := []byte{
					0x11,       // Version 1, Type 1
					0x09,       // Code: PADI
					0x00, 0x00, // Session ID: 0
					0x00, 0x04, // Length: 4
				}

				// When parsing
				hdr, err := pppoe.ParsePPPoEHeader(data)

				// Then it should succeed
				Expect(err).NotTo(HaveOccurred())
				Expect(hdr.VerType).To(Equal(uint8(0x11)))
				Expect(hdr.Code).To(Equal(uint8(pppoe.CodePADI)))
				Expect(hdr.SessionID).To(Equal(uint16(0)))
				Expect(hdr.Length).To(Equal(uint16(4)))
			})

			DescribeTable("parsing different PPPoE codes",
				func(code uint8, expectedCode uint8) {
					data := []byte{0x11, code, 0x00, 0x01, 0x00, 0x00}
					hdr, err := pppoe.ParsePPPoEHeader(data)
					Expect(err).NotTo(HaveOccurred())
					Expect(hdr.Code).To(Equal(expectedCode))
				},
				Entry("PADI", uint8(0x09), uint8(pppoe.CodePADI)),
				Entry("PADO", uint8(0x07), uint8(pppoe.CodePADO)),
				Entry("PADR", uint8(0x19), uint8(pppoe.CodePADR)),
				Entry("PADS", uint8(0x65), uint8(pppoe.CodePADS)),
				Entry("PADT", uint8(0xA7), uint8(pppoe.CodePADT)),
				Entry("Session", uint8(0x00), uint8(pppoe.CodeSession)),
			)
		})

		Context("when parsing an invalid PPPoE header", func() {
			It("should return an error for data that is too short", func() {
				// Given data shorter than 6 bytes
				data := []byte{0x11, 0x09, 0x00}

				// When parsing
				hdr, err := pppoe.ParsePPPoEHeader(data)

				// Then it should fail
				Expect(err).To(HaveOccurred())
				Expect(hdr).To(BeNil())
				Expect(err.Error()).To(ContainSubstring("too short"))
			})
		})

		Context("when serializing a PPPoE header", func() {
			It("should produce valid bytes", func() {
				// Given a PPPoE header
				hdr := &pppoe.PPPoEHeader{
					VerType:   0x11,
					Code:      pppoe.CodePADS,
					SessionID: 0x1234,
					Length:    10,
				}

				// When serializing
				data := hdr.Serialize()

				// Then it should produce correct bytes
				Expect(data).To(HaveLen(6))
				Expect(data[0]).To(Equal(uint8(0x11)))
				Expect(data[1]).To(Equal(uint8(pppoe.CodePADS)))
				Expect(binary.BigEndian.Uint16(data[2:4])).To(Equal(uint16(0x1234)))
				Expect(binary.BigEndian.Uint16(data[4:6])).To(Equal(uint16(10)))
			})

			It("should round-trip correctly", func() {
				// Given an original header
				original := &pppoe.PPPoEHeader{
					VerType:   0x11,
					Code:      pppoe.CodePADR,
					SessionID: 0xABCD,
					Length:    100,
				}

				// When serializing and parsing back
				data := original.Serialize()
				parsed, err := pppoe.ParsePPPoEHeader(data)

				// Then it should match
				Expect(err).NotTo(HaveOccurred())
				Expect(parsed.VerType).To(Equal(original.VerType))
				Expect(parsed.Code).To(Equal(original.Code))
				Expect(parsed.SessionID).To(Equal(original.SessionID))
				Expect(parsed.Length).To(Equal(original.Length))
			})
		})
	})

	Describe("PPPoE Tags", func() {

		Context("when parsing tags", func() {
			It("should parse a single tag correctly", func() {
				// Given a service name tag
				data := []byte{
					0x01, 0x01, // Tag type: Service-Name
					0x00, 0x08, // Length: 8
					'i', 'n', 't', 'e', 'r', 'n', 'e', 't', // Value
				}

				// When parsing
				tags, err := pppoe.ParseTags(data)

				// Then it should succeed
				Expect(err).NotTo(HaveOccurred())
				Expect(tags).To(HaveLen(1))
				Expect(tags[0].Type).To(Equal(uint16(pppoe.TagServiceName)))
				Expect(string(tags[0].Value)).To(Equal("internet"))
			})

			It("should parse multiple tags", func() {
				// Given multiple tags
				data := []byte{
					0x01, 0x01, 0x00, 0x03, 'i', 's', 'p', // Service-Name: "isp"
					0x01, 0x02, 0x00, 0x05, 'B', 'N', 'G', '-', '1', // AC-Name: "BNG-1"
				}

				// When parsing
				tags, err := pppoe.ParseTags(data)

				// Then it should find both
				Expect(err).NotTo(HaveOccurred())
				Expect(tags).To(HaveLen(2))
				Expect(tags[0].Type).To(Equal(uint16(pppoe.TagServiceName)))
				Expect(tags[1].Type).To(Equal(uint16(pppoe.TagACName)))
			})

			It("should stop at End-Of-List tag", func() {
				// Given tags with EOL
				data := []byte{
					0x01, 0x01, 0x00, 0x03, 'i', 's', 'p',
					0x00, 0x00, 0x00, 0x00, // End-Of-List
					0x01, 0x02, 0x00, 0x05, 'B', 'N', 'G', '-', '1', // Should not be parsed
				}

				// When parsing
				tags, err := pppoe.ParseTags(data)

				// Then it should only find one tag
				Expect(err).NotTo(HaveOccurred())
				Expect(tags).To(HaveLen(1))
			})

			DescribeTable("parsing different tag types",
				func(tagType uint16, value []byte) {
					data := make([]byte, 4+len(value))
					binary.BigEndian.PutUint16(data[0:2], tagType)
					binary.BigEndian.PutUint16(data[2:4], uint16(len(value)))
					copy(data[4:], value)

					tags, err := pppoe.ParseTags(data)
					Expect(err).NotTo(HaveOccurred())
					Expect(tags).To(HaveLen(1))
					Expect(tags[0].Type).To(Equal(tagType))
					Expect(tags[0].Value).To(Equal(value))
				},
				Entry("Service-Name", uint16(pppoe.TagServiceName), []byte("internet")),
				Entry("AC-Name", uint16(pppoe.TagACName), []byte("BNG-AC-01")),
				Entry("Host-Uniq", uint16(pppoe.TagHostUniq), []byte{0x01, 0x02, 0x03, 0x04}),
				Entry("AC-Cookie", uint16(pppoe.TagACCookie), []byte{0xDE, 0xAD, 0xBE, 0xEF}),
			)
		})

		Context("when serializing tags", func() {
			It("should produce valid bytes", func() {
				// Given tags
				tags := []pppoe.Tag{
					{Type: pppoe.TagServiceName, Value: []byte("test")},
					{Type: pppoe.TagACName, Value: []byte("AC1")},
				}

				// When serializing
				data := pppoe.SerializeTags(tags)

				// Then it should produce correct bytes
				Expect(data).To(HaveLen(4 + 4 + 4 + 3)) // 2 headers + values
			})

			It("should round-trip correctly", func() {
				// Given original tags
				original := []pppoe.Tag{
					{Type: pppoe.TagServiceName, Value: []byte("broadband")},
					{Type: pppoe.TagHostUniq, Value: []byte{0x11, 0x22, 0x33}},
				}

				// When serializing and parsing
				data := pppoe.SerializeTags(original)
				parsed, err := pppoe.ParseTags(data)

				// Then it should match
				Expect(err).NotTo(HaveOccurred())
				Expect(parsed).To(HaveLen(2))
				Expect(parsed[0].Type).To(Equal(original[0].Type))
				Expect(parsed[0].Value).To(Equal(original[0].Value))
				Expect(parsed[1].Type).To(Equal(original[1].Type))
				Expect(parsed[1].Value).To(Equal(original[1].Value))
			})
		})

		Context("when finding tags", func() {
			It("should find an existing tag", func() {
				tags := []pppoe.Tag{
					{Type: pppoe.TagServiceName, Value: []byte("isp")},
					{Type: pppoe.TagACName, Value: []byte("AC1")},
				}

				found := pppoe.FindTag(tags, pppoe.TagACName)
				Expect(found).NotTo(BeNil())
				Expect(string(found.Value)).To(Equal("AC1"))
			})

			It("should return nil for non-existent tag", func() {
				tags := []pppoe.Tag{
					{Type: pppoe.TagServiceName, Value: []byte("isp")},
				}

				found := pppoe.FindTag(tags, pppoe.TagACCookie)
				Expect(found).To(BeNil())
			})
		})
	})

	Describe("LCP Packets", func() {

		Context("when parsing LCP packets", func() {
			It("should parse a Configure-Request", func() {
				// Given an LCP Configure-Request
				data := []byte{
					0x01,       // Code: Configure-Request
					0x01,       // Identifier
					0x00, 0x08, // Length: 8
					0x05, 0x06, 0x12, 0x34, 0x56, 0x78, // Magic Number option
				}

				// When parsing
				pkt, err := pppoe.ParseLCPPacket(data)

				// Then it should succeed
				Expect(err).NotTo(HaveOccurred())
				Expect(pkt.Code).To(Equal(uint8(pppoe.LCPCodeConfigRequest)))
				Expect(pkt.Identifier).To(Equal(uint8(1)))
				Expect(pkt.Length).To(Equal(uint16(8)))
				Expect(pkt.Data).To(HaveLen(4))
			})

			DescribeTable("parsing LCP codes",
				func(code uint8, expectedCode uint8) {
					data := []byte{code, 0x01, 0x00, 0x04}
					pkt, err := pppoe.ParseLCPPacket(data)
					Expect(err).NotTo(HaveOccurred())
					Expect(pkt.Code).To(Equal(expectedCode))
				},
				Entry("Configure-Request", uint8(1), uint8(pppoe.LCPCodeConfigRequest)),
				Entry("Configure-Ack", uint8(2), uint8(pppoe.LCPCodeConfigAck)),
				Entry("Configure-Nak", uint8(3), uint8(pppoe.LCPCodeConfigNak)),
				Entry("Configure-Reject", uint8(4), uint8(pppoe.LCPCodeConfigReject)),
				Entry("Terminate-Request", uint8(5), uint8(pppoe.LCPCodeTermRequest)),
				Entry("Terminate-Ack", uint8(6), uint8(pppoe.LCPCodeTermAck)),
				Entry("Echo-Request", uint8(9), uint8(pppoe.LCPCodeEchoRequest)),
				Entry("Echo-Reply", uint8(10), uint8(pppoe.LCPCodeEchoReply)),
			)
		})

		Context("when serializing LCP packets", func() {
			It("should round-trip correctly", func() {
				original := &pppoe.LCPPacket{
					Code:       pppoe.LCPCodeConfigRequest,
					Identifier: 42,
					Data:       []byte{0x01, 0x04, 0x05, 0xD4}, // MRU option
				}

				data := original.Serialize()
				parsed, err := pppoe.ParseLCPPacket(data)

				Expect(err).NotTo(HaveOccurred())
				Expect(parsed.Code).To(Equal(original.Code))
				Expect(parsed.Identifier).To(Equal(original.Identifier))
				Expect(parsed.Data).To(Equal(original.Data))
			})
		})
	})

	Describe("LCP Options", func() {

		Context("when parsing LCP options", func() {
			It("should parse MRU option", func() {
				data := []byte{
					0x01,       // Type: MRU
					0x04,       // Length: 4
					0x05, 0xD4, // Value: 1492
				}

				opts, err := pppoe.ParseLCPOptions(data)
				Expect(err).NotTo(HaveOccurred())
				Expect(opts).To(HaveLen(1))
				Expect(opts[0].Type).To(Equal(uint8(pppoe.LCPOptMRU)))
				Expect(binary.BigEndian.Uint16(opts[0].Data)).To(Equal(uint16(1492)))
			})

			It("should parse Magic Number option", func() {
				data := []byte{
					0x05,                   // Type: Magic Number
					0x06,                   // Length: 6
					0x12, 0x34, 0x56, 0x78, // Value
				}

				opts, err := pppoe.ParseLCPOptions(data)
				Expect(err).NotTo(HaveOccurred())
				Expect(opts).To(HaveLen(1))
				Expect(opts[0].Type).To(Equal(uint8(pppoe.LCPOptMagicNumber)))
			})

			It("should parse multiple options", func() {
				data := []byte{
					0x01, 0x04, 0x05, 0xD4, // MRU: 1492
					0x05, 0x06, 0x11, 0x22, 0x33, 0x44, // Magic Number
					0x03, 0x04, 0xC0, 0x23, // Auth Protocol: PAP
				}

				opts, err := pppoe.ParseLCPOptions(data)
				Expect(err).NotTo(HaveOccurred())
				Expect(opts).To(HaveLen(3))
			})
		})

		Context("when serializing LCP options", func() {
			It("should round-trip correctly", func() {
				original := []pppoe.LCPOption{
					{Type: pppoe.LCPOptMRU, Data: []byte{0x05, 0xD4}},
					{Type: pppoe.LCPOptMagicNumber, Data: []byte{0xAA, 0xBB, 0xCC, 0xDD}},
				}

				data := pppoe.SerializeLCPOptions(original)
				parsed, err := pppoe.ParseLCPOptions(data)

				Expect(err).NotTo(HaveOccurred())
				Expect(parsed).To(HaveLen(2))
				Expect(parsed[0].Type).To(Equal(original[0].Type))
				Expect(parsed[0].Data).To(Equal(original[0].Data))
			})
		})
	})

	Describe("Ethernet Frame Building", func() {
		It("should build a valid Ethernet frame", func() {
			dst, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
			src, _ := net.ParseMAC("11:22:33:44:55:66")
			payload := []byte{0x01, 0x02, 0x03, 0x04}

			frame := pppoe.BuildEthernetFrame(dst, src, pppoe.EtherTypePPPoEDiscovery, payload)

			Expect(frame).To(HaveLen(14 + 4)) // 14 byte header + payload
			Expect(frame[0:6]).To(Equal([]byte(dst)))
			Expect(frame[6:12]).To(Equal([]byte(src)))
			Expect(binary.BigEndian.Uint16(frame[12:14])).To(Equal(uint16(pppoe.EtherTypePPPoEDiscovery)))
			Expect(frame[14:]).To(Equal(payload))
		})
	})
})
