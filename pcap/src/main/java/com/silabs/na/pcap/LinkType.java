/*

Copyright 2020 Silicon Labs.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

package com.silabs.na.pcap;

/**
 * Link type is a top-level description of what link layer is in the packet.
 * !!!! NOTE !!!!: This file is generated via `gradle generateLinkType`
 *
 * See: http://www.tcpdump.org/linktypes.html
 *
 * @author Timotej Ecimovic
 */
public enum LinkType {
  NULL(0),
  EN10MB(1),
  EN3MB(2),
  AX25(3),
  PRONET(4),
  CHAOS(5),
  IEEE802(6),
  ARCNET(7),
  SLIP(8),
  PPP(9),
  FDDI(10),
  ATM_RFC1483(11),
  RAW(12),
  SLIP_BSDOS(15),
  PPP_BSDOS(16),
  HIPPI(15),
  ATM_CLIP(19),
  REDBACK_SMARTEDGE(32),
  PPP_SERIAL(50),
  PPP_ETHER(51),
  SYMANTEC_FIREWALL(99),
  MATCHING_MIN(104),
  C_HDLC(104),

  IEEE802_11(105),
  FRELAY(107),
  LOOP(108),
  ENC(109),
  HDLC(112),
  LINUX_SLL(113),
  LTALK(114),
  ECONET(115),
  IPFILTER(116),
  PFLOG(117),
  CISCO_IOS(118),
  PRISM_HEADER(119),
  AIRONET_HEADER(120),
  HHDLC(121),
  IP_OVER_FC(122),
  SUNATM(123),
  RIO(124),
  PCI_EXP(125),
  AURORA(126),
  IEEE802_11_RADIO(127),
  TZSP(128),
  ARCNET_LINUX(129),
  JUNIPER_MLPPP(130),
  JUNIPER_MLFR(131),
  JUNIPER_ES(132),
  JUNIPER_GGSN(133),
  JUNIPER_MFR(134),
  JUNIPER_ATM2(135),
  JUNIPER_SERVICES(136),
  JUNIPER_ATM1(137),
  APPLE_IP_OVER_IEEE1394(138),
  MTP2_WITH_PHDR(139),
  MTP2(140),
  MTP3(141),
  SCCP(142),
  DOCSIS(143),
  LINUX_IRDA(144),
  IBM_SP(145),
  IBM_SN(146),
  USER0(147),
  USER1(148),
  USER2(149),
  USER3(150),
  USER4(151),
  USER5(152),
  USER6(153),
  USER7(154),
  USER8(155),
  USER9(156),
  USER10(157),
  USER11(158),
  USER12(159),
  USER13(160),
  USER14(161),
  USER15(162),
  IEEE802_11_RADIO_AVS(163),
  JUNIPER_MONITOR(164),
  BACNET_MS_TP(165),
  PPP_PPPD(166),

  JUNIPER_PPPOE(167),
  JUNIPER_PPPOE_ATM(168),
  GPRS_LLC(169),
  GPF_T(170),
  GPF_F(171),
  GCOM_T1E1(172),
  GCOM_SERIAL(173),
  JUNIPER_PIC_PEER(174),
  ERF_ETH(175),
  ERF_POS(176),
  LINUX_LAPD(177),
  JUNIPER_ETHER(178),
  JUNIPER_PPP(179),
  JUNIPER_FRELAY(180),
  JUNIPER_CHDLC(181),
  MFR(182),
  JUNIPER_VP(183),
  A429(184),
  A653_ICM(185),
  USB_FREEBSD(186),
  USB(186),
  BLUETOOTH_HCI_H4(187),
  IEEE802_16_MAC_CPS(188),
  USB_LINUX(189),
  CAN20B(190),
  IEEE802_15_4_LINUX(191),
  PPI(192),
  IEEE802_16_MAC_CPS_RADIO(193),
  JUNIPER_ISM(194),
  IEEE802_15_4_WITHFCS(195),

  SITA(196),
  ERF(197),
  RAIF1(198),
  IPMB_KONTRON(199),
  JUNIPER_ST(200),
  BLUETOOTH_HCI_H4_WITH_PHDR(201),
  AX25_KISS(202),
  LAPD(203),
  PPP_WITH_DIR(204),
  C_HDLC_WITH_DIR(205),
  FRELAY_WITH_DIR(206),
  LAPB_WITH_DIR(207),
  IPMB_LINUX(209),
  FLEXRAY(210),
  MOST(211),
  LIN(212),
  X2E_SERIAL(213),
  X2E_XORAYA(214),
  IEEE802_15_4_NONASK_PHY(215),
  LINUX_EVDEV(216),
  GSMTAP_UM(217),
  GSMTAP_ABIS(218),
  MPLS(219),
  USB_LINUX_MMAPPED(220),
  DECT(221),
  AOS(222),
  WIHART(223),
  FC_2(224),
  FC_2_WITH_FRAME_DELIMS(225),
  IPNET(226),
  CAN_SOCKETCAN(227),
  IPV4(228),
  IPV6(229),
  IEEE802_15_4_NOFCS(230),
  DBUS(231),
  JUNIPER_VS(232),
  JUNIPER_SRX_E2E(233),
  JUNIPER_FIBRECHANNEL(234),
  DVB_CI(235),
  MUX27010(236),
  STANAG_5066_D_PDU(237),
  JUNIPER_ATM_CEMIC(238),
  NFLOG(239),
  NETANALYZER(240),
  NETANALYZER_TRANSPARENT(241),
  IPOIB(242),
  MPEG_2_TS(243),
  NG40(244),
  NFC_LLCP(245),
  PFSYNC(246),
  INFINIBAND(247),
  SCTP(248),
  USBPCAP(249),
  RTAC_SERIAL(250),
  BLUETOOTH_LE_LL(251),
  WIRESHARK_UPPER_PDU(252),
  NETLINK(253),
  BLUETOOTH_LINUX_MONITOR(254),
  BLUETOOTH_BREDR_BB(255),
  BLUETOOTH_LE_LL_WITH_PHDR(256),
  PROFIBUS_DL(257),

  PKTAP(258),
  EPON(259),
  IPMI_HPM_2(260),
  ZWAVE_R1_R2(261),
  ZWAVE_R3(262),
  WATTSTOPPER_DLM(263),
  ISO_14443(264),
  RDS(265),
  USB_DARWIN(266),
  OPENFLOW(267),
  SDLC(268),
  TI_LLN_SNIFFER(269),
  LORATAP(270),
  VSOCK(271),
  NORDIC_BLE(272),
  DOCSIS31_XRA31(273),
  ETHERNET_MPACKET(274),
  DISPLAYPORT_AUX(275),
  LINUX_SLL2(276),
  SERCOS_MONITOR(277),
  OPENVIZSLA(278),
  EBHSCR(279),
  VPP_DISPATCH(280),
  DSA_TAG_BRCM(281),
  DSA_TAG_BRCM_PREPEND(282),
  IEEE802_15_4_TAP(283),
  DSA_TAG_DSA(284),
  DSA_TAG_EDSA(285),
  ELEE(286),
  Z_WAVE_SERIAL(287),
  USB_2_0(288),
  ATSC_ALP(289),
  ETW(290),
  NETANALYZER_NG(291),
  ZBOSS_NCP(292),
  // Start of footer
  UNKNOWN(Integer.MAX_VALUE);

  private final int code;

  LinkType(final int code) {
    this.code = code;
  }

  /**
   * Returns the code as defined by the spec for this type.
   *
   * @return Code for the type.
   */
  public int code() {
    return code;
  }

  /**
   * Given a code, returns the enum value that matches it.
   *
   * @param code Value to resolve.
   * @return Matching enum value, or UNKNOWN.
   */
  public static LinkType resolve(final int code) {
    for (final LinkType lt : values()) {
      if (code == lt.code)
        return lt;
    }
    return UNKNOWN;
  }
}
