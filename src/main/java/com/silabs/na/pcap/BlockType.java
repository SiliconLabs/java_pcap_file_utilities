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
 * PCAPNG is made of blocks. These are the valid block types.
 *
 * See section 3.2 of PCAPNG spec.
 *
 * @author Timotej Ecimovic
 */
public enum BlockType {
  INTERFACE_DESCRIPTION_BLOCK(0x00000001),
  PACKET_BLOCK(0x00000002),
  SIMPLE_PACKET_BLOCK(0x00000003),
  NAME_RESOLUTION_BLOCK(0x00000004),
  INTERFACE_STATISTICS_BLOCK(0x00000005),
  ENHANCED_PACKET_BLOCK(0x00000006),
  IRIG_TIMESTAMP_BLOCK(0x00000007),
  ARINC429_IN_AFDX_ENCAPSULATION_INFORMATION_BLOCK(0x00000008),
  SYSTEMD_JOURNAL_EXPORT_BLOCK(0x00000009),
  DECRYPTION_SECRETS_BLOCK(0x0000000A),
  CUSTOM_BLOCK_THAT_REWRITERS_CAN_COPY(0x00000BAD),
  CUSTOM_BLOCK_THAT_REWRITERS_SHOULD_NOT_COPY(0x40000BAD),
  SECTION_HEADER_BLOCK(0x0A0D0D0A),
  UNKNOWN(0xFFFFFFFF);

  private final int typeCode;

  BlockType(final int typeCode) {
    this.typeCode = typeCode;
  }

  /**
   * Type code nubmer as defined by the PCAPNG spec.
   *
   * @return Type code.
   */
  public int typeCode() {
    return typeCode;
  }

  /**
   * Given a type code, return the enum value that matches it.
   *
   * @param code Integer to resolve.
   * @return Corresponding enum value, or UNKNOWN if the number doesn't match any.
   */
  public static BlockType resolve(final int code) {
    for (BlockType t : values()) {
      if (t.typeCode == code)
        return t;
    }
    return UNKNOWN;
  }
}