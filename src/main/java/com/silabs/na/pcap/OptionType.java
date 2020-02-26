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
 * All known option types.
 *
 * @author Timotej Ecimovic
 */
public enum OptionType {

  SHB_HARDWARE(BlockType.SECTION_HEADER_BLOCK, 2, -1, true),
  SHB_OS(BlockType.SECTION_HEADER_BLOCK, 3, -1, true),
  SHB_USERAPPL(BlockType.SECTION_HEADER_BLOCK, 4, -1, true),

  IF_NAME(BlockType.INTERFACE_DESCRIPTION_BLOCK, 2, -1, true),
  IF_DESCRIPTION(BlockType.INTERFACE_DESCRIPTION_BLOCK, 3, -1, true),
  IF_IPV4ADDR(BlockType.INTERFACE_DESCRIPTION_BLOCK, 4, 8, false),
  IF_IPV6ADDR(BlockType.INTERFACE_DESCRIPTION_BLOCK, 5, 17, false),
  IF_MACADDR(BlockType.INTERFACE_DESCRIPTION_BLOCK, 6, 6, false),
  IF_EUIADDR(BlockType.INTERFACE_DESCRIPTION_BLOCK, 7, 8, false),
  IF_SPEED(BlockType.INTERFACE_DESCRIPTION_BLOCK, 8, 8, false),
  IF_TSRESOL(BlockType.INTERFACE_DESCRIPTION_BLOCK, 9, 1, false),
  IF_TZONE(BlockType.INTERFACE_DESCRIPTION_BLOCK, 10, 4, false),
  IF_FILTER(BlockType.INTERFACE_DESCRIPTION_BLOCK, 11, -1, false),
  IF_OS(BlockType.INTERFACE_DESCRIPTION_BLOCK, 12, -1, true),
  IF_FCSLEN(BlockType.INTERFACE_DESCRIPTION_BLOCK, 13, 1, false),
  IF_TSOFFSET(BlockType.INTERFACE_DESCRIPTION_BLOCK, 14, 8, false),
  IF_HARDWARE(BlockType.INTERFACE_DESCRIPTION_BLOCK, 15, -1, true),

  EPB_FLAGS(BlockType.ENHANCED_PACKET_BLOCK, 2, 4, false),
  EPB_HASH(BlockType.ENHANCED_PACKET_BLOCK, 3, -1, false),
  EPB_DROPCOUNT(BlockType.ENHANCED_PACKET_BLOCK, 4, 8, false),

  ISB_STARTTIME(BlockType.INTERFACE_STATISTICS_BLOCK, 2, 8, false),
  ISB_ENDTIME(BlockType.INTERFACE_STATISTICS_BLOCK, 3, 8, false),
  ISB_IFRECV(BlockType.INTERFACE_STATISTICS_BLOCK, 4, 8, false),
  ISB_IFDROP(BlockType.INTERFACE_STATISTICS_BLOCK, 5, 8, false),
  ISB_FILTERACCEPT(BlockType.INTERFACE_STATISTICS_BLOCK, 6, 8, false),
  ISB_OSDROP(BlockType.INTERFACE_STATISTICS_BLOCK, 7, 8, false),
  ISB_USRDELIV(BlockType.INTERFACE_STATISTICS_BLOCK, 8, 8, false),

  OPT_ENDOFOPT(null, 0, 0, false),
  OPT_COMMENT(null, 1, -1, true),
  OPT_CUSTOM_SAFETOCOPY_ASCII(null, 2988, -1, true),
  OPT_CUSTOM_SAFETOCOPY_BINARY(null, 2989, -1, false),
  OPT_CUSTOM_UNSAFETOCOPY_ASCII(null, 19372, -1, true),
  OPT_CUSTOM_UNSAFETOCOPY_BINARY(null, 19373, -1, true),

  UNKNOWN(null, Integer.MIN_VALUE, -1, false);

  private BlockType type;
  private int code;
  private int length; // -1 == VARIABLE
  private boolean isAscii;

  private static OptionType[] globalOptionTypes = { OPT_ENDOFOPT, OPT_COMMENT,
                                                    OPT_CUSTOM_SAFETOCOPY_ASCII,
                                                    OPT_CUSTOM_SAFETOCOPY_BINARY,
                                                    OPT_CUSTOM_UNSAFETOCOPY_ASCII,
                                                    OPT_CUSTOM_UNSAFETOCOPY_BINARY };

  private OptionType(final BlockType t, final int code, final int length,
      final boolean isAscii) {
    this.type = t;
    this.code = code;
    this.length = length;
    this.isAscii = isAscii;
  }

  public boolean isAscii() {
    return isAscii;
  }

  public int code() {
    return code;
  }

  /**
   * Length, of -1 for variable.
   *
   * @return
   */
  public int length() {
    return length;
  }

  public BlockType blockType() {
    return type;
  }

  /**
   * Returns the option type, or UNKNOWN.
   *
   * @param b
   * @param code
   * @return
   */
  public static OptionType lookup(final BlockType b, final int code) {
    for (OptionType ot : globalOptionTypes) {
      if (code == ot.code)
        return ot;
    }

    for (OptionType ot : OptionType.values()) {
      if (ot.type == b && ot.code == code)
        return ot;
    }
    return UNKNOWN;
  }
}
