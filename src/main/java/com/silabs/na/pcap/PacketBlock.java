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

import com.silabs.na.pcap.util.ByteArrayUtil;

/**
 * Single packet read from PCAP or PCAPNG.
 *
 * @author Timotej Ecimovic
 */
public class PacketBlock {

  private final long nanoseconds;
  private final byte[] data;

  /**
   * Creates a new packet block with given timestamp and data.
   *
   * @param nanoseconds
   *          Timestamp.
   * @param data
   *          Data inside this packet.
   */
  public PacketBlock(final long nanoseconds, final byte[] data) {
    this.nanoseconds = nanoseconds;
    this.data = data;
  }

  @Override
  public String toString() {
    return String
        .format("%d ns: %s", nanoseconds, ByteArrayUtil.formatByteArray(data));
  }

  /**
   * Byte array that contain the payload of this packet.
   * 
   * @return byte array
   */
  public byte[] data() {
    return data;
  }

  /**
   * Returns time in nanosecond precision. It is possible to return
   * Lang.MIN_VALUE in case of simple packet block which does not contain
   * timestamp.
   *
   * @return nanoseconds
   */
  public long nanoseconds() {
    return nanoseconds;
  }
}
