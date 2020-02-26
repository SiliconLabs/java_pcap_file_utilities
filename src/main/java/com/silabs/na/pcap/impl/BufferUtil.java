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

package com.silabs.na.pcap.impl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.ReadableByteChannel;

import com.silabs.na.pcap.ByteArrayUtil;

/**
 * Local utility class.
 *
 * @author Timotej Ecimovic
 */
class BufferUtil {

  private BufferUtil() {
  }

  /**
   * Calculates the padding bytes to a given byte boundary.
   *
   * @param dataLength
   * @param byteBoundary
   * @return
   */
  static int paddingLength(final int dataLength, final int byteBoundary) {
    int rem = (dataLength % byteBoundary);
    if (rem == 0)
      return 0;
    else
      return byteBoundary - rem;
  }

  /**
   * Reads N bytes of integer from the channel, using an intermediate buffer and
   * it's endianess. Buffer will be cleared and flipped along the way, so don't
   * expect any data to be preserved in it.
   *
   * @param rbc
   * @param buffer
   * @param n
   * @return
   * @throws IOException
   */
  static int readNByteIntFromChannel(final ReadableByteChannel rbc,
                                     final ByteBuffer buffer,
                                     final int n) throws IOException {
    buffer.clear();
    buffer.limit(n);
    int howMany = rbc.read(buffer);
    if (howMany != n)
      throw new IOException("Reading " + n + " bytes, only " + howMany
          + " read.");
    buffer.flip();
    return readNByteIntFromBuffer(buffer, n);
  }

  /**
   * Read buffers from channel into a byte buffer.
   *
   * @param rbc
   * @param buffer
   * @param length
   * @return
   * @throws IOException
   */
  static byte[] readBytesFromChannel(final ReadableByteChannel rbc,
                                     final ByteBuffer buffer,
                                     final int length) throws IOException {
    buffer.clear();
    byte[] data = new byte[length];
    int totalRead = 0;
    // Read entire array from rbc.
    while (totalRead < length) {
      buffer.position(0);
      if (length - totalRead > buffer.capacity()) {
        buffer.limit(buffer.capacity());
      } else {
        buffer.limit(length - totalRead);
      }
      int readNow = rbc.read(buffer);
      if (readNow == -1)
        throw new IOException("Unexpected EOF.");
      buffer.flip();
      buffer.get(data, totalRead, readNow);
      totalRead += readNow;
    }
    return data;
  }

  /**
   * Reads a N byte integer from buffer and return it.
   *
   * @param buffer
   * @param n
   * @return
   */
  static int readNByteIntFromBuffer(final ByteBuffer buffer, final int n) {
    byte[] bytes = new byte[n];
    buffer.get(bytes);
    return ByteArrayUtil
        .byteArrayToInt(bytes, 0, n, buffer.order() == ByteOrder.BIG_ENDIAN);
  }

}
