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

package com.silabs.na.pcap.util;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.ReadableByteChannel;

/**
 * Local utility class.
 *
 * @author Timotej Ecimovic
 */
public class BufferUtil {

  private BufferUtil() {
  }

  /**
   * Calculates the padding bytes to a given byte boundary.
   *
   * @param dataLength   Length of the data.
   * @param byteBoundary Byte boundary.
   * @return the number of bytes that should be added to the padding.
   */
  public static int paddingLength(final int dataLength, final int byteBoundary) {
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
   * @param rbc    Byte channel for reading.
   * @param buffer The temporary buffer used for the operation.
   * @param n      Number of bytes that make up the int.
   * @return Integer value of the read buffer.
   * @throws IOException if something fails with underlying IO operations.
   */
  public static int readNByteIntFromChannel(final ReadableByteChannel rbc,
                                            final ByteBuffer buffer,
                                            final int n) throws IOException {
    buffer.clear();
    buffer.limit(n);
    int howMany = rbc.read(buffer);
    if (howMany != n)
      throw new IOException("Reading " + n + " bytes, only " + howMany + " read.");
    buffer.flip();
    return readNByteIntFromBuffer(buffer, n);
  }

  /**
   * Read buffers from channel into a byte buffer.
   *
   * @param rbc    Byte channel for reading.
   * @param buffer The temporary buffer used for the operation.
   * @param length Number of bytes to read.
   * @return Bytes that were read.
   * @throws IOException if something fails with underlying IO operations.
   */
  public static byte[] readBytesFromChannel(final ReadableByteChannel rbc,
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
   * @param buffer Buffer from which to read bytes.
   * @param n      Number of bytes that make up an integer.
   * @return Integer value.
   */
  public static int readNByteIntFromBuffer(final ByteBuffer buffer, final int n) {
    byte[] bytes = new byte[n];
    buffer.get(bytes);
    return ByteArrayUtil.byteArrayToInt(bytes, 0, n, buffer.order() == ByteOrder.BIG_ENDIAN);
  }

  /**
   * This method creates a byte buffer, possibly changing the endianess from the default java
   * bit endian, into little endian, if that's the local platform.
   * 
   * @param size Size of buffer to allocate initially.
   * @return {@link ByteBuffer}
   */
  public static ByteBuffer createByteBuffer(int size) {
    ByteBuffer bb = ByteBuffer.allocateDirect(size);
    // Wireshark is sensitive to byte order. If the files from live interface are not in the
    // the same order as the native byte order of the machine it complains. Hence we 
    // set this to native byte order by default.
    bb.order(ByteOrder.nativeOrder());
    return bb;
  }

}
