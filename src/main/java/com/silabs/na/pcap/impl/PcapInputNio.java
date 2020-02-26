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

import com.silabs.na.pcap.Block;
import com.silabs.na.pcap.BlockType;
import com.silabs.na.pcap.IPcapInput;
import com.silabs.na.pcap.PacketBlock;

/**
 * The PCAP implementation variant.
 * https://wiki.wireshark.org/Development/LibpcapFileFormat
 *
 * @author Timotej Ecimovic
 */
public class PcapInputNio implements IPcapInput {

  public static final int MAGIC = 0xa1b2c3d4;
  public static final int NANOSEC_MAGIC = 0xa1b23c4d;

  private final boolean isNanosec;

  private final int majorVersion;
  private final int minorVersion;
  private final int snaplen;
  private final int network;

  private final ReadableByteChannel rbc;
  private final ByteBuffer buffer;

  // Starts the pcap stream, with the is rolled up at 4 bytes into it.
  public PcapInputNio(final ReadableByteChannel rbc, final boolean isBigEndian,
      final boolean isNanosec) throws IOException {
    this.rbc = rbc;
    this.isNanosec = isNanosec;
    this.buffer = ByteBuffer.allocateDirect(1024);
    buffer.order(isBigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
    buffer.position(0);
    buffer.limit(20);
    if (rbc.read(buffer) != 20)
      throw new IOException("Insufficient data for global header");
    buffer.flip();
    this.majorVersion = BufferUtil.readNByteIntFromBuffer(buffer, 2);
    this.minorVersion = BufferUtil.readNByteIntFromBuffer(buffer, 2);

    // Ignore 4 bytes of thiszone, we don't need this.
    // Ignore 4 bytes of sigfigs: always 0
    buffer.position(buffer.position() + 8);

    this.snaplen = BufferUtil.readNByteIntFromBuffer(buffer, 4);
    this.network = BufferUtil.readNByteIntFromBuffer(buffer, 4);
  }

  public String version() {
    return majorVersion + "." + minorVersion;
  }

  public int network() {
    return network;
  }

  public int snapLen() {
    return snaplen;
  }

  /**
   * Returns next packet block, or null when at the end of the file.
   *
   * @return
   * @throws IOException
   */
  @Override
  public Block nextBlock() throws IOException {
    long sec;
    long usec;
    int inclLen;
    int bytesReadCounter;

    buffer.position(0);
    buffer.limit(16);

    bytesReadCounter = rbc.read(buffer);

    if (bytesReadCounter == -1) // EOF
      return null;

    if (bytesReadCounter != 16)
      throw new IOException("Insufficient data for packet header");

    buffer.flip();
    sec = BufferUtil.readNByteIntFromBuffer(buffer, 4);
    usec = BufferUtil.readNByteIntFromBuffer(buffer, 4);
    inclLen = BufferUtil.readNByteIntFromBuffer(buffer, 4);
    // Skip orig len

    buffer.clear();
    byte[] data = BufferUtil.readBytesFromChannel(rbc, buffer, inclLen);

    // We're using the obsolete packet block for this case.
    long t;
    if (isNanosec) {
      t = sec * 1000000000 + usec;
    } else {
      t = sec * 1000000000 + usec * 1000;
    }
    PacketBlock pb = new PacketBlock(t, data);
    return new Block(BlockType.PACKET_BLOCK, pb.getClass(), pb, null);
  }

  @Override
  public String type() {
    return "pcap";
  }

  @Override
  public void close() throws IOException {
    rbc.close();
  }
}
