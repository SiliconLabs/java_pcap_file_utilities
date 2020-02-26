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
import java.util.ArrayList;
import java.util.List;

import com.silabs.na.pcap.Block;
import com.silabs.na.pcap.BlockType;
import com.silabs.na.pcap.ByteArrayUtil;
import com.silabs.na.pcap.IPcapInput;
import com.silabs.na.pcap.InterfaceDescriptionBlock;
import com.silabs.na.pcap.InterfaceStatisticsBlock;
import com.silabs.na.pcap.LinkType;
import com.silabs.na.pcap.Option;
import com.silabs.na.pcap.OptionType;
import com.silabs.na.pcap.OtherBlock;
import com.silabs.na.pcap.PacketBlock;
import com.silabs.na.pcap.SectionHeaderBlock;

/**
 * PCAP NG format: https://github.com/pcapng/pcapng/
 *
 * First 4 bytes must be: 0a0d0d0a, which is a section header block.
 *
 * This class is NOT thread safe. Different threads should create different
 * instance of this class.
 *
 * @author Timotej Ecimovic
 */
public class PcapngInputNio implements IPcapInput {

  static final int BYTE_ORDER_MAGIC = 0x1A2B3C4D;
  static final int BYTE_ORDER_MAGIC_LE = 0x4D3C2B1A;

  private final ReadableByteChannel rbc;

  private int currentSnapLen = 0; // Zero = no limit
  private boolean bigEndian;
  private boolean hasJustStarted;
  private int timeStampResolution = 6;

  // Reading utils
  private final ByteBuffer buffer = ByteBuffer.allocateDirect(1024);

  /**
   * Is is 4 bytes into it.
   *
   * @param is
   */
  public PcapngInputNio(final ReadableByteChannel rbc) {
    this.rbc = rbc;
    this.hasJustStarted = true;
  }

  @Override
  public String type() {
    return "pcapng";
  }

  @Override
  public void close() throws IOException {
    rbc.close();
  }

  private void skip(final int n) throws IOException {
    buffer.clear();
    buffer.limit(n);
    long howMany = rbc.read(buffer);
    if (howMany != n) {
      throw new IOException("Expected " + n + ", skipped " + howMany);
    }
  }

  // We process these differently because they contain endianess.
  private Block nextSectionHeaderBlock() throws IOException {

    int major;
    int minor;

    byte[] totalLength = BufferUtil.readBytesFromChannel(rbc, buffer, 4);
    byte[] bomBytes = BufferUtil.readBytesFromChannel(rbc, buffer, 4);

    int bom = ByteArrayUtil.byteArrayToInt(bomBytes, 0, 4, true);
    if (bom == PcapngInputNio.BYTE_ORDER_MAGIC) {
      // Big endian
      bigEndian = true;
      buffer.order(ByteOrder.BIG_ENDIAN);
    } else if (bom == BYTE_ORDER_MAGIC_LE) {
      bigEndian = false;
      buffer.order(ByteOrder.LITTLE_ENDIAN);
    } else {
      throw new IOException("Invalid byte order magic. Corrupt block.");
    }

    major = BufferUtil.readNByteIntFromChannel(rbc, buffer, 2);
    minor = BufferUtil.readNByteIntFromChannel(rbc, buffer, 2);

    byte[] sectionLen = BufferUtil.readBytesFromChannel(rbc, buffer, 8);
    int sectionLength = ByteArrayUtil
        .byteArrayToInt(sectionLen, 0, 8, bigEndian);

    // Total lengh is ENTIRE BLOCK, including the type and the 2 copies
    // of the length and so on.
    int totLen = ByteArrayUtil.byteArrayToInt(totalLength, 0, 4, bigEndian);

    // SHB eats 28 bytes for rest of crap.
    int optionLen = totLen - 28;

    List<Option> opts = null;

    if (optionLen > 0)
      opts = readOptions(optionLen);

    // And jump over final length
    skip(4);

    SectionHeaderBlock shb = new SectionHeaderBlock(bigEndian, major, minor,
                                                    sectionLength);

    return new Block(BlockType.SECTION_HEADER_BLOCK, shb.getClass(), shb, opts);
  }

  private List<Option> readOptions(final int expectedLen) throws IOException {
    List<Option> list = new ArrayList<>();
    int optionCode;
    int optionLen;
    int remaining = expectedLen;

    while (remaining > 0) {
      optionCode = BufferUtil.readNByteIntFromChannel(rbc, buffer, 2);
      optionLen = BufferUtil.readNByteIntFromChannel(rbc, buffer, 2);
      remaining -= 4;
      final int length = optionLen;

      byte[] optionData = BufferUtil.readBytesFromChannel(rbc, buffer, length);
      remaining -= optionLen;

      int rem = optionLen % 4;
      if (rem != 0) {
        skip(4 - rem); // Option padding
        remaining -= (4 - rem);
      }

      if (optionCode == 0 && optionLen == 0)
        break;

      Option opt = new Option(optionCode, optionData);
      list.add(opt);
    }

    return list;
  }

  private Block nextOtherBlock(final int typeCode,
                               final int totLen) throws IOException {
    byte[] body;
    if (totLen > 12) {
      body = BufferUtil.readBytesFromChannel(rbc, buffer, totLen - 12);
    } else {
      body = new byte[0];
    }
    OtherBlock ob = new OtherBlock(body);
    return new Block(BlockType.resolve(typeCode), ob.getClass(), ob, null);
  }

  private Block nextInterfaceStatisticsBlock(final int totLen) throws IOException {
    int interfaceId = BufferUtil.readNByteIntFromChannel(rbc, buffer, 4);
    byte[] timeHighLow = BufferUtil.readBytesFromChannel(rbc, buffer, 8);
    long timestamp = calculateNanoseconds(timeHighLow);

    List<Option> opts = null;
    int optLen = totLen - 24;
    if (optLen > 0) {
      opts = readOptions(optLen);
    }

    InterfaceStatisticsBlock isb = new InterfaceStatisticsBlock(interfaceId,
                                                                timestamp);
    return new Block(BlockType.INTERFACE_STATISTICS_BLOCK, isb.getClass(), isb,
                     opts);

  }

  private Block nextInterfaceDescriptionBlock(final int totLen) throws IOException {
    int linkType;
    int snapLen;
    List<Option> opts = null;

    linkType = BufferUtil.readNByteIntFromChannel(rbc, buffer, 2);
    BufferUtil.readNByteIntFromChannel(rbc, buffer, 2);
    snapLen = BufferUtil.readNByteIntFromChannel(rbc, buffer, 4);
    currentSnapLen = snapLen;

    int optLen = totLen - 20;
    if (optLen > 0) {
      opts = readOptions(optLen);
    }

    // We extract option code 9, which is timestamp resolution
    if (opts != null) {
      for (Option o : opts) {
        if (o.code() == OptionType.IF_TSRESOL.code()) {
          timeStampResolution = o.value()[0];
        }
      }
    }

    InterfaceDescriptionBlock idb = new InterfaceDescriptionBlock(LinkType
        .resolve(linkType), snapLen);
    return new Block(BlockType.INTERFACE_DESCRIPTION_BLOCK, idb.getClass(), idb,
                     opts);
  }

  private long calculateNanoseconds(final byte[] timeHighLow) {
    // Now calculate actual nanoseconds.
    byte[] time;
    if (bigEndian) {
      time = timeHighLow;
    } else {
      time = new byte[8];
      time[0] = timeHighLow[3];
      time[1] = timeHighLow[2];
      time[2] = timeHighLow[1];
      time[3] = timeHighLow[0];
      time[4] = timeHighLow[7];
      time[5] = timeHighLow[6];
      time[6] = timeHighLow[5];
      time[7] = timeHighLow[4];
    }
    long ns = ByteArrayUtil.byteArrayToLong(time, 0, 8, true); // This is always
                                                               // big
    // endian

    int remainingPrecision = 9 - timeStampResolution;
    while (remainingPrecision > 0) {
      remainingPrecision--;
      ns *= 10;
    }
    return ns;
  }

  private Block nextSimplePacketBlock(final int totLen) throws IOException {
    int packetLen = BufferUtil.readNByteIntFromChannel(rbc, buffer, 4);
    byte[] data = BufferUtil.readBytesFromChannel(rbc, buffer, totLen - 16);
    int actualLen = packetLen;
    if (currentSnapLen != 0 && currentSnapLen < actualLen)
      actualLen = currentSnapLen;

    byte[] actualData;
    if (actualLen < data.length) {
      actualData = new byte[actualLen];
      System.arraycopy(data, 0, actualData, 0, actualLen);
    } else {
      actualData = data;
    }
    PacketBlock pb = new PacketBlock(Long.MIN_VALUE, actualData);
    return new Block(BlockType.SIMPLE_PACKET_BLOCK, pb.getClass(), pb, null);
  }

  private Block nextEnhancedPacketBlock(final int totLen) throws IOException {

    BufferUtil.readNByteIntFromChannel(rbc, buffer, 4); // Interface ID

    byte[] timeHighLow = BufferUtil.readBytesFromChannel(rbc, buffer, 8);
    int capturedLength = BufferUtil.readNByteIntFromChannel(rbc, buffer, 4);
    BufferUtil.readNByteIntFromChannel(rbc, buffer, 4); // Original packet
                                                        // length

    final int length = capturedLength;

    byte[] data = BufferUtil.readBytesFromChannel(rbc, buffer, length);

    // Padding to 4-byte boundary
    int rem = capturedLength % 4;

    int actualLength = capturedLength;
    if (rem != 0) {
      actualLength += (4 - rem);
      skip(4 - rem); // padding
    }

    List<Option> opts = null;
    int optionsLength = totLen - ((8 * 4) + actualLength);
    if (optionsLength > 0)
      opts = readOptions(optionsLength);

    long ns = calculateNanoseconds(timeHighLow);

    PacketBlock pb = new PacketBlock(ns, data);
    return new Block(BlockType.ENHANCED_PACKET_BLOCK, pb.getClass(), pb, opts);

  }

  @Override
  public Block nextBlock() throws IOException {
    int typeCode;
    Block b;

    if (hasJustStarted) {
      typeCode = BlockType.SECTION_HEADER_BLOCK.typeCode();
      hasJustStarted = false;
    } else {
      buffer.clear();
      buffer.limit(4);
      int howMany = rbc.read(buffer);
      if (howMany == -1)
        return null; // EOF
      if (howMany != 4)
        throw new IOException("Insufficient data for block type");
      buffer.flip();
      typeCode = BufferUtil.readNByteIntFromBuffer(buffer, 4);
    }

    if (typeCode == BlockType.SECTION_HEADER_BLOCK.typeCode()) {
      // This is a section header, so we have separate processing for this,
      // since
      // we need to determine endianess.
      b = nextSectionHeaderBlock();
    } else {
      // Block starts with a length.
      int totLen = BufferUtil.readNByteIntFromChannel(rbc, buffer, 4);
      if (typeCode == BlockType.ENHANCED_PACKET_BLOCK.typeCode()) {
        b = nextEnhancedPacketBlock(totLen);
      } else if (typeCode == BlockType.INTERFACE_DESCRIPTION_BLOCK.typeCode()) {
        b = nextInterfaceDescriptionBlock(totLen);
      } else if (typeCode == BlockType.INTERFACE_STATISTICS_BLOCK.typeCode()) {
        b = nextInterfaceStatisticsBlock(totLen);
      } else if (typeCode == BlockType.SIMPLE_PACKET_BLOCK.typeCode()) {
        b = nextSimplePacketBlock(totLen);
      } else {
        b = nextOtherBlock(typeCode, totLen);
      }
      // There is always another copy of the length at the end.
      skip(4);
    }

    return b;
  }
}
