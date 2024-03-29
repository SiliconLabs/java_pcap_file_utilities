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

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;

import com.silabs.na.pcap.BlockType;
import com.silabs.na.pcap.IPcapOutput;
import com.silabs.na.pcap.LinkType;
import com.silabs.na.pcap.Option;
import com.silabs.na.pcap.OptionType;
import com.silabs.na.pcap.Pcap;
import com.silabs.na.pcap.util.BufferUtil;

/**
 * Pcapng implementation of the output stream.
 *
 * @author Timotej Ecimovic
 */
public class PcapngOutput implements IPcapOutput {

  private FileChannel channel = null;
  private final List<Integer> timestampResolutions = new ArrayList<>();
  private final List<LinkType> linkTypes = new ArrayList<>();
  private int lastInterfaceIdWritten = -1; // Growing index

  /**
   * Creates the output stream for the pcapng. Note that this method does NOT write
   * the mandatory section header block. So you should do that immediatelly after the
   * opening of the file.
   * 
   * This method calls file open with WRITE, CREATE and TRUNCATE_EXISTING options,
   * so it effectivelly overwrite any file in place and resets it to zero length.
   * 
   * If you wish to append to existing file, use the other constructor and
   * use StandardOpenOption.APPEND
   *
   * @param f File to write into.
   * @throws IOException in case of failures with underlying operations.
   */
  public PcapngOutput(final File f) throws IOException {
    this(f, 
         StandardOpenOption.WRITE,
         StandardOpenOption.CREATE,
         StandardOpenOption.TRUNCATE_EXISTING);
  }

  /**
   * Creates the output stream for the pcapng. Note that this method does NOT write
   * the mandatory section header block. So you should do that immediatelly after the
   * opening of the file.
   * 
   * This method will truncate an existing file.
   *
   * @param f File to write into.
   * @param openOptions Standard open options passed to File channel. See {@link StandardOpenOption}.
   * @throws IOException in case of failures with underlying operations.
   */
  public PcapngOutput(final File f, StandardOpenOption... openOptions) throws IOException {
    channel = FileChannel.open(f.toPath(), openOptions);
  }

  private void writeBlock(final BlockType blockType,
                          final ByteBuffer data) throws IOException {
    int totalBlockLength = 12 + data.remaining();
    ByteBuffer bb = BufferUtil.createByteBuffer(totalBlockLength);
    bb.putInt(blockType.typeCode());
    bb.putInt(totalBlockLength);
    bb.put(data);
    bb.putInt(totalBlockLength);
    bb.flip();
    while (bb.hasRemaining())
      channel.write(bb);
  }

  private static void addOption(final ByteBuffer bb,
                                final int code,
                                final byte[] value) {
    bb.putShort((short) code);
    short len = (short) (value == null ? 0 : value.length);
    bb.putShort(len);
    if (len > 0) {
      int rem = BufferUtil.paddingLength(len, 4);
      bb.put(value);
      for (int i = 0; i < rem; i++)
        bb.put((byte) 0x00);
    }
  }

  /**
   * Returns the total length, in bytes, required by options.
   *
   * @param options
   * @return
   */
  private static int lengthOfOptions(final List<Option> options) {
    if ( options == null || options.isEmpty() )
      return 0;

    int totalSize = 4; // Start with 4 bytes for the terminating sentinel

    for ( Option o: options )
      totalSize += o.size();

    return totalSize;
  }

  private static void writeOptions(final ByteBuffer bb,
                                   final List<Option> options) {
    if (options == null || options.isEmpty())
      return;

    for (Option o : options) {
      addOption(bb, o.code(), o.value());
    }
    addOption(bb, 0, null);
  }

  /**
   * Writes an interface description block. You MUST write one of those before
   * you write enhanced packet block.
   *
   * @param linkType Link type for the block.
   * @param timestampResolution Timestamp resolution for the block. See Pcap.RESOLUTION_* constants.
   * @throws IOException in case of errors with underlying IO operations
   */
  @Override
  public int writeInterfaceDescriptionBlock(final LinkType linkType,
                                             final int timestampResolution) throws IOException {
    this.linkTypes.add(linkType);
    this.timestampResolutions.add(timestampResolution);

    int size = 8;
    List<Option> options = new ArrayList<>();
    if (timestampResolution != 6) {
      byte[] resol = new byte[1];
      resol[0] = (byte) timestampResolution;
      options.add(new Option(OptionType.IF_TSRESOL.code(), resol));
    }
    size += lengthOfOptions(options);
    ByteBuffer bb = BufferUtil.createByteBuffer(size);
    bb.putShort((short) linkType.code()); // Link type
    bb.putShort((short) 0); // reserved
    bb.putInt(0); // Snap len

    writeOptions(bb, options);

    bb.flip();
    writeBlock(BlockType.INTERFACE_DESCRIPTION_BLOCK, bb);
    lastInterfaceIdWritten++;
    return lastInterfaceIdWritten;
  }

  /**
   * Writes enhanced packet block.
   *
   * @param interfaceId Interface id of this packet. The interface description block with a given interface id
   * had to exist earlier in the file.
   * @param timestamp Timestamp in nanoseconds.
   * @param data Payload of the packet.
   */
  @Override
  public void writeEnhancedPacketBlock(final int interfaceId,
                                       final long timestamp,
                                       final byte[] data) throws IOException {
    int padding = BufferUtil.paddingLength(data.length, 4);
    int totLengh = 40 + data.length + padding;

    if (linkTypes.size() <= interfaceId
        || timestampResolutions.size() <= interfaceId) {
      throw new IOException("Can't write enhanced packet block with an interface ID index being larger than the number of previous interface description blocks.");
    }

    ByteBuffer bb = BufferUtil.createByteBuffer(totLengh);
    bb.putInt(interfaceId);
    bb.putInt((int) (timestamp >>> 32));
    bb.putInt((int) (timestamp & 0x00000000FFFFFFFFl));
    bb.putInt(data.length);
    bb.putInt(data.length);
    bb.put(data);
    for (int i = 0; i < padding; i++)
      bb.put((byte) 0x00);
    bb.flip();
    writeBlock(BlockType.ENHANCED_PACKET_BLOCK, bb);
  }

  /**
   * Writes a section header block.
   *
   * @param hardware String describing hardware used for creating this file.
   * @param osName String describing operating system used in creation of this file.
   * @param applicationName Name of the application creating the PCAPNG file.
   * @throws IOException in case of underlying IO exceptions.
   */
  public void writeSectionHeaderBlock(final String hardware,
                                      final String osName,
                                      final String applicationName) throws IOException {
    List<Option> options = new ArrayList<>();
    if ( hardware != null )
      options.add(new Option(OptionType.SHB_HARDWARE.code(), hardware.getBytes()));
    if ( osName != null )
      options.add(new Option(OptionType.SHB_OS.code(), osName.getBytes()));
    if ( applicationName != null )
      options.add(new Option(OptionType.SHB_USERAPPL.code(), applicationName.getBytes()));
    ByteBuffer bb = BufferUtil.createByteBuffer(16 + lengthOfOptions(options));
    bb.putInt(PcapngInputNio.BYTE_ORDER_MAGIC);
    bb.putShort((short) Pcap.PCAPNG_VERSION_MAJOR);
    bb.putShort((short) Pcap.PCAPNG_VERSION_MINOR);
    bb.putLong(0xFFFFFFFFFFFFFFFFl);
    writeOptions(bb, options);
    bb.flip();
    writeBlock(BlockType.SECTION_HEADER_BLOCK, bb);
  }

  /**
   * Closes the output stream.
   */
  @Override
  public void close() throws IOException {
    channel.close();
  }

}
