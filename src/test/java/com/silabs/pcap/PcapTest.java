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

package com.silabs.pcap;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.silabs.na.pcap.Block;
import com.silabs.na.pcap.IPcapInput;
import com.silabs.na.pcap.IPcapOutput;
import com.silabs.na.pcap.InterfaceDescriptionBlock;
import com.silabs.na.pcap.LinkType;
import com.silabs.na.pcap.PacketBlock;
import com.silabs.na.pcap.Pcap;
import com.silabs.na.pcap.SectionHeaderBlock;

/**
 * Unit test for the pcap library.
 *
 * @author Timotej Ecimovic
 */
class PcapTest {
  /**
   * Unit test that writes out a generated PCAPNG file into a temporary file,
   * then reads it back in, testing equality.
   *
   * @throws IOException
   */
  @Test
  void testWriteAndReadBack() throws IOException {
    final int PACKET_COUNT = 200;
    File f = File.createTempFile("test_", "pcap");
    f.deleteOnExit();

    try (IPcapOutput out = Pcap.openForWriting(f)) {
      out.writeInterfaceDescriptionBlock(LinkType.BACNET_MS_TP,
                                         Pcap.RESOLUTION_MICROSECONDS);
      for (int i = 10; i < 10 + PACKET_COUNT; i++) {
        byte[] data = new byte[i];
        Arrays.fill(data, (byte) i);
        out.writeEnhancedPacketBlock(0, i, data);
      }
    }

    try (IPcapInput in = Pcap.openForReading(f)) {
      Block block = in.nextBlock();
      Assertions.assertNotNull(block);
      Assertions.assertTrue(block.containsDataOfType(SectionHeaderBlock.class));
      SectionHeaderBlock shb = (SectionHeaderBlock) block.data();
      Assertions.assertEquals(Pcap.PCAPNG_VERSION_MAJOR, shb.majorVersion());
      Assertions.assertEquals(Pcap.PCAPNG_VERSION_MINOR, shb.minorVersion());

      block = in.nextBlock();
      Assertions.assertNotNull(block);
      Assertions.assertTrue(block
          .containsDataOfType(InterfaceDescriptionBlock.class));
      InterfaceDescriptionBlock idb = (InterfaceDescriptionBlock) block.data();
      Assertions.assertEquals(LinkType.BACNET_MS_TP, idb.linkType());

      int n = 0;
      while ((block = in.nextBlock()) != null) {
        Assertions.assertTrue(block.containsDataOfType(PacketBlock.class));
        PacketBlock pb = (PacketBlock) block.data();
        byte[] data = pb.data();
        Assertions.assertEquals(10 + n, data.length);
        byte[] expected = new byte[10 + n];
        Arrays.fill(expected, (byte) (10 + n));
        Assertions.assertArrayEquals(expected, data);
        n++;
      }
      Assertions.assertEquals(PACKET_COUNT, n);
    }
  }
}
