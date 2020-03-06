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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import com.silabs.na.pcap.impl.PcapInputNio;
import com.silabs.na.pcap.impl.PcapngInputNio;
import com.silabs.na.pcap.impl.PcapngOutput;
import com.silabs.na.pcap.util.ByteArrayUtil;

/**
 * Entry level API for pcap support.
 *
 * @author Timotej Ecimovic
 */
public class Pcap {

  public static final int RESOLUTION_MICROSECONDS = 6;
  public static final int RESOLUTION_NANOSECONDS = 9;

  public static final int PCAPNG_VERSION_MAJOR = 1;
  public static final int PCAPNG_VERSION_MINOR = 0;

  private Pcap() {
  }

  /**
   * Returns true if this file is of a correct type.
   *
   * @param f
   * @return
   * @throws IOException
   */
  public static boolean isFileCorrectType(final File f) {
    try {
      openForReading(f).close();
      return true;
    } catch (IOException ioe) {
      return false;
    }
  }

  public static IPcapOutput openForWriting(final File f) throws IOException {
    return openForWriting(f,
                          System.getProperty("os.arch"),
                          System.getProperty("os.name") + ", ver " + System.getProperty("os.version"),
                          "java-pcap");
  }

  public static IPcapOutput openForWriting(final File f,
                                           final String hardware,
                                           final String osName,
                                           final String applicationName) throws IOException {
    PcapngOutput po = new PcapngOutput(f);
    po.writeSectionHeaderBlock(hardware, osName, applicationName);
    return po;
  }

  /**
   * Opens a static file and returns the pcap stream.
   *
   * @param f
   * @return
   * @throws IOException
   */
  @SuppressWarnings("resource")
  public static IPcapInput openForReading(final File f) throws IOException {

    FileInputStream fis = new FileInputStream(f);
    byte[] magic = new byte[4];
    if (fis.read(magic) != 4) {
      fis.close();
      throw new IOException("Insufficient data.");
    }

    int magicBE = ByteArrayUtil.byteArrayToInt(magic, 0, 4, true);
    if (magicBE == BlockType.SECTION_HEADER_BLOCK.typeCode())
      return new PcapngInputNio(fis.getChannel());

    if (magicBE == PcapInputNio.MAGIC)
      return new PcapInputNio(fis.getChannel(), true, false);

    if (magicBE == PcapInputNio.NANOSEC_MAGIC)
      return new PcapInputNio(fis.getChannel(), true, true);

    int magicLE = ByteArrayUtil.byteArrayToInt(magic, 0, 4, false);
    if (magicLE == PcapInputNio.MAGIC)
      return new PcapInputNio(fis.getChannel(), false, false);
    if (magicLE == PcapInputNio.NANOSEC_MAGIC)
      return new PcapInputNio(fis.getChannel(), false, true);

    fis.close();
    throw new IOException("Invalid PCAP file format.");

  }
}
