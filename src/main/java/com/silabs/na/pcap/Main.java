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
import java.io.IOException;
import java.io.PrintStream;

/**
 * Main class for the CLI interface.
 *
 * @author Timotej Ecimovic
 */
public class Main {

  private final PrintStream out;

  private Main(final PrintStream out) {
    this.out = out;
  }

  private void usage() {
    out.println("Usage: java -jar silabs-pcap.jar [PCAPFILE]");
  }

  private void run(final String[] args) {
    if (args.length == 0) {
      usage();
    } else {
      try {
        analyzeFile(args[0]);
      } catch (IOException ioe) {
        out.println("Error reading file: " + args[0]);
        out.println("Message: " + ioe.getMessage());
      }
    }
  }

  private String formatOption(final BlockType type, final Option o) {
    boolean isAscii = false;

    OptionType ot = OptionType.lookup(type, o.code());
    if (ot != null)
      isAscii = ot.isAscii();

    if (isAscii)
      return o.code() + ": " + new String(o.value());
    else
      return o.code() + ": " + ByteArrayUtil.formatByteArray(o.value());
  }

  private void analyzeFile(final String path) throws IOException {
    File f = new File(path);
    try (IPcapInput in = Pcap.openForReading(f)) {
      out.println("File type: " + in.type());
      Block b;
      int n = 0;
      while ((b = in.nextBlock()) != null) {
        out.println(String.format("%06d", (n++)) + ": " + b.type().name());
        if (b.containsDataOfType(PacketBlock.class)) {
          PacketBlock pb = (PacketBlock) b.data();
          out.println("  - nanoseconds: " + pb.nanoseconds());
          out.println("  - packet: "
              + ByteArrayUtil.formatByteArray(pb.data()));
        } else if (b.containsDataOfType(SectionHeaderBlock.class)) {
          SectionHeaderBlock shb = (SectionHeaderBlock) b.data();
          out.println("  - endianess: "
              + (shb.isBigEndian() ? "big endian" : "little endian"));
          out.println("  - version: " + shb.majorVersion() + "."
              + shb.minorVersion());
        } else if (b.containsDataOfType(InterfaceDescriptionBlock.class)) {
          InterfaceDescriptionBlock idb = (InterfaceDescriptionBlock) b.data();
          out.println("  - link type: " + idb.linkType().name());
        } else if (b.containsDataOfType(InterfaceStatisticsBlock.class)) {
          InterfaceStatisticsBlock isb = (InterfaceStatisticsBlock) b.data();
          out.println("  - interface: " + isb.interfaceId());
          out.println("  - nanoseconds: " + isb.timestamp());
        } else if (b.containsDataOfType(OtherBlock.class)) {
          OtherBlock ob = (OtherBlock) b.data();
          out.println("  - body: " + ByteArrayUtil.formatByteArray(ob.body()));
        }
        if (b.options() != null && b.options().length > 0) {
          out.println("  - options:");
          for (Option o : b.options()) {
            out.println("    - " + formatOption(b.type(), o));
          }
        }
      }
    }
  }

  public static void main(final String[] args) {
    Main m = new Main(System.out);
    m.run(args);
  }

}
