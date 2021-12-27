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
import java.io.InputStream;
import java.io.PrintStream;
import java.net.URL;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

import com.silabs.na.pcap.util.ByteArrayUtil;

/**
 * Main class for the CLI interface. The only purpose of this class is to
 * provide an interface to a command line usage of a jar file.
 *
 * There is no other useful API here.
 *
 * @author Timotej Ecimovic
 */
public class Main {

  private enum Command {
    DUMP("print out the full information about all blocks in the file"),
    SUMMARY("print out the summary of the file");

    private String description;

    Command(final String description) {
      this.description = description;
    }
  }

  private final PrintStream out;

  private Main(final PrintStream out) {
    this.out = out;
  }

  private void usage() {
    out.println("Usage: java -jar silabs-pcap.jar [-v] [COMMAND] [PCAPFILE]");
    out.println("Valid commands:");
    for (Command c : Command.values()) {
      out.println("  " + c.name().toLowerCase() + ": " + c.description);
    }
  }

  private void printVersionAndExit() {
    String date = "unknown";
    String hash = "unknown";
    String version = "unknown";

    URL u = getClass().getClassLoader().getResource("build_pcap.stamp");
    if (u != null) {
      Properties p = new Properties();
      try {
        try (InputStream is = u.openStream()) {
          p.load(is);
        }
        date = p.getProperty("date");
        hash = p.getProperty("hash");
        version = p.getProperty("version");
      } catch (Exception e) {
        System.err.println("Error reading build information.");
      }
    }
    System.out.println("Library information:");
    System.out.println("  - version: " + version);
    System.out.println("  - date: " + date);
    System.out.println("  - hash: " + hash);
    System.exit(0);
  }


  private void run(final String[] args) {
    if (args.length == 0) {
      usage();
    } else if ( args[0].equals("-v")) {
      printVersionAndExit();
    } else {
      String commandS = args[0];
      Command actualCommand = null;
      for (Command c : Command.values()) {
        if (c.name().toLowerCase().equals(commandS.toLowerCase())) {
          actualCommand = c;
          break;
        }
      }
      if (actualCommand == null) {
        usage();
      } else {
        String path = args[1];
        try {
          switch (actualCommand) {
          case DUMP:
            dumpFile(path);
            break;
          case SUMMARY:
            summarizeFile(path);
            break;
          }
        } catch (IOException ioe) {
          out.println("Error processing file: " + path);
          out.println("Message: " + ioe.getMessage());
        }

      }
    }
  }

  private String formatOption(final BlockType type, final Option o) {
    boolean isAscii = false;

    OptionType ot = OptionType.lookup(type, o.code());
    if (ot != null)
      isAscii = ot.isAscii();
    StringBuilder sb = new StringBuilder();
    sb.append(o.code());
    if (ot != null) {
      sb.append(" (").append(ot.name()).append(")");
    }
    sb.append(": ");
    if (isAscii)
      sb.append(new String(o.value()));
    else
      sb.append(ByteArrayUtil.formatByteArray(o.value()));
    return sb.toString();
  }

  private void summarizeFile(final String path) throws IOException {
    File f = new File(path);
    Map<BlockType, Integer> blockTypeCounters = new LinkedHashMap<>();
    int n = 0;
    try (IPcapInput in = Pcap.openForReading(f)) {
      Block b;
      while ((b = in.nextBlock()) != null) {
        n++;
        Integer x = blockTypeCounters.get(b.type());
        if (x == null) {
          blockTypeCounters.put(b.type(), 1);
        } else {
          blockTypeCounters.put(b.type(), x + 1);
        }
      }
    }
    out.println("Total block count: " + n);
    out.println("Counts per block type: ");
    for (BlockType bt : blockTypeCounters.keySet()) {
      out.println("  - " + bt.name() + ": " + blockTypeCounters.get(bt));
    }
  }

  /**
   * Logic that gets executed on a file when the "dump" command is used.
   *
   * @param path
   *          String path of the file to open.
   * @throws IOException
   *           when underlying IO operation fails.
   */
  public void dumpFile(final String path) throws IOException {
    File f = new File(path);
    try (IPcapInput in = Pcap.openForReading(f)) {
      out.println("File type: " + in.type());
      Block b;
      int n = 0;
      while ((b = in.nextBlock()) != null) {
        out.println(String.format("Block #%06d", (n++)) + ": "
                    + b.type().name());
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
        out.println();
      }
    }
  }

  /**
   * Execution entry point.
   *
   * @param args
   *          Command line arguments.
   */
  public static void main(final String[] args) {
    Main m = new Main(System.out);
    m.run(args);
  }

}
