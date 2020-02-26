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

/**
 * Section header block starts the pcapng files and contains sections.
 *
 * @author Timotej Ecimovic
 */
public class SectionHeaderBlock {

  private final boolean bigEndian;
  private final int major;
  private final int minor;
  private final int sectionLength;

  public SectionHeaderBlock(final boolean bigEndian, final int major,
      final int minor, final int sectionLength) {
    this.bigEndian = bigEndian;
    this.major = major;
    this.minor = minor;
    this.sectionLength = sectionLength;
  }

  @Override
  public String toString() {
    return "Section header: ver=" + major + "." + minor + ", len="
        + sectionLength + "," + (bigEndian ? "big endian" : "little endian");
  }

  public int majorVersion() {
    return major;
  }

  public int minorVersion() {
    return minor;
  }

  public boolean isBigEndian() {
    return bigEndian;
  }

  public boolean isLittleEndian() {
    return !bigEndian;
  }

}
