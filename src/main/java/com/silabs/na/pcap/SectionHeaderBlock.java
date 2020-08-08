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

  /**
   * Creates a section header block with a given values.
   * 
   * @param bigEndian
   *          If true, then this section is big endian.
   * @param major
   *          Major version of the PCAPNG format used.
   * @param minor
   *          Minor version of a PCAPNG format used.
   * @param sectionLength
   *          Length of a section, in bytes. May be -1, "indicating
   *          unspecified".
   */
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

  /**
   * Major version of the PCAPNG format used.
   * 
   * @return major version
   */
  public int majorVersion() {
    return major;
  }

  /**
   * Minor version of the PCAPNG format used.
   * 
   * @return minor version
   */
  public int minorVersion() {
    return minor;
  }

  /**
   * Returns the information on endiannes of this section.
   *
   * @return true, if this section is big endian, false if little-endian
   */
  public boolean isBigEndian() {
    return bigEndian;
  }

  /**
   * Returns the information on endiannes of this section.
   *
   * @return true, if this section is little endian, false if big endian
   */
  public boolean isLittleEndian() {
    return !bigEndian;
  }

}
