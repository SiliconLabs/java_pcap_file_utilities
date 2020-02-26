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
public class InterfaceDescriptionBlock {

  private final LinkType linkType;
  private final int snapLen;

  public InterfaceDescriptionBlock(final LinkType linkType, final int snapLen) {
    this.linkType = linkType;
    this.snapLen = snapLen;
  }

  @Override
  public String toString() {
    return "IDB: linkType=" + linkType + ", snapLen = " + snapLen;
  }

  public LinkType linkType() {
    return linkType;
  }

  public int snapLen() {
    return snapLen;
  }
}
