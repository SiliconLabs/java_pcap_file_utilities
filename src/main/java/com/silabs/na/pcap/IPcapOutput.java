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

import java.io.Closeable;
import java.io.IOException;

/**
 * Output stream of PCAPNG data.
 *
 * @author Timotej Ecimovic
 */
public interface IPcapOutput extends Closeable {
  /**
   * Writes the enhanced packet block.
   *
   * @param interfaceId Id of the interface for the enhanced packet block.
   * @param timestamp Timestamp in nanoseconds.
   * @param data Payload for the output.
   * @throws IOException in case of errors with underlying IO operations.
   */
  public void writeEnhancedPacketBlock(int interfaceId,
                                       long timestamp,
                                       byte[] data) throws IOException;

  /**
   * Writes the interface description block. Each consequent call to this method
   * assign a growing index to these blocks. The interfaceId argument to the
   * writeEnhancedPacketBlock() must correspond to these.
   *
   * Consequently, you are NOT allowed to call writeEnhancedPacketBlock without
   * previously calling writeInterfaceDescriptionBlock().
   *
   * @param linkType Link type for the data from this interface.
   * @param timestampResolution See Pcap.RESOLUTION constants.
   * @throws IOException in case of errors with underlying IO operations.
   */
  public void writeInterfaceDescriptionBlock(final LinkType linkType,
                                             final int timestampResolution) throws IOException;
}
