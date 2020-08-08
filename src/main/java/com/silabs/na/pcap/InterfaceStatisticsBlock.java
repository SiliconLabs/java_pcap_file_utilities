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
 * Interface statistics block.
 *
 * @author Timotej Ecimovic
 */
public class InterfaceStatisticsBlock {

  private final int interfaceId;
  private final long timestamp;

  public InterfaceStatisticsBlock(final int interfaceId, final long timestamp) {
    this.interfaceId = interfaceId;
    this.timestamp = timestamp;
  }

  /**
   * Returns the interface ID that this block contains statistics for.
   * 
   * @return interface id
   */
  public int interfaceId() {
    return interfaceId;
  }

  /**
   * Returns the timestamp of the statistics block.
   *
   * @return timestamp
   */
  public long timestamp() {
    return timestamp;
  }

}
