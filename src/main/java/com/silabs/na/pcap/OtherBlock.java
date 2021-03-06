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
 * Block that is unknown and simply contains a binary blob.
 *
 * @author Timotej Ecimovic
 */
public class OtherBlock {

  private final byte[] body;

  /**
   * Create a block with a given payload.
   *
   * @param body
   *          Payload for the block.
   */
  public OtherBlock(final byte[] body) {
    this.body = body;
  }

  /**
   * Returns a binary content of this block, without any further breakdown.
   * 
   * @return block payload as a byte array.
   */
  public byte[] body() {
    return body;
  }

}
