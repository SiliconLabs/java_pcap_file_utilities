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
 * A stream api to retrieve packets from the file.
 *
 * @author Timotej Ecimovic
 */
public interface IPcapInput extends Closeable {

  /**
   * Returns the type of the file.
   *
   * @return
   */
  public String type();

  /**
   * Returns the next packet block.
   *
   * @return
   */
  public Block nextBlock() throws IOException;
}
