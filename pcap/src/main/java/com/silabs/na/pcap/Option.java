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

import com.silabs.na.pcap.util.BufferUtil;

/**
 * Options are TLVs at the end of the blocks.
 *
 * @author Timotej Ecimovic
 */
public class Option {
  private final int code;
  private final byte[] value;

  /**
   * Creates an option with given type and value.
   *
   * @param code
   *          Code of option.
   * @param value
   *          Value of option.
   */
  public Option(final int code, final byte[] value) {
    this.code = code;
    this.value = value;
  }

  /**
   * Returns the code of option.
   *
   * @return code of option.
   */
  public int code() {
    return code;
  }

  /**
   * Returns the value of option.
   *
   * @return value of option.
   */
  public byte[] value() {
    return value;
  }

  /**
   * Returns the total size of this option in bytes. The size includes the
   * entire length including 2 byte code, 2 byte length and padding.
   *
   * @return Total option size in bytes.
   */
  public int size() {
    return 4 + value.length + BufferUtil.paddingLength(value.length, 4);
  }
}
