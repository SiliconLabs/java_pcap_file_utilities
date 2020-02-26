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

package com.silabs.pcap;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.silabs.na.pcap.ByteArrayUtil;

/**
 * Unit test for the utilities that are part of the pcap library.
 *
 * @author Timotej Ecimovic
 */
class UtilTest {

  /**
   * Tests the byte formatting.
   */
  @Test
  public void testByteArrayUtil() {
    byte[] test = { 0x01, 0x02, (byte)0xAA, (byte)0xBB };
    String formatted = ByteArrayUtil.formatByteArray(test);
    Assertions.assertEquals("01 02 AA BB", formatted);

    formatted = ByteArrayUtil.formatByteArray(test, false);
    Assertions.assertEquals("0102AABB", formatted);

    byte[] test2 = { 0x01, 0x02, (byte)0xAA, (byte)0xBB, 0x42, 0x33 };
    formatted = ByteArrayUtil.formatByteArray(test2, 1, 4, false, false);
    Assertions.assertEquals("02aabb42", formatted);
  }
}
