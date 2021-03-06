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

package com.silabs.na.pcap.util;

/**
 * Various static utilities for dealing with byte arrays and formatting them.
 *
 * Created on Jul 26, 2005
 *
 * @author Timotej Ecimovic
 */
public class ByteArrayUtil {

  // Don't want to instantiate this class.
  private ByteArrayUtil() {
  }

  /**
   * Formats a byte array with possible spaces between bytes.
   *
   * @param raw Byte array to format.
   * @param useSpace flag to specify if space should be present between each byte.
   * @return Byte array formatted as a String.
   */
  public static String formatByteArray(final byte[] raw,
                                       final boolean useSpace) {
    if (raw == null)
      return null;
    return formatByteArray(raw, 0, raw.length, useSpace, true);
  }

  /**
   * Simple formatting of byte array into a "ab cd ef" kind of a string
   * @param raw Byte array to format.
   * @return Byte array formatted as a String.
   */
  public static String formatByteArray(final byte[] raw) {
    return formatByteArray(raw, true);
  }

  /**
   * Formats a byte array into a string.
   *
   * @param raw Byte array to format.
   * @param start Start index into raw byte.
   * @param length Number of bytes to use from start index.
   * @param useSpace If true, then put space characted between bytes.
   * @param upperCase If true, then hex values are in uppercase, otherwise lowercase.
   * @return Formatted byte array.
   */
  public static String formatByteArray(final byte[] raw,
                                       final int start,
                                       final int length,
                                       final boolean useSpace,
                                       final boolean upperCase) {
    if (raw == null)
      return null;
    StringBuilder result = new StringBuilder();
    formatByteArray(raw, start, length, useSpace, false, upperCase, result);
    return result.toString();
  }

  // Formats byte array into the provided string buffer.
  // This is the bottom-most method that does the actual work.
  // upper level API methods call this with various arguments
  private static final char[] LOWER_CASE = { '0', '1', '2', '3', '4', '5', '6',
                                             '7', '8', '9', 'a', 'b', 'c', 'd',
                                             'e', 'f' };
  private static final char[] UPPER_CASE = { '0', '1', '2', '3', '4', '5', '6',
                                             '7', '8', '9', 'A', 'B', 'C', 'D',
                                             'E', 'F' };

  private static void formatByteArray(final byte[] raw,
                                      final int start,
                                      final int length,
                                      final boolean useSpace,
                                      final boolean use0xPrefixAndComma,
                                      final boolean useUpperCase,
                                      final StringBuilder result) {
    if (raw == null)
      return;
    char[] charArray;
    if (useUpperCase)
      charArray = UPPER_CASE;
    else
      charArray = LOWER_CASE;
    for (int i = start; i < (start + length); i++) {
      if (useSpace && (i != start))
        result.append((use0xPrefixAndComma ? ", " : " "));
      if (use0xPrefixAndComma) {
        result.append("0x");
      }
      try {
        byte nibHi = (byte) ((raw[i] >> 4) & 0x000F);
        byte nibLo = (byte) (raw[i] & 0x000F);
        // Speed up. The toHexInt() is ridiculous, as it
        // allocates 32 bytes for each digit, and runs GC up against the wall.
        // In case of ISD, which does HUGE amount of these calls, it becomes
        // the single largest source of GC activity.
        // So this is implementation that doesn't use any heap,
        // just few bytes of stack.
        result.append(charArray[nibHi]);
        result.append(charArray[nibLo]);
      } catch (ArrayIndexOutOfBoundsException e) {
        result.append("  ");
      }
    }

  }

  /**
   * Converts an array of bytes into an unsigned integer. The length should be
   * at most 4. When the length is 4 bytes, is there a way to make sure this an
   * unsigned integer without using a long?
   *
   * @param raw Byte array to read into integer.
   * @param offset Start index for reading.
   * @param length How many bytes to read.
   * @param bigEndian True if the laid out integer is in big-endian format.
   * @return Integer value
   * @throws ArrayIndexOutOfBoundsException if specified offset and length don't fit into the array.
   */
  public static int byteArrayToInt(final byte[] raw,
                                   final int offset,
                                   final int length,
                                   final boolean bigEndian) {
    int value = 0;
    int index = bigEndian ? (offset + length) - 1 : offset;
    int increment = bigEndian ? -1 : 1;
    for (int i = 0; i < length; i++) {
      value += (raw[index] & 0xFF) << (8 * i);
      index += increment;
    }
    return value;
  }

  /**
   * Takes a long and lays it out into a destination array in big- or
   * little-endian format. It will use 8 bytes of the array.
   *
   * @param value Long value to convert.
   * @param dest Destination byte array. Should be at least 8 long.
   * @param offset Offset into the byte array where the value should be put.
   * @param bigEndian True if the bytes should be laid out in big endian order.
   * @throws ArrayIndexOutOfBoundsException if there is not enough space.
   */
  public static void longToByteArray(final long value,
                                     final byte[] dest,
                                     final int offset,
                                     final boolean bigEndian) {
    long v = value;
    for (int i = 0; i < 8; i++) {
      int index = bigEndian ? offset + 7 - i : offset + i;
      dest[index] = (byte) (v & 0x00FF);
      v >>= 8;
    }
  }

  /**
   * Converts an array of bytes into a long. The length should be at most 8.
   *
   * @param raw
   *          Byte array for input.
   * @param offset
   *          Index into the byte array where reading should start.
   * @param length
   *          How many bytes to read.
   * @param bigEndian
   *          If true, the big-endian byte order is assumed.
   * @return long value
   * @throws ArrayIndexOutOfBoundsException
   *           if something is wrong with indexes.
   */
  public static long byteArrayToLong(final byte[] raw,
                                     final int offset,
                                     final int length,
                                     final boolean bigEndian) {
    long value = 0;
    int index = bigEndian ? (offset + length) - 1 : offset;
    int increment = bigEndian ? -1 : 1;
    for (int i = 0; i < length; i++) {
      value |= ((long) (raw[index] & 0x00FF)) << (8 * i);
      index += increment;
    }
    return value;
  }

}
