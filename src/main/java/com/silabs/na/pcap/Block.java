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

import java.util.List;

/**
 * PcapNG format is made of blocks. This class abstracts one block.
 *
 * @author Timotej Ecimovic
 */
public class Block {

  private final BlockType type;
  private final Class<?> objectType;
  private final Object data;
  private final List<Option> options;

  private Block(final BlockType type, final List<Option> options,
      final Class<?> objectType, final Object data) {
    this.type = type;
    this.objectType = objectType;
    this.data = data;
    this.options = options;
  }

  /**
   * Create a block from a given object type.
   */
  public Block(final BlockType type, final Class<?> objectType, final Object o,
      final List<Option> options) {
    this(type, options, objectType, o);
  }

  public Option[] options() {
    if (options == null)
      return new Option[0];
    else
      return options.toArray(new Option[options.size()]);
  }

  public BlockType type() {
    return type;
  }

  public boolean containsDataOfType(final Class<?> dataType) {
    return objectType == dataType;
  }

  public Object data() {
    return data;
  }

  @Override
  public String toString() {
    return "Type: " + type.name();
  }
}
