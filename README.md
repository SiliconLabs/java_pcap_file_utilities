# What is this?

Java-pcap is a java implementation of PCAP and PCAPNG file format.
This library provides classes and methods required to read both PCAP and
PCAPNG file format and write out the PCAPNG file format.

# How do I build this library?

You can build it using gradle via:
```
./gradlew jar
```
This will result in a file:

`build/libs/java-pcap-<VERSION>.jar`

# How do I use this library?

A quick and dirty way is to simply use the jar from command line:
```
java -jar build/libs/java-pcap-<VERSION>.jar <PCAP_FILE>
```
This will read the pcap or pcapng file provided and print out the details
from that file.

# Can I contribute to this library?

Yes, please do. Follow the normal github guidelines around pull requests and we will consider your submission and merge the code back into the library when approved.

# What are the APIs for reading a PCAP or PCAPNG file?

The simplest example of a loop that reads entire block inside the pcap or
pcapng file is as follows:
```
File f = ...;
try (IPcapInput in = Pcap.read(f)) {
    Block b;
    while ( (b=in.nextBlock()) != null ) {
        ... // do something with a block
    }
}
```

For a more detailed example, see the simple file creation and reading
in a unit test under:

`src/test/java/com/silabs.pcap/PcapTest.java`

# References

  * [Description of the PCAP format](https://wiki.wireshark.org/Development/LibpcapFileFormat)
  * [Description of the PCAPNG format](https://github.com/pcapng/pcapng/)
 

# License

This library was originally developed by Silicon Labs.
It is now provided as open source, licensed by [Apache 2.0 license](LICENSE-2.0.txt). 