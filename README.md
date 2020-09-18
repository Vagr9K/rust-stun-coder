<div align="center" style="margin-bottom:30px">
    <a href='https://github.com/vagr9k/rust-stun-coder/blob/master/LICENSE'>
    <img src="https://img.shields.io/github/license/vagr9k/rust-stun-coder.svg" alt="Logo" />
    </a>
    <a href='https://github.com/vagr9k/rust-stun-coder'>
    <img src="https://img.shields.io/github/tag/vagr9k/rust-stun-coder.svg" alt="Logo" />
    </a>
    <a href='https://crates.io/crates/stun-coder'>
        <img src="https://img.shields.io/crates/v/stun-coder.svg" alt="Crates.io Version" />
    </a>
</div>


# STUN Coder

 STUN Coder is a STUN protocol encoder and decoder for Rust.
 The implementation is done according to [Session Traversal Utilities for NAT (STUN)](https://tools.ietf.org/html/rfc5389).
 STUN extensions specified by the [Interactive Connectivity Establishment (ICE) protocol](https://tools.ietf.org/html/rfc8445#section-7.1) are also supported.

## Usage

 An example of creating and encoding a STUN binding request:

```rust

 // Create a request message
 let message = stun_coder::StunMessage::create_request()
             .add_attribute(stun_coder::StunAttribute::Software {
                 description: String::from("rust-stun-coder"),
             })
             .add_message_integrity()
             .add_fingerprint();

 // Encode it into bytes
 let encoded_message = message.encode(Some("TEST_PASS")).unwrap();

 println!("{:#X?}", encoded_message);

```

 An example that decodes a sample request with Long-Term Authentication

 ```rust

 // Encoded message
 let msg_bytes: Vec<u8> = vec![
     0x01, 0x01, 0x00, 0x48, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34,
     0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x0b, 0x74, 0x65, 0x73, 0x74,
     0x20, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x00, 0x00, 0x20, 0x00, 0x14, 0x00, 0x02,
     0xa1, 0x47, 0x01, 0x13, 0xa9, 0xfa, 0xa5, 0xd3, 0xf1, 0x79, 0xbc, 0x25, 0xf4, 0xb5,
     0xbe, 0xd2, 0xb9, 0xd9, 0x00, 0x08, 0x00, 0x14, 0xBD, 0x3, 0x6D, 0x6A, 0x33, 0x17,
     0x50, 0xDF, 0xE2, 0xED, 0xC5, 0x8E, 0x64, 0x34, 0x55, 0xCF, 0xF5, 0xC8, 0xE2, 0x64,
     0x80, 0x28, 0x00, 0x04, 0x4F, 0x26, 0x02, 0x93,
 ];

 // Integrity key used for verification
 let integrity_key = Some("VOkJxbRl1RmTxUk/WvJxBt");

 // Decode the message
 let decoded_msg = stun_coder::StunMessage::decode(&msg_bytes, integrity_key).unwrap();

 println!("{:?}", decoded_msg);
```


 Example function that fetches the server reflexive address of all the local interfaces:

 ```rust
 use std::io::{Error, ErrorKind};
 use std::net::{SocketAddr, UdpSocket};

 // Fetches mapped address of a local Socket
 fn get_mapped_addr(binding_addr: SocketAddr) -> Result<SocketAddr, std::io::Error> {
     // Use Google's public STUN server
     let stun_server = "stun.l.google.com:19302";

     // Create a binding message
     let binding_msg = stun_coder::StunMessage::create_request()
         .add_attribute(stun_coder::StunAttribute::Software {
             description: String::from("rust-stun-coder"),
         }) // Add software attribute
         .add_message_integrity() // Add message integrity attribute
         .add_fingerprint(); // Add fingerprint attribute

     let integrity_pass = "STUN_CODER_PASS"; // Integrity password to use

     // Encode the binding_msg
     let bytes = binding_msg.encode(Some(integrity_pass)).unwrap();

     // Open a UDP socket
     let udp_socket = UdpSocket::bind(binding_addr)?;

     // Connect to the STUN server
     udp_socket.connect(stun_server.clone())?;

     // Send the binding request message
     udp_socket.send(&bytes)?;

     // Wait for a response
     let mut response_buf = [0; 32];
     udp_socket.recv(&mut response_buf)?;

     // Decode the response
     let stun_response =
         stun_coder::StunMessage::decode(&response_buf, Some(integrity_pass)).unwrap();

     // Find the XorMappedAddress attribute in the response
     // It will contain our reflexive transport address
     for attr in stun_response.get_attributes() {
         if let stun_coder::StunAttribute::XorMappedAddress { socket_addr } = attr {
             return Ok(*socket_addr);
         }
     }

     Err(Error::new(
         ErrorKind::InvalidData,
         "No XorMappedAddress has been set in response.",
     ))
 }

 // Fetches server reflexive addresses of local interfaces
 fn get_mapped_addresses() {
     // Gather local interfaces
     let local_interfaces = get_if_addrs::get_if_addrs().unwrap();

     // Attempt to get a mapped address for each one of them
     for interface in local_interfaces.iter() {
         // Exclude loopback interfaces
         if interface.is_loopback() {
             continue;
         }

         // Form a local socket for the interface on port 2000
         let host_addr = interface.ip();
         let binding_addr = SocketAddr::new(host_addr, 2000);

         match get_mapped_addr(binding_addr) {
             Ok(mapped_socket_addr) => {
                 println!(
                     "Mapped host address {} to remote {}.",
                     binding_addr, mapped_socket_addr
                 );
             }
             Err(err) => {
                 println!(
                     "Failed to map host address {}. Error: {}.",
                     binding_addr, err
                 );
             }
         }
     }
 }
 ```

## Author

Ruben Harutyunyan ([@Vagr9K](https://twitter.com/Vagr9K))
