# Control.Client.Udp Architecture

`PiSubmarine.Control.Client.Udp` is a transport adapter that implements `Control::Api::Input::ISink` for remote
operators.

It keeps lease acquisition and renewal inside the transport layer, injects the active lease id into outgoing
`OperatorCommand` payloads, serializes commands, and protects each UDP datagram with AEAD using:

- cleartext lease id as packet header and associated data
- lease secret as AEAD key
- nonce from `Security.Nonce.Api`
