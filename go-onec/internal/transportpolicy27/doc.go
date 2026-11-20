// Package transportpolicy27 implements an experimental, explicitly selected
// subset of the native 8.3.27.2342 transport policy. It has no network or native
// library dependencies. Product connections use it only through explicit
// transport-policy selection, independently of the advertised build.
//
// The supported subset is a fresh 1024-bit RSA key, an empty known-key ID,
// #base64 binary fields, levels n/c and cipher mode zero (DES-EDE3-CBC).
// The first reply is encrypted even for n; c uses serialized request/reply
// exchanges with an incremented little-endian IV and a level marker. This
// protocol compatibility code does not establish peer authentication.
//
// Source: exact rtrsrvc.dll SHA-256
// ef8aac04965cafcf35252be1d3bfec237d88e52215f3db3b14c7e59b4d3ba310,
// inet.dll SHA-256
// b404bbf08bfeb1a2c6b58c64af69fb24f563c94444a4e0ce01cda919fdba98af,
// and core83.dll SHA-256
// 83001ee41c5368a9ae6c73fd9a1a58fb2129db462cf882baceac4ce2877ef0d9.
// Evidence anchors are recorded alongside each operation. Original COM-client
// exchanges with synthetic peers do not establish Go-client interoperability
// with a native server. Tests here use public synthetic data.
package transportpolicy27
