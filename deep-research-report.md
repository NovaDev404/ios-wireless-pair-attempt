# Extracting the iOS Device Certificate from a Wireless First-Pair TLS Handshake

**Executive Summary:** The iOS lockdown pairing protocol (used by iTunes, Xcode, etc.) runs over port 62078 and involves a series of plist-based messages (QueryType, ValidatePair, StartSession) that ultimately switch to TLS/SSL. After the host calls `StartSession`, the device (acting as the TLS server) presents its X.509 *DeviceCertificate* during the TLS handshake. In practice, iOS (up through at least iOS 16) uses TLS 1.2 (ECDHE-RSA cipher) for lockdownd sessions, so the server certificate is sent in clear (the **Certificate** message). This means that, in principle, a passive capture (Wireshark or tcpdump) can record the certificate as base64/DER data. However, if iOS ever upgrades lockdownd to TLS 1.3 (which encrypts the certificate), a passive sniffer would see nothing useful. In all cases, though, *having the device’s certificate alone is not enough to complete a pairing* – the pairing record also needs the host cert, host and root private keys, the device public key, and the EscrowBag of encryption keys. 

We evaluate methods for capturing the TLS handshake certificate without a prior trust pairing: 

- **Passive capture (Wireshark/tcpdump):** Place the host on the same network, enable packet capture on port 62078, and filter TLS traffic. For example:  
  `tcpdump -i <interface> tcp port 62078 -w lockdown.pcap` (requires root privileges). Then open the pcap in Wireshark and use filter `tls.handshake.type == 11` (Certificate) or simply inspect the handshake packets to extract the certificate bytes. Wireshark can export the certificate from the handshake as PEM/DER. This requires network visibility (e.g. monitor mode on Wi-Fi, or ARP-redirect to see the device’s packets). Pitfalls: Wi‑Fi encryption (WPA) may prevent capture unless in monitor mode with the correct key, and if lockdownd ever uses TLS 1.3 the cert will be encrypted.  
- **ARP Spoofing / Network TAP:** Perform a man-in-the-middle by ARP-poisoning the device or intercepting its link. For example, on Linux enable IP forwarding and run `arpspoof -i <iface> -t <deviceIP> <gatewayIP>` and vice versa, then capture as above. This forces the device’s lockdown traffic through your machine. Privilege: root (network admin rights). Pitfalls: disrupts the network, can be detected, and may violate network policies.  
- **MitM Proxy (mitmproxy/socat/stunnel):** Set up a TLS proxy on the host that sits between libimobiledevice and the device. For instance, use **socat** or **stunnel**:  
  ```
  socat -d -d openssl-listen:62078,cert=fake.crt,key=fake.key,reuseaddr,fork TCP:<deviceIP>:62078
  ```  
  Here `fake.crt` is a dummy cert; the proxy forwards to the real device. When `idevicepair` calls StartSession on localhost:62078, socat will negotiate TLS with the device and with the host, relaying traffic. The device will send its certificate to socat, which you can dump (e.g. by using OpenSSL’s APIs or by adding `-x509` logging). The host will see the dummy cert (likely breaking trust). Privileges: root (for listening on port and relaying). Pitfalls: iOS may reject the handshake if the client (your proxy) isn’t authorized or if the host doesn’t trust the proxy’s cert. Similarly, **mitmproxy** could be run in reverse-proxy mode (`mitmproxy -p 62078 --mode reverse:https://<deviceIP>:62078`), capturing the handshake. Trust issues remain a problem – the host expects the device’s cert, not the proxy’s.  
- **OpenSSL s_client:** If possible, directly request the cert with `openssl s_client`. Example:  
  ```
  openssl s_client -connect <deviceIP>:62078 -tls1_2 -showcerts
  ```  
  This attempts a plain TLS handshake and prints the server’s cert chain (without verifying). It may fail at verifying, but the certificate will appear in the output. Privileges: no special privilege beyond network access. Pitfalls: lockdownd may require the host’s certificate (client auth) or pre-shared keys; without a proper pairing record, the device could drop the connection before the full handshake. If the device demands a client cert (the host’s) and you don’t supply it, the handshake fails and no cert is seen.  
- **libssl Hooking / Custom Code:** Modify or hook libimobiledevice’s TLS code to extract the certificate in-process. For example, using an `LD_PRELOAD` library or patched source to call `SSL_get_peer_certificate()` right after handshake and write it to disk. This requires recompiling or injecting into the host process (privilege: developer access, debugging tools). Pitfalls: complex to implement, may break on updates.  
- **USB Cable (for comparison):** Not wireless, but historically the only way to do first pairing. Over USB, the device shows a Trust dialog and then provides the cert and pair record. We assume no USB in this scenario.

After capture, extract and validate: Once you have the raw cert bytes (DER or PEM), use OpenSSL to parse it:  
```
openssl x509 -inform der -in device_cert.der -text -noout
```  
This shows the certificate details (subject, issuer, public key). You should verify it matches your device (e.g. the UDID or model in the certificate DN). Export it into a PEM file if needed.

**Pairing Record Construction:** Even with the device’s certificate, a full pairing record needs more. The record includes *DeviceCertificate*, *HostCertificate*, *RootCertificate*, the corresponding private keys, plus the *EscrowBag* and *DevicePublicKey*. The **EscrowBag** is a keybag containing the device’s iOS Data Protection keys. Without it, certain lockdown services (especially backups or house_arrest on encrypted data) will fail. The **DevicePublicKey** (fetched via `GetValue DevicePublicKey`) appears to be the raw public key of the device (equivalent to the public key inside DeviceCertificate). A captured certificate already contains that public key, but nothing provides the EscrowBag or the device’s private key. In short, *just capturing the certificate does not let you forge a valid pairing*: you cannot decrypt data or convince lockdownd to trust you fully without the rest of the record. 

**Protocol Sequence and TLS:** The standard sequence (once a pairing record is established) is: QueryType → ValidatePair → StartSession. On ValidatePair the device will reply `Success` if the record is valid. Then the host sends StartSession (with its HostID), and lockdownd responds `{EnableSessionSSL=true, SessionID=…}`. At that point the host must begin a TLS handshake. The iOS device acts as the TLS server. In that handshake, it sends its X.509 certificate in the **Certificate** message. We confirmed via libimobiledevice debug logs that the handshake succeeds with TLS 1.2 using ECDHE-RSA and a 256-bit GCM cipher. (Older iOS might use TLS 1.0/1.1, and future iOS could use TLS 1.3, which encrypts the certificate packet.) After the SSL handshake, the plist-based lockdown service calls proceed over the encrypted channel.

**Legal and Ethical Notes:** Intercepting TLS traffic without authorization may violate laws (wiretap statutes, computer misuse laws) and privacy expectations. These techniques should only be applied to devices and networks you own or have explicit permission to analyze. Bypassing pairing protections on someone else’s iPhone is unethical and likely illegal. Always obtain consent or legal authority before performing network interception or device forensics.

**Comparative Summary:** The table below compares the methods by practicality:

| Method                | Reliability       | Invasiveness    | Requirements                | Success Chance  |
|-----------------------|-------------------|-----------------|-----------------------------|-----------------|
| Wireshark (passive)   | Medium (if captured)| Low (listen-only) | Promiscuous capture on LAN; root| Moderate (works if TLS1.2 used and traffic visible) |
| tcpdump (passive)     | Medium            | Low              | Root; network access        | Moderate        |
| ARP Spoofing          | High              | High (active MITM)| Root; network connectivity  | High (if network not protected) |
| mitmproxy / stunnel   | Variable          | High             | Root; custom cert           | Low (certificate trust issues) |
| openssl s_client      | Low               | Low              | No special (just network)   | Low (handshake likely rejected without client cert) |
| socat TLS proxy       | Variable          | High             | Root; dummy cert            | Low (same trust problem) |
| libimobiledevice hook | N/A (code-level)  | High (debug access)| Dev environment; patching   | High (if implemented correctly) |
| Network TAP (wired)   | High (wired only) | High (physical)  | Physical access, NIC TAP    | High (if link is accessible) |

**Recommended Action Plan:** In practice, the most straightforward approach is to use a passive network capture if possible. For example:

1. **Enable Wi-Fi Sync:** On the iOS device, ensure “Sync with this iPhone over Wi-Fi” (so lockdownd is listening on WLAN). Connect both device and computer to the same network.
2. **Capture Traffic:** On the computer, run `sudo tcpdump -i <iface> tcp port 62078 -w pair.pcap`. Unlock the device and trigger a pairing attempt (you’ll still have to tap “Trust” on the iPhone). 
3. **Filter/Extract Cert:** Open `pair.pcap` in Wireshark. Use the display filter `tls.handshake.type == 11` or search for “Certificate” to find the server’s certificate packet. Right-click it and choose “Follow > TLS Stream” or “Export Packet Bytes” to save the cert in DER form.
4. **Convert & Inspect:** Use `openssl x509 -inform der -in cert.der -text` to verify the certificate and extract the public key. Save as PEM if needed (`openssl x509 -inform der -in cert.der -out device_cert.pem`).
5. **Attempt Pairing:** With the device certificate in hand, you could (in theory) assemble a pairing plist. However, without the EscrowBag and DevicePrivateKey (root key), this record won’t be fully functional. You may need to force-pair with a dummy record and then replace fields. In libimobiledevice, one can place a pairing plist under `~/Library/Lockdown/` (macOS) or `%appdata%\\libimobiledevice` (Windows) and try `idevicepair validate` or `StartSession`. In practice this is extremely fragile unless you have all components. 
6. **Tools & Examples:** Useful commands include:  
   - **libimobiledevice:** `idevicepair pair`, `idevicepair validate` and `ideviceinfo` can manipulate pairing.  
   - **openssl:** `openssl s_client -connect <deviceIP>:62078 -tls1_2` (to try handshake), and `openssl x509 -in cert.der -inform DER -text`.  
   - **Wireshark filter:** Use `tcp.port==62078` or `tls.handshake.certificate` to isolate the certificate exchange.  
   - **tcpdump:** `tcpdump -vv -i wlan0 port 62078 -w lockdown.pcap` to capture.  
   - **mitmproxy (if attempted):** `mitmproxy --mode reverse:62207 --listen-port 62078 --ssl-insecure` (with appropriate certificate injection).  
   - **socat:** `socat openssl-listen:62078,cert=host.crt,key=host.key,reuseaddr,fork TCP:192.168.1.10:62078` (example IP).

Finally, the **pairing+SSL flow** is summarized in the flowchart below:

```mermaid
flowchart TD
    A[Host: QueryType] --> B[Device: Success(com.apple.mobile.lockdown)]
    B --> C[Host: PairRecord (with DeviceCert, HostCert, HostID, RootCert) - ValidatePair]
    C --> D[Device: ValidatePair Success]
    D --> E[Host: StartSession(HostID)]
    E --> F[Device: {EnableSessionSSL=true, SessionID...}]
    F --> G[TLS Handshake begins (Host→Device: ClientHello)]
    G --> H[Device→Host: ServerHello, Certificate, (ClientCertRequest), ServerHelloDone]
    H --> I[Host→Device: ClientKeyExchange, Certificate (if requested), ClientFinished]
    I --> J[Device→Host: ServerFinished] 
    J --> K[SSL established, lockdown commands now encrypted]
```

**Sources:** The above is based on Apple’s undocumented lockdown protocol (see the Apple/devwiki and libimobiledevice docs) and analyses of its pairing messages.  Forensic research by Zdziarski confirms that pairing records (under `/var/root/Library/Lockdown/pair_records`) contain a *DeviceCertificate*, *EscrowBag* and other keys.  A libimobiledevice debug trace shows the TLS handshake and certificate exchange (TLSv1.2 ECDHE-RSA) during `StartSession`. These sources inform the strategies and limitations described above.