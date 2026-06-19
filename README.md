# WebTrust Windows
A failed attempt to make wireless iOS pairing  
For working wireless RPPairing pairing on iOS 27, check out [StephenDev0/StikPair](https://github.com/StephenDev0/StikPair).

---
`lockdown-client` - My original attempt at full wireless pairing file generation  
`lockdown-simple` - My second attempt to just extract the public key from the devicecertificate from a request  
`server.js` - The main server code


## Run
1. Install WireGuard for Windows
2. Install Node.js
3. In the project folder run:

npm install
npm start

Open the site in your browser.

## What to do
- Click **Start server tunnel**
- Download the **client .conf**
- Import it into the WireGuard app on iPhone
- Turn the tunnel on

When the handshake reaches the server, the page shows **Connection received!**
