# WebTrust Windows
A failed attempt to make wireless iOS pairing

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

## Important
- The endpoint must be reachable from the iPhone
- If you're testing from outside your home network, your router needs UDP forwarding for port 51820
- The server needs to be started as Administrator for tunnel install/start to work
