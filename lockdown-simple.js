const net = require('net');
const plist = require('plist');
const forge = require('node-forge');
const crypto = require('crypto');
const tls = require('tls');

class SimpleLockdownClient {
  constructor(deviceIp, port = 62078, debugCallback = null) {
    this.deviceIp = deviceIp;
    this.port = port;
    this.socket = null;
    this.label = 'WebTrust';
    this.hostId = this.generateUUID();
    this.debugCallback = debugCallback;
    this.debugLogs = [];
  }

  debug(step, message, data = null) {
    const timestamp = new Date().toISOString();
    const logEntry = { timestamp, step, message, data };
    this.debugLogs.push(logEntry);
    console.log(`[${timestamp}] [${step}] ${message}`, data ? JSON.stringify(data, null, 2) : '');
    if (this.debugCallback) {
      this.debugCallback(logEntry);
    }
  }

  generateUUID() {
    return crypto.randomUUID();
  }

  async connect() {
    this.debug('CONNECT_START', `Attempting to connect to ${this.deviceIp}:${this.port}`);
    return new Promise((resolve, reject) => {
      this.socket = net.createConnection(this.port, this.deviceIp, () => {
        this.debug('CONNECT_SUCCESS', `Successfully connected to ${this.deviceIp}:${this.port}`);
        resolve();
      });

      this.socket.on('error', (err) => {
        this.debug('CONNECT_ERROR', `Connection failed to ${this.deviceIp}:${this.port}`, { error: err.message });
        reject(err);
      });
      this.socket.setTimeout(10000);
    });
  }

  async sendPlist(dict) {
    const plistXml = plist.build(dict);
    const buffer = Buffer.from(plistXml, 'utf8');
    const lengthBuffer = Buffer.alloc(4);
    lengthBuffer.writeUInt32BE(buffer.length, 0);
    
    this.debug('SEND_PLIST', `Sending plist request: ${dict.Request || 'unknown'}`, { 
      request: dict.Request,
      size: buffer.length,
      plistXml: plistXml
    });
    
    return new Promise((resolve, reject) => {
      this.socket.write(Buffer.concat([lengthBuffer, buffer]), (err) => {
        if (err) {
          this.debug('SEND_PLIST_ERROR', 'Failed to send plist', { error: err.message });
          reject(err);
        }
        else {
          this.debug('SEND_PLIST_SUCCESS', 'Plist sent successfully');
          resolve();
        }
      });
    });
  }

  async receivePlist() {
    this.debug('RECEIVE_PLIST_START', 'Waiting for plist response');
    return new Promise((resolve, reject) => {
      let lengthBuffer = Buffer.alloc(0);
      
      const onLengthData = (data) => {
        lengthBuffer = Buffer.concat([lengthBuffer, data]);
        if (lengthBuffer.length >= 4) {
          this.socket.removeListener('data', onLengthData);
          const length = lengthBuffer.readUInt32BE(0);
          this.debug('RECEIVE_PLIST_LENGTH', `Received length header: ${length} bytes`);
          let payloadBuffer = Buffer.alloc(0);
          
          const onPayloadData = (data) => {
            payloadBuffer = Buffer.concat([payloadBuffer, data]);
            if (payloadBuffer.length >= length) {
              this.socket.removeListener('data', onPayloadData);
              try {
                const plistXml = payloadBuffer.toString('utf8');
                this.debug('RECEIVE_PLIST_RAW', 'Received raw plist XML', { xml: plistXml });
                const dict = plist.parse(plistXml);
                this.debug('RECEIVE_PLIST_SUCCESS', 'Plist parsed successfully', { 
                  result: dict.Result,
                  type: dict.Type,
                  request: dict.Request,
                  fullResponse: dict
                });
                resolve(dict);
              } catch (err) {
                this.debug('RECEIVE_PLIST_ERROR', 'Failed to parse plist', { error: err.message });
                reject(new Error('Failed to parse plist: ' + err.message + ' - XML: ' + payloadBuffer.toString('utf8')));
              }
            }
          };
          
          this.socket.on('data', onPayloadData);
        }
      };
      
      this.socket.on('data', onLengthData);
      this.socket.on('error', (err) => {
        this.debug('RECEIVE_PLIST_SOCKET_ERROR', 'Socket error while receiving plist', { error: err.message });
        reject(err);
      });
      this.socket.setTimeout(10000);
    });
  }

  async startSession() {
    this.debug('START_SESSION_START', 'Starting session');
    const request = {
      Label: this.label,
      HostID: this.hostId,
      Request: 'StartSession'
    };
    
    await this.sendPlist(request);
    const response = await this.receivePlist();
    this.debug('START_SESSION_RESPONSE', 'Received StartSession response', { 
      result: response.Result,
      sessionId: response.SessionID,
      enableSSL: response.EnableSessionSSL,
      fullResponse: response
    });
    
    if (response.Result && response.Result !== 'Success') {
      this.debug('START_SESSION_FAILED', 'StartSession failed', { result: response.Result });
      throw new Error('StartSession failed: ' + response.Result);
    }
    
    this.debug('START_SESSION_SUCCESS', 'Session started successfully', { 
      sessionId: response.SessionID,
      enableSSL: response.EnableSessionSSL
    });
    return {
      sessionId: response.SessionID,
      enableSSL: response.EnableSessionSSL
    };
  }

  async captureDeviceCertificateViaTLS() {
    this.debug('CAPTURE_CERT_START', 'Starting TLS certificate capture using proper lockdownd protocol');
    
    try {
      // Step 1: Connect with plaintext socket
      this.debug('CAPTURE_CERT_CONNECT', 'Connecting to device via plaintext');
      await this.connect();
      
      // Step 2: Send StartSession on the same socket
      this.debug('CAPTURE_CERT_START_SESSION', 'Sending StartSession request');
      const sessionResult = await this.startSession();
      this.debug('CAPTURE_CERT_SESSION_RESULT', 'StartSession response', sessionResult);
      
      // Step 3: If device wants SSL, upgrade the SAME socket to TLS
      if (sessionResult.enableSSL) {
        this.debug('CAPTURE_CERT_UPGRADE_TLS', 'Upgrading socket to TLS');
        
        return new Promise((resolve, reject) => {
          this.socket = tls.connect({
            socket: this.socket,
            rejectUnauthorized: false,
          });

          this.socket.once('secureConnect', () => {
            this.debug('CAPTURE_CERT_SECURE_CONNECTED', 'TLS handshake completed');
            try {
              const cert = this.socket.getPeerCertificate(true);
              this.debug('CAPTURE_CERT_RECEIVED', 'Peer certificate received', {
                subject: cert.subject,
                issuer: cert.issuer,
                serialNumber: cert.serialNumber,
                valid_from: cert.valid_from,
                valid_to: cert.valid_to,
                fingerprint256: cert.fingerprint256
              });
              
              if (!cert || !cert.raw) {
                this.debug('CAPTURE_CERT_NO_CERT', 'No peer certificate returned');
                resolve(null);
                this.socket.end();
                return;
              }
              
              // Convert DER to base64
              const certBase64 = Buffer.from(cert.raw).toString('base64');
              this.debug('CAPTURE_CERT_SUCCESS', 'Certificate extracted successfully', {
                certLength: cert.raw.length,
                base64Length: certBase64.length
              });
              
              this.socket.end();
              resolve(certBase64);
            } catch (err) {
              this.debug('CAPTURE_CERT_ERROR', 'Error getting peer certificate', { error: err.message });
              this.socket.end();
              reject(err);
            }
          });

          this.socket.once('error', (err) => {
            this.debug('CAPTURE_CERT_SOCKET_ERROR', 'TLS socket error', { error: err.message });
            reject(err);
          });

          this.socket.setTimeout(10000, () => {
            this.debug('CAPTURE_CERT_TIMEOUT', 'TLS connection timed out');
            this.socket.destroy(new Error('TLS timeout'));
            reject(new Error('TLS timeout'));
          });
        });
      } else {
        this.debug('CAPTURE_CERT_NO_SSL', 'Device did not request SSL');
        return null;
      }
    } catch (err) {
      this.debug('CAPTURE_CERT_PROTOCOL_ERROR', 'Error in lockdownd protocol', { error: err.message });
      throw err;
    }
  }

  extractPublicKeyFromCertificate(certBase64) {
    this.debug('EXTRACT_PUBKEY_START', 'Extracting public key from certificate using crypto.X509Certificate');
    
    try {
      // Decode base64 to get DER bytes
      const certDerBytes = Buffer.from(certBase64, 'base64');
      this.debug('EXTRACT_PUBKEY_DER_DECODED', 'Certificate DER decoded', { 
        derLength: certDerBytes.length
      });
      
      // Use Node's crypto.X509Certificate to parse the certificate
      const x509 = new crypto.X509Certificate(certDerBytes);
      this.debug('EXTRACT_PUBKEY_CERT_PARSED', 'Certificate parsed using crypto.X509Certificate', {
        subject: x509.subject,
        issuer: x509.issuer,
        serialNumber: x509.serialNumber,
        validFrom: x509.validFrom,
        validTo: x509.validTo,
        fingerprint: x509.fingerprint
      });
      
      // Extract public key using Node's crypto API
      const publicKeyPem = String(x509.publicKey.export({ format: 'pem', type: 'spki' }));
      this.debug('EXTRACT_PUBKEY_EXTRACTED', 'Public key extracted from certificate', {
        publicKeyPem: publicKeyPem
      });
      
      // Also get the public key in base64 format (without PEM headers)
      const publicKeyBase64 = publicKeyPem
        .replace('-----BEGIN PUBLIC KEY-----', '')
        .replace('-----END PUBLIC KEY-----', '')
        .replace(/\s+/g, '')
        .trim();
      
      this.debug('EXTRACT_PUBKEY_SUCCESS', 'Public key extraction complete', {
        publicKeyPem: publicKeyPem,
        publicKeyBase64: publicKeyBase64,
        publicKeyLength: publicKeyBase64.length
      });
      
      return {
        publicKeyPem,
        publicKeyBase64,
        certificate: {
          subject: x509.subject,
          issuer: x509.issuer,
          serialNumber: x509.serialNumber,
          validFrom: x509.validFrom,
          validTo: x509.validTo,
          fingerprint: x509.fingerprint
        }
      };
    } catch (e) {
      this.debug('EXTRACT_PUBKEY_ERROR', 'Error extracting public key from certificate', { 
        error: e.message,
        stack: e.stack 
      });
      throw e;
    }
  }

  async getSessionAndExtractPublicKey() {
    this.debug('MAIN_START', 'Extracting public key from device via TLS');
    
    try {
      // Capture device certificate via TLS handshake
      this.debug('MAIN_CAPTURE_CERT', 'Attempting to capture device certificate via TLS');
      const deviceCertBase64 = await this.captureDeviceCertificateViaTLS();
      
      if (!deviceCertBase64) {
        this.debug('MAIN_NO_CERT', 'Failed to capture device certificate');
        throw new Error('Failed to capture device certificate');
      }
      
      this.debug('MAIN_CERT_CAPTURED', 'Device certificate captured', {
        certLength: deviceCertBase64.length
      });
      
      // Extract public key from certificate
      const publicKeyInfo = this.extractPublicKeyFromCertificate(deviceCertBase64);
      
      this.debug('MAIN_SUCCESS', 'Successfully extracted public key from device certificate', {
        publicKeyInfo: publicKeyInfo
      });
      
      return {
        deviceCertificate: deviceCertBase64,
        publicKeyInfo
      };
    } catch (e) {
      this.debug('MAIN_ERROR', 'Error in public key extraction', {
        error: e.message,
        stack: e.stack
      });
      throw e;
    }
  }

  disconnect() {
    this.debug('DISCONNECT', 'Disconnecting from device');
    if (this.socket) {
      this.socket.end();
      this.socket = null;
    }
    this.debug('DISCONNECT_DONE', 'Disconnected');
  }
}

module.exports = SimpleLockdownClient;
