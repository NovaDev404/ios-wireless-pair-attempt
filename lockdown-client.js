const net = require('net');
const plist = require('plist');
const forge = require('node-forge');
const crypto = require('crypto');
const tls = require('tls');

class LockdownClient {
  constructor(deviceIp, port = 62078, debugCallback = null) {
    this.deviceIp = deviceIp;
    this.port = port;
    this.socket = null;
    this.label = 'WebTrust';
    this.hostId = this.generateUUID();
    this.systemBUID = this.generateBUID();
    this.pairRecord = null;
    this.debugCallback = debugCallback;
    this.debugLogs = [];
  }

  debug(step, message, data = null) {
    const timestamp = new Date().toISOString();
    const logEntry = { timestamp, step, message, data };
    this.debugLogs.push(logEntry);
    if (this.debugCallback) {
      this.debugCallback(logEntry);
    }
  }

  generateUUID() {
    return crypto.randomUUID();
  }

  generateBUID() {
    // Generate a random BUID (Base Unique Identifier)
    const bytes = crypto.randomBytes(16);
    return bytes.toString('base64').replace(/[+/=]/g, '').substring(0, 40);
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
    
    this.debug('SEND_PLIST', `Sending plist request: ${dict.Request || dict.Request || 'unknown'}`, { 
      request: dict.Request,
      size: buffer.length 
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
                const dict = plist.parse(plistXml);
                this.debug('RECEIVE_PLIST_SUCCESS', 'Plist parsed successfully', { 
                  result: dict.Result,
                  type: dict.Type,
                  request: dict.Request
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

  async queryType() {
    this.debug('QUERY_TYPE_START', 'Querying lockdown service type');
    await this.sendPlist({
      Label: this.label,
      Request: 'QueryType'
    });
    
    const response = await this.receivePlist();
    this.debug('QUERY_TYPE_RESPONSE', 'Received QueryType response', { 
      result: response.Result,
      type: response.Type 
    });
    
    // Some iOS versions don't include Result field in QueryType response
    // If Type is present and correct, consider it successful
    if (response.Result && response.Result !== 'Success') {
      this.debug('QUERY_TYPE_FAILED', 'QueryType failed', { result: response.Result });
      throw new Error('QueryType failed: ' + response.Result + ' - Response: ' + JSON.stringify(response));
    }
    
    if (!response.Type) {
      this.debug('QUERY_TYPE_FAILED', 'QueryType failed - no Type field');
      throw new Error('QueryType failed: no Type field in response - Response: ' + JSON.stringify(response));
    }
    
    this.debug('QUERY_TYPE_SUCCESS', `Service type confirmed: ${response.Type}`);
    return response.Type;
  }

  async getDevicePublicKey() {
    this.debug('GET_DEVICE_PUBLIC_KEY_START', 'Requesting device public key');
    await this.sendPlist({
      Label: this.label,
      Request: 'GetValue',
      Key: 'DevicePublicKey'
    });
    
    const response = await this.receivePlist();
    this.debug('GET_DEVICE_PUBLIC_KEY_RESPONSE', 'Received GetValue response', { 
      result: response.Result,
      hasValue: !!response.Value,
      valueLength: response.Value ? response.Value.length : 0
    });
    
    if (response.Result && response.Result !== 'Success') {
      this.debug('GET_DEVICE_PUBLIC_KEY_FAILED', 'GetValue failed', { result: response.Result });
      throw new Error('GetValue failed: ' + response.Result);
    }
    
    if (!response.Value) {
      this.debug('GET_DEVICE_PUBLIC_KEY_FAILED', 'GetValue failed - no Value field');
      throw new Error('GetValue failed: no Value field in response - Response: ' + JSON.stringify(response));
    }
    
    this.debug('GET_DEVICE_PUBLIC_KEY_SUCCESS', 'Device public key retrieved', { 
      keyLength: response.Value.length 
    });
    return response.Value;
  }

  generateHostCertificates() {
    this.debug('GEN_HOST_CERTS_START', 'Generating host certificates');
    
    // Generate RSA key pair for host
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const publicKey = forge.pki.publicKeyToPem(keys.publicKey);
    const privateKey = forge.pki.privateKeyToPem(keys.privateKey);
    this.debug('GEN_HOST_CERTS_HOST_KEY', 'Host RSA key pair generated');
    
    // Generate root CA certificate
    const rootKeys = forge.pki.rsa.generateKeyPair(2048);
    const rootPrivateKey = forge.pki.privateKeyToPem(rootKeys.privateKey);
    const rootCert = forge.pki.createCertificate();
    rootCert.publicKey = rootKeys.publicKey;
    rootCert.serialNumber = '01';
    rootCert.validity.notBefore = new Date();
    rootCert.validity.notAfter = new Date();
    rootCert.validity.notAfter.setFullYear(rootCert.validity.notBefore.getFullYear() + 10);
    rootCert.setSubject([{ name: 'commonName', value: 'WebTrust Root CA' }]);
    rootCert.setIssuer([{ name: 'commonName', value: 'WebTrust Root CA' }]);
    rootCert.setExtensions([{
      name: 'basicConstraints',
      cA: true
    }]);
    rootCert.sign(rootKeys.privateKey);
    this.debug('GEN_HOST_CERTS_ROOT_CA', 'Root CA certificate generated');
    
    // Generate host certificate
    const hostCert = forge.pki.createCertificate();
    hostCert.publicKey = keys.publicKey;
    hostCert.serialNumber = '02';
    hostCert.validity.notBefore = new Date();
    hostCert.validity.notAfter = new Date();
    hostCert.validity.notAfter.setFullYear(hostCert.validity.notBefore.getFullYear() + 1);
    hostCert.setSubject([{ name: 'commonName', value: this.hostId }]);
    hostCert.setIssuer(rootCert.subject.attributes);
    hostCert.setExtensions([{
      name: 'basicConstraints',
      cA: false
    }]);
    hostCert.sign(rootKeys.privateKey);
    this.debug('GEN_HOST_CERTS_HOST_CERT', 'Host certificate generated', { hostId: this.hostId });
    
    // Convert certificates to PEM and then to base64
    const rootCertPem = forge.pki.certificateToPem(rootCert);
    const hostCertPem = forge.pki.certificateToPem(hostCert);
    
    const rootCertBase64 = Buffer.from(rootCertPem).toString('base64');
    const hostCertBase64 = Buffer.from(hostCertPem).toString('base64');
    
    this.debug('GEN_HOST_CERTS_SUCCESS', 'Host certificates generated and encoded');
    
    return {
      HostCertificate: hostCertBase64,
      RootCertificate: rootCertBase64,
      HostID: this.hostId,
      SystemBUID: this.systemBUID,
      HostPrivateKey: privateKey,
      RootPrivateKey: rootPrivateKey
    };
  }

  generatePairRecord(devicePublicKey) {
    // Generate RSA key pair for host
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const publicKey = forge.pki.publicKeyToPem(keys.publicKey);
    const privateKey = forge.pki.privateKeyToPem(keys.privateKey);
    
    // Generate root CA certificate
    const rootKeys = forge.pki.rsa.generateKeyPair(2048);
    const rootPrivateKey = forge.pki.privateKeyToPem(rootKeys.privateKey);
    const rootCert = forge.pki.createCertificate();
    rootCert.publicKey = rootKeys.publicKey;
    rootCert.serialNumber = '01';
    rootCert.validity.notBefore = new Date();
    rootCert.validity.notAfter = new Date();
    rootCert.validity.notAfter.setFullYear(rootCert.validity.notBefore.getFullYear() + 10);
    rootCert.setSubject([{ name: 'commonName', value: 'WebTrust Root CA' }]);
    rootCert.setIssuer([{ name: 'commonName', value: 'WebTrust Root CA' }]);
    rootCert.setExtensions([{
      name: 'basicConstraints',
      cA: true
    }]);
    rootCert.sign(rootKeys.privateKey);
    
    // Generate host certificate
    const hostCert = forge.pki.createCertificate();
    hostCert.publicKey = keys.publicKey;
    hostCert.serialNumber = '02';
    hostCert.validity.notBefore = new Date();
    hostCert.validity.notAfter = new Date();
    hostCert.validity.notAfter.setFullYear(hostCert.validity.notBefore.getFullYear() + 1);
    hostCert.setSubject([{ name: 'commonName', value: this.hostId }]);
    hostCert.setIssuer(rootCert.subject.attributes);
    hostCert.setExtensions([{
      name: 'basicConstraints',
      cA: false
    }]);
    hostCert.sign(rootKeys.privateKey);
    
    // Parse device public key
    const deviceKeyData = Buffer.from(devicePublicKey, 'base64');
    const deviceKey = forge.pki.publicKeyFromAsn1(forge.asn1.fromDer(deviceKeyData));
    
    // Generate device certificate
    const deviceCert = forge.pki.createCertificate();
    deviceCert.publicKey = deviceKey;
    deviceCert.serialNumber = '03';
    deviceCert.validity.notBefore = new Date();
    deviceCert.validity.notAfter = new Date();
    deviceCert.validity.notAfter.setFullYear(deviceCert.validity.notBefore.getFullYear() + 1);
    deviceCert.setSubject([{ name: 'commonName', value: 'Device' }]);
    deviceCert.setIssuer(rootCert.subject.attributes);
    deviceCert.setExtensions([{
      name: 'basicConstraints',
      cA: false
    }]);
    deviceCert.sign(rootKeys.privateKey);
    
    // Convert certificates to PEM and then to base64
    const rootCertPem = forge.pki.certificateToPem(rootCert);
    const hostCertPem = forge.pki.certificateToPem(hostCert);
    const deviceCertPem = forge.pki.certificateToPem(deviceCert);
    
    const rootCertBase64 = Buffer.from(rootCertPem).toString('base64');
    const hostCertBase64 = Buffer.from(hostCertPem).toString('base64');
    const deviceCertBase64 = Buffer.from(deviceCertPem).toString('base64');
    
    return {
      DeviceCertificate: deviceCertBase64,
      HostCertificate: hostCertBase64,
      RootCertificate: rootCertBase64,
      HostID: this.hostId,
      SystemBUID: this.systemBUID,
      HostPrivateKey: privateKey,
      RootPrivateKey: rootPrivateKey
    };
  }

  async pair() {
    this.debug('PAIR_START', 'Starting pairing process');
    
    // NEW APPROACH: Try to extract device certificate via TLS handshake BEFORE pairing
    this.debug('PAIR_EXTRACT_CERT_BEFORE_PAIR', 'Attempting to extract device certificate via TLS handshake before pairing');
    let deviceCertBase64 = null;
    
    try {
      // Try to extract certificate from TLS handshake
      deviceCertBase64 = await this.captureDeviceCertificateViaTLS();
      if (deviceCertBase64) {
        this.debug('PAIR_EXTRACT_CERT_SUCCESS', 'Device certificate extracted successfully via TLS handshake');
      } else {
        this.debug('PAIR_EXTRACT_CERT_FAILED', 'Could not extract device certificate via TLS, will try GetValue');
      }
    } catch (e) {
      this.debug('PAIR_EXTRACT_CERT_ERROR', 'Error during TLS certificate extraction', { error: e.message });
    }
    
    // If TLS extraction failed, try GetValue for DevicePublicKey
    let devicePublicKey = null;
    if (!deviceCertBase64) {
      this.debug('PAIR_GET_DEVICE_KEY', 'Trying to get device public key via GetValue');
      try {
        devicePublicKey = await this.getDevicePublicKey();
        this.debug('PAIR_GET_DEVICE_KEY_SUCCESS', 'Device public key retrieved successfully');
      } catch (e) {
        this.debug('PAIR_GET_DEVICE_KEY_FAILED', 'Failed to get device public key, will use placeholder', { error: e.message });
      }
    }
    
    // Generate host certificates
    const hostPairRecord = this.generateHostCertificates();
    
    let rootCertBase64, rootPrivateKey;
    
    if (deviceCertBase64) {
      // Use the extracted certificate directly
      this.debug('PAIR_USE_EXTRACTED_CERT', 'Using extracted device certificate');
      rootCertBase64 = hostPairRecord.RootCertificate;
      rootPrivateKey = hostPairRecord.RootPrivateKey;
    } else if (devicePublicKey) {
      // Use real device public key to generate device certificate
      this.debug('PAIR_GEN_REAL_DEVICE_CERT', 'Generating device certificate with real public key');
      const rootKeys = forge.pki.rsa.generateKeyPair(2048);
      rootPrivateKey = forge.pki.privateKeyToPem(rootKeys.privateKey);
      const rootCert = forge.pki.createCertificate();
      rootCert.publicKey = rootKeys.publicKey;
      rootCert.serialNumber = '01';
      rootCert.validity.notBefore = new Date();
      rootCert.validity.notAfter = new Date();
      rootCert.validity.notAfter.setFullYear(rootCert.validity.notBefore.getFullYear() + 10);
      rootCert.setSubject([{ name: 'commonName', value: 'WebTrust Root CA' }]);
      rootCert.setIssuer([{ name: 'commonName', value: 'WebTrust Root CA' }]);
      rootCert.setExtensions([{
        name: 'basicConstraints',
        cA: true
      }]);
      rootCert.sign(rootKeys.privateKey);
      
      const deviceKeyData = Buffer.from(devicePublicKey, 'base64');
      const deviceKey = forge.pki.publicKeyFromAsn1(forge.asn1.fromDer(deviceKeyData));
      
      const deviceCert = forge.pki.createCertificate();
      deviceCert.publicKey = deviceKey;
      deviceCert.serialNumber = '03';
      deviceCert.validity.notBefore = new Date();
      deviceCert.validity.notAfter = new Date();
      deviceCert.validity.notAfter.setFullYear(deviceCert.validity.notBefore.getFullYear() + 1);
      deviceCert.setSubject([{ name: 'commonName', value: 'Device' }]);
      deviceCert.setIssuer(rootCert.subject.attributes);
      deviceCert.setExtensions([{
        name: 'basicConstraints',
        cA: false
      }]);
      deviceCert.sign(rootKeys.privateKey);
      
      const rootCertPem = forge.pki.certificateToPem(rootCert);
      const deviceCertPem = forge.pki.certificateToPem(deviceCert);
      
      rootCertBase64 = Buffer.from(rootCertPem).toString('base64');
      deviceCertBase64 = Buffer.from(deviceCertPem).toString('base64');
      this.debug('PAIR_GEN_REAL_DEVICE_CERT_DONE', 'Device certificate generated with real public key');
    } else {
      // Fallback to placeholder device certificate
      this.debug('PAIR_PLACEHOLDER_DEVICE_CERT', 'Generating placeholder device certificate');
      const deviceKeys = forge.pki.rsa.generateKeyPair(2048);
      const rootKeys = forge.pki.rsa.generateKeyPair(2048);
      rootPrivateKey = forge.pki.privateKeyToPem(rootKeys.privateKey);
      const rootCert = forge.pki.createCertificate();
      rootCert.publicKey = rootKeys.publicKey;
      rootCert.serialNumber = '01';
      rootCert.validity.notBefore = new Date();
      rootCert.validity.notAfter = new Date();
      rootCert.validity.notAfter.setFullYear(rootCert.validity.notBefore.getFullYear() + 10);
      rootCert.setSubject([{ name: 'commonName', value: 'WebTrust Root CA' }]);
      rootCert.setIssuer([{ name: 'commonName', value: 'WebTrust Root CA' }]);
      rootCert.setExtensions([{
        name: 'basicConstraints',
        cA: true
      }]);
      rootCert.sign(rootKeys.privateKey);
      
      const deviceCert = forge.pki.createCertificate();
      deviceCert.publicKey = deviceKeys.publicKey;
      deviceCert.serialNumber = '03';
      deviceCert.validity.notBefore = new Date();
      deviceCert.validity.notAfter = new Date();
      deviceCert.validity.notAfter.setFullYear(deviceCert.validity.notBefore.getFullYear() + 1);
      deviceCert.setSubject([{ name: 'commonName', value: 'Device' }]);
      deviceCert.setIssuer(rootCert.subject.attributes);
      deviceCert.setExtensions([{
        name: 'basicConstraints',
        cA: false
      }]);
      deviceCert.sign(rootKeys.privateKey);
      
      const rootCertPem = forge.pki.certificateToPem(rootCert);
      const deviceCertPem = forge.pki.certificateToPem(deviceCert);
      
      rootCertBase64 = Buffer.from(rootCertPem).toString('base64');
      deviceCertBase64 = Buffer.from(deviceCertPem).toString('base64');
      this.debug('PAIR_PLACEHOLDER_DEVICE_CERT_DONE', 'Placeholder device certificate generated');
    }
    
    // Send pair request with all certificates
    const pairRequest = {
      Label: this.label,
      PairRecord: {
        DeviceCertificate: deviceCertBase64,
        HostCertificate: hostPairRecord.HostCertificate,
        RootCertificate: rootCertBase64,
        HostID: hostPairRecord.HostID,
        SystemBUID: hostPairRecord.SystemBUID
      },
      Request: 'Pair',
      ProtocolVersion: '2'
    };
    
    this.debug('PAIR_SEND_REQUEST', 'Sending Pair request', { 
      hostId: hostPairRecord.HostID,
      systemBUID: hostPairRecord.SystemBUID,
      certSource: deviceCertBase64 ? (devicePublicKey ? 'from_public_key' : 'extracted') : 'placeholder'
    });
    await this.sendPlist(pairRequest);
    
    // Wait for user to trust on device
    this.debug('PAIR_WAITING_FOR_TRUST', 'Waiting for user to trust on device');
    const response = await this.receivePlist();
    this.debug('PAIR_RESPONSE', 'Received Pair response', { 
      result: response.Result,
      error: response.Error,
      hasEscrowBag: !!response.EscrowBag
    });
    
    if (response.Result && response.Result !== 'Success') {
      this.debug('PAIR_FAILED', 'Pair request failed', { result: response.Result, error: response.Error });
      throw new Error('Pair failed: ' + (response.Error || response.Result));
    }
    
    if (response.Error) {
      this.debug('PAIR_FAILED_ERROR', 'Pair request returned error', { error: response.Error });
      throw new Error('Pair failed: ' + response.Error);
    }
    
    this.debug('PAIR_SUCCESS', 'Pair request successful');
    
    // Store complete pair record
    this.pairRecord = {
      DeviceCertificate: deviceCertBase64,
      HostCertificate: hostPairRecord.HostCertificate,
      RootCertificate: rootCertBase64,
      HostID: hostPairRecord.HostID,
      SystemBUID: hostPairRecord.SystemBUID,
      HostPrivateKey: hostPairRecord.HostPrivateKey,
      RootPrivateKey: rootPrivateKey,
      EscrowBag: response.EscrowBag || null
    };
    
    this.debug('PAIR_COMPLETE', 'Pairing process complete', { 
      hasEscrowBag: !!this.pairRecord.EscrowBag,
      deviceCertLength: this.pairRecord.DeviceCertificate.length,
      certSource: devicePublicKey ? 'from_public_key' : (deviceCertBase64 ? 'extracted' : 'placeholder')
    });
    return this.pairRecord;
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
      enableSSL: response.EnableSessionSSL
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

  async getDeviceCertificateViaSSL() {
    this.debug('GET_DEVICE_CERT_VIA_SSL_START', 'Attempting to extract device certificate via TLS handshake interception');
    
    try {
      this.debug('GET_DEVICE_CERT_VIA_SSL_START_SESSION', 'Starting session to trigger TLS handshake');
      const sessionResult = await this.startSession();
      this.debug('GET_DEVICE_CERT_VIA_SSL_SESSION_RESULT', 'Session started, SSL should be enabled', { 
        sessionId: sessionResult.sessionId,
        enableSSL: sessionResult.enableSSL
      });
      
      // Now attempt to intercept the TLS handshake to capture the device certificate
      // We'll create a TLS connection to the device and capture the certificate it presents
      this.debug('GET_DEVICE_CERT_VIA_SSL_INTERCEPT', 'Attempting TLS handshake to capture device certificate');
      
      const deviceCert = await this.captureDeviceCertificateViaTLS();
      
      if (deviceCert) {
        this.debug('GET_DEVICE_CERT_VIA_SSL_SUCCESS', 'Device certificate captured via TLS handshake');
        return deviceCert;
      } else {
        this.debug('GET_DEVICE_CERT_VIA_SSL_NO_CERT', 'Failed to capture device certificate via TLS');
      }
    } catch (e) {
      this.debug('GET_DEVICE_CERT_VIA_SSL_ERROR', 'Error during TLS certificate extraction', { error: e.message });
    }
    
    this.debug('GET_DEVICE_CERT_VIA_SSL_NULL', 'Returning null (certificate extraction failed)');
    return null;
  }

  async captureDeviceCertificateViaTLS() {
    this.debug('CAPTURE_CERT_START', 'Starting TLS certificate capture via raw socket');
    
    return new Promise((resolve, reject) => {
      let capturedCert = null;
      let buffer = Buffer.alloc(0);
      
      // Create a raw TCP socket to capture the TLS handshake
      const rawSocket = new net.Socket();
      
      rawSocket.connect(this.port, this.deviceIp, () => {
        this.debug('CAPTURE_CERT_CONNECTED', 'Raw socket connected');
        
        // Send StartSession to trigger TLS handshake
        const startSessionRequest = {
          Label: this.label,
          HostID: this.hostId,
          Request: 'StartSession'
        };
        
        const plistXml = plist.build(startSessionRequest);
        const plistBuffer = Buffer.from(plistXml, 'utf8');
        const lengthBuffer = Buffer.alloc(4);
        lengthBuffer.writeUInt32BE(plistBuffer.length, 0);
        
        rawSocket.write(Buffer.concat([lengthBuffer, plistBuffer]), (err) => {
          if (err) {
            this.debug('CAPTURE_CERT_SEND_ERROR', 'Failed to send StartSession', { error: err.message });
            rawSocket.destroy();
            resolve(null);
          } else {
            this.debug('CAPTURE_CERT_SENT', 'StartSession sent, waiting for TLS handshake');
          }
        });
      });
      
      rawSocket.on('data', (data) => {
        buffer = Buffer.concat([buffer, data]);
        this.debug('CAPTURE_CERT_DATA', `Received ${data.length} bytes, total ${buffer.length} bytes`);
        
        // Try to extract TLS Certificate message from the buffer
        const cert = this.extractCertificateFromTLSHandshake(buffer);
        if (cert) {
          this.debug('CAPTURE_CERT_EXTRACTED', 'Certificate extracted from TLS handshake');
          capturedCert = cert;
          rawSocket.destroy();
        }
        
        // Limit buffer size to prevent memory issues
        if (buffer.length > 10000) {
          this.debug('CAPTURE_CERT_BUFFER_LIMIT', 'Buffer size limit reached');
          rawSocket.destroy();
        }
      });
      
      rawSocket.on('error', (err) => {
        this.debug('CAPTURE_CERT_ERROR', 'Socket error', { error: err.message });
        if (!capturedCert) {
          resolve(null);
        }
      });
      
      rawSocket.on('close', () => {
        this.debug('CAPTURE_CERT_CLOSED', 'Socket closed');
        resolve(capturedCert);
      });
      
      rawSocket.setTimeout(5000, () => {
        this.debug('CAPTURE_CERT_TIMEOUT', 'Connection timed out');
        rawSocket.destroy();
        resolve(capturedCert);
      });
    });
  }

  extractCertificateFromTLSHandshake(buffer) {
    this.debug('EXTRACT_CERT_START', 'Attempting to extract certificate from TLS handshake buffer');
    
    try {
      // TLS handshake starts with 0x16 (Handshake type)
      // Look for TLS handshake records
      let offset = 0;
      
      while (offset + 5 <= buffer.length) {
        const recordType = buffer[offset];
        const recordVersion = buffer.readUInt16BE(offset + 1);
        const recordLength = buffer.readUInt16BE(offset + 3);
        
        this.debug('EXTRACT_CERT_RECORD', `TLS record: type=${recordType}, version=${recordVersion}, length=${recordLength}`);
        
        // Check if this is a Handshake record (0x16)
        if (recordType === 0x16) {
          // Parse handshake messages within the record
          const recordData = buffer.slice(offset + 5, offset + 5 + recordLength);
          const cert = this.extractCertificateFromHandshakeMessages(recordData);
          if (cert) {
            return cert;
          }
        }
        
        offset += 5 + recordLength;
      }
    } catch (e) {
      this.debug('EXTRACT_CERT_ERROR', 'Error parsing TLS handshake', { error: e.message });
    }
    
    return null;
  }

  extractCertificateFromHandshakeMessages(data) {
    this.debug('EXTRACT_CERT_HANDSHAKE', 'Parsing handshake messages');
    
    try {
      let offset = 0;
      
      while (offset + 4 <= data.length) {
        const handshakeType = data[offset];
        const handshakeLength = data.readUInt24BE(offset + 1);
        
        this.debug('EXTRACT_CERT_MSG', `Handshake: type=${handshakeType}, length=${handshakeLength}`);
        
        // Check if this is a Certificate message (0x0B)
        if (handshakeType === 0x0B) {
          const certData = data.slice(offset + 4, offset + 4 + handshakeLength);
          const cert = this.extractCertificateFromCertificateMessage(certData);
          if (cert) {
            return cert;
          }
        }
        
        offset += 4 + handshakeLength;
      }
    } catch (e) {
      this.debug('EXTRACT_CERT_MSG_ERROR', 'Error parsing handshake messages', { error: e.message });
    }
    
    return null;
  }

  extractCertificateFromCertificateMessage(data) {
    this.debug('EXTRACT_CERT_MSG_DETAIL', 'Parsing Certificate message');
    
    try {
      // Skip certificates list length (3 bytes)
      if (data.length < 3) return null;
      
      let offset = 3;
      
      while (offset + 3 <= data.length) {
        const certLength = data.readUInt24BE(offset);
        
        this.debug('EXTRACT_CERT_ENTRY', `Certificate entry: length=${certLength}`);
        
        if (certLength > 0 && offset + 3 + certLength <= data.length) {
          const certData = data.slice(offset + 3, offset + 3 + certLength);
          
          // Convert to base64
          const certBase64 = certData.toString('base64');
          this.debug('EXTRACT_CERT_SUCCESS', 'Successfully extracted certificate', { 
            certLength: certLength,
            base64Length: certBase64.length 
          });
          
          return certBase64;
        }
        
        offset += 3 + certLength;
      }
    } catch (e) {
      this.debug('EXTRACT_CERT_ENTRY_ERROR', 'Error parsing certificate entry', { error: e.message });
    }
    
    return null;
  }

  async validatePair() {
    this.debug('VALIDATE_PAIR_START', 'Validating pair record');
    const request = {
      Label: this.label,
      PairRecord: {
        DeviceCertificate: this.pairRecord.DeviceCertificate,
        HostCertificate: this.pairRecord.HostCertificate,
        RootCertificate: this.pairRecord.RootCertificate,
        HostID: this.pairRecord.HostID
      },
      Request: 'ValidatePair',
      ProtocolVersion: '2'
    };
    
    this.debug('VALIDATE_PAIR_SEND', 'Sending ValidatePair request');
    await this.sendPlist(request);
    const response = await this.receivePlist();
    this.debug('VALIDATE_PAIR_RESPONSE', 'Received ValidatePair response', { result: response.Result });
    
    if (response.Result && response.Result !== 'Success') {
      this.debug('VALIDATE_PAIR_FAILED', 'ValidatePair failed', { result: response.Result });
      throw new Error('ValidatePair failed: ' + response.Result);
    }
    
    this.debug('VALIDATE_PAIR_SUCCESS', 'Pair record validated successfully');
    return true;
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

module.exports = LockdownClient;
