/**
 * SentinelKey Web Serial API Bridge
 * Department of ECE - HITAM Major Project
 * Handles direct USB-Serial communication between Chrome/Edge and ESP32
 * Supports physical hardware tokens and 4-faculty simulation testbed.
 */

const FACULTY_SIMULATION_KEYS = {
  "ESP32-SENTINEL-FAC01": "a4f839c0e2b1754890d937c8e9fa014389025cb48e910243bfae840291437801",
  "ESP32-SENTINEL-FAC02": "b5f940d1f3c2865901e048d9fa0b125490136dc59f021354c0bf951302548902",
  "ESP32-SENTINEL-FAC03": "c60a51e204d3976a12f159e00b1c236501247ed6a0132465d1c0a62413659a03",
  "ESP32-SENTINEL-FAC04": "d71b62f315e4a87b23026af11c2d347612358fe7b1243576e2d1b7352476ab04"
};

class SentinelKeyBridge {
  constructor() {
    this.port = null;
    this.reader = null;
    this.writer = null;
    this.baudRate = 115200;
    this.isConnected = false;
    this.isEmulationMode = false;
    this.activeDeviceId = "ESP32-SENTINEL-FAC01";
    this.onStatusChange = null;
    this.onPromptPresence = null;
  }

  isSupported() {
    return "serial" in navigator;
  }

  setDeviceId(devId) {
    if (devId) {
      this.activeDeviceId = devId;
    }
  }

  async connect() {
    if (this.isEmulationMode) {
      this.isConnected = true;
      if (this.onStatusChange) {
        this.onStatusChange("CONNECTED_VIRTUAL", `Virtual SentinelKey Armed: ${this.activeDeviceId}`);
      }
      return { deviceId: this.activeDeviceId, mode: "VIRTUAL" };
    }

    if (!this.isSupported()) {
      throw new Error("Web Serial API is not supported in this browser. Please use Google Chrome or Microsoft Edge (version 89+).");
    }

    try {
      if (this.onStatusChange) this.onStatusChange("REQUESTING_PORT", "Select ESP32 USB Serial Port...");
      
      this.port = await navigator.serial.requestPort();
      await this.port.open({ baudRate: this.baudRate });

      this.writer = this.port.writable.getWriter();
      this.reader = this.port.readable.getReader();
      this.isConnected = true;

      // Probe firmware identity and hardware ID
      await this.writeLine("PING");
      const pingResp = await this.readLine(1500);

      await this.writeLine("DEVICE_INFO");
      const infoResp = await this.readLine(2000);

      let detectedId = this.activeDeviceId;
      let detectedMac = "";
      let detectedPubkey = "";
      if (infoResp) {
        const parts = infoResp.split(":");
        for (const p of parts) {
          if (p.startsWith("DEVICE_ID=")) {
            detectedId = p.replace("DEVICE_ID=", "").trim();
            this.activeDeviceId = detectedId;
          } else if (p.startsWith("MAC=") || p.startsWith("EFUSE_MAC=")) {
            detectedMac = p.replace("MAC=", "").replace("EFUSE_MAC=", "").trim();
            this.activeMac = detectedMac;
          } else if (p.startsWith("PUBKEY=")) {
            detectedPubkey = p.replace("PUBKEY=", "").trim();
            this.activePubkey = detectedPubkey;
          }
        }
      }

      if (this.onStatusChange) {
        const macInfo = this.activeMac ? ` [MAC: ${this.activeMac}]` : "";
        this.onStatusChange("CONNECTED_HARDWARE", `ESP32 Connected: ${detectedId}${macInfo} (${pingResp || "READY"})`);
      }

      return { deviceId: detectedId, mac: this.activeMac, pubKey: this.activePubkey, mode: "PHYSICAL", rawInfo: infoResp };
    } catch (err) {
      this.isConnected = false;
      if (this.onStatusChange) this.onStatusChange("ERROR", err.message);
      throw err;
    }
  }

  async disconnect() {
    try {
      if (this.reader) {
        await this.reader.cancel();
        this.reader.releaseLock();
        this.reader = null;
      }
      if (this.writer) {
        await this.writer.close();
        this.writer.releaseLock();
        this.writer = null;
      }
      if (this.port) {
        await this.port.close();
        this.port = null;
      }
      this.isConnected = false;
      if (this.onStatusChange) this.onStatusChange("DISCONNECTED", "Token Disconnected");
    } catch (e) {
      console.warn("Disconnect error:", e);
    }
  }

  async writeLine(text) {
    if (!this.writer) throw new Error("Port not connected.");
    const encoder = new TextEncoder();
    await this.writer.write(encoder.encode(text + "\n"));
  }

  async readLine(timeoutMs = 5000) {
    if (!this.reader) throw new Error("Port not connected.");
    const decoder = new TextDecoder();
    let received = "";
    const start = Date.now();

    while (Date.now() - start < timeoutMs) {
      const { value, done } = await Promise.race([
        this.reader.read(),
        new Promise((_, reject) => setTimeout(() => reject(new Error("Serial read timeout")), timeoutMs))
      ]);

      if (done) break;
      if (value) {
        received += decoder.decode(value);
        if (received.includes("\n")) {
          const lines = received.split("\n");
          return lines[0].trim();
        }
      }
    }
    return received.trim();
  }

  /**
   * Challenge-Response Exchange
   * Sends CHALLENGE:<nonce> to ESP32, awaits presence button/touch, returns signature
   */
  async executeChallenge(nonce, targetDeviceId = null) {
    const devId = targetDeviceId || this.activeDeviceId;
    if (this.isEmulationMode) {
      return await this._simulateHardwareResponse(nonce, devId);
    }

    if (!this.isConnected) {
      await this.connect();
    }

    if (this.onStatusChange) this.onStatusChange("CHALLENGING", "Transmitting nonce to silicon PUF core...");

    await this.writeLine(`CHALLENGE:${nonce}`);

    const decoder = new TextDecoder();
    let buffer = "";
    const timeoutMs = 25000;
    const startTime = Date.now();

    while (Date.now() - startTime < timeoutMs) {
      const { value, done } = await this.reader.read();
      if (done) break;
      if (value) {
        buffer += decoder.decode(value);
        const lines = buffer.split("\n");
        buffer = lines.pop();

        for (const rawLine of lines) {
          const line = rawLine.trim();
          console.log("[ESP32 SERIAL]:", line);

          if (line.startsWith("PROMPT:AWAITING_PHYSICAL_PRESENCE")) {
            if (this.onPromptPresence) this.onPromptPresence(true);
            if (this.onStatusChange) this.onStatusChange("AWAITING_BUTTON", "Touch Pin D4 (Touch0) or Press Button on ESP32!");
          } else if (line.startsWith("SIGNATURE:")) {
            if (this.onPromptPresence) this.onPromptPresence(false);
            if (this.onStatusChange) this.onStatusChange("SIGNED", "Silicon signature successfully calculated!");
            const sig = line.substring(10).trim();
            return sig;
          } else if (line.startsWith("ERROR:")) {
            if (this.onPromptPresence) this.onPromptPresence(false);
            throw new Error(`ESP32 Security Exception: ${line}`);
          }
        }
      }
    }

    if (this.onPromptPresence) this.onPromptPresence(false);
    throw new Error("Challenge-response timed out. Please touch Pin D4 on your ESP32 board to confirm presence.");
  }

  /**
   * Classroom Attendance Attestation Protocol
   * Signs the SHA-256 canonical attendance digest for non-repudiation
   */
  async signAttendance(attendanceDigest, targetDeviceId = null) {
    return await this.executeChallenge(attendanceDigest, targetDeviceId);
  }

  /**
   * Software Emulation for testbeds and physical-less evaluations
   */
  async _simulateHardwareResponse(nonce, devId) {
    if (this.onStatusChange) this.onStatusChange("CHALLENGING", `Virtual PUF Core [${devId}] Sampling SRAM Entropy...`);
    await new Promise(r => setTimeout(r, 400));

    if (this.onPromptPresence) this.onPromptPresence(true);
    if (this.onStatusChange) this.onStatusChange("AWAITING_BUTTON", "Confirming Physical Presence (Pin D4 Touch)...");

    // Realistic human physical presence confirmation delay
    await new Promise(r => setTimeout(r, 1200));

    if (this.onPromptPresence) this.onPromptPresence(false);
    if (this.onStatusChange) this.onStatusChange("SIGNED", "Silicon signature reconstructed and validated!");

    // Use corresponding golden key from 4-faculty setup
    const key = FACULTY_SIMULATION_KEYS[devId] || FACULTY_SIMULATION_KEYS["ESP32-SENTINEL-FAC01"];
    const sig = await this._computeSha256Hmac(key, nonce);
    return sig.toUpperCase();
  }

  async _computeSha256Hmac(keyHex, message) {
    const keyBytes = new Uint8Array(keyHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const msgBytes = new TextEncoder().encode(message);

    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const signatureBuffer = await crypto.subtle.sign("HMAC", cryptoKey, msgBytes);
    const hashArray = Array.from(new Uint8Array(signatureBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
  }
}

// Global instance
window.sentinelBridge = new SentinelKeyBridge();

