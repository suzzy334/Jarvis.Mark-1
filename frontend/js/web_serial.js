/**
 * SentinelKey Web Serial API Bridge — PRODUCTION HARDENED
 * Department of ECE — HITAM Major Project
 * 
 * Handles direct USB-Serial communication between Chrome/Edge and ESP32.
 * Physical hardware tokens ONLY — NO simulation, NO emulation, NO fallback.
 * 
 * SECURITY INVARIANTS:
 *   - No golden keys, HMAC keys, or secret material in client-side code.
 *   - No software simulation or virtual PUF modes.
 *   - All cryptographic operations occur ONLY on the physical ESP32 hardware.
 *   - Challenge-response protocol relayed verbatim (browser never signs).
 */

class SentinelKeyBridge {
  constructor() {
    this.port = null;
    this.reader = null;
    this.writer = null;
    this.baudRate = 115200;
    this.isConnected = false;
    this.activeDeviceId = null;
    this.activeMac = null;
    this.activePubkey = null;
    this.onStatusChange = null;
    this.onPromptPresence = null;
  }

  /**
   * Check if Web Serial API is available in this browser.
   * Only Chrome 89+ and Edge 89+ support this.
   */
  isSupported() {
    return "serial" in navigator;
  }

  setDeviceId(devId) {
    if (devId) {
      this.activeDeviceId = devId;
    }
  }

  /**
   * Connect to a physical ESP32 SentinelKey USB token.
   * Opens a serial port, probes the firmware, and returns device identity.
   */
  async connect() {
    if (!this.isSupported()) {
      throw new Error(
        "Web Serial API is not supported in this browser. " +
        "Please use Google Chrome or Microsoft Edge (version 89+)."
      );
    }

    try {
      if (this.onStatusChange) {
        this.onStatusChange("REQUESTING_PORT", "Select ESP32 USB Serial Port...");
      }

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

      let detectedId = this.activeDeviceId || "UNKNOWN";
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
        this.onStatusChange(
          "CONNECTED_HARDWARE",
          `ESP32 Connected: ${detectedId}${macInfo} (${pingResp || "READY"})`
        );
      }

      return {
        deviceId: detectedId,
        mac: this.activeMac,
        pubKey: this.activePubkey,
        mode: "PHYSICAL",
        rawInfo: infoResp
      };
    } catch (err) {
      this.isConnected = false;
      if (this.onStatusChange) {
        this.onStatusChange("ERROR", err.message);
      }
      throw err;
    }
  }

  /**
   * Safely disconnect from the serial port.
   */
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
      this.activeDeviceId = null;
      this.activeMac = null;
      this.activePubkey = null;
      if (this.onStatusChange) {
        this.onStatusChange("DISCONNECTED", "Token Disconnected");
      }
    } catch (e) {
      console.warn("[SentinelKey] Disconnect error:", e);
    }
  }

  /**
   * Write a line to the serial port (appends newline).
   */
  async writeLine(text) {
    if (!this.writer) throw new Error("Serial port not connected.");
    const encoder = new TextEncoder();
    await this.writer.write(encoder.encode(text + "\n"));
  }

  /**
   * Read a line from the serial port with timeout.
   */
  async readLine(timeoutMs = 5000) {
    if (!this.reader) throw new Error("Serial port not connected.");
    const decoder = new TextDecoder();
    let received = "";
    const start = Date.now();

    while (Date.now() - start < timeoutMs) {
      try {
        const { value, done } = await Promise.race([
          this.reader.read(),
          new Promise((_, reject) =>
            setTimeout(() => reject(new Error("Serial read timeout")), timeoutMs)
          )
        ]);

        if (done) break;
        if (value) {
          received += decoder.decode(value);
          if (received.includes("\n")) {
            const lines = received.split("\n");
            return lines[0].trim();
          }
        }
      } catch (e) {
        // Timeout — return what we have
        break;
      }
    }
    return received.trim();
  }

  /**
   * Read ALL available lines from serial within a timeout window.
   * Used for challenge-response where multiple lines are expected.
   */
  async readAllLines(timeoutMs = 25000) {
    if (!this.reader) throw new Error("Serial port not connected.");
    const decoder = new TextDecoder();
    let buffer = "";
    const lines = [];
    const startTime = Date.now();

    while (Date.now() - startTime < timeoutMs) {
      try {
        const { value, done } = await Promise.race([
          this.reader.read(),
          new Promise((_, reject) =>
            setTimeout(() => reject(new Error("timeout")), Math.max(100, timeoutMs - (Date.now() - startTime)))
          )
        ]);

        if (done) break;
        if (value) {
          buffer += decoder.decode(value);
          const parts = buffer.split("\n");
          buffer = parts.pop(); // Keep incomplete line in buffer
          for (const rawLine of parts) {
            const line = rawLine.trim();
            if (line.length > 0) lines.push(line);
          }
        }
      } catch (e) {
        break;
      }
    }
    
    // Flush remaining buffer
    if (buffer.trim().length > 0) {
      lines.push(buffer.trim());
    }
    
    return lines;
  }

  /**
   * Challenge-Response Exchange (Physical Hardware ONLY)
   * 
   * 1. Sends CHALLENGE:<nonce> to ESP32 over USB Serial
   * 2. ESP32 enters AWAIT_PRESENCE state (LED pulses rapidly)
   * 3. User must physically touch GPIO 4 / press BOOT button within 15 seconds
   * 4. ESP32 reconstructs private key from SRAM, signs nonce, wipes key
   * 5. Returns ECDSA signature (r||s) as 128-char hex string
   */
  async executeChallenge(nonce, targetDeviceId = null) {
    if (!this.isConnected) {
      await this.connect();
    }

    if (this.onStatusChange) {
      this.onStatusChange("CHALLENGING", "Transmitting nonce to silicon PUF core...");
    }

    // Send challenge command to ESP32
    const cmdPrefix = "CHALLENGE";
    await this.writeLine(`${cmdPrefix}:${nonce}`);

    // Read response stream with presence prompt handling
    const decoder = new TextDecoder();
    let buffer = "";
    const timeoutMs = 25000; // 25s (15s presence + 10s signing margin)
    const startTime = Date.now();

    while (Date.now() - startTime < timeoutMs) {
      try {
        const { value, done } = await Promise.race([
          this.reader.read(),
          new Promise((_, reject) =>
            setTimeout(() => reject(new Error("Serial read timeout")), timeoutMs)
          )
        ]);

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
              if (this.onStatusChange) {
                this.onStatusChange(
                  "AWAITING_BUTTON",
                  "🔴 TOUCH Pin D4 or PRESS BOOT Button on ESP32 to confirm your identity!"
                );
              }
            } else if (line.startsWith("INFO:PRESENCE_CONFIRMED")) {
              if (this.onStatusChange) {
                this.onStatusChange("SIGNING", "Physical presence confirmed. Computing ECDSA signature...");
              }
            } else if (line.startsWith("SIGNATURE:")) {
              if (this.onPromptPresence) this.onPromptPresence(false);
              if (this.onStatusChange) {
                this.onStatusChange("SIGNED", "✅ Silicon ECDSA signature computed and transmitted!");
              }
              const sig = line.substring("SIGNATURE:".length).trim();
              return sig;
            } else if (line.startsWith("ERR:PRESENCE_TIMEOUT")) {
              if (this.onPromptPresence) this.onPromptPresence(false);
              throw new Error(
                "Physical presence timeout (15 seconds). " +
                "You must touch Pin D4 or press the BOOT button on your ESP32 to sign."
              );
            } else if (line.startsWith("ERROR:")) {
              if (this.onPromptPresence) this.onPromptPresence(false);
              throw new Error(`ESP32 Security Exception: ${line}`);
            }
          }
        }
      } catch (err) {
        if (this.onPromptPresence) this.onPromptPresence(false);
        throw err;
      }
    }

    if (this.onPromptPresence) this.onPromptPresence(false);
    throw new Error(
      "Challenge-response timed out. Please touch Pin D4 on your ESP32 board to confirm presence."
    );
  }

  /**
   * Classroom Attendance Attestation Protocol
   * Signs the SHA-256 canonical attendance digest for non-repudiation.
   * Requires physical GPIO 4 touch — faculty must be physically present.
   */
  async signAttendance(attendanceDigest, targetDeviceId = null) {
    if (this.onStatusChange) {
      this.onStatusChange("ATTENDANCE_SIGNING", "Preparing attendance commitment signature...");
    }
    return await this.executeChallenge(attendanceDigest, targetDeviceId);
  }
}

// Global instance — physical hardware only
window.sentinelBridge = new SentinelKeyBridge();
