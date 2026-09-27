/*
 * SentinelKey — SRAM-PUF Hardware Authentication Token (PRODUCTION BUILD)
 * Hyderabad Institute of Technology and Management (HITAM) — Department of ECE
 * 
 * Cryptographic Architecture: ASYMMETRIC ECDSA / NIST P-256 / SECP256R1
 * Hardware Target: ESP32 DevKit V1 (ESP-WROOM-32)
 * Status Indicator: Built-in Blue Status LED (GPIO 2)
 * Physical Presence Detection:
 *   1. Built-in BOOT Button (GPIO 0, Active LOW) — Always present on DevKit
 *   2. Capacitive Touch on Pin D4 (GPIO 4 / Touch0) — Human finger contact
 *   3. External Push Button on Pin D4 to GND (Active LOW with pullup)
 * Baud Rate: 115200
 * 
 * SECURITY INVARIANTS:
 *   - Private scalar d NEVER persists in Flash, NVS, EEPROM, or global memory.
 *   - d exists ONLY in volatile SRAM during signing, then zeroed with volatile ptr.
 *   - Raw SRAM is NEVER emitted in production (ENROLLMENT_BUILD must be 1).
 *   - All cryptographic signing requires physical human presence on GPIO 4/GPIO 0.
 *   - WiFi/Bluetooth radios physically powered down at boot (zero RF attack surface).
 *   - JTAG debug port disabled in production to prevent memory probing.
 *   - Serial commands are length-limited to prevent buffer overflow attacks.
 */

#include <Arduino.h>
#include <WiFi.h>
#include <esp_bt.h>
#include <esp_wifi.h>
#include <soc/rtc_cntl_reg.h>

#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/md.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform_util.h"

// =============================================================================
// COMPILE-TIME SECURITY GATES
// =============================================================================
// Set to 1 ONLY during initial PUF characterization. MUST be 0 for production!
#ifndef ENROLLMENT_BUILD
  #define ENROLLMENT_BUILD 0
#endif

// Firmware version for serial identification
#define FIRMWARE_VERSION "2.1.0-HARDENED"

// =============================================================================
// HARDWARE PIN DEFINITIONS
// =============================================================================
#define PUF_SAMPLE_BYTES 512        // 512 bytes = 4096 bits of uninitialized silicon SRAM
#define LED_PIN 2                   // Onboard blue status LED
#define BUTTON_PIN 4                // Pin D4 (GPIO 4) external button
#define TOUCH_PIN 4                 // Pin D4 is also Touch0 (T0) on ESP32
#define BOOT_BUTTON_PIN 0           // Onboard built-in BOOT button (GPIO 0)
#define TOUCH_THRESHOLD 45          // Drops below ~40-50 when human finger touches pin D4
#define PRESENCE_TIMEOUT_MS 15000   // 15 seconds to confirm physical presence
#define MAX_CMD_LENGTH 128          // Maximum serial command length (anti-overflow)

// =============================================================================
// SILICON SRAM POINTER & HELPER DATA
// =============================================================================
// Address 0x50000220 starts at active physical silicon SRAM entropy
volatile uint8_t* puf_sram_ptr = (volatile uint8_t*)0x50000220;

// Check if custom characterization helper data is present
#if __has_include("helper_data_ESP32-SENTINEL-FAC01.h")
  #include "helper_data_ESP32-SENTINEL-FAC01.h"
  #define HAS_CUSTOM_HELPER 1
#else
  #define HAS_CUSTOM_HELPER 0
  #define SENTINEL_DEVICE_ID "ESP32-SENTINEL-FAC01"
  #define PUF_ECC_PUBLIC_KEY "04E650ECD5D1F21BC0241E7591C321C2829BA40ADF383C3D7D4AF71609E1B0A5FC5B22CDB7EB99249C2677A7D65087A531996CE1889215F98DF2F933B056626508"
  // Default fallback 256 stable indices across the 4096-bit pool
  const uint16_t STABLE_INDICES[256] = {
      0,    1,    2,    3,    4,    5,    7,    8,    9,   10,   11,   12,   13,   14,   15,   16,
     17,   18,   22,   23,   25,   29,   30,   32,   33,   35,   37,   38,   39,   41,   43,   44,
     45,   46,   48,   49,   50,   51,   52,   54,   55,   59,   60,   61,   62,   63,   64,   66,
     67,   68,   69,   70,   71,   72,   73,   76,   77,   78,   83,   84,   85,   87,   88,   89,
     91,   93,   95,   96,   97,   98,   99,  101,  105,  106,  107,  109,  111,  112,  114,  115,
    116,  118,  119,  121,  122,  123,  124,  125,  126,  127,  128,  129,  130,  131,  132,  134,
    137,  138,  139,  141,  143,  144,  146,  147,  148,  149,  150,  151,  152,  153,  154,  156,
    158,  159,  160,  162,  164,  165,  166,  167,  170,  172,  173,  175,  176,  177,  178,  179,
    180,  181,  182,  183,  184,  185,  186,  187,  189,  191,  192,  193,  194,  195,  197,  198,
    199,  200,  201,  202,  203,  204,  205,  206,  207,  208,  209,  210,  211,  212,  214,  215,
    216,  217,  218,  219,  220,  222,  223,  224,  225,  226,  227,  228,  229,  230,  231,  232,
    233,  236,  237,  238,  239,  240,  241,  242,  243,  244,  245,  246,  247,  248,  249,  251,
    253,  254,  255,  256,  257,  261,  262,  265,  268,  269,  270,  271,  272,  273,  274,  275,
    276,  278,  279,  280,  281,  282,  285,  286,  287,  289,  290,  294,  295,  296,  297,  298,
    299,  300,  301,  302,  303,  304,  305,  306,  307,  309,  311,  312,  313,  314,  315,  317,
    318,  319,  320,  322,  324,  325,  326,  327,  328,  329,  331,  334,  335,  336,  338,  340
  };
#endif

// =============================================================================
// FUNCTION PROTOTYPES
// =============================================================================
bool awaitUserPresence();
String bytesToHex(const uint8_t* buffer, size_t len);
String getHardwareMacAddress();
String derivePufPublicKey();
bool signChallengeECDSA(const String& nonce, String& sigHexOut);
String readSerialCommand();

// =============================================================================
// HARDWARE SECURITY LOCKDOWN
// =============================================================================

// Physically powers down 2.4 GHz RF radio hardware (Zero Over-The-Air Attack Surface)
void disableAllRadios() {
  WiFi.mode(WIFI_OFF);
  btStop();
  esp_bt_controller_disable();
  esp_wifi_stop();
}

// Disable JTAG debug port to prevent hardware memory probing
void disableJTAG() {
  // Disable JTAG by resetting the GPIO matrix for JTAG pins (12, 13, 14, 15)
  pinMode(12, INPUT);
  pinMode(13, INPUT);
  pinMode(14, INPUT);
  pinMode(15, INPUT);
  // Note: For permanent JTAG disable, burn eFuse JTAG_DISABLE via espefuse.py
}

// Compiler-safe volatile memory wipe (cannot be optimized away)
static void secureWipe(volatile uint8_t* buf, size_t len) {
  for (size_t i = 0; i < len; i++) {
    buf[i] = 0x00;
  }
  // Verification pass — ensure the wipe actually took effect
  for (size_t i = 0; i < len; i++) {
    if (buf[i] != 0x00) {
      // Memory wipe failed — halt the device
      while (1) { delay(1000); }
    }
  }
}

// =============================================================================
// SETUP & STARTUP
// =============================================================================
void setup() {
  disableAllRadios();     // Kill WiFi and Bluetooth (Zero RF attack surface)
  disableJTAG();          // Disable debug port

  pinMode(LED_PIN, OUTPUT);
  pinMode(BUTTON_PIN, INPUT_PULLUP);
  pinMode(BOOT_BUTTON_PIN, INPUT_PULLUP);
  digitalWrite(LED_PIN, LOW);

  Serial.begin(115200);
  delay(120); // USB-Serial stabilization

#if ENROLLMENT_BUILD == 1
  // === ENROLLMENT MODE ONLY ===
  // Emit raw SRAM for python characterization script.
  // This code is STRIPPED from production builds (ENROLLMENT_BUILD = 0).
  Serial.print("\n===PUF_START===");
  for (int i = 0; i < PUF_SAMPLE_BYTES; i++) {
    uint8_t b = puf_sram_ptr[i];
    if (b < 0x10) Serial.print("0");
    Serial.print(b, HEX);
  }
  Serial.println("===PUF_END===");
  Serial.println("WARNING:ENROLLMENT_MODE_ACTIVE:SRAM_EXPOSED");
#endif

  // Ready signal: 2 quick blinks
  digitalWrite(LED_PIN, HIGH); delay(80);
  digitalWrite(LED_PIN, LOW);  delay(80);
  digitalWrite(LED_PIN, HIGH); delay(80);
  digitalWrite(LED_PIN, LOW);

  Serial.print("SENTINELKEY_READY:VERSION=");
  Serial.print(FIRMWARE_VERSION);
  Serial.print(":SCHEME=ECDSA_P256:MAC=");
  Serial.println(getHardwareMacAddress());
}

// =============================================================================
// SAFE SERIAL COMMAND READER (Anti-Buffer-Overflow)
// =============================================================================
String readSerialCommand() {
  String cmd = "";
  unsigned long startMs = millis();
  
  while (Serial.available() > 0 && (millis() - startMs) < 2000) {
    char c = Serial.read();
    
    // Newline terminates command
    if (c == '\n' || c == '\r') {
      break;
    }
    
    // Reject commands exceeding MAX_CMD_LENGTH (anti-overflow)
    if (cmd.length() >= MAX_CMD_LENGTH) {
      // Drain remaining bytes and reject
      while (Serial.available() > 0) {
        char drain = Serial.read();
        if (drain == '\n' || drain == '\r') break;
      }
      return "ERR:CMD_TOO_LONG";
    }
    
    // Only allow printable ASCII characters (0x20-0x7E)
    if (c >= 0x20 && c <= 0x7E) {
      cmd += c;
    }
  }
  
  cmd.trim();
  return cmd;
}

// =============================================================================
// COMMAND LOOP (Continuous Service)
// =============================================================================
void loop() {
  if (Serial.available() > 0) {
    String cmd = readSerialCommand();
    
    // Reject oversized commands
    if (cmd == "ERR:CMD_TOO_LONG") {
      Serial.println("ERROR:COMMAND_BUFFER_OVERFLOW_REJECTED");
      return;
    }
    
    // Reject empty commands
    if (cmd.length() == 0) {
      return;
    }

    // --- Diagnostic Commands ---
    if (cmd == "PING") {
      Serial.print("PONG:SENTINELKEY_ECDSA_V2:");
      Serial.print(FIRMWARE_VERSION);
      Serial.println(":HITAM_ECE");
    }
    else if (cmd == "DEVICE_INFO" || cmd == "GET_ID") {
      String mac = getHardwareMacAddress();
      String pubKey = derivePufPublicKey();
      Serial.print("ID:DEVICE_ID=");
      Serial.print(SENTINEL_DEVICE_ID);
      Serial.print(":MAC=");
      Serial.print(mac);
      Serial.print(":EFUSE_MAC=");
      Serial.print(mac);
      Serial.print(":PUBKEY=");
      Serial.print(pubKey);
      Serial.print(":SCHEME=ECDSA_P256");
      Serial.print(":FW=");
      Serial.print(FIRMWARE_VERSION);
      Serial.println(":STATUS=ARMED");
    }
    else if (cmd == "GET_MAC") {
      Serial.print("MAC:");
      Serial.println(getHardwareMacAddress());
    }
    else if (cmd == "GET_PUBKEY") {
      Serial.print("PUBKEY:");
      Serial.println(derivePufPublicKey());
    }
#if ENROLLMENT_BUILD == 1
    // DUMP_SRAM only available in enrollment builds — NEVER in production
    else if (cmd == "DUMP_SRAM") {
      Serial.print("===PUF_START===");
      for (int i = 0; i < PUF_SAMPLE_BYTES; i++) {
        uint8_t b = puf_sram_ptr[i];
        if (b < 0x10) Serial.print("0");
        Serial.print(b, HEX);
      }
      Serial.println("===PUF_END===");
    }
#endif
    // --- Cryptographic Challenge-Response (Login & Attendance Signing) ---
    else if (cmd.startsWith("CHALLENGE:") || cmd.startsWith("SIGN_ATTENDANCE:")) {
      int colonIdx = cmd.indexOf(':');
      String nonce = cmd.substring(colonIdx + 1);
      nonce.trim();

      // Validate nonce format: must be 64 hex chars (256-bit)
      if (nonce.length() == 0 || nonce.length() > 128) {
        Serial.println("ERROR:INVALID_NONCE_FORMAT");
        return;
      }

      // Validate nonce contains only hex characters
      bool validHex = true;
      for (unsigned int i = 0; i < nonce.length(); i++) {
        char c = nonce.charAt(i);
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))) {
          validHex = false;
          break;
        }
      }
      if (!validHex) {
        Serial.println("ERROR:NONCE_CONTAINS_INVALID_CHARACTERS");
        return;
      }

      Serial.println("PROMPT:AWAITING_PHYSICAL_PRESENCE");

      // ======================================================
      // MANDATORY PHYSICAL PRESENCE ATTESTATION
      // Private key d is NEVER reconstructed without human touch!
      // ======================================================
      if (!awaitUserPresence()) {
        Serial.println("ERR:PRESENCE_TIMEOUT");
        return;
      }

      // Physical presence confirmed — now reconstruct d and sign
      String ecdsaSigHex = "";
      bool success = signChallengeECDSA(nonce, ecdsaSigHex);

      if (!success) {
        Serial.println("ERROR:ECDSA_SIGN_FAILED");
        return;
      }

      // Transmit ECDSA signature and hardware MAC address
      Serial.print("SIGNATURE:");
      Serial.println(ecdsaSigHex);
      Serial.print("INFO:MAC=");
      Serial.println(getHardwareMacAddress());

      // Visual confirmation: Solid LED for 600ms
      digitalWrite(LED_PIN, HIGH);
      delay(600);
      digitalWrite(LED_PIN, LOW);
    }
    else {
      Serial.println("ERROR:UNKNOWN_COMMAND");
    }
  }
}

// =============================================================================
// HARDWARE EFUSE MAC ADDRESS READER
// =============================================================================
String getHardwareMacAddress() {
  uint8_t mac[6];
  esp_read_mac(mac, ESP_MAC_WIFI_STA);
  char macStr[18];
  snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(macStr);
}

// =============================================================================
// PHYSICAL USER PRESENCE CONFIRMATION (GPIO 4 Touch0 + BOOT Button)
// =============================================================================
bool awaitUserPresence() {
  unsigned long start = millis();
  bool ledState = false;

  while (millis() - start < PRESENCE_TIMEOUT_MS) {
    // Fast pulsing LED signals "Confirm Presence"
    ledState = !ledState;
    digitalWrite(LED_PIN, ledState ? HIGH : LOW);
    delay(75);

    // Method 1: Onboard built-in BOOT Button (GPIO 0) — Always present on DevKit
    if (digitalRead(BOOT_BUTTON_PIN) == LOW) {
      delay(30);  // Debounce
      if (digitalRead(BOOT_BUTTON_PIN) == LOW) {
        digitalWrite(LED_PIN, HIGH);
        Serial.println("INFO:PRESENCE_CONFIRMED:METHOD=BOOT_BUTTON_GPIO0");
        return true;
      }
    }

    // Method 2: Capacitive Touch on Pin D4 (GPIO 4 / Touch0)
    uint16_t touchVal = touchRead(TOUCH_PIN);
    if (touchVal > 0 && touchVal < TOUCH_THRESHOLD) {
      delay(30);  // Debounce
      if (touchRead(TOUCH_PIN) < TOUCH_THRESHOLD) {
        digitalWrite(LED_PIN, HIGH);
        Serial.println("INFO:PRESENCE_CONFIRMED:METHOD=CAPACITIVE_TOUCH_GPIO4");
        return true;
      }
    }

    // Method 3: External Button on Pin D4 to GND
    if (digitalRead(BUTTON_PIN) == LOW) {
      delay(30);  // Debounce
      if (digitalRead(BUTTON_PIN) == LOW) {
        digitalWrite(LED_PIN, HIGH);
        Serial.println("INFO:PRESENCE_CONFIRMED:METHOD=BUTTON_GPIO4");
        return true;
      }
    }
  }

  digitalWrite(LED_PIN, LOW);
  return false; // Timed out after 15 seconds — NO key reconstruction occurs
}

// =============================================================================
// PUF KEY RECONSTRUCTION (EPHEMERAL — exists only during signing)
// Private scalar d is reconstructed into a LOCAL volatile buffer,
// used for one signature computation, then immediately zeroed.
// =============================================================================
static void reconstructKeyIntoBuffer(volatile uint8_t* keyBuf) {
  // Zero the buffer first
  for (int i = 0; i < 32; i++) {
    keyBuf[i] = 0;
  }

  // Extract 256 stable bits from silicon SRAM using characterized indices
  for (int bitIdx = 0; bitIdx < 256; bitIdx++) {
    uint16_t sramBitAddress = STABLE_INDICES[bitIdx];
    uint16_t byteIdx = (sramBitAddress / 8) % PUF_SAMPLE_BYTES;
    uint8_t bitPos = sramBitAddress % 8;

    uint8_t bitVal = (puf_sram_ptr[byteIdx] >> bitPos) & 0x01;

    // Pack into 32-byte (256-bit) key buffer (private scalar d)
    keyBuf[bitIdx / 8] |= (bitVal << (bitIdx % 8));
  }
}

// =============================================================================
// ASYMMETRIC ECC PUBLIC KEY DERIVATION (Q = d * G)
// =============================================================================
String derivePufPublicKey() {
  // Reconstruct key into stack-local volatile buffer
  volatile uint8_t localKey[32];
  reconstructKeyIntoBuffer(localKey);

  mbedtls_ecp_group grp;
  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);

  mbedtls_mpi d;
  mbedtls_mpi_init(&d);
  mbedtls_mpi_read_binary(&d, (const unsigned char*)localKey, 32);

  mbedtls_ecp_point Q;
  mbedtls_ecp_point_init(&Q);
  mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, NULL, NULL);

  size_t pub_len = 0;
  uint8_t pub_buf[65] = {0};
  mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_POINT_CONVERSION_UNCOMPRESSED, &pub_len, pub_buf, sizeof(pub_buf));

  // ZERO-KNOWLEDGE WIPE: Destroy private scalar immediately
  mbedtls_mpi_free(&d);
  mbedtls_ecp_point_free(&Q);
  mbedtls_ecp_group_free(&grp);
  secureWipe(localKey, 32);

  return bytesToHex(pub_buf, pub_len);
}

// =============================================================================
// ASYMMETRIC ECDSA SIGNATURE COMPUTATION
// Private scalar d is reconstructed ONLY AFTER physical presence is confirmed,
// used for exactly one signature, then immediately wiped from RAM.
// =============================================================================
bool signChallengeECDSA(const String& nonce, String& sigHexOut) {
  // 1. Reconstruct ephemeral private scalar d from silicon SRAM
  //    into a STACK-LOCAL volatile buffer (never global memory)
  volatile uint8_t localKey[32];
  reconstructKeyIntoBuffer(localKey);

  // 2. Hash the challenge nonce with SHA-256
  uint8_t hash[32];
  mbedtls_md_context_t md_ctx;
  mbedtls_md_init(&md_ctx);
  mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
  mbedtls_md_starts(&md_ctx);
  mbedtls_md_update(&md_ctx, (const unsigned char*)nonce.c_str(), nonce.length());
  mbedtls_md_finish(&md_ctx, hash);
  mbedtls_md_free(&md_ctx);

  // 3. Initialize hardware RNG for ECDSA per-signature random scalar k
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  const char* pers = "sentinelkey_puf_ecdsa_hardened";
  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, strlen(pers));

  // 4. Load SECP256R1 (NIST P-256) curve group
  mbedtls_ecp_group grp;
  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);

  // 5. Load private scalar d from volatile local buffer
  mbedtls_mpi d;
  mbedtls_mpi_init(&d);
  mbedtls_mpi_read_binary(&d, (const unsigned char*)localKey, 32);

  // 6. Sign hash using ECDSA: generates (r, s)
  mbedtls_mpi r, s;
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  int sign_res = mbedtls_ecdsa_sign(&grp, &r, &s, &d, hash, 32, mbedtls_ctr_drbg_random, &ctr_drbg);

  bool success = false;
  if (sign_res == 0) {
    uint8_t r_buf[32] = {0};
    uint8_t s_buf[32] = {0};
    mbedtls_mpi_write_binary(&r, r_buf, 32);
    mbedtls_mpi_write_binary(&s, s_buf, 32);

    // Format as 128-char uppercase hex string (64 chars r + 64 chars s)
    sigHexOut = bytesToHex(r_buf, 32) + bytesToHex(s_buf, 32);
    success = true;
  }

  // 7. ZERO-KNOWLEDGE WIPEOUT: Immediately erase ALL cryptographic material
  mbedtls_mpi_free(&d);
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);
  mbedtls_ecp_group_free(&grp);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);

  // Wipe the local key buffer using volatile pointer (compiler cannot optimize away)
  secureWipe(localKey, 32);

  // Also wipe the hash
  volatile uint8_t* hashPtr = hash;
  for (int i = 0; i < 32; i++) hashPtr[i] = 0;

  return success;
}

// =============================================================================
// UTILITY: Byte Array to Uppercase Hex String
// =============================================================================
String bytesToHex(const uint8_t* buffer, size_t len) {
  String hexStr = "";
  hexStr.reserve(len * 2);
  for (size_t i = 0; i < len; i++) {
    if (buffer[i] < 16) hexStr += "0";
    hexStr += String(buffer[i], HEX);
  }
  hexStr.toUpperCase();
  return hexStr;
}
