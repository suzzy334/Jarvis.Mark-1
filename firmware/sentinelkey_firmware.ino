/*
 * SentinelKey - SRAM-PUF Based Hardware Authentication Token
 * Hyderabad Institute of Technology and Management (HITAM) - Department of ECE
 * 
 * Cryptographic Architecture: OPTION B (ASYMMETRIC ECDSA / NIST P-256 / SECP256R1)
 * Hardware Target: ESP32 DevKit V1 (ESP-WROOM-32)
 * Status Indicator: Built-in Blue Status LED (GPIO 2)
 * Physical Presence Detection:
 *   1. Built-in BOOT Button (GPIO 0, Active LOW) - Zero external wiring required!
 *   2. Capacitive Touch on Pin D4 (GPIO 4 / Touch0) - Human finger contact
 *   3. External Push Button on Pin D4 to GND (Active LOW with pullup)
 * Baud Rate: 115200
 */

#include <Arduino.h>
#include <WiFi.h>
#include <esp_bt.h>
#include <esp_wifi.h>

#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/md.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#define PUF_SAMPLE_BYTES 512       // 512 bytes = 4096 bits of uninitialized silicon SRAM
#define LED_PIN 2                  // Onboard blue status LED
#define BUTTON_PIN 4               // Pin D4 (GPIO 4) external button
#define TOUCH_PIN 4                // Pin D4 is also Touch0 (T0) on ESP32
#define BOOT_BUTTON_PIN 0          // Onboard built-in BOOT button (GPIO 0)
#define TOUCH_THRESHOLD 45         // Drops below ~40-50 when human finger touches pin D4
#define PRESENCE_TIMEOUT_MS 15000  // 15 seconds to confirm presence

// Physically powers down 2.4 GHz RF radio hardware (Zero Over-The-Air Attack Surface)
void disableAllRadios() {
  WiFi.mode(WIFI_OFF);
  btStop();
  esp_bt_controller_disable();
  esp_wifi_stop();
}

// -----------------------------------------------------------------------------
// SILICON SRAM POINTER & HELPER DATA
// -----------------------------------------------------------------------------
// Address 0x50000220 starts at active physical silicon SRAM entropy
volatile uint8_t* puf_sram_ptr = (volatile uint8_t*)0x50000220;

// Ephemeral 256-bit Golden Key (Private Scalar d for SECP256R1)
// ZERO-KNOWLEDGE RULE: Exists only in RAM during signing, then zeroed!
uint8_t golden_key[32];

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

// Function prototypes
bool awaitUserPresence();
void reconstructGoldenKey();
void wipeGoldenKey();
String bytesToHex(const uint8_t* buffer, size_t len);
String getHardwareMacAddress();
String derivePufPublicKey();
bool signChallengeECDSA(const String& nonce, String& sigHexOut);

// -----------------------------------------------------------------------------
// SETUP & STARTUP EMISSION
// -----------------------------------------------------------------------------
void setup() {
  disableAllRadios(); // Kill WiFi and Bluetooth (Zero RF attack surface)

  pinMode(LED_PIN, OUTPUT);
  pinMode(BUTTON_PIN, INPUT_PULLUP);
  pinMode(BOOT_BUTTON_PIN, INPUT_PULLUP);
  digitalWrite(LED_PIN, LOW);

  Serial.begin(115200);
  delay(120); // USB-Serial stabilization

  // Emit full 512-byte raw PUF snapshot for automated python characterization
  Serial.print("\n===PUF_START===");
  for (int i = 0; i < PUF_SAMPLE_BYTES; i++) {
    uint8_t b = puf_sram_ptr[i];
    if (b < 0x10) Serial.print("0");
    Serial.print(b, HEX);
  }
  Serial.println("===PUF_END===");

  // Ready signal: 2 quick blinks
  digitalWrite(LED_PIN, HIGH); delay(80);
  digitalWrite(LED_PIN, LOW);  delay(80);
  digitalWrite(LED_PIN, HIGH); delay(80);
  digitalWrite(LED_PIN, LOW);

  Serial.print("SENTINELKEY_READY:SCHEME=OPTION_B_ASYMMETRIC:MAC=");
  Serial.println(getHardwareMacAddress());
}

// -----------------------------------------------------------------------------
// COMMAND LOOP (Continuous Service)
// -----------------------------------------------------------------------------
void loop() {
  if (Serial.available() > 0) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();

    if (cmd == "PING") {
      Serial.println("PONG:SENTINELKEY_ASYMMETRIC_V2:HITAM_ECE");
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
      Serial.print(":SCHEME=ASYMMETRIC_ECDSA");
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
    else if (cmd == "DUMP_SRAM") {
      Serial.print("===PUF_START===");
      for (int i = 0; i < PUF_SAMPLE_BYTES; i++) {
        uint8_t b = puf_sram_ptr[i];
        if (b < 0x10) Serial.print("0");
        Serial.print(b, HEX);
      }
      Serial.println("===PUF_END===");
    }
    else if (cmd.startsWith("CHALLENGE:") || cmd.startsWith("SIGN_ATTENDANCE:")) {
      int colonIdx = cmd.indexOf(':');
      String nonce = cmd.substring(colonIdx + 1);
      nonce.trim();

      if (nonce.length() == 0) {
        Serial.println("ERROR:EMPTY_CHALLENGE_NONCE");
        return;
      }

      Serial.println("PROMPT:AWAITING_PHYSICAL_PRESENCE");

      // Verify physical user presence (Touch Pin D4 OR Press BOOT button)
      if (!awaitUserPresence()) {
        Serial.println("ERROR:USER_PRESENCE_TIMEOUT");
        return;
      }

      // OPTION B: Sign challenge nonce with private scalar d via ECDSA (NIST P-256)
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

// -----------------------------------------------------------------------------
// HARDWARE EFUSE MAC ADDRESS READER
// -----------------------------------------------------------------------------
String getHardwareMacAddress() {
  uint8_t mac[6];
  esp_read_mac(mac, ESP_MAC_WIFI_STA);
  char macStr[18];
  snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(macStr);
}

// -----------------------------------------------------------------------------
// PHYSICAL USER PRESENCE CONFIRMATION
// -----------------------------------------------------------------------------
bool awaitUserPresence() {
  unsigned long start = millis();
  bool ledState = false;

  while (millis() - start < PRESENCE_TIMEOUT_MS) {
    // Fast pulsing LED signals "Confirm Presence"
    ledState = !ledState;
    digitalWrite(LED_PIN, ledState ? HIGH : LOW);
    delay(75);

    // Method 1: Onboard built-in BOOT Button (GPIO 0) - Always present on DevKit!
    if (digitalRead(BOOT_BUTTON_PIN) == LOW) {
      delay(30);
      if (digitalRead(BOOT_BUTTON_PIN) == LOW) {
        digitalWrite(LED_PIN, HIGH);
        Serial.println("INFO:PRESENCE_DETECTED_VIA_BOOT_BUTTON");
        return true;
      }
    }

    // Method 2: Capacitive Touch on Pin D4 (GPIO 4 / Touch0)
    uint16_t touchVal = touchRead(TOUCH_PIN);
    if (touchVal > 0 && touchVal < TOUCH_THRESHOLD) {
      delay(30);
      if (touchRead(TOUCH_PIN) < TOUCH_THRESHOLD) {
        digitalWrite(LED_PIN, HIGH);
        Serial.println("INFO:PRESENCE_DETECTED_VIA_TOUCH_D4");
        return true;
      }
    }

    // Method 3: External Button on Pin D4 to GND
    if (digitalRead(BUTTON_PIN) == LOW) {
      delay(30);
      if (digitalRead(BUTTON_PIN) == LOW) {
        digitalWrite(LED_PIN, HIGH);
        Serial.println("INFO:PRESENCE_DETECTED_VIA_BUTTON_D4");
        return true;
      }
    }
  }

  digitalWrite(LED_PIN, LOW);
  return false; // Timed out after 15 seconds
}

// -----------------------------------------------------------------------------
// PUF KEY RECONSTRUCTION & ZERO-KNOWLEDGE ERASE
// -----------------------------------------------------------------------------
void reconstructGoldenKey() {
  memset(golden_key, 0, sizeof(golden_key));

  for (int bitIdx = 0; bitIdx < 256; bitIdx++) {
    uint16_t sramBitAddress = STABLE_INDICES[bitIdx];
    uint16_t byteIdx = (sramBitAddress / 8) % PUF_SAMPLE_BYTES;
    uint8_t bitPos = sramBitAddress % 8;

    uint8_t bitVal = (puf_sram_ptr[byteIdx] >> bitPos) & 0x01;

    // Pack into 32-byte (256-bit) golden key (private scalar d)
    golden_key[bitIdx / 8] |= (bitVal << (bitIdx % 8));
  }
}

void wipeGoldenKey() {
  volatile uint8_t* p = golden_key;
  for (size_t i = 0; i < sizeof(golden_key); i++) {
    p[i] = 0;
  }
}

// -----------------------------------------------------------------------------
// OPTION B: ASYMMETRIC ECC PUBLIC KEY DERIVATION (Q = d * G)
// -----------------------------------------------------------------------------
String derivePufPublicKey() {
  reconstructGoldenKey();

  mbedtls_ecp_group grp;
  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);

  mbedtls_mpi d;
  mbedtls_mpi_init(&d);
  mbedtls_mpi_read_binary(&d, golden_key, 32);

  mbedtls_ecp_point Q;
  mbedtls_ecp_point_init(&Q);
  mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, NULL, NULL);

  size_t pub_len = 0;
  uint8_t pub_buf[65] = {0};
  mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_POINT_CONVERSION_UNCOMPRESSED, &pub_len, pub_buf, sizeof(pub_buf));

  // Zero-knowledge wipe
  mbedtls_mpi_free(&d);
  mbedtls_ecp_point_free(&Q);
  mbedtls_ecp_group_free(&grp);
  wipeGoldenKey();

  return bytesToHex(pub_buf, pub_len);
}

// -----------------------------------------------------------------------------
// OPTION B: ASYMMETRIC ECDSA SIGNATURE COMPUTATION
// -----------------------------------------------------------------------------
bool signChallengeECDSA(const String& nonce, String& sigHexOut) {
  // 1. Reconstruct ephemeral private scalar d from silicon SRAM
  reconstructGoldenKey();

  // 2. Hash the challenge nonce with SHA-256
  uint8_t hash[32];
  mbedtls_md_context_t md_ctx;
  mbedtls_md_init(&md_ctx);
  mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
  mbedtls_md_starts(&md_ctx);
  mbedtls_md_update(&md_ctx, (const unsigned char*)nonce.c_str(), nonce.length());
  mbedtls_md_finish(&md_ctx, hash);
  mbedtls_md_free(&md_ctx);

  // 3. Initialize RNG for ECDSA per-signature random scalar k
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  const char* pers = "sentinelkey_puf_ecdsa";
  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, strlen(pers));

  // 4. Load SECP256R1 (NIST P-256) curve group
  mbedtls_ecp_group grp;
  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);

  // 5. Load private scalar d
  mbedtls_mpi d;
  mbedtls_mpi_init(&d);
  mbedtls_mpi_read_binary(&d, golden_key, 32);

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

  // 7. ZERO-KNOWLEDGE WIPEOUT: Immediately erase private scalar d and crypto context
  mbedtls_mpi_free(&d);
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);
  mbedtls_ecp_group_free(&grp);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  wipeGoldenKey();

  return success;
}

String bytesToHex(const uint8_t* buffer, size_t len) {
  String hexStr = "";
  for (size_t i = 0; i < len; i++) {
    if (buffer[i] < 16) hexStr += "0";
    hexStr += String(buffer[i], HEX);
  }
  hexStr.toUpperCase();
  return hexStr;
}
