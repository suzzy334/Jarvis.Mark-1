#include <Arduino.h>

// 512 bytes = 4096 bits of raw silicon entropy
#define PUF_SAMPLE_BYTES 512

// Start at 0x50000220 to skip the 32 bytes of RTC bootloader zeroes
volatile uint8_t* puf_sram_ptr = (volatile uint8_t*)0x50000220;

void setup() {
  // Must match the 115200 baud rate in collect_puf_data.py
  Serial.begin(115200);
  
  // Brief delay to let the USB serial bridge stabilize after a reboot
  delay(150);

  // Print the exact framing expected by your Python collector script
  Serial.print("\n===PUF_START===");
  
  for (int i = 0; i < PUF_SAMPLE_BYTES; i++) {
    uint8_t b = puf_sram_ptr[i];
    if (b < 0x10) {
      Serial.print("0"); // Pad single hex digits with a leading zero
    }
    Serial.print(b, HEX);
  }
  
  Serial.println("===PUF_END===");
}

void loop() {
  // The board idles here. 
  // The Python script will automatically toggle the DTR/RTS lines 
  // to hardware-reset the ESP32 and trigger setup() again.
  delay(1000);
}