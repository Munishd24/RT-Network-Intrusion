/*
 * ESP32 IDS Hardware Alert Firmware
 * ----------------------------------
 * Polls the Flask API every 2 seconds via HTTP GET /latest
 * and drives physical indicators:
 *   • OLED SSD1306 (128×64) — displays threat status
 *   • RGB LED — color-coded severity
 *   • Passive Buzzer — audible alarm on CRITICAL
 *
 * Wiring (see README for circuit diagram):
 *   ESP32 GPIO 25 → Red LED   (through 220Ω resistor)
 *   ESP32 GPIO 26 → Green LED (through 220Ω resistor)
 *   ESP32 GPIO 27 → Blue LED  (through 220Ω resistor)
 *   ESP32 GPIO 14 → Buzzer +  (through NPN transistor base)
 *   ESP32 GPIO 21 → OLED SDA
 *   ESP32 GPIO 22 → OLED SCL
 */

#include <WiFi.h>
#include <HTTPClient.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

// ── Wi-Fi Credentials ─────────────────────────────────────────────
const char* ssid     = "YOUR_WIFI_SSID";
const char* password = "YOUR_WIFI_PASSWORD";

// ── Flask Server URL ──────────────────────────────────────────────
// Replace with the IP of the machine running sniffer.py
const char* serverURL = "http://YOUR_PC_IP:5000/latest";

// ── Pin Definitions ───────────────────────────────────────────────
#define RED_PIN    25
#define GREEN_PIN  26
#define BLUE_PIN   27
#define BUZZER_PIN 14

// ── OLED Config ───────────────────────────────────────────────────
#define SCREEN_WIDTH  128
#define SCREEN_HEIGHT  64
#define OLED_RESET     -1
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

// ── State Tracking (avoid redundant redraws) ──────────────────────
String lastSeverity = "";

// ══════════════════════════════════════════════════════════════════
//  SETUP
// ══════════════════════════════════════════════════════════════════
void setup() {
    Serial.begin(115200);

    // Configure output pins
    pinMode(RED_PIN,    OUTPUT);
    pinMode(GREEN_PIN,  OUTPUT);
    pinMode(BLUE_PIN,   OUTPUT);
    pinMode(BUZZER_PIN, OUTPUT);

    // Initialize OLED
    if (!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
        Serial.println(F("OLED init failed"));
        while (true) delay(1000);  // halt
    }

    // Splash screen
    display.clearDisplay();
    display.setTextColor(WHITE);
    display.setTextSize(1);
    display.setCursor(20, 10);
    display.println(F("IDS Hardware"));
    display.setCursor(30, 28);
    display.println(F("Alert Unit"));
    display.setCursor(16, 48);
    display.println(F("Connecting..."));
    display.display();

    // Connect to Wi-Fi
    WiFi.begin(ssid, password);
    Serial.print("Connecting to WiFi");
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.println("\nWiFi connected — IP: " + WiFi.localIP().toString());

    // Show connected status
    display.clearDisplay();
    display.setCursor(10, 10);
    display.println(F("WiFi Connected!"));
    display.setCursor(10, 30);
    display.println(WiFi.localIP().toString());
    display.setCursor(10, 50);
    display.println(F("Monitoring..."));
    display.display();
    delay(1500);

    // Start with green (all clear)
    setLED(false, true, false);
}

// ══════════════════════════════════════════════════════════════════
//  HELPERS
// ══════════════════════════════════════════════════════════════════

void setLED(bool r, bool g, bool b) {
    digitalWrite(RED_PIN,   r ? HIGH : LOW);
    digitalWrite(GREEN_PIN, g ? HIGH : LOW);
    digitalWrite(BLUE_PIN,  b ? HIGH : LOW);
}

void showOLED(const char* line1, const char* line2, const char* line3 = "") {
    display.clearDisplay();

    display.setTextSize(1);
    display.setTextColor(WHITE);

    // Line 1 — top (title)
    display.setCursor(0, 4);
    display.println(line1);

    // Line 2 — middle (main info, slightly larger)
    display.setTextSize(2);
    display.setCursor(0, 22);
    display.println(line2);

    // Line 3 — bottom (detail)
    display.setTextSize(1);
    display.setCursor(0, 50);
    display.println(line3);

    display.display();
}

void buzz(int onMs, int offMs, int repeats) {
    for (int i = 0; i < repeats; i++) {
        digitalWrite(BUZZER_PIN, HIGH);
        delay(onMs);
        digitalWrite(BUZZER_PIN, LOW);
        if (i < repeats - 1) delay(offMs);
    }
}

// ══════════════════════════════════════════════════════════════════
//  MAIN LOOP
// ══════════════════════════════════════════════════════════════════
void loop() {
    if (WiFi.status() != WL_CONNECTED) {
        showOLED("!! ERROR !!", "WiFi", "Reconnecting...");
        setLED(true, true, false);  // yellow = warning
        WiFi.reconnect();
        delay(5000);
        return;
    }

    HTTPClient http;
    http.begin(serverURL);
    http.setTimeout(3000);
    int httpCode = http.GET();

    if (httpCode == 200) {
        String payload = http.getString();
        Serial.println("Response: " + payload);

        if (payload.indexOf("CRITICAL") > -1) {
            if (lastSeverity != "CRITICAL") {
                setLED(true, false, false);        // RED
                showOLED("!! CRITICAL !!", "INTRUDER", "Attack detected!");
                buzz(200, 100, 3);                 // 3 quick beeps
                lastSeverity = "CRITICAL";
            }
        }
        else if (payload.indexOf("MEDIUM") > -1) {
            if (lastSeverity != "MEDIUM") {
                setLED(true, true, false);         // YELLOW
                showOLED("-- WARNING --", "MEDIUM", "Suspicious activity");
                buzz(150, 200, 1);
                lastSeverity = "MEDIUM";
            }
        }
        else if (payload.indexOf("LOW") > -1) {
            if (lastSeverity != "LOW") {
                setLED(false, false, true);        // BLUE
                showOLED("Low Alert", "MONITOR", "Watching traffic...");
                lastSeverity = "LOW";
            }
        }
        else {
            if (lastSeverity != "NONE") {
                setLED(false, true, false);        // GREEN
                showOLED("Network Status:", "ALL CLEAR", "No threats found");
                lastSeverity = "NONE";
            }
        }
    }
    else {
        Serial.println("HTTP error: " + String(httpCode));
        showOLED("Server Error", "HTTP", String(httpCode).c_str());
        setLED(true, false, true);  // magenta = server error
    }

    http.end();
    delay(2000);  // poll every 2 seconds
}
