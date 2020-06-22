///////////////////////////////////////////////////////////////////////////////////////
// Ninebot BLE Communication Sketch
// by Joey Babcock - https://joeybabcock.me/blog/
// ------------------------------------------------------------------------------------
// The sketch automaticlly connects to a device broadcasting the correct service UUID
// Once connected, enter one of the following characters below in the serial monitor 
// to perform the requested operation.
// ----------------
// l - lock scooter
// u - unlock scooter
// b - fetch battery ercentage
// s - fetch speed
// m - fetch mileage in miles
// k - fetch mileage in kimometers
///////////////////////////////////////////////////////////////////////////////////////

#include "BLEDevice.h"

#ifndef NULL
#define NULL 0
#endif

static BLEUUID serviceUUID("6E400001-B5A3-F393-E0A9-E50E24DCCA9E");
static BLEUUID rxCharactaristicUUID("6E400002-B5A3-F393-E0A9-E50E24DCCA9E");
static BLEUUID txCharactaristicUUID("6E400003-B5A3-F393-E0A9-E50E24DCCA9E");

byte prefix[] =           {0x5A, 0xA5, 0x01, 0x3D, 0x20};
byte writeReg[] =         {0x02};
byte readReg[] =          {0x01};

byte lock[] =             {0x5A, 0xA5, 0x01, 0x3D, 0x20, 0x02, 0x70, 0x01, 0x2E, 0xFF}; // l
byte unlock[] =           {0x5A, 0xA5, 0x01, 0x3D, 0x20, 0x02, 0x71, 0x01, 0x2D, 0xFF}; // u
byte headlightOn[] =      {0x5A, 0xA5, 0x01, 0x3D, 0x20, 0x02, 0x90, 0x01, 0x0E, 0xFF}; // h
byte headlightOff[] =     {0x5A, 0xA5, 0x01, 0x3D, 0x20, 0x02, 0x90, 0x00, 0x0F, 0xFF}; // o
byte readBatteryLevel[] = {0x5A, 0xA5, 0x01, 0x3D, 0x20, 0x01, 0xB4, 0x01, 0xEB, 0xFE}; // b
byte readSpeed[] =        {0x5A, 0xA5, 0x01, 0x3D, 0x20, 0x01, 0xB5, 0x04, 0xE7, 0xFE}; // s
byte readMileage[] =      {0x5A, 0xA5, 0x01, 0x3D, 0x20, 0x01, 0xB9, 0x04, 0xE3, 0xFE}; // 
byte readTotalMileage[] = {0x5A, 0xA5, 0x01, 0x3D, 0x20, 0x01, 0x29, 0x04, 0x73, 0xFF}; // m
byte alarmMode3[] =       {0x5A, 0xA5, 0x01, 0x3D, 0x20, 0x02, 0xC6, 0x09, 0xD0, 0xFE}; // 

static boolean doConnect = false;
static boolean connected = false;
static boolean doScan = false;
static boolean scanning = false;

uint8_t* lastData;
uint8_t batteryLevel;

static BLERemoteCharacteristic* pRemoteRXCharacteristic;
static BLERemoteCharacteristic* pRemoteTXCharacteristic;
static BLEAdvertisedDevice* myDevice;

int delayTime = 100;

static void notifyCallback(BLERemoteCharacteristic* pBLERemoteCharacteristic, uint8_t* pData, size_t length, bool isNotify) {
    Serial.println("Recieved Data on TX: ");
    Serial.print("{");
    for(int i = 0; i < length; i++)
    {
      Serial.print("0x");
      Serial.print(pData[i], HEX);
      Serial.print(", ");
    }
    Serial.print("}");
    Serial.println("");
    lastData = pData;
}

class MyClientCallback : public BLEClientCallbacks {
  void onConnect(BLEClient* pclient) {
      //Nothing at the moment
  }

  void onDisconnect(BLEClient* pclient) {
      connected = false;
      Serial.println("onDisconnect");
  }
};

bool connectToServer() {
    Serial.print("Attempting a connection to ");
    Serial.println(myDevice->getAddress().toString().c_str());
    
    BLEClient*  pClient  = BLEDevice::createClient();
    Serial.println(" - Created client");

    pClient->setClientCallbacks(new MyClientCallback());

    // Connect to the remove BLE Server.
    pClient->connect(myDevice);  // if you pass BLEAdvertisedDevice instead of address, it will be recognized type of peer device address (public or private)
    Serial.println(" - Connected to server");

    // Obtain a reference to the service we are after in the remote BLE server.
    BLERemoteService* pRemoteService = pClient->getService(serviceUUID);
    if (pRemoteService == nullptr) {
        Serial.print("Failed to find service UUID: ");
        Serial.println(serviceUUID.toString().c_str());
        pClient->disconnect();
        return false;
    }
    Serial.println(" - Found service");


    // Obtain a reference to the characteristic in the service of the remote BLE server.
    pRemoteRXCharacteristic = pRemoteService->getCharacteristic(rxCharactaristicUUID);
    pRemoteTXCharacteristic = pRemoteService->getCharacteristic(txCharactaristicUUID);
    if (pRemoteRXCharacteristic == nullptr) {
        Serial.print("Failed to find TX characteristic UUID: ");
        Serial.println(rxCharactaristicUUID.toString().c_str());
        pClient->disconnect();
        return false;
    }
    if (pRemoteTXCharacteristic == nullptr) {
        Serial.print("Failed to find TX characteristic UUID: ");
        Serial.println(txCharactaristicUUID.toString().c_str());
        pClient->disconnect();
        return false;
    }
    
    Serial.println(" - Found characteristics");

    // Read the value of the characteristic.
    if(pRemoteRXCharacteristic->canRead()) {
      std::string value = pRemoteRXCharacteristic->readValue();
      Serial.print("The characteristic value was: ");
      Serial.println(value.c_str());
    }

    if(pRemoteTXCharacteristic->canNotify())
    {
        pRemoteTXCharacteristic->registerForNotify(notifyCallback);
    }

    connected = true;
    return true;
}

class MyAdvertisedDeviceCallbacks: public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice advertisedDevice) {
    Serial.print("Advertised Device found: ");
    Serial.println(advertisedDevice.toString().c_str());

    if (advertisedDevice.haveServiceUUID() && advertisedDevice.isAdvertisingService(serviceUUID)) {
      Serial.println("UART Device found!");
      BLEDevice::getScan()->stop();
      myDevice = new BLEAdvertisedDevice(advertisedDevice);
      doConnect = true;
      doScan = true;
      scanning = false;
    }
  }
};


void setup() {
  Serial.begin(115200);
  Serial.println("Starting Arduino Ninebot...");
  BLEDevice::init("");
  BLEScan* pBLEScan = BLEDevice::getScan();
  pBLEScan->setAdvertisedDeviceCallbacks(new MyAdvertisedDeviceCallbacks());
  pBLEScan->setInterval(1349);
  pBLEScan->setWindow(449);
  pBLEScan->setActiveScan(true);
  pBLEScan->start(5, false);
  scanning = true;
}

void loop() {
    if(scanning && !doScan)
    {
        BLEDevice::getScan()->stop();
    }
    else if(!doScan)
    {
        BLEDevice::getScan()->start(5, false);
        delay(5000);
    }
    
    if (doConnect == true) {
        if(connectToServer()) {
            Serial.println("Connected to Ninebot BLE Server.");
            connected = true;
        } 
        else 
        {
            Serial.println("Failed to connect to Ninebot BLE Server.");
        }
        doConnect = false;
    }
  
    while (Serial.available() > 0) {
        char incomingCharacter = Serial.read();
        uint8_t returnedData;
        int calc;
        switch (incomingCharacter) {
            case 'l':
                pRemoteRXCharacteristic->writeValue(lock, sizeof(lock));
                Serial.println("Locked Scooter");
                break;
            case 'u':
                pRemoteRXCharacteristic->writeValue(unlock, sizeof(unlock));
                Serial.println("Unlocked Scooter");
                break;
            case 'h':
                pRemoteRXCharacteristic->writeValue(headlightOn, sizeof(headlightOn));
                Serial.println("Headlight Turned On");
                break;
            case 'o':
                pRemoteRXCharacteristic->writeValue(headlightOff, sizeof(headlightOff));
                Serial.println("Headlight Turned Off");
                break;
            case 'b':
                pRemoteRXCharacteristic->writeValue(readBatteryLevel, sizeof(readBatteryLevel));
                delay(delayTime); // Give the scooter time to fetch the level
                Serial.println("Battery Percentage:");
                returnedData = int(lastData[7]);
                if(returnedData != NULL)
                {
                  Serial.println(returnedData);
                }
                else
                {
                    Serial.println("0");
                }
                break;
            case 's':
                pRemoteRXCharacteristic->writeValue(readSpeed, sizeof(readSpeed));
                delay(delayTime); // Give the scooter time to fetch the level
                Serial.println("Speed:");
                returnedData = int(lastData[7]);
                if(returnedData != NULL)
                {
                  Serial.println((float)returnedData / 10.0);
                }
                else
                {
                    Serial.println("0");
                }
                break;
            case 'm':
                pRemoteRXCharacteristic->writeValue(readTotalMileage, sizeof(readTotalMileage));
                delay(delayTime); // Give the scooter time to fetch the level
                Serial.println("Mileage(mi):");
                calc = int(lastData[7]) + (256 * int(lastData[8]));
                if(calc != NULL)
                {
                  Serial.println((float)calc * 0.000621371);
                }
                else
                {
                    Serial.println("0");
                }
                break;
            case 'k':
                pRemoteRXCharacteristic->writeValue(readTotalMileage, sizeof(readTotalMileage));
                delay(delayTime); // Give the scooter time to fetch the level
                Serial.println("Mileage(km):");
                calc = int(lastData[7]) + (256 * int(lastData[8]));
                if(calc != NULL)
                {
                  Serial.println((float)calc * 0.001);
                }
                else
                {
                    Serial.println("0");
                }
                break;
        }
    }
}
