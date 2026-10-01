// AEGIS modified subset: persistent mutation APIs removed; transport allowlist added.
/*
  This file is part of the ArduinoECCX08 library.
  Copyright (c) 2018 Arduino SA. All rights reserved.

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include <Arduino.h>

#include "ECCX08.h"

const uint32_t ECCX08Class::_wakeupFrequency = 100000u;  // 100 kHz
const uint32_t ECCX08Class::_normalFrequency = 100000u; // conservative bring-up bus speed

ECCX08Class::ECCX08Class(TwoWire& wire, uint8_t address) :
  _wire(&wire),
  _address(address)
{
}

ECCX08Class::~ECCX08Class()
{
}

int ECCX08Class::begin(uint8_t i2cAddress)
{
  _address = i2cAddress;
  return begin();
}

int ECCX08Class::begin()
{
  _wire->begin();

  if (!wakeup() || !idle()) return 0;
  
  long ver = version() & 0x0F00000;

  if (ver != 0x0500000 && ver != 0x0600000) {
    return 0;
  }

  return 1;
}

void ECCX08Class::end()
{
  // First wake up the device otherwise the chip didn't react to a sleep commando
  wakeup();
  sleep();
#ifdef WIRE_HAS_END
  _wire->end();
#endif
}

int ECCX08Class::serialNumber(byte sn[])
{
  if (!read(0, 0, &sn[0], 4)) {
    return 0;
  }

  if (!read(0, 2, &sn[4], 4)) {
    return 0;
  }

  if (!read(0, 3, &sn[8], 4)) {
    return 0;
  }

  return 1;
}

String ECCX08Class::serialNumber()
{
  String result = (char*)NULL;
  byte sn[12];

  if (!serialNumber(sn)) {
    return result;
  }

  result.reserve(18);

  for (int i = 0; i < 9; i++) {
    byte b = sn[i];

    if (b < 16) {
      result += "0";
    }
    result += String(b, HEX);
  }

  result.toUpperCase();

  return result;
}





int ECCX08Class::random(byte data[], size_t length)
{
  if (!wakeup()) {
    return 0;
  }

  while (length) {
    if (!sendCommand(0x1b, 0x00, 0x0000)) {
      return 0;
    }

    delay(23);

    byte response[32];

    if (!receiveResponse(response, sizeof(response))) {
      return 0;
    }

    int copyLength = min(32, (int)length);
    memcpy(data, response, copyLength);

    length -= copyLength;
    data += copyLength;
  }

  delay(1);

  idle();

  return 1;
}



int ECCX08Class::generatePublicKey(int slot, byte publicKey[])
{
  if (!wakeup()) {
    return 0;
  }

  if (!sendCommand(0x40, 0x00, slot)) {
    return 0;
  }

  delay(115);

  if (!receiveResponse(publicKey, 64)) {
    return 0;
  }

  delay(1);

  idle();

  return 1;
}



int ECCX08Class::ecSign(int slot, const byte message[], byte signature[])
{
  byte rand[32];

  if (!random(rand, sizeof(rand))) {
    return 0;
  }

  if (!challenge(message)) {
    return 0;
  }

  if (!sign(slot, signature)) {
    return 0;
  }

  return 1;
}













int ECCX08Class::locked()
{
  byte config[4];

  if (!read(0, 0x15, config, sizeof(config))) {
    return 0;
  }

  if (config[2] == 0x00 && config[3] == 0x00) {
    return 1; // locked
  }

  return 0;
}



int ECCX08Class::readConfiguration(byte data[])
{
  for (int i = 0; i < 128; i += 32) {
    if (!read(0, i / 4, &data[i], 32)) {
      return 0;
    }
  }

  return 1;
}



int ECCX08Class::wakeup()
{
  _wire->setClock(_wakeupFrequency);
  _wire->beginTransmission(0x00);
  _wire->endTransmission();

  delayMicroseconds(1500);

  byte response;

  if (!receiveResponse(&response, sizeof(response)) || response != 0x11) {
    return 0;
  }

  _wire->setClock(_normalFrequency);

  return 1;
}

int ECCX08Class::sleep()
{
  _wire->beginTransmission(_address);
  _wire->write(0x01);

  if (_wire->endTransmission() != 0) {
    return 0;
  }

  delay(1);

  return 1;
}

int ECCX08Class::idle()
{
  _wire->beginTransmission(_address);
  _wire->write(0x02);

  if (_wire->endTransmission() != 0) {
    return 0;
  }

  delay(1);

  return 1;
}

long ECCX08Class::version()
{
  uint32_t version = 0;

  if (!wakeup()) {
    return 0;
  }

  if (!sendCommand(0x30, 0x00, 0x0000)) {
    return 0;
  }

  delay(2);

  if (!receiveResponse(&version, sizeof(version))) {
    return 0;
  }

  delay(1);
  idle();

  return version;
}

int ECCX08Class::challenge(const byte message[])
{
  uint8_t status;

  if (!wakeup()) {
    return 0;
  }

  // Nounce, pass through
  if (!sendCommand(0x16, 0x03, 0x0000, message, 32)) {
    return 0;
  }

  delay(29);

  if (!receiveResponse(&status, sizeof(status))) {
    return 0;
  }

  delay(1);
  idle();

  if (status != 0) {
    return 0;
  }

  return 1;
}



int ECCX08Class::sign(int slot, byte signature[])
{
  if (!wakeup()) {
    return 0;
  }

  if (!sendCommand(0x41, 0x80, slot)) {
    return 0;
  }

  delay(70);

  if (!receiveResponse(signature, 64)) {
    return 0;
  }

  delay(1);
  idle();

  return 1;
}

int ECCX08Class::read(int zone, int address, byte buffer[], int length)
{
  if (!wakeup()) {
    return 0;
  }

  if (length != 4 && length != 32) {
    return 0;
  }

  if (length == 32) {
    zone |= 0x80;
  }

  if (!sendCommand(0x02, zone, address)) {
    return 0;
  }

  delay(5);

  if (!receiveResponse(buffer, length)) {
    return 0;
  }

  delay(1);
  idle();

  return length;
}







int ECCX08Class::sendCommand(uint8_t opcode, uint8_t param1, uint16_t param2, const byte data[], size_t dataLength)
{
  // AEGIS persistent-write firewall. No Lock, Write, or private-key GenKey.
  const bool allowed =
    (opcode == 0x02 && (param1 == 0 || param1 == 0x80)) || // config READ only
    (opcode == 0x30 && param1 == 0) || // Info
    (opcode == 0x1b && param1 == 0) || // Random
    (opcode == 0x16 && param1 == 3) || // Nonce passthrough (volatile)
    (opcode == 0x40 && param1 == 0) || // derive PUBLIC key only
    (opcode == 0x41 && param1 == 0x80); // external digest Sign
  if (!allowed || dataLength > 64) return 0;

  int commandLength = 8 + dataLength; // 1 for type, 1 for length, 1 for opcode, 1 for param1, 2 for param2, 2 for crc
  byte command[commandLength]; 
  
  command[0] = 0x03;
  command[1] = sizeof(command) - 1;
  command[2] = opcode;
  command[3] = param1;
  memcpy(&command[4], &param2, sizeof(param2));
  if (dataLength) memcpy(&command[6], data, dataLength);

  uint16_t crc = crc16(&command[1], 8 - 3 + dataLength);
  memcpy(&command[6 + dataLength], &crc, sizeof(crc));

  _wire->beginTransmission(_address);
  _wire->write(command, commandLength);
  if (_wire->endTransmission() != 0) {
    return 0;
  }

  return 1;
}

int ECCX08Class::receiveResponse(void* response, size_t length)
{
  if (!response || length == 0 || length > 64) return 0;
  const size_t expected=length+3;
  byte packet[67]={};
  for(int attempt=0;attempt<20;attempt++) {
    size_t received=_wire->requestFrom((uint8_t)_address,(uint8_t)expected,(bool)true);
    size_t count=0;
    while(_wire->available()) {
      int value=_wire->read();
      if(count<sizeof(packet)) packet[count]=uint8_t(value);
      ++count;
    }
    if(received==expected && count==expected && packet[0]==expected) {
      uint16_t crc=packet[expected-2] | (uint16_t(packet[expected-1])<<8);
      if(crc!=crc16(packet,expected-2)) return 0;
      memcpy(response,packet+1,length);return 1;
    }
    if(received!=0) return 0; // malformed/status response is not expected payload
    delay(2);
  }
  return 0;
}

uint16_t ECCX08Class::crc16(const byte data[], size_t length)
{
  if (data == NULL || length == 0) {
    return 0;
  }

  uint16_t crc = 0;

  while (length) {
    byte b = *data;

    for (uint8_t shift = 0x01; shift > 0x00; shift <<= 1) {
      uint8_t dataBit = (b & shift) ? 1 : 0;
      uint8_t crcBit = crc >> 15;

      crc <<= 1;
      
      if (dataBit != crcBit) {
        crc ^= 0x8005;
      }
    }

    length--;
    data++;
  }

  return crc;
}

#ifdef CRYPTO_WIRE
ECCX08Class ECCX08(CRYPTO_WIRE, 0x60);
#else
ECCX08Class ECCX08(Wire, 0x60);
#endif