# NinebotCrypto

NinebotCrypto is a library based on majsi's reverse-engineering of Ninebot/Xiaomi first crypto protocol.

This protocol encrypts legacy Ninebot packets which documentation can be found [here](https://wiki.scooterhacking.org/doku.php?id=nbdocs "here").

## Known supported BLE versions
- **Xiaomi M365 Pro**: BLE110, BLE122
- **Xiaomi M365 Pro 2 / 1S / Lite**: BLE129, BLE132. On some devices only 5AAB is enabled on the latter - library might not work. Stick to 129 if possible.
- **Ninebot ESx**: BLE109, BLE110
- **Ninebot Max**: BLE110, BLE113, BLE114
- **Ninebot E-series**: BLE209, BLE213
- **Ninebot F-series**: BLE307

Other unlisted versions and Xiaomi-Ninebot scooters might be compatible with this library. Please let us know through a Github issue if that's the case.

## How to use
We will be going over the general principle of how to implement chained crypto on your app. The initial 5B message might be enough for some BLE versions, but you will be using the default keys and the crypto counter will not increment. We recommend implementing the library fully as shown in the below example to maximize compatibility for all versions and for increased stability and reliability. Please keep in mind some details might differ according to the language you're using.
Make sure you have a knowledge of the legacy Ninebot-Xiaomi protocol before beginning.

1. Import the NinebotCrypto library into your project
2. Create a NinebotCrypto object with the name of your choosing that's accessible in the scope of your scooter communication stack. For this example, I will call it *MsgCrypto*. Make sure it's persistent so you don't have to go through the pairing procedure at every request.
3. Make the outbound messages from your device pass through `MsgCrypto.encrypt(MessageData)`.
4. Make the inbound messages from your scooter pass through `MsgCrypto.decrypt(MessageData)`.
5. Send a packet to the dashboard with the command 0x5B. Argument is at 0. No payload. (`3e215b00`)
6. Parse the reply from the previous message. The reply consists of:
	- `213e5b` - indicating it's the reply you're looking for.
	- an argument that will be either 00 or 01. This indicates whether the scooter was already paired to another app. It is not needed for the library and can be ignored.
	- A 30 bytes payload.  You will need to extract the scooter S/N from it. Serial number starts at offset 16 and is 14 bytes long. Keep that data as it will be needed later for the pairing process.
	- Since this message is decrypted using the lib, all other relevant infos will have been extracted and processed already. 
7. Each second, send a packet to the dashboard with the command 0x5C. Argument is at 0. Payload is a 16 bytes chain of random data used as the new communication key. Since this message is encrypted using the lib, it will automatically register it. Make sure the data is kept the same during the entirety of the pairing session. Do not randomize it at each loop.
8. Prompt the user to press the power button to pair with the scooter.
9. Wait for a `213e5c01` reply to stop sending the above packet. The 01 argument indicates power button has been pressed. Some BLE versions might reply with `213e5c00` to acknowledge the new key. Others might wait until the power button has been pressed. Some BLE versions might also allow you to pair without the arg being at 01 - thus bypassing the press of the button. Due to those inconsistencies, it is recommended to always wait for the 01 argument before proceeding to the next step. 
10. Send a packet to the dashboard with the command 0x5D. Argument is at 0. Payload is your previously saved S/N data. It is recommend to implement a few retries for this command as you don't always get a reply on the first try.
11. The scooter will reply with `213e5d01`. Congratulations, you are now paired! Keep your NinebotCrypto object alive and keep passing your messages through the library's methods.

**Tip:** If you want compat for both crypto and legacy protocols, you can implement a flag that will bypass the crypto lib methods depending on whether or not you get an answer from the initial 0x5B message.


## Known issues
See [#13](https://github.com/scooterhacking/NinebotCrypto/issues/13): crypto iterator bug, communication issues on newer scooters

See [#16](https://github.com/scooterhacking/NinebotCrypto/issues/16): C version is currently broken, use C++ if possible
