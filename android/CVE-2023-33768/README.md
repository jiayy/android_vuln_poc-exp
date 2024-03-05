# CVE-2023-33768
[Description]
Incorrect signature verification of the firmware during the Device
Firmware Update process of Belkin Wemo Smart Plug WSP080 v1.2 allows
attackers to cause a Denial of Service (DoS) via a crafted firmware
file.

 

 [Additional Information]
 When updating the firmware of the Wemo smart plug via its mobile application, we found that if firmware signature of the smart plug firmware binary is invalid it can cause the Wemo smart plug to stop responding (become bricked).

 We exploit the Wemo Android App (com.belkin.wemoandroid) to inject modified firmware into the Wemo Smart Plug.
 The original firmware is located at:
 http://app.xbcs.net/firmware/Wemo-RTOS/715-f30e070f6/WEMO_WW_4.00.20111600.PVT-RTOS-SNSV4_tz.bin.enc.
 We change this URL in the Wemo App by injecting code in the onResponse method of the Android Volley library.
 We change the URL that points to a binary in which we modified one byte.
 Specifically we modify the binary in the following way:
 @00124C90 (4th line at end of firmware file)
 A3 E0 49 D5 changed to A3 E0 50 D5.

 We confirm the modified firmware is sent to the device by intercepting the network traffic to the smart plug.
 After the modified firmware is received by the Smart Plug the plug stops responding and cannot be reset or detected by the mobile application.

 

 [Vulnerability Type]
 Denial of Service

 

 [Vendor of Product]
 Belkin

 

 [Affected Product Code Base]
 Wemo Smart Plug WSP080 - Wemo Android App (com.belkin.wemoandroid) (1.2)

 

 [Affected Component]
 http://app.xbcs.net/firmware/Wemo-RTOS/715-f30e070f6/WEMO_WW_4.00.20111600.PVT-RTOS-SNSV4_tz.bin.enc

 

 [Attack Type]
 Remote

 

 [Attack Vectors]
 This attack can be performed by just modifying at least one byte of the firmware binary at any point during the delivery of the firmware binary to the Smart Plug.
 This can be done when firmware is downloaded to the mobile device or the MQTT server or when it is in trasition on any of the networks.


# Steps
1. Host the [crafted_firmware_tz.bin.enc](crafted_firmware_tz.bin.enc) file on a web server.
2. Replace the original firmware URL (http://34.135.183.171/wemo/WEMO_WW_4.00.20111600.PVT-RTOS-SNSV4_tz.bin.enc) in [brickDevice.py](brickDevice.py) with the URL of the hosted file.
3. Pair the Wemo Smart Plug with the Wemo App.
4. Run the [brickDevice.py](brickDevice.py) script.
5. The Wemo Smart Plug will stop responding and cannot be reset or detected by the mobile application.

# Publication
https://www.computer.org/csdl/proceedings-article/eurosp/2023/651200b047/1OFthXNYuRy
https://research.utwente.nl/en/publications/aot-attack-on-things-a-security-analysis-of-iot-firmware-updates
