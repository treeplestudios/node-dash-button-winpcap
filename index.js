"use strict";

var Cap = require('cap').Cap,
    decoders = require('cap').decoders,
    PROTOCOL = decoders.PROTOCOL

var stream = require('stream'),
    _ = require('underscore'),
    interfaceAddresses = require('interface-addresses'),
    addresses = interfaceAddresses()

var create_session = function (arp_interface) {
    try {
          var c = new Cap(),
          device = (arp_interface) ? Cap.findDevice(addresses[arp_interface]) : Cap.findDevice(addresses['Ethernet']), // in windows it uses the name of the network card
          filter = 'arp',
          bufSize = 10 * 1024 * 1024,
          buffer = new Buffer(65535);

        var linkType = c.open(device, filter, bufSize, buffer);
        c.setMinBytes && c.setMinBytes(0);

        //var session = pcap.createSession(arp_interface);
    } catch (err) {
        console.error(err);
        console.error("Failed to create pcap session: couldn't find devices to listen on.\n" + "Try running with elevated privileges via 'sudo'");
        throw new Error('Error: No devices to listen');
    }
    return {linkType: linkType, session: c, buffer: buffer};
};

//Function to register the node button
var register = function(mac_addresses, arp_interface, timeout) {
    if (timeout === undefined || timeout === null) {
     timeout = 5000;
    }
    if (Array.isArray(mac_addresses)){
        //console.log("array detected")
    } else {
        //console.log("single element detected")
        mac_addresses = [mac_addresses];//cast to array
    }
    var cap_info = create_session(arp_interface);
    var readStream = new stream.Readable({
        objectMode: true
    });
    var just_emitted = {};
    mac_addresses.forEach(function(mac_address){
        just_emitted[mac_address] = false;
    });

    cap_info.session.on('packet', function(nbytes, trunc) {

        if (cap_info.linkType === 'ETHERNET') {
            var ret = decoders.Ethernet(cap_info.buffer);

            if (ret.info.type === PROTOCOL.ETHERNET.ARP) {
                //console.log('Decoding ARP ...');
                //console.log('ret', ret.info.srcmac);

                //for element in the mac addresses array
                mac_addresses.forEach(function (mac_address) {
                    if (!just_emitted[mac_address] &&
                      _.isEqual(ret.info.srcmac, mac_address)) {
                        readStream.emit('detected', mac_address);
                        just_emitted[mac_address] = true;
                        setTimeout(function () { just_emitted[mac_address] = false; }, timeout);
                    }
                });
            }
        }
    });
    return readStream;
};

if (process.env.NODE_ENV === 'test') {
    module.exports = {  hex_to_int_array: hex_to_int_array, 
                        int_array_to_hex: int_array_to_hex,
                        create_session: create_session,
                        register: register
                    };
} else {
    module.exports = register;
}
