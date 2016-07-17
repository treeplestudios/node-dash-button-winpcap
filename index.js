"use strict";

var Cap = require('cap').Cap,
    decoders = require('cap').decoders,
    PROTOCOL = decoders.PROTOCOL

var stream = require('stream');
var _ = require('underscore');
var hex_to_int_array = require('./helpers.js').hex_to_int_array;
var int_array_to_hex = require('./helpers.js').int_array_to_hex;


var create_session = function (arp_interface) {
    try {
          var c = new Cap(),
          device = Cap.findDevice('192.168.1.2'),
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
    //pcap_session.on('packet', function(raw_packet) {
    cap_info.session.on('packet', function(nbytes, trunc) {
        var packet;

        /**
         * Perform a try/catch on packet decoding until pcap
         * offers a non-throwing mechanism to listen for errors
         * (We're just ignoring these errors because TCP packets with an
         *  unknown offset should have no impact on this application) 
         *
         * See https://github.com/mranney/node_pcap/issues/153
         */

        if (cap_info.linkType === 'ETHERNET') {
            var ret = decoders.Ethernet(cap_info.buffer);

            if (ret.info.type === PROTOCOL.ETHERNET.ARP) {
                //console.log('Decoding ARP ...');
                //console.log('ret', ret.info.srcmac);
            }
        }

        if(ret.info.type === PROTOCOL.ETHERNET.ARP) { //ensures it is an arp packet
            //for element in the mac addresses array
            mac_addresses.forEach(function(mac_address){
                if(!just_emitted[mac_address] && 
                    _.isEqual(ret.info.srcmac, mac_address)) {
                    readStream.emit('detected', mac_address);
                    just_emitted[mac_address] = true;
                    setTimeout(function () { just_emitted[mac_address] = false; }, timeout);
                }                
            });
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
