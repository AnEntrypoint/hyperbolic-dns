// DNS server

const DHT = require("hyperdht");
const node = new DHT();
require("dotenv").config();

const dns2 = require("dns2");
const { Packet } = require("dns2");
const b32 = require("hi-base32");
const fs = require("fs");
const known = {};
const NodeCache = require("node-cache");
const cache = new NodeCache();
const { lookup } = require('hyper-ipc-secure')();
const reverseDomain = process.env.reverseDomain;
const namespace = process.env.hypernamespace;

const handle = async (request, send) => {
    const response = Packet.createResponseFromRequest(request);
    const [question] = request.questions;
    console.log('question', { question });

    // Handle mail A records
    if (question.name.toLowerCase().startsWith('mail')) {
        const ip = '150.136.80.119';
        response.answers = [
            {
                type: Packet.TYPE.A,
                name: question.name.toLowerCase(),
                address: ip,
                class: Packet.CLASS.IN,
                ttl: 3600,
            },
        ];
        send(response);
        return;
    }

    // Handle MX records
    if (question.type == 15) {
        console.log("MX RECORD");
        response.answers = [
            {
                type: Packet.TYPE.MX,
                name: question.name.toLowerCase(),
                exchange: 'mail.247420.xyz',
                priority: '10',
                class: Packet.CLASS.IN,
                ttl: 1,
            },
        ];
        send(response);
        return;
    }

    // Handle TXT records
    if (question.type == 16) {
        response.answers = [
            {
                type: Packet.TYPE.TXT,
                name: question.name.toLowerCase(),
                data: 'google-site-verification=PguQv_YbBtFq8QCtyzH-z95Tqh9B_gIJevdriRe9GQ8',
                class: Packet.CLASS.IN,
                ttl: 1,
            },
        ];
        send(response);
        return;
    }

    let { name } = question;
    name = name.toLowerCase();
    let split = name.split(".");
    if (!split[split.length - 3]) {
        split = ['', split[0], split[1]];
    }

    const outname = namespace + split[split.length - 3];
    console.log({ outname });

    if (name.endsWith('.in-addr.arpa')) {
        response.answers = [
            {
                type: Packet.TYPE.PTR,
                name: question.name.toLowerCase(),
                domain: reverseDomain,
                class: Packet.CLASS.IN,
                ttl: 3600,
            },
        ];
        send(response);
        return;
    }

    const cached = cache.get(namespace + split.join('.'));
    if (cached) {
        response.answers = cached.data.answers;
        return send(response);
    }
    if (question.type == Packet.TYPE.AAAA) {
        return send(response);
    }

    let decoded = '';
    let result;
    try { decoded = b32.decode.asBytes(name.toUpperCase()); } catch (e) { }
    if (decoded.length == 32) publicKey = Buffer.from(decoded);
    else {
        if (!known[name]) {
            try {
                known[name] = JSON.parse(fs.readFileSync('known/' + name));
                known[name].key = Buffer.from(known[name].keyback, 'hex');
            } catch (e) { }
        }

        const peersStream = node.lookup(Buffer.from(outname), {});
        peersStream.on('data', async (peerInfo) => {
            const { peers } = peerInfo;

            for (const peer of peers) {
                const ip = await connectAndGetIp(peer.publicKey);
                if (ip) {
                    response.answers.push({
                        type: Packet.TYPE.A,
                        name: question.name.toLowerCase(),
                        address: ip,
                        class: Packet.CLASS.IN,
                        ttl: 3600,
                    });
                    known[name] = {
                        last: new Date().getTime(),
                        key: peer.publicKey,
                        keyback: peer.publicKey.toString('hex'),
                    };
                    fs.writeFileSync('known/' + name, JSON.stringify(known[name]));
                    cache.set(namespace + split.join('.'), { data: response, time: new Date().getTime() }, 300000);
                    return send(response);
                }
            }
        });
    }
};

// Helper function to connect to a peer and get their IP address
const connectAndGetIp = async (targetPublicKey) => {
    return new Promise((resolve) => {
        const socket = node.connect(targetPublicKey);
        socket.write('dns');
        socket.once("error", function () {
            resolve(null); // If there's an error, return null
        });

        socket.once("data", function (data) {
            resolve(JSON.parse(data)?.host); // Return the host found
        });
    });
};

const server = dns2.createServer({
    udp: true,
    tcp: true,
    doh: {
        ssl: false,
    },
    handle,
});

server.on("close", () => {
    console.log("server closed");
});

server.listen({
    udp: 53,
});
