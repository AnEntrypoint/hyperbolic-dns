const DHT = require("@hyperswarm/dht");
const node = new DHT();

require("dotenv").config();
const dns2 = require("dns2");
const { Packet } = require("dns2");
const b32 = require("hi-base32");
const fs = require("fs");
const pending = {};
const known = {};
const NodeCache = require("node-cache");
const cache = new NodeCache();

const handle = async (request, send) => {
    const response = Packet.createResponseFromRequest(request);
    const [question] = request.questions;
    let { name } = question;
    console.log({ name })
    name = name.toLowerCase();
    let split = name.split(".");
    if (!split[split.length - 3]) {
        return send(response);
    }

    const outname = 'hyperbolic' + split[split.length - 3];
    if (name.endsWith('.in-addr.arpa')) {
        const response = Packet.createResponseFromRequest(request);
        response.answers = [
            {
                type: Packet.TYPE.PTR,
                name: question.name.toLowerCase(),
                domain: 'lan.247420.xyz',
                class: Packet.CLASS.IN,
                ttl: 3600,
            }
        ];
        send(response);
        return;
    }
    const cached = cache.get('hyperbolic' + split.join('.'));
    if (cached) {
        response.answers = cached.data.answers;
        return send(response);
    }
    if (question.type == Packet.TYPE.AAAA) {
        return send(response);
    }


    if (!split) {
        console.log("no name sending early", question);
        return send(response);
    }

    let target;
    let decoded = '';
    let result;
    try { decoded = b32.decode.asBytes(name.toUpperCase()) } catch (e) { }
    if (decoded.length == 32) publicKey = Buffer.from(decoded);
    else {
        if (!known[name]) {
            try {
                known[name] = JSON.parse(fs.readFileSync('known/' + name));
                known[name].key = Buffer.from(known[name].keyback, 'hex');
            } catch (e) {
            }
        }
        if (known[name] && new Date().getTime() - known[name].last < 15 * 60 * 1000) {
            console.log('key cached from file');
            const hash = DHT.hash(Buffer.from(outname));
            result = await toArray(node.lookup(hash));
        } else {
            console.log('trying to look it up')
            const hash = DHT.hash(Buffer.from(outname));
            console.log("hash is:", outname);
            result = await toArray(node.lookup(hash));
            //console.log('result is', JSON.stringify(result, null, 2))
        }
        async function toArray(iterable) {
            const result = []
            for await (const data of iterable) result.push(data)
            return result
        }

        const connectAndGetIp = (target) => {
            return new Promise(res => {
                console.log('connecting to', target.toString('hex'));
                let socket = node.connect(target);
                socket.write('dns');
                socket.once("error", function (data) {
                    send(response);
                    res();
                });

                socket.once("data", function (data) {
                    console.log("PEER RESPONSE", data.toString());
                    if (!response.authorities.length) {
                        response.header.aa = 1;
                    }
                    send(response);
                    res(JSON.parse(data)?.host);
                });

            })
        }

        if (result.length > 0) {
            const loopConnections = async () => {
                let ip;
                for (res of result) {
                    for (peer of res.peers) {
                        //console.log("KNOWN", name, known[name])
                        if (known[name]?.key == peer.publicKey) {
                        } else if(known[name]?.key && known[name]?.ip) {
                            console.log(known[name]);
                        }
                        console.log('connecting to ', peer);
                        if(!known[name]) known[name]={};
                        known[name].ip = ip = await connectAndGetIp(peer.publicKey);

                        if (ip) {
                            console.log('IP FOUND', {ip});
                            known[name] = {};
                            known[name].last = new Date().getTime();
                            known[name].key = peer.publicKey;
                            known[name].keyback = known[name]?.key?.toString('hex');
                            fs.writeFileSync('known/' + name, JSON.stringify(known[name]));
                            response.answers.push({
                                type: Packet.TYPE.A,
                                name: question.name.toLowerCase(),
                                address: ip,
                                class: Packet.CLASS.IN,
                                ttl: 3600,
                            });
                            cache.set('hyperbolic' + split.join('.'), { data: response, time: new Date().getTime() }, 300000);
                            continue;
                        }
                    }
                    if (ip) continue;
                }
            }
            loopConnections();
            if (known[name]) target = known[name].key;
        } else {
            console.log('no results');
        }
    }

    if (!target) {
        console.log(response.answers);
        send(response);
    }
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
