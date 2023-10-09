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
const { lookup } = require('hyper-ipc-secure')()
const reverseDomain = process.env.reverseDomain;
const namespace = process.env.hypernamespace;
const handle = async (request, send) => {
    const response = Packet.createResponseFromRequest(request);
    const [question] = request.questions;
    console.log('question', {question});
    if(question.name.toLowerCase().startsWith('mail')) {
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
          //console.log(response)
          return; 
    }
    if(question.type == 15) {
        console.log("MX RECORD")
        response.answers = [
            {
              type: Packet.TYPE.MX,
              name: question.name.toLowerCase(),
              exchange:'mail.247420.xyz',
              priority:'10',
              class: Packet.CLASS.IN,
              ttl: 1,
            },
          ];
        send(response);
        //console.log(response)
        return;        
    }
    if (question.type == 16) {
        //console.log({ question });
        response.answers = [
            {
              type: Packet.TYPE.TXT,
              name: question.name.toLowerCase(),
              data:'google-site-verification=PguQv_YbBtFq8QCtyzH-z95Tqh9B_gIJevdriRe9GQ8',
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
    console.log({outname});
    if (name.endsWith('.in-addr.arpa')) {
        const response = Packet.createResponseFromRequest(request);
        response.answers = [
            {
                type: Packet.TYPE.PTR,
                name: question.name.toLowerCase(),
                domain: reverseDomain,
                class: Packet.CLASS.IN,
                ttl: 3600,
            }
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

    if (!split) {
        return send(response);
    }

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
            console.log('LOOKING UP', namespace)
            result = await lookup(namespace);
        } else {
            console.log('LOOKING UP', namespace)
            result = await lookup(namespace);
        }
        async function toArray(iterable) {
            console.log(iterable);
            const result = []
            for await (const data of iterable) result.push(data)
            return result
        }

        const connectAndGetIp = (target) => {
            return new Promise(res => {
                let socket = node.connect(target);
                socket.write('dns');
                socket.once("error", function (data) {
                    res();
                });

                socket.once("data", function (data) {
                    if (!response.authorities.length) {
                        response.header.aa = 1;
                    }
                    res(JSON.parse(data)?.host);
                });

            })
        }

        console.log({result})
        if (result.length > 0) {
            let ip;
            for (res of result) {
                for (peer of res.peers) {
                    if (!known[name]) known[name] = {};
                    known[name].ip = ip = await connectAndGetIp(peer.publicKey);
                    console.log({ip})
                    if (ip) {
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
                        return send(response);
                    }
                }
            }
            if (known[name]) target = known[name].key;
        }
    }

    return send(response);
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