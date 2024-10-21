const dns2 = require("dns2");
const { Packet } = require("dns2");
require("dotenv").config();

const server = dns2.createServer({
    udp: true,
    tcp: true,
    doh: {
        ssl: false,
    },
    handle: (request, send) => {
        const response = Packet.createResponseFromRequest(request);
        const [question] = request.questions;

        console.log('Question:', { question });

        if (question.type === Packet.TYPE.A) {
            // Respond with A record
            const ip = '150.136.80.119'; // This can be dynamically set as needed
            response.answers.push({
                type: Packet.TYPE.A,
                name: question.name.toLowerCase(),
                address: ip,
                class: Packet.CLASS.IN,
                ttl: 3600,
            });
            send(response);
            return;
        }

        if (question.type === Packet.TYPE.MX) {
            // Respond with MX record
            response.answers.push({
                type: Packet.TYPE.MX,
                name: question.name.toLowerCase(),
                exchange: 'mail.247420.xyz',
                priority: 10,
                class: Packet.CLASS.IN,
                ttl: 3600,
            });
            send(response);
            return;
        }

        if (question.type === Packet.TYPE.TXT) {
            // Respond with TXT record
            response.answers.push({
                type: Packet.TYPE.TXT,
                name: question.name.toLowerCase(),
                data: 'google-site-verification=PguQv_YbBtFq8QCtyzH-z95Tqh9B_gIJevdriRe9GQ8',
                class: Packet.CLASS.IN,
                ttl: 3600,
            });
            send(response);
            return;
        }

        // Default response for unsupported queries
        send(response); // Simply returning the response with no answers if we don't know how to handle it
    },
});

server.on("close", () => {
    console.log("Server closed");
});

server.listen({
    udp: 53,  // Listening on UDP port 53 for DNS queries
    tcp: 53,  // Listening on TCP port 53 for DNS queries as well
});
