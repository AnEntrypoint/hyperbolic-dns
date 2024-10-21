// server.js
const express = require('express');
const dns2 = require("dns2");
const { Packet } = require("dns2");
const bodyParser = require('body-parser');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// In-memory store for registered subdomains
const registeredSubdomains = {};

// Middleware to parse JSON bodies
app.use(bodyParser.json());

// Endpoint to handle registration
app.post('/register', (req, res) => {
    const token = req.headers['authorization'];

    // Verify Bearer token
    if (!token || token !== `Bearer ${process.env.BEARER_TOKEN}`) {
        return res.status(403).json({ error: 'Unauthorized' });
    }

    const { name, host } = req.body;

    // Validate input
    if (!name || !host) {
        return res.status(400).json({ error: 'Missing name or host in the request body.' });
    }

    // Save the registration in memory
    registeredSubdomains[name.toLowerCase()] = host;
    console.log(`Registered subdomain: ${name} with host: ${host}`);

    return res.status(200).json({ message: `Successfully registered ${name}` });
});

// Create DNS server
const dnsServer = dns2.createServer({
    udp: true,
    tcp: true,
    doh: {
        ssl: false,
    },
    handle: (request, send) => {
        const response = Packet.createResponseFromRequest(request);
        const [question] = request.questions;

        console.log('Question:', { question });

        const subdomain = question.name.toLowerCase();

        // Check for registered subdomains
        if (registeredSubdomains[subdomain]) {
            const host = registeredSubdomains[subdomain];

            // Respond with A record
            response.answers.push({
                type: Packet.TYPE.A,
                name: subdomain,
                address: host, // Respond with the corresponding host
                class: Packet.CLASS.IN,
                ttl: 3600,
            });
            send(response);
            return;
        }

        // Respond with no answer for unregistered subdomains
        send(response); // No answer if the domain is not registered
    },
});

// Start the DNS server
dnsServer.on("close", () => {
    console.log("DNS server closed");
});
dnsServer.listen({
    udp: 53,  // Listening on UDP port 53 for DNS queries
    tcp: 53,  // Listening on TCP port 53 for DNS queries as well
});

// Start the Express server
app.listen(PORT, () => {
    console.log(`Webhook registration server running on http://localhost:${PORT}`);
});
