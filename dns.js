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

        const name = question.name.toLowerCase();
        console.log({ subdomain })
        // Registering a wildcard subdomain
        const parts = name.split('.');
        if (parts.length = 2) {
            response.answers.push({
                type: Packet.TYPE.A,
                name: subdomain,
                address: process.env.HOSTIP,
                class: Packet.CLASS.IN,
                ttl: 3600,
            });
        }
        parts.pop()
        parts.pop();
        if (subdomain.endsWith('dns')) {
            response.answers.push({
                type: Packet.TYPE.A,
                name: subdomain,
                address: process.env.HOSTIP,
                class: Packet.CLASS.IN,
                ttl: 3600,
            });
        }
        // Check for registered exact match
        if (subdomain.endsWith(registeredSubdomains[subdomain])) {
            const host = registeredSubdomains[subdomain];
            response.answers.push({
                type: Packet.TYPE.A,
                name: subdomain,
                address: host,
                class: Packet.CLASS.IN,
                ttl: 3600,
            });

            return;
        }
        send(response);
    },
});

// Start the DNS server
dnsServer.on("close", () => {
    console.log("DNS server closed");
});
dnsServer.listen({
    udp: 53,
    tcp: 53,
});

// Start the webhook server
app.listen(PORT, () => {
    console.log(`Webhook registration server running on http://localhost:${PORT}`);
});
