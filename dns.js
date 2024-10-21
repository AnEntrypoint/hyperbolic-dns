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
    console.log('Received registration request:', req.body);

    // Verify Bearer token
    console.log('Verifying token:', token);
    if (!token || token !== `Bearer ${process.env.BEARER_TOKEN}`) {
        console.error('Unauthorized request, invalid token');
        return res.status(403).json({ error: 'Unauthorized' });
    }

    const { name, host } = req.body;

    // Validate input
    if (!name || !host) {
        console.error('Invalid input, missing name or host:', { name, host });
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

        console.log('Received DNS question:', { question });

        const name = question.name.toLowerCase();
        console.log('Processing DNS query for:', name);

        // Process and respond to DNS queries
        const parts = name.split('.');
        parts.pop();
        parts.pop();
        const subdomain = parts.join('.');
        console.log('Extracted subdomain:', subdomain);

        // Handle wildcard and dns entries
        if (parts.length === 2) {
            console.log('Detected a wildcard subdomain query for:', subdomain);
            response.answers.push({
                type: Packet.TYPE.A,
                name: name,
                address: process.env.HOSTIP,
                class: Packet.CLASS.IN,
                ttl: 3600,
            });
        }

        // Check if subdomain ends with 'dns'
        if (subdomain.endsWith('dns')) {
            console.log('Subdomain ends with "dns", adding entry:', subdomain);
            response.answers.push({
                type: Packet.TYPE.A,
                name: name,
                address: process.env.HOSTIP,
                class: Packet.CLASS.IN,
                ttl: 3600,
            });
        }

        // Check for registered exact match
        if (registeredSubdomains[subdomain]) {
            console.log('Found registered subdomain:', subdomain);
            const host = registeredSubdomains[subdomain];
            response.answers.push({
                type: Packet.TYPE.A,
                name: name,
                address: host,
                class: Packet.CLASS.IN,
                ttl: 3600,
            });
        } else {
            console.log('No record found for:', subdomain);
        }

        // Send response
        send(response);
        console.log('DNS response sent for:', name);
    },
});

// Start the DNS server
dnsServer.on("close", () => {
    console.log("DNS server closed");
});
dnsServer.listen({
    udp: 53,
    tcp: 53,
}, () => {
    console.log('DNS server listening on 53');
});

// Start the webhook server
app.listen(PORT, () => {
    console.log(`Webhook registration server running on http://localhost:${PORT}`);
});