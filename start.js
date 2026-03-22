// Force Google DNS before anything else loads
const dns = require('dns');
dns.setServers(['8.8.8.8', '8.8.4.4']);

// Now load the actual server
require('./server.js');
