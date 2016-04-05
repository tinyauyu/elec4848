var ecdh = require('ecdh');
var net = require('net');


/*
// Keep track of the chat clients
var clients = [];

// Start a TCP Server
net.createServer(function (socket) {

  // Identify this client
  socket.name = socket.remoteAddress + ":" + socket.remotePort 

  // Put this new client in the list
  clients.push(socket);

  // Send a nice welcome message and announce
  //socket.write("Welcome " + socket.name + "\n");
  //broadcast(socket.name + " joined the chat\n", socket);

  // Handle incoming messages from clients.
  socket.on('data', function (data) {
    broadcast(socket.name + "> " + data, socket);
  });

  // Remove the client from the list when it leaves
  socket.on('end', function () {
    clients.splice(clients.indexOf(socket), 1);
    broadcast(socket.name + " left the chat.\n");
  });
  
  // Send a message to all clients
  function broadcast(message, sender) {
    clients.forEach(function (client) {
      // Don't want to send it to sender
      if (client === sender) return;
      client.write(message);
    });
    // Log it to the server output too
    process.stdout.write(message)
  }

}).listen(5000);

// Put a friendly message on the terminal of the server.
console.log("Chat server running at port 5000\n");
*/



// Pick some curve
var curve = ecdh.getCurve('secp160r1'),

// Generate random keys for Alice and Bob
aliceKeys = ecdh.generateKeys(curve),
bobKeys = ecdh.generateKeys(curve);

// Or you may get the keys from buffers:
//	aliceKeys = {
//		publicKey: ecdh.PublicKey.fromBuffer(curve, buf1),
//		privateKey: ecdh.PrivateKey.fromBuffer(curve, buf2)
//	};

console.log('Alice public key:', aliceKeys.publicKey.buffer.toString('hex'));
console.log('Alice private key:', aliceKeys.privateKey.buffer.toString('hex'));
console.log('Bob public key:', bobKeys.publicKey.buffer);
console.log('Bob private key:', bobKeys.privateKey.buffer);

/*
var readline = require('readline');

var rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

rl.question("Enter public key: ", function(answer) {
  // TODO: Log the answer in a database
  bobKey = {
	publicKey: answer
  }

  rl.close();
});
*/



// Alice generate the shared secret:
var aliceSharedSecret = aliceKeys.privateKey.deriveSharedSecret(bobKeys.publicKey);
console.log('shared secret:', aliceSharedSecret.toString('hex'));

// Checking that Bob has the same secret:
var bobSharedSecret = bobKeys.privateKey.deriveSharedSecret(aliceKeys.publicKey),
equals = (bobSharedSecret.toString('hex') === aliceSharedSecret.toString('hex'));
console.log('Shared secrets are', equals ? 'equal :)' : 'not equal!!');
