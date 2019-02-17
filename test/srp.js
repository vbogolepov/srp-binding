var assert = require("assert");
const crypto = require('crypto')
const srp = require("../");

describe("srp", function() {
  describe("test srp", function () {
    it("returns a status", function () {

      var modulus = Buffer.from('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF', 'hex')

      var generator = Buffer.from('05', 'hex')
      var salt = Buffer.from('BEB25379D1A8581EB5A727673A2441EE', 'hex')//crypto.randomBytes(15)

      const server = new srp.SrpObject();
      console.log('InitServerSRP6a status: ' + server.InitServerSRP6a())
      console.log('server SetUsername status: ' + (server.SetUsername('alice') == 0 ? 'success' : 'failed'))
      console.log('server SetParams status: ' + (server.SetParams(modulus, generator, salt) == 0 ? 'success' : 'failed'))
      console.log('server SetPassword status: ' + (server.SetPassword('password123') == 0 ? 'success' : 'failed'))

      const client = new srp.SrpObject();
      console.log('InitClientSRP6a status: ' + (client.InitClientSRP6a() == 0 ? 'success' : 'failed'))
      console.log('client SetUsername status: ' + (client.SetUsername('alice') == 0 ? 'success' : 'failed'))
      console.log('client SetParams status: ' + (client.SetParams(modulus, generator, salt) == 0 ? 'success' : 'failed'))

      var cpub = client.GenPub();
      var spub = server.GenPub();

      console.log('client GenPub: ' + cpub.toString('hex'))
      console.log('server GenPub: ' + spub.toString('hex'))

      var Ssecret = server.ComputeKey(cpub);
      console.log('server ComputeKey secret: ' + Ssecret.toString('hex'))

      console.log('client SetPassword status: ' + (client.SetPassword('password123') == 0 ? 'success' : 'failed'))

      var Csecret = client.ComputeKey(spub);

      console.log('client ComputeKey secret: ' + Csecret.toString('hex'))

      var Cresp = client.Respond()
      console.log('client Respond: ' + Cresp.toString('hex'))

      console.log('server Verify status: ' + (server.Verify(Cresp) == 0 ? 'success' : 'failed'))
      client.DeInit();
      server.DeInit()
    });
  });
});
