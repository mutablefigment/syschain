import botan.hash.sha2_32 : SHA256;
import botan.passhash.bcrypt;
import std.stdio;
import std.digest : toHexString;
import memutils.unique;
import botan.libstate.lookup;
import std.algorithm.comparison : equal;
import std.container : SList;
import botan.rng.rng;
import botan.rng.auto_rng;
import memutils.unique;
import botan.pubkey.pubkey;
import botan.pubkey.algo.rsa;
import botan.rng.rng;
import botan.rng.auto_rng;
import std.stdio;
import memutils.unique;
import botan.libstate.lookup;
import botan.codec.hex : hexEncode;
import std.datetime;
import core.time;

import std.digest.sha : sha256Of;

import botan.pubkey.pkcs8;
import botan.pubkey.x509_key;

import vibe.core.core;
import vibe.core.log;
import vibe.http.router;
import vibe.http.server;
import vibe.web.rest;

import sharedinterface.serverinterface;
import vibe.data.bson;
import sharedinterface.block;

struct HashNode
{
	int id;
	string hash;
}

void main()
{
	Unique!AutoSeededRNG rng = new AutoSeededRNG;

	// FIXME: make 2 functions here!
	auto privKey = loadOrGenKey(rng, false);
	auto pubkey = RSAPublicKey(privKey);

	auto sign = PKSigner(privKey, "EMSA1(SHA-224)");
	auto verify = PKVerifier(pubkey, "EMSA1(SHA-224)");

	// auto msg = cast(ubyte[])"hello world!";
	// auto sig = sign.signMessage(msg.ptr, msg.length, *rng);
	// auto sig_hex = hexEncode(cast(const(ubyte)*)sig.ptr, sig.length);
	// writeln(sig_hex);
	
	// bool isvalid = verify.verifyMessage(msg.ptr, msg.length, sig.ptr, sig.length);
	// writeln("sig is valid ", isvalid);


	// auto sha = retrieveHash("SHA-256").clone(); // on the GC
	// auto fulltext = cast(string)msg;

	auto hash_bcrypt = generateBcrypt("This is a secret password", *rng, 10);
	writeln("initlaSec ", hash_bcrypt);
	writeln("firstHash ", toHexString(sha256Of(hash_bcrypt)).dup);

	//
	
 	bool isValid = checkBcrypt("This is a secret password", "$2a$10$ZCDW2lUbHn4d5LknRB8LP.xp.CFm9XPsNokBtGOpiy8.xwswQENbm");//hash_bcrypt);
	writeln("Bcrypt hash is valid for same input ", isValid);


	// make genisis block of the hashchain
	// auto root_node = HashNode();
	// root_node.id = 1;
	// root_node.hash = root;
	// auto hashList = SList!HashNode(root_node);
	auto hashList = generateHashList(hash_bcrypt, 10, true);

	writeln("lastHash ", hashList.front().hash);



	auto mbr_sha_hex = "7D0101F414526AAAE10F04839225E27AEA09933F3060011F6A683FFE84197494"; //dumpMBR
	
	// auto root_node = HashNode();
	// root_node.id = 1;
	// FIXME: this cannot be the boot hash, as it is publicly known!!!;
	// we need to derive a secret value from a userpassword maybe,
	// then hash that as the input for the hashchain. and then
	// after getting he hashchain we sign the last hash with our privatekey 
	// to prove that we are who we say we are, and then send it off to the 
	// server! so that no one knows our secrete starting token!
	// root_node.hash = "secret token here";
	//
	// ONLY NEW GENISIS BLOCKS AFTER REBUIDING THE GPT NEED 
	// TO USE THE HASHCHAIN TOKENS FOR UPDATES!!!!
	//
	// think about token rescheduling here, could be just with the idea 
	// above by signing the last token using the RSAKey, then the server 
	// can validate the new token chain!
	// rescheduling keys should be done only once in a blue moon!
	
	// auto hashList = SList!HashNode(root_node);

	// Create a pem format of the pubkey
	string pub_pem = x509_key.PEM_encode(privKey);

	// Register the client with the server
	auto client = new RestInterfaceClient!IServerAPI("http://127.0.0.1:8080/");
	client.register_device(pub_pem);

	// Register the last hashchain token!
	string hash_token = hashList.front().hash;
	string signed_token = signHash(hash_token, &sign, rng);
	writeln(signed_token);
	client.register_token(pub_pem, hash_token, signed_token);

	Block genisis = Block();
	genisis.id 	  			    = 1;
	genisis.isGenisis			= true;
	genisis.genisisPubkey		= pub_pem;
	genisis.bootHash 			= mbr_sha_hex;

	// on the genisis node the previous block hash is
	// hash the current block, 
	// SHA(id + boothash + pubkey)
	genisis.previousblock_hash   = null; //hashGenisisBlock(genisis, sha);
	string genisisblocksignature = signHash(genisis.previousblock_hash, &sign, rng); 
	genisis.signature_bytes_hex  = genisisblocksignature;

	genisis.updateWithHashChainToken = hashList.front().hash;
	// hashList.removeFront();

	Bson gen_bson = genisis.serializeToBson();
	client.create_genisis_block(pub_pem, gen_bson);


	// create the first real block
	Block first = Block();
	first.id 			= 2;
	first.isGenisis 	= false;
	first.genisisPubkey = genisis.genisisPubkey;
	// FIXME: foreach new block recalculate the boothash!!!
	// this is imperative for this system to validate the 
	// boot integrity
	first.bootHash      = mbr_sha_hex;

	// Calculate the previous block hash
	// SHA(prev.id + prev.previousblockhash + prev.signature)
	first.previousblock_hash  = calculatePrevBlockHash(genisis);
	
	// calculate the current blockhash
	// SHA(curr.id + curr.boothash + prev.previousblockhash)
	string first_block_hash   = calculateCurrBlockHash(first);

	// Sign the calculated current blockhash
	string first_block_sig    = signHash(first_block_hash, &sign, rng);

	// Put it int the block
	first.signature_bytes_hex = first_block_sig;
	first.updateWithHashChainToken = hashList.front().hash;
	// hashList.removeFront();

	prettyPrint(first);

	Bson first_bson = first.serializeToBson();
	client.new_block(pub_pem, first_bson);	 

	// create the second block
	Block second = Block();
	second.id = 3;
	second.isGenisis = false;
	second.genisisPubkey = genisis.genisisPubkey;
	second.bootHash		 = mbr_sha_hex;
	second.previousblock_hash = calculatePrevBlockHash(first);
	second.signature_bytes_hex = signHash(calculateCurrBlockHash(second), &sign, rng);
	second.updateWithHashChainToken = hashList.front().hash;

	prettyPrint(second);

	Bson second_bson = second.serializeToBson();
	client.new_block(pub_pem, second_bson);	

	// writeln("\r\n ******* \r\n");
	// prettyPrint(genisis);
	// writeln("\r\n ******* \r\n");
	// prettyPrint(first);
	// writeln("\r\n ******* \r\n");
	// prettyPrint(second);
	// writeln("\r\n ******* \r\n");

	// FIXME: make this into a unit test!!!
	writeln("Second sha, ", calculatePrevBlockHash(genisis));
	writeln("Matches 2.blockhash == SHA(1) ???", second.previousblock_hash == calculatePrevBlockHash(first));


	// FIXME: NOW we update the boothash
	string new_boot_hash = "E052D8CECEEF87A885F15674A45C140A0F9713B7D90FF1E62E50934A5082D047";

	Block up = Block();
	up.id = 4;
	up.isGenisis = false;
	up.genisisPubkey = genisis.genisisPubkey;
	up.bootHash = new_boot_hash;
	up.previousblock_hash = calculatePrevBlockHash(second);
	up.signature_bytes_hex = signHash(calculateCurrBlockHash(up), &sign, rng);
	
	hashList.removeFront();

	// FIXME: check token!
	auto sum = sha256Of(hashList.front().hash);
	//writeln(toHexString(sum), " COMPARE ", genisis.updateWithHashChainToken);
	if (toHexString(sum) == genisis.updateWithHashChainToken)
	{
	 	writeln("We are updating the boot hash from ", mbr_sha_hex);
		writeln("to                                 ", new_boot_hash);
		writeln("Using token ", hashList.front().hash);
	}

	up.updateWithHashChainToken = hashList.front().hash; 

	writeln("\r\n ******* \r\n");
	prettyPrint(up);
	writeln("\r\n ******* \r\n");


	Bson up_bson = up.serializeToBson();
	client.new_block(pub_pem, up_bson);	



	// up.genisisPubkey = "test";

	// Bson block_data = up.serializeToBson();
	// writeln(block_data);
	// writeln("----> ", calculateCurrBlockHash(up));
	// client.new_block(block_data);

	// auto last = client.last_block();
	// writeln(last);

	// writeln(block_data == last);



	// hashList = generateHashList(sha, hashList, 1_000, false);
	// writeln("last hash is ", hashList.front().hash);

	// auto lastHash = cast(ubyte[])hashList.front().hash;
	// auto keysig = sign.signMessage(lastHash.ptr, lastHash.length, *rng);
	// auto keysig_hex = hexEncode(cast(const(ubyte)*)sig.ptr, sig.length);


	// writeln("\r\nLasthash is ", hashList.front().hash, "\r\nSignature ", keysig_hex);

	// long currTime = Clock.currTime().toUnixTime();
	// writeln(currTime);

    // string pub_pem = x509_key.PEM_encode(privKey);
	
	// // exporting the private rsa key: using empty password
	// // pkcs8.PEM_encode(privKey);



	// writeln(pub_pem);


	// Block genblock = Block();
	// genblock.unixtimestamp 		 = 1;
	// genblock.previousblock_hash  = null;
	// genblock.isGenisis 			 = true;
	// genblock.genisisPubkey		 = pub_pem;

	// auto t = cast(ubyte)genblock.unixtimestamp; //currtime
	// auto p = cast(ubyte[])genblock.genisisPubkey;

	// // sha.update(t ~ p);	
	// sha.update(t ~ p);
	// auto root_hash = sha.finished()[]; // from botan
	// auto root_hash_txt = hexEncode(root_hash.ptr, root_hash.length);
	// writeln(root_hash_txt);

	// auto rootsig = sign.signMessage(root_hash.ptr, root_hash.length, *rng);
	// auto rootsig_hex = hexEncode(cast(const(ubyte)*)rootsig.ptr, rootsig.length);

	// genblock.signature_bytes_hex = rootsig_hex;


	// writeln("root ", rootsig_hex);

	// auto t1 = cast(ubyte)genblock.unixtimestamp;
	// auto p1 = cast(ubyte[])genblock.genisisPubkey;
	// auto s1 = cast(ubyte[])genblock.signature_bytes_hex;


	// // sha.update(t ~ p);	
	// sha.update(t1 ~ p1 ~ s1);
	// auto me_hash1 = sha.finished()[]; // from botan

	// auto mesig1 = sign.signMessage(me_hash1.ptr, me_hash1.length, *rng);
	// auto mesig_hex1 = hexEncode(cast(const(ubyte)*)mesig1.ptr, mesig1.length);

	// writeln("\r\nsig1 ", mesig_hex1);

	// Block block1 = Block();
	// auto newtime = Clock.currTime().toUnixTime();

	// auto t2 = cast(ubyte)genblock.unixtimestamp; //currtime
	// auto p2 = cast(ubyte[])genblock.genisisPubkey;

	// sha.update(t2 ~ p2);
	// auto root_hash1 = sha.finished()[]; // from botan
	// auto root_hash_txt1 = hexEncode(root_hash1.ptr, root_hash1.length);
	// writeln(root_hash_txt1);

	// block1.unixtimestamp 	   = 2;
	// block1.previousblock_hash  = root_hash_txt1;
	// block1.signature_bytes_hex = mesig_hex1;
	// block1.isGenisis		   = false;
	// block1.genisisPubkey	   = pub_pem;

	// writeln("\r\n");
	// writeln(block1);
	// writeln(hexEncode(me_hash1.ptr, me_hash1.length));

	// bool hashMatch = root_hash == root_hash1;
	// writeln("Hashes Match? ", hashMatch);


	// sha.update(hashList.front().hash);
	// auto d = toHexString(sha.finished()[]);
	// // writeln("2, ", d);
	// auto second_node = HashNode();
	// second_node.id = 2;
	// second_node.hash = d;
	// hashList.insertFront(second_node);
	// writeln(hashList.front().hash);


	// sha.update(d);
	// auto c = toHexString(sha.finished()[]);
	// // writeln("3, ", c);

}



PrivateKey loadOrGenKey(RandomNumberGenerator rng, bool genkey = false)
{
	import std.file: write, readText;
	import botan.filters.data_src;


	if (genkey)
	{
		auto priv_key = RSAPrivateKey(rng, 1024);
		auto pubkey = RSAPublicKey(priv_key);

		auto pbe_time = 10.msecs;
		string pem_priv = pkcs8.PEM_encode(priv_key);
		string pub_pem  = x509_key.PEM_encode(priv_key);

		write("./priv.pem", pem_priv);
		write("./pub.pem", pub_pem);

		return priv_key;
	}
	else
	{
    	PrivateKey restored_priv = pkcs8.loadKey("./priv.pem", rng, "");

		return restored_priv;
	}
}



SList!HashNode generateHashList(string initial_secret, int depth, bool print)
{

	auto initial_node = HashNode();
	initial_node.id = 0;
	auto initial_hash = sha256Of(initial_secret);
	initial_node.hash = toHexString(initial_hash).dup;
	
	auto hash_list = SList!HashNode(initial_node);
	hash_list.insertFront(initial_node);
	if (print) 
		writefln("%d ->\t %s", hash_list.front().id, hash_list.front().hash);


	for (int i = 1; i < depth; ++i)
	{
		auto node = HashNode();
		node.id = i;
		auto hash = sha256Of(hash_list.front().hash);
		node.hash = toHexString(hash).dup;
		hash_list.insertFront(node);
		if (print) 
		{ 
			writefln("%d ->\t %s", hash_list.front().id, hash_list.front().hash);
		}
	}

	return hash_list;
}

string dumpMBR()
{
	import std.file : read;
	import std.process : executeShell;
	
	const string output = "/tmp/mbr.bak";
	auto dump_cmd = "dd if=/dev/sda of=/tmp/mbr.bak bs=1024k count=1 status=none";
	writeln("Dumping MBR into ", output);
	auto dump = executeShell(dump_cmd);
	if (dump.status != 0)
		writeln("Failed to dump MBR!");

	writeln("Finished dumping");
	ubyte[] file_content = cast(ubyte[])read(output);

	writeln("Calculating hash");
	auto hash = toHexString(sha256Of(file_content));

	writeln("Boot Record hash is -> ", hash);

	string mbr_hex = "test";
	return mbr_hex;

	// auto hash_bcrypt = generateBcrypt(mbr_hex, *rng, 10);
	// writeln("Bcrypt of MBR -> ", hash_bcrypt);

	// bool isValid = checkBcrypt(mbr_hex, "$2a$10$WGh3GTBc3IZkLacItjuLM.qZctYjdiMMXLoVUQqGgsc8kIzSrd9aa");//hash_bcrypt);
	// writeln("Bcrypt hash is valid for same input ", isValid);

}


