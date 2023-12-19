module sharedinterface.block;

import std.digest;
import std.digest.sha;
import botan.codec.hex : hexEncode;
import memutils.unique;
import botan.pubkey.pubkey;
import botan.pubkey.algo.rsa;
import botan.rng.rng;
import botan.rng.auto_rng;

import std.stdio;

// Blockchain shit
struct Block
{
	// Id of the current block
	long 	id;

	// Wheter the block is the first
	// one or not, is needed because 
	// we calcualte the previousblockhash on 
	// the genisis node differently:
	//
	// on the genisis node the previous block hash is
	// the hash of the current block, 
	// FIXME: should we add the last hashchain token here? probably, but maybe not
	// SHA(id + pubkey)
	bool 	isGenisis = false;


    string current_block_hash;
	// Calculate the previous block hash
	// SHA(prev.id + prev.previousblock_hash + prev.signature_bytes_hx)
	string	previousblock_hash;

	// Calculate and sign the current blockhash
	// TODO: add boothash in here! maybe?? no!
	// SIGN(SHA(curr.id + curr.previousblockhash)) 	
	string 	signature_bytes_hex;

	// The publickey that is/was used to sign all the 
	// changes in the chain, but also to verify signatures against!
	string  genisisPubkey = "";

	// TODO: the boothash
	string  bootHash;

	// TODO: intergrate with the hashchain tokens
	// that will be depleted after a while and 
	// need proof that you are in possesion of the privatekey?
	string  updateWithHashChainToken = "";

	// This is used for the Sign of Life function!
	// each boot puts a new block on the server with the timestamp
	long    unix_time_stamp;

	//TODO: create a hash of the bootloader directory!! this one changes 
	// sometimes, so we need a initramfs rebuild hook to update our hash!
	// this hash then has to be sent to the "blockchain" as an update 
	// authenticated using one of the "hashchain" tokens,
	// once these run out, we need to reschedule a whole bunch of tokens
	// using the bcrypt function and then signing the new "key-bundle" using 
	// our super secret private key that lives on a external usb stick that 
	// is only plugged in for system updates or something!
	//
	// Also we need a way to verify the "blockchain" and the updates, 
	// to make sure that the updates and rescheduled keys were signed with the
	// correct private key
	// also maybe broadcast keyreschedules as a block on the "blockchain" just to 
	// get some more transperancy into the system lifecycle.
	//
	// Alternativly add some statistic or telemetry to the block for even better 
	// attestation of device integrity or health ... or just to have some 
	// nice statistics we can render 
	// on a webpage
	//
	// Write a "blockchain" server that keeps track of the blocks and updates 
	// and also validates the updates with the RSA Publickey
	// and maybe if I have time, render the list or a admin panel to 
	// track telemetry accross time and machines!
	//
	// MACHINES NEED TO BE ENCRYPTED OR THE RSAPRIVATEKEY AT LEAST NEEDS TO BE AIRGAPPED
	// allow to broadcast changes later if you update your machine in an airgapped 
	// environment?
}

void prettyPrint(Block block)
{
	writeln("id                 \t", block.id);
	writeln("boothash           \t", block.bootHash);
	writeln("currentblock_hash  \t", block.current_block_hash);
    writeln("previousblock_hash \t", block.previousblock_hash); 	
	writeln("signature_bytes_hex\r\n", block.signature_bytes_hex);
	writeln("\r\ngenisisPubkey \r\n", block.genisisPubkey);
	writeln("isGenisis  \t\t", block.isGenisis);
	writeln("updateWithHashChainToken ", block.updateWithHashChainToken);
}

string calculatePrevBlockHash(Block block)
{
	ubyte id = cast(ubyte)block.id;
	ubyte[] prev_hash_bytes = cast(ubyte[])block.previousblock_hash;
	ubyte[] prev_block_sig  = cast(ubyte[])block.signature_bytes_hex;

	// sha.update(id ~ prev_hash_bytes ~ prev_block_sig);
	// auto prev_block_hash = sha.finished()[];
	auto prev_block_hash = sha256Of(id ~ prev_hash_bytes ~ prev_block_sig);

	return hexEncode(prev_block_hash.ptr, prev_block_hash.length);
}

string calculateCurrBlockHash(Block block)
{
	ubyte current_id = cast(ubyte)block.id;
	ubyte[] boot_hash = cast(ubyte[])block.bootHash;
	ubyte[] prev_hash_bytes = cast(ubyte[])block.previousblock_hash;

	// sha.update(current_id ~ boot_hash ~ prev_hash_bytes);
	// ubyte[] current_block_hash = sha.finished()[];
	
	auto current_block_hash = sha256Of(current_id /*~ boot_hash*/ ~ prev_hash_bytes);

	
	return hexEncode(current_block_hash.ptr, current_block_hash.length);
}

string hashGenisisBlock(Block gen)
{
	ubyte id = cast(ubyte)gen.id;
	ubyte[] boot_hash = cast(ubyte[])gen.bootHash;
	ubyte[] pubkey_bytes = cast(ubyte[])gen.genisisPubkey;

	//sha.update(id ~ boot_hash ~ pubkey_bytes);
	//ubyte[] gen_hash = sha.finished()[]; // from botan
	auto gen_hash = sha256Of(id /*~ boot_hash*/ ~ pubkey_bytes);
	
	return hexEncode(gen_hash.ptr, gen_hash.length);
}

string signHash(string hash, PKSigner* signer, RandomNumberGenerator rng)
{
	ubyte[] msg = cast(ubyte[])hash;
	auto sig = signer.signMessage(msg.ptr, msg.length, rng);
	return hexEncode(cast(const(ubyte)*)sig.ptr, sig.length);
}
