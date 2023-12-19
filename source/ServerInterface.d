module sharedinterface.ServerInterface;

import vibe.data.bson;

interface IServerAPI 
{
	// POST /register_device
	// registers a new public_key
	@property void register_device(string publickey_pem);

	// POST /register_token
	// register a hashchain token
	// using the lasttoken of the hashchain 
	// and the signing it using the public key
	void register_token(string pubkey, string token, string signature);

	// POST /reschedule_token
	// reschedule a new token list, after the old one got used up
	// check here that all the tokens got used and that the last 
	// block has the last token in it,
	// also check the signature!!
	void reschedule_token(string token, string signature);

	// POST /create_genisis_block ... creates a new 
	// "blockchain"
	// check signature against the one we got from register_device
	void create_genisis_block(string pubkey, Bson bson_data);

	// PUT /new_block
	// adds a new block to the "blockchain"
	// FIXME:
	// - check if hash matches the previous blockhash
	// - check if the block is signed using the registered pubkey
	// - if new boothash, check and use up a hashchain token
	void new_block(string pubkey, Bson bson_data);

	// GET /last_block
	// returns the last block of the blockchain
	// so the client can compute the local boot_hash
	// and check the signature
	Bson last_block(string pubkey);
}