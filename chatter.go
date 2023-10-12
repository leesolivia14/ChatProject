// Implementation of a forward-secure, end-to-end encrypted messaging client
// supporting key compromise recovery and out-of-order message delivery.
// Directly inspired by Signal/Double-ratchet protocol but missing a few
// features. No asynchronous handshake support (pre-keys) for example.
//
// SECURITY WARNING: This code is meant for educational purposes and may
// contain vulnerabilities or other bugs. Please do not use it for
// security-critical applications.
//
// GRADING NOTES: This is the only file you need to modify for this assignment.
// You may add additional support files if desired. You should modify this file
// to implement the intended protocol, but preserve the function signatures
// for the following methods to ensure your implementation will work with
// standard test code:
//
// *NewChatter
// *EndSession
// *InitiateHandshake
// *ReturnHandshake
// *FinalizeHandshake
// *SendMessage
// *ReceiveMessage
//
// In addition, you'll need to keep all of the following structs' fields:
//
// *Chatter
// *Session
// *Message
//
// You may add fields if needed (not necessary) but don't rename or delete
// any existing fields.
//
// Original version
// Joseph Bonneau February 2019

package chatterbox

import (
	//"bytes" //un-comment for helpers like bytes.equal
	"encoding/binary"
	"errors"
	"fmt" //un-comment if you want to do any debug printing.
)

// Labels for key derivation

// Label for generating a check key from the initial root.
// Used for verifying the results of a handshake out-of-band.
const HANDSHAKE_CHECK_LABEL byte = 0x11

// Label for ratcheting the root key after deriving a key chain from it
const ROOT_LABEL = 0x22

// Label for ratcheting the main chain of keys
const CHAIN_LABEL = 0x33

// Label for deriving message keys from chain keys
const KEY_LABEL = 0x44

// Chatter represents a chat participant. Each Chatter has a single long-term
// key Identity, and a map of open sessions with other users (indexed by their
// identity keys). You should not need to modify this.
type Chatter struct {
	Identity *KeyPair
	Sessions map[PublicKey]*Session
}

// Session represents an open session between one chatter and another.
// You should not need to modify this, though you can add additional fields
// if you want to.
type Session struct {
	MyDHRatchet       *KeyPair
	PartnerDHRatchet  *PublicKey
	RootChain         *SymmetricKey
	SendChain         *SymmetricKey
	ReceiveChain      *SymmetricKey
	CachedReceiveKeys map[int]*SymmetricKey
	SendCounter       int
	LastUpdate        int
	ReceiveCounter    int
}

// Message represents a message as sent over an untrusted network.
// The first 5 fields are send unencrypted (but should be authenticated).
// The ciphertext contains the (encrypted) communication payload.
// You should not need to modify this.
type Message struct {
	Sender        *PublicKey
	Receiver      *PublicKey
	NextDHRatchet *PublicKey
	//^^ new public diffie hellman ratchet key
	Counter    int
	LastUpdate int
	Ciphertext []byte
	IV         []byte
}

// EncodeAdditionalData encodes all of the non-ciphertext fields of a message
// into a single byte array, suitable for use as additional authenticated data
// in an AEAD scheme. You should not need to modify this code.
func (m *Message) EncodeAdditionalData() []byte {
	buf := make([]byte, 8+3*FINGERPRINT_LENGTH)

	binary.LittleEndian.PutUint32(buf, uint32(m.Counter))
	binary.LittleEndian.PutUint32(buf[4:], uint32(m.LastUpdate))

	if m.Sender != nil {
		copy(buf[8:], m.Sender.Fingerprint())
	}
	if m.Receiver != nil {
		copy(buf[8+FINGERPRINT_LENGTH:], m.Receiver.Fingerprint())
	}
	if m.NextDHRatchet != nil {
		copy(buf[8+2*FINGERPRINT_LENGTH:], m.NextDHRatchet.Fingerprint())
	}

	return buf
}

// NewChatter creates and initializes a new Chatter object. A long-term
// identity key is created and the map of sessions is initialized.
// You should not need to modify this code.
func NewChatter() *Chatter {
	c := new(Chatter)
	c.Identity = GenerateKeyPair()
	c.Sessions = make(map[PublicKey]*Session)
	return c
}

// EndSession erases all data for a session with the designated partner.
// All outstanding key material should be zeroized and the session erased.
func (c *Chatter) EndSession(partnerIdentity *PublicKey) error {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return errors.New("Don't have that session open to tear down")
	}

	delete(c.Sessions, *partnerIdentity)

	// TODO: your code here to zeroize remaining state

	return nil
}

// InitiateHandshake prepares the first message sent in a handshake, containing
// an ephemeral DH share. The partner which calls this method is the initiator.
func (c *Chatter) InitiateHandshake(partnerIdentity *PublicKey) (*PublicKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return nil, errors.New("Already have session open")
	}

	c.Sessions[*partnerIdentity] = &Session{
		CachedReceiveKeys: make(map[int]*SymmetricKey),
		// TODO: your code here
		SendCounter:    0,
		LastUpdate:     0,
		ReceiveCounter: 0,
		MyDHRatchet:    GenerateKeyPair(),
	}

	// TODO: your code here
	//alice's eph key being returned
	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return &c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey, nil
	}

	return nil, nil
	//errors.New("Not implemented")
}

// ReturnHandshake prepares the second message sent in a handshake, containing
// an ephemeral DH share. The partner which calls this method is the responder.
func (c *Chatter) ReturnHandshake(partnerIdentity,
	partnerEphemeral *PublicKey) (*PublicKey, *SymmetricKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return nil, nil, errors.New("Already have session open")
	}

	c.Sessions[*partnerIdentity] = &Session{
		CachedReceiveKeys: make(map[int]*SymmetricKey),
		// TODO: your code here
		SendCounter:    0,
		LastUpdate:     0,
		ReceiveCounter: 0,
		MyDHRatchet:    GenerateKeyPair(),
	}
	//create a new session with Bob by storing Bob's
	//public key in Alice's new session map by storing partner identity
	//c.Sessions[*partnerIdentity].CachedRecievedKeys[0] = *partnerIdentity

	// TODO: your code here
	//calculate g^Ab, g^aB, g^ab
	ApubBeph := DHCombine(partnerIdentity, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey)
	AephBpub := DHCombine(partnerEphemeral, &c.Identity.PrivateKey)
	AephBeph := DHCombine(partnerEphemeral, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey)

	//compute the rootKey withthose three values
	rootKey := CombineKeys(ApubBeph, AephBpub, AephBeph)

	//storing Alice's ephemeral key
	c.Sessions[*partnerIdentity].PartnerDHRatchet = partnerEphemeral
	//storing the rootKey
	c.Sessions[*partnerIdentity].RootChain = rootKey

	//computing the checkKey
	checkKey := rootKey.DeriveKey(HANDSHAKE_CHECK_LABEL)

	//storing the rootKey BOB
	//made change here by making sendchain the rootKey thats been ratcheted once
	c.Sessions[*partnerIdentity].ReceiveChain = rootKey.DeriveKey(CHAIN_LABEL)

	//return Bob ephemeral key and the rootKey
	return &c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey, checkKey, nil
}

// FinalizeHandshake lets the initiator receive the responder's ephemeral key
// and finalize the handshake.The partner which calls this method is the initiator.
func (c *Chatter) FinalizeHandshake(partnerIdentity,
	partnerEphemeral *PublicKey) (*SymmetricKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return nil, errors.New("Can't finalize session, not yet open")
	}

	// TODO: your code here
	//calculate g^Ab, g^aB, g^ab
	BephApub := DHCombine(partnerEphemeral, &c.Identity.PrivateKey)
	BpubAeph := DHCombine(partnerIdentity, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey)
	BephAeph := DHCombine(partnerEphemeral, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey)

	//computing the second root key with the three calculated values
	rootKeyTwo := CombineKeys(BephApub, BpubAeph, BephAeph)

	//storing Bob's ephemeral key and rootKeyTwo
	c.Sessions[*partnerIdentity].PartnerDHRatchet = partnerEphemeral

	//computing the checkKey
	checkKeyTwo := rootKeyTwo.DeriveKey(HANDSHAKE_CHECK_LABEL)

	//storing the rootKey
	c.Sessions[*partnerIdentity].RootChain = rootKeyTwo
	//setting sendchain to rootchain for first message
	c.Sessions[*partnerIdentity].SendChain = rootKeyTwo.DeriveKey(CHAIN_LABEL)

	return checkKeyTwo, nil
	//return nil, nil
	//errors.New("Not implemented")
}

// SendMessage is used to send the given plaintext string as a message.
// You'll need to implement the code to ratchet, derive keys and encrypt this message.
func (c *Chatter) SendMessage(partnerIdentity *PublicKey,
	plaintext string) (*Message, error) {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return nil, errors.New("Can't send message to partner with no open session")
	}

	//increment send counter by 1
	c.Sessions[*partnerIdentity].SendCounter += 1
	//create new random IV
	currIV := NewIV()
	//make new random additionalData?
	data := []byte("data")

	var msgKey *SymmetricKey

	if c.Sessions[*partnerIdentity].SendChain == nil {
		c.Sessions[*partnerIdentity].SendChain = NewSymmetricKey()
	}

	if c.Sessions[*partnerIdentity].ReceiveCounter != 0 {
		//making g^b2 and b2
		newDHKey := GenerateKeyPair()

		c.Sessions[*partnerIdentity].MyDHRatchet = newDHKey

		//making g^a1b2

		//ga1  //b2 PART SEND
		//gb2  //a1
		gabTwo := DHCombine(c.Sessions[*partnerIdentity].PartnerDHRatchet, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey)

		fmt.Println("SEND's created ga1b2: ", gabTwo)
		fmt.Println("SEND's created gb2: ", c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey)
		fmt.Println("SEND's created ga1: ", c.Sessions[*partnerIdentity].PartnerDHRatchet)

		//ratcheting the rootKey
		rootKeyRatchet := c.Sessions[*partnerIdentity].RootChain.DeriveKey(ROOT_LABEL)

		//new root key
		c.Sessions[*partnerIdentity].RootChain = CombineKeys(rootKeyRatchet, gabTwo)

		//g^a1b2
		gabTwoSendChain := c.Sessions[*partnerIdentity].RootChain.DeriveKey(CHAIN_LABEL)
		c.Sessions[*partnerIdentity].SendChain = gabTwoSendChain
	}

	msgKey = c.Sessions[*partnerIdentity].SendChain.DeriveKey(KEY_LABEL)
	newSendChain := c.Sessions[*partnerIdentity].SendChain.DeriveKey(CHAIN_LABEL)
	c.Sessions[*partnerIdentity].SendChain = newSendChain

	message := &Message{
		Sender:   &c.Identity.PublicKey,
		Receiver: partnerIdentity,
		// TODO: your code here
		NextDHRatchet: &c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey,
		//&c.Identity.PublicKey,
		Counter: c.Sessions[*partnerIdentity].SendCounter,
		//LastUpdate: c.Sessions[*partnerIdentity].LastUpdate + 1,
		IV:         currIV,
		Ciphertext: msgKey.AuthenticatedEncrypt(plaintext, data, currIV),
	}

	// TODO: your code here

	return message, nil
	//errors.New("Not implemented")
}

// ReceiveMessage is used to receive the given message and return the correct
// plaintext. This method is where most of the key derivation, ratcheting
// and out-of-order message handling logic happens.
func (c *Chatter) ReceiveMessage(message *Message) (string, error) {

	if _, exists := c.Sessions[*message.Sender]; !exists {
		return "", errors.New("Can't receive message from partner with no open session")
	}

	// TODO: your code here
	//increment send counter by 1
	c.Sessions[*message.Sender].ReceiveCounter += 1
	//computing the data
	data := []byte("data")

	var msgKeyBob *SymmetricKey

	// fixing segfault
	if c.Sessions[*message.Sender].ReceiveChain == nil {
		c.Sessions[*message.Sender].ReceiveChain = NewSymmetricKey()
	}

	if c.Sessions[*message.Sender].PartnerDHRatchet != message.NextDHRatchet {
		//making g^a1b2
		gabTwo := DHCombine(message.NextDHRatchet, &c.Sessions[*message.Sender].MyDHRatchet.PrivateKey)
		fmt.Println("RECEIEVE's recreated ga1b2: ", gabTwo)
		fmt.Println("RECEIEVE's created gb2: ", message.NextDHRatchet)
		fmt.Println("RECEIVE's created ga1: ", c.Sessions[*message.Sender].MyDHRatchet.PublicKey)

		//ratcheting the current RootChain with ROOT_LABEL
		kRootOneRatcheted := c.Sessions[*message.Sender].RootChain.DeriveKey(ROOT_LABEL)

		//Combining step to make Kroot2 with ratcheted kroot1 and g^ab2
		kRootTwo := CombineKeys(kRootOneRatcheted, gabTwo)

		//setting old RootChain (rootKey) to new RootChain (rootKeyRatchet)
		c.Sessions[*message.Sender].RootChain = kRootTwo

		//new receiveChain with ratcheted rootKey and ROOT_LABEL, and then combing that with g^a1b2
		krootTwoReceiveChain := c.Sessions[*message.Sender].RootChain.DeriveKey(CHAIN_LABEL)

		//setting the old receivechain to the new receivechain
		c.Sessions[*message.Sender].ReceiveChain = krootTwoReceiveChain

		//making g^a1b2
		//gabTwo := DHCombine(c.Sessions[*partnerIdentity].PartnerDHRatchet, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey)

		//ratcheting the rootKey
		//rootKeyRatchet := c.Sessions[*partnerIdentity].RootChain.DeriveKey(ROOT_LABEL)

		//new root key
		//c.Sessions[*partnerIdentity].RootChain = CombineKeys(rootKeyRatchet, gabTwo)

		//g^a1b2
		//gabTwoSendChain := c.Sessions[*partnerIdentity].RootChain.DeriveKey(CHAIN_LABEL)
		//c.Sessions[*partnerIdentity].SendChain = gabTwoSendChain

		c.Sessions[*message.Sender].PartnerDHRatchet = message.NextDHRatchet
	}

	msgKeyBob = c.Sessions[*message.Sender].ReceiveChain.DeriveKey(KEY_LABEL)
	newReceiveChain := c.Sessions[*message.Sender].ReceiveChain.DeriveKey(CHAIN_LABEL)
	c.Sessions[*message.Sender].ReceiveChain = newReceiveChain

	//deciphering using newly computed msgKey
	plainMessage, err := msgKeyBob.AuthenticatedDecrypt(message.Ciphertext, data, message.IV)
	fmt.Println("receive message error for decryption: ", err, ".")

	//new received message, so counter increments
	c.Sessions[*message.Sender].ReceiveCounter += 1

	if plainMessage != "" {
		return plainMessage, nil
	}

	return "", nil

	//errors.New("Not implemented")
}
