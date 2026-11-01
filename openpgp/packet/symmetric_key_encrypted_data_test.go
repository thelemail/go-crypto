package packet

// These test vectors contain V4 or V6 symmetric key encrypted packets followed
// by an integrity protected packet (SEIPD v1 or v2).

type packetSequence struct {
	password         string
	packets          string
	contents         string
	faultyDataPacket string
}

func keyAndIpePackets() []*packetSequence {
	return []*packetSequence{symEncRFC9580, symEncRFC4880}
}

// From OpenPGP RFC9580 A.9 https://www.rfc-editor.org/rfc/rfc9580.html#name-sample-aead-eax-encryption-
var symEncRFC9580 = &packetSequence{
	password: "password",
	packets:  "c340061e07010b0308a5ae579d1fc5d82bff69224f919993b3506fa3b59a6a73cff8c5efc5f41c57fb54e1c226815d7828f5f92c454eb65ebe00ab5986c68e6e7c55d269020701069ff90e3b321964f3a42913c8dcc6619325015227efb7eaeaa49f04c2e674175d4a3d226ed6afcb9ca9ac122c1470e11c63d4c0ab241c6a938ad48bf99a5a99b90bba8325de61047540258ab7959a95ad051dda96eb15431dfef5f5e2255ca78261546e339a",
	contents: "cb1362000000000048656c6c6f2c20776f726c6421d50eae5bf0cd6705500355816cb0c8ff",
	// Missing last authentication chunk
	faultyDataPacket: "d259020701069ff90e3b321964f3a42913c8dcc6619325015227efb7eaeaa49f04c2e674175d4a3d226ed6afcb9ca9ac122c1470e11c63d4c0ab241c6a938ad48bf99a5a99b90bba8325de61047540258ab7959a95ad051dda96eb",
}

// From the OpenPGP interoperability test suite (Test: S2K mechanisms, iterated min + esk)
var symEncRFC4880 = &packetSequence{
	password: "password",
	packets:  "c32e0409030873616c7a6967657200080674a0d96a4a6e122b1d5bbaa3fac117b9cbb46c7e38f12967386b57e2f79d11d23f01cee77ceed8544e6d52c78bd33c81bd366c8673b68955ddbd1ade98fe6a9b4e27ae54cd10dda7cd3a4637f44e0ead895ebebdcf0c679f1342745628f104e7",
	contents: "cb1462000000000048656c6c6f20576f726c64203a29",
}
