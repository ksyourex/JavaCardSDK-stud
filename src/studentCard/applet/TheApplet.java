package applet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class TheApplet extends Applet {

	static final byte P_LECTURE  						= (byte)0x60;
	static final byte INS_TESTDES_ECB_NOPAD_DEC 		= (byte)0x29;
	static final byte INS_TESTDES_ECB_NOPAD_ENC 		= (byte)0x28;
	static final byte INS_DES_ECB_NOPAD_DEC 			= (byte)0x21;
	static final byte INS_DES_ECB_NOPAD_ENC 			= (byte)0x20;
	static final byte UPDATECARDKEY						= (byte)0x14;
	static final byte UNCIPHERFILEBYCARD				= (byte)0x13;
	static final byte CIPHERFILEBYCARD					= (byte)0x12;
	static final byte CIPHERANDUNCIPHERNAMEBYCARD		= (byte)0x11;
	static final byte READFILEFROMCARD					= (byte)0x10;
	static final byte WRITEFILETOCARD					= (byte)0x09;
	static final byte UPDATEWRITEPIN					= (byte)0x08;
	static final byte UPDATEREADPIN						= (byte)0x07;
	static final byte DISPLAYPINSECURITY				= (byte)0x06;
	static final byte DESACTIVATEACTIVATEPINSECURITY	= (byte)0x05;
	static final byte ENTERREADPIN						= (byte)0x04;
	static final byte ENTERWRITEPIN						= (byte)0x03;
	static final byte READNAMEFROMCARD					= (byte)0x02;
	static final byte WRITENAMETOCARD					= (byte)0x01;
	
	final static short SW_EOF		            	    = (short)0x8800;
	static final short NRVSIZE 							= (short)1024;
	static final short SW_VERIFICATION_FAILED 			= (short)0x6300;
	static final short SW_PIN_VERIFICATION_REQUIRED 	= (short)0x6301;

	static byte[] NRV 									= new byte[NRVSIZE];
	
	boolean pinSec;	

	OwnerPIN readPin;
	OwnerPIN writePin;

	byte[] name;
	byte[] file;
	short fileSize;
	short ptrReadFile;

	/* Crypto */
	static final byte[] theDESKey = new byte[] {(byte)0xCA, (byte)0xCA, (byte)0xCA, (byte)0xCA, (byte)0xCA, (byte)0xCA, (byte)0xCA, (byte)0xCA};
	private Cipher cDES_ECB_NOPAD_enc, cDES_ECB_NOPAD_dec;
	private Key secretDESKey;
	boolean keyDES, DES_ECB_NOPAD, DES_CBC_NOPAD;
	
	protected TheApplet() {
		pinSec = false;
		this.name = new byte[0xff];
		this.fileSize = 0;
		this.ptrReadFile = 0;
		this.file = new byte[8000];

		byte[] pincodeR = {(byte)0x31, (byte)0x31, (byte)0x31, (byte)0x31}; // PIN code "1111"
		readPin = new OwnerPIN((byte)3, (byte)8); 							// 3 tries 8=Max Size
		readPin.update(pincodeR, (short)0, (byte)4); 						// from pincode, offset 0, length 4

		byte[] pincodeW = {(byte)0x30, (byte)0x30, (byte)0x30, (byte)0x30}; // PIN code "0000"
		writePin = new OwnerPIN((byte)3, (byte)8); 							// 3 tries 8=Max Size
		writePin.update(pincodeW,(short)0, (byte)4); 						// from pincode, offset 0, length 4

		initKeyDES(); 
		initDES_ECB_NOPAD();
		
		this.register();
	}
	
	private void initKeyDES() {
	    try {
		    secretDESKey = KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
		    ((DESKey)secretDESKey).setKey(theDESKey, (short)0);
		    keyDES = true;
	    } catch(Exception e) {keyDES = false;}
	}

	private void initDES_ECB_NOPAD() {
	    if(keyDES) try {
		    cDES_ECB_NOPAD_enc = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
		    cDES_ECB_NOPAD_dec = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
		    cDES_ECB_NOPAD_enc.init( secretDESKey, Cipher.MODE_ENCRYPT );
		    cDES_ECB_NOPAD_dec.init( secretDESKey, Cipher.MODE_DECRYPT );
		    DES_ECB_NOPAD = true;
	    } catch(Exception e) {DES_ECB_NOPAD = false;}
	}
	
	public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
		new TheApplet();
	} 

	public boolean select() {return true;} 
	
	public void deselect() {}

	public void process(APDU apdu) throws ISOException {
		if(selectingApplet() == true)
			return;

		byte[] buffer = apdu.getBuffer();

		switch(buffer[1]) 	{
			case UPDATECARDKEY: updateCardKey(apdu); break;
			case UNCIPHERFILEBYCARD: uncipherFileByCard(apdu); break;
			case CIPHERFILEBYCARD: cipherFileByCard(apdu); break;
			case READFILEFROMCARD: readFileFromCard(apdu); break;
			case WRITEFILETOCARD: writeFileToCard(apdu); break;
			case UPDATEWRITEPIN: updateWritePIN(apdu); break;
			case UPDATEREADPIN: updateReadPIN(apdu); break;
			case DISPLAYPINSECURITY: displayPINSecurity(apdu); break;
			case DESACTIVATEACTIVATEPINSECURITY: desactivateActivatePINSecurity(apdu); break;
			case ENTERREADPIN: enterReadPIN(apdu); break;
			case ENTERWRITEPIN: enterWritePIN(apdu); break;
			case READNAMEFROMCARD: readNameFromCard(apdu); break;
			case WRITENAMETOCARD: writeNameToCard(apdu); break;
			
			case INS_TESTDES_ECB_NOPAD_ENC: if(DES_ECB_NOPAD) 
											testCipherGeneric(cDES_ECB_NOPAD_enc, KeyBuilder.LENGTH_DES, NBTESTSDESCIPHER); return;
			case INS_TESTDES_ECB_NOPAD_DEC: if(DES_ECB_NOPAD) 
											testCipherGeneric(cDES_ECB_NOPAD_dec, KeyBuilder.LENGTH_DES, NBTESTSDESUNCIPHER); return;

			case INS_DES_ECB_NOPAD_ENC: if(DES_ECB_NOPAD)
										cipherGeneric(apdu, cDES_ECB_NOPAD_enc, KeyBuilder.LENGTH_DES); return;
			case INS_DES_ECB_NOPAD_DEC: if(DES_ECB_NOPAD) 
										cipherGeneric(apdu, cDES_ECB_NOPAD_dec, KeyBuilder.LENGTH_DES); return;
			
			default: ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	
	void verify(APDU apdu, OwnerPIN pin) {
		apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		if(!pin.check( buffer, (byte)5, buffer[4])) 
			ISOException.throwIt(SW_VERIFICATION_FAILED);
	}

	void updateCardKey(APDU apdu) {
		apdu.setIncomingAndReceive();
		
		byte [] buffer;
		buffer = apdu.getBuffer();
		Util.arrayCopy(buffer,(byte)5,theDESKey,(short)0,(byte)8);
		
		initKeyDES(); 
		initDES_ECB_NOPAD();
	}
	
	// Write the method ciphering/unciphering data from the computer.
	// The result is sent back to the computer.
	private void cipherGeneric(APDU apdu, Cipher cipher, short keyLength) {
		apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		short length_unsigned= (short)(buffer[4]&(short)(0x00FF));
		
		cipher.doFinal(buffer, (short)5, length_unsigned, buffer, (short)5);
		apdu.setOutgoingAndSend((short)5, length_unsigned);
	}

	private void testCipherGeneric(Cipher cipher, short keyLength, short nbLoops) {
		for(i=0; i<nbLoops; i++)
			cipher.doFinal(dataToCipher, (short)0, (short)(keyLength/8), ciphered, (short)0);
	}
	
	void uncipherFileByCard (APDU apdu) {}
	
	void cipherFileByCard (APDU apdu) {}

	void readFileFromCard(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short NBapdu = (short)(fileSize/127);
		byte reste = (byte)(fileSize%127);
		
		if (buffer[2] == 0 && buffer[3] == 0)      
			ptrReadFile = 0;
		if (NBapdu == ptrReadFile){
			Util.arrayCopy(file, (short)(ptrReadFile*127), buffer, (short)0, (short)reste);         
			apdu.setOutgoingAndSend((short)0, (short)reste);      
			ptrReadFile =- 1;
		}
		else if (ptrReadFile == -1){
			ISOException.throwIt(SW_EOF);
		}
		else {
			Util.arrayCopy(file, (short)(ptrReadFile*127), buffer, (short)0, (short)127);       
			apdu.setOutgoingAndSend((short)0, (short)127);
			ptrReadFile++;
		}
	}

	void writeFileToCard(APDU apdu) {
		apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();

		if(buffer[2] == 0 && buffer[3] == 0)
			fileSize=0;

		Util.arrayCopy(buffer, (short)5, file, fileSize, (short)buffer[4]);
		fileSize += buffer[4];
	}

	void updateWritePIN(APDU apdu) {
		byte [] buffer;
		byte [] writePinNewCode = {(byte)0x34, (byte)0x34, (byte)0x34, (byte)0x34};

		if (!writePin.isValidated())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);

		apdu.setIncomingAndReceive();
		buffer = apdu.getBuffer();
		Util.arrayCopy(buffer,(byte)5,writePinNewCode,(short)0,(byte)4);
		writePin.update(writePinNewCode,(short)0,(byte)4);
	}

	void updateReadPIN(APDU apdu) {
		byte [] buffer;
		byte [] readPinNewCode = {(byte)0x34, (byte)0x34, (byte)0x34, (byte)0x34}; 

		if(!readPin.isValidated())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);

		apdu.setIncomingAndReceive();
		buffer = apdu.getBuffer();
		Util.arrayCopy(buffer,(byte)5,readPinNewCode,(short)0,(byte)4);
		readPin.update(readPinNewCode,(short)0,(byte)4); 
	}

	void displayPINSecurity(APDU apdu) {
		apdu.setIncomingAndReceive();
		byte [] buffer = apdu.getBuffer();
		buffer[0] = buffer[1] = (pinSec ? (byte)0x01 : (byte)0x00);
		apdu.setOutgoingAndSend((short)0, (byte) 2);
	}

	void desactivateActivatePINSecurity(APDU apdu) {
		pinSec = !pinSec;
	}

	void enterReadPIN(APDU apdu) {
		verify(apdu, readPin);
	}

	void enterWritePIN(APDU apdu) {
		verify(apdu, writePin);
	}

	void readNameFromCard(APDU apdu) {
		if(!pinSec) {
			if (!readPin.isValidated()) 
				ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		}

		byte[] buffer = apdu.getBuffer();
		Util.arrayCopy(NRV, (short)1, buffer, (short)0, (byte)NRV[0]);
		apdu.setOutgoingAndSend((short)0, NRV[0]);  
	}

	void writeNameToCard(APDU apdu) {
		if(!pinSec) {
			if (!writePin.isValidated()) 
				ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		}

		byte[] buffer = apdu.getBuffer();
		apdu.setIncomingAndReceive();
		Util.arrayCopy(buffer, (short)4, NRV ,(short)0, (short)(buffer[4]+1));
	}
}
