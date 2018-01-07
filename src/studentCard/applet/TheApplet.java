package applet;

import javacard.framework.*;

public class TheApplet extends Applet {

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
	static byte[] NRV 									= new byte[NRVSIZE];

	static final short SW_VERIFICATION_FAILED 			= (short)0x6300;
	static final short SW_PIN_VERIFICATION_REQUIRED 	= (short)0x6301;

	boolean pinSec;	

	OwnerPIN readPin;
	OwnerPIN writePin;

	byte[] name;
	byte[] file;
	short fileSize;
	short ptrReadFile;
	static final byte P_LECTURE  						= (byte)0x60;

	protected TheApplet() {
		pinSec = false;
		this.name = new byte[0xff];
		this.fileSize = 0;
		this.ptrReadFile = 0;
		this.file = new byte[8000];

		byte[] pincodeR = {(byte)0x31, (byte)0x31, (byte)0x31, (byte)0x31}; // PIN code "1111"
		readPin = new OwnerPIN((byte)3, (byte)8); // 3 tries 8=Max Size
		readPin.update(pincodeR, (short)0, (byte)4); // from pincode, offset 0, length 4

		byte[] pincodeW = {(byte)0x30, (byte)0x30, (byte)0x30, (byte)0x30}; // PIN code "0000"
		writePin = new OwnerPIN((byte)3, (byte)8); // 3 tries 8=Max Size
		writePin.update(pincodeW,(short)0, (byte)4); // from pincode, offset 0, length 4

		this.register();
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
		
	}

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
