package applet;

import javacard.framework.*;

public class TheApplet extends Applet {  

	final static byte  BINARY_WRITE = (byte) 0xD0;
	final static byte  BINARY_READ  = (byte) 0xB0;
	final static byte  SELECT       = (byte) 0xA4;
	final static byte  PIN_VERIFY   = (byte) 0x20;
	
	final static short SW_VERIFICATION_FAILED = (short)0x6300;
	final static short SW_PIN_VERIFICATION_REQUIRED = (short)0x6301;

	final static short NVRSIZE      = (short)1024;
	static byte[] NVR               = new byte[NVRSIZE];

	OwnerPIN pin;

	protected TheApplet() {
		byte[] pincode = {(byte)0x30,(byte)0x30,(byte)0x30,(byte)0x30}; // PIN code "0000"
		pin = new OwnerPIN((byte)3,(byte)8); // 3 tries 8=Max Size
		pin.update(pincode,(short)0,(byte)4); // from pincode, offset 0, length 4

		register();
	}

	public static void install( byte[] bArray, short bOffset, byte bLength ){
		new TheApplet();
	}

	public boolean select(){
		if ( pin.getTriesRemaining() == 0 )
			return false;

		return true;
	}

	public void deselect(){
		pin.reset();
	}

	void verify( APDU apdu ) {
		apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		if( !pin.check( buffer, (byte)5, buffer[4] ) ) 
			ISOException.throwIt( SW_VERIFICATION_FAILED );
	}

	public void process(APDU apdu) throws ISOException {
		byte[] buffer = apdu.getBuffer();
		switch (buffer[1]) {
	  
			case SELECT: return;
			   
			case BINARY_READ:
				if ( ! pin.isValidated() )
					ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
				Util.arrayCopy(NVR,(byte)0,buffer,(short)0,buffer[4]);
				apdu.setOutgoingAndSend((short)0,buffer[4]);
				break;
		
			case BINARY_WRITE:
				if ( ! pin.isValidated() )
					ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
				apdu.setIncomingAndReceive();  
				Util.arrayCopy(buffer,(short)5,NVR,(short)0,buffer[4]);
				break;
			
			case PIN_VERIFY:
				verify(apdu);
				break;

			default:  
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
  
	}

}
