//JavaCard 2.1.1


package applet;


import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;




public class TheApplet extends Applet {


    private final static byte CLA_TEST				= (byte)0x90;


    private final static byte INS_DES_ECB_NOPAD_ENC           	= (byte)0x20;
    private final static byte INS_DES_ECB_NOPAD_DEC           	= (byte)0x21;
    private final static byte INS_TESTDES_ECB_NOPAD_ENC       	= (byte)0x28;
    private final static byte INS_TESTDES_ECB_NOPAD_DEC       	= (byte)0x29;


	static final byte[] theDESKey = 
		new byte[] { (byte)0xCA, (byte)0xCA, (byte)0xCA, (byte)0xCA, (byte)0xCA, (byte)0xCA, (byte)0xCA, (byte)0xCA };



    // cipher instances
    private Cipher 
	    cDES_ECB_NOPAD_enc, cDES_ECB_NOPAD_dec;


    // key objects
			
    private Key 
	    secretDESKey, secretDES2Key, secretDES3Key;


    // "Foo" (name, also sent after termining an operation)
    private byte[] name = { (byte)0x03, (byte)0x46, (byte)0x6F, (byte)0x6F };
    // data's size
    private final static short DTRSIZE = (short)256;//256bytes==2048bits//FOO 8160;//mqos.jpg is 100x20, so...
    // loop variable
    private short i, j, k, x, y;
    // read/write tests array size
    //private final static short WRITINGSIZE = 10;
    // to generate random data
    private final static short RANDOMSIZE = 1000; // <=DTRSIZE
    short offset;
    short length;
    // to perform reading/writing test
    private static final short ARRAY_SIZE = 10;
    private static final short NBWRITEMEM = 100;
    private static final short NBREADMEM = 100;
    private byte[] data;
    private byte[] dataToCipher = {1,2,3,4,5,6,7,8};
    private byte[] ciphered = new byte[8];
    /*
    //size of file, short = byte1 + byte2
    private byte[] fileSize1 = new byte[]{ (byte)0xAB, (byte)0xBC };
    //size of file2, short = byte1 + byte2
    private byte[] fileSize2 = new byte[]{ (byte)0xCD, (byte)0xDE };
    */
    //stack counter
    private byte[] stackCounter = { 0x00 };
    //nb loop DES tests
    private final static short NBTESTSDESCIPHER = 100;
    private final static short NBTESTSDESUNCIPHER = 100;
    /*
    //nb loop RSA tests
    private final static short NBTESTSRSACIPHER = 100;
    private final static short NBTESTSRSAUNCIPHER = 100;
    */
    //private final static short MEMTESTSIZE = 10;
    //VM loop size
    //private final static short VMLOOPSIZE = 30;
    //to test capabilities of the card
    boolean 
	    pseudoRandom, secureRandom,
	    SHA1, MD5, RIPEMD160,
	    keyDES, DES_ECB_NOPAD, DES_CBC_NOPAD;


    protected TheApplet() { 
	    initKeyDES(); 
	    initDES_ECB_NOPAD(); 

	    this.register();
    }


    private void initKeyDES() {
	    try {
		    secretDESKey = KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
		    ((DESKey)secretDESKey).setKey(theDESKey,(short)0);
		    keyDES = true;
	    } catch( Exception e ) {
		    keyDES = false;
	    }
    }


    private void initDES_ECB_NOPAD() {
	    if( keyDES ) try {
		    cDES_ECB_NOPAD_enc = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
		    cDES_ECB_NOPAD_dec = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
		    cDES_ECB_NOPAD_enc.init( secretDESKey, Cipher.MODE_ENCRYPT );
		    cDES_ECB_NOPAD_dec.init( secretDESKey, Cipher.MODE_DECRYPT );
		    DES_ECB_NOPAD = true;
	    } catch( Exception e ) {
		    DES_ECB_NOPAD = false;
	    }
    }


    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
	    new TheApplet();
    }


    public void process(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();

        if( selectingApplet() == true )
          return ;

        if( buffer[ISO7816.OFFSET_CLA] != CLA_TEST )
            ISOException.throwIt( ISO7816.SW_CLA_NOT_SUPPORTED );

        try { switch( buffer[ISO7816.OFFSET_INS] ) {

	case INS_TESTDES_ECB_NOPAD_ENC: if( DES_ECB_NOPAD ) 
		testCipherGeneric( cDES_ECB_NOPAD_enc, KeyBuilder.LENGTH_DES, NBTESTSDESCIPHER  ); return;
	case INS_TESTDES_ECB_NOPAD_DEC: if( DES_ECB_NOPAD ) 
		testCipherGeneric( cDES_ECB_NOPAD_dec, KeyBuilder.LENGTH_DES, NBTESTSDESUNCIPHER   ); return;

	case INS_DES_ECB_NOPAD_ENC: if( DES_ECB_NOPAD )
		cipherGeneric( apdu, cDES_ECB_NOPAD_enc, KeyBuilder.LENGTH_DES ); return;
	case INS_DES_ECB_NOPAD_DEC: if( DES_ECB_NOPAD ) 
		cipherGeneric( apdu, cDES_ECB_NOPAD_dec, KeyBuilder.LENGTH_DES  ); return;
	    }
	} catch( Exception e ) {
	}
    }


	private void cipherGeneric( APDU apdu, Cipher cipher, short keyLength ) {
		// Write the method ciphering/unciphering data from the computer.
		// The result is sent back to the computer.
	}


	private void testCipherGeneric( Cipher cipher, short keyLength, short nbLoops ) {
		for( i = 0; i < nbLoops; i++ )
			cipher.doFinal( dataToCipher, (short)0, (short)(keyLength/8), ciphered, (short)0 );
	}


}
