package client;

import java.util.Date;
import java.io.*;
import opencard.core.service.*;
import opencard.core.terminal.*;
import opencard.core.util.*;
import opencard.opt.util.*;




public class TheClient {


	
    private final static byte CLA_TEST				= (byte)0x90;
    private final static byte INS_TESTDES_ECB_NOPAD_ENC       	= (byte)0x28;
    private final static byte INS_TESTDES_ECB_NOPAD_DEC       	= (byte)0x29;
    private final static byte INS_DES_ECB_NOPAD_ENC           	= (byte)0x20;
    private final static byte INS_DES_ECB_NOPAD_DEC           	= (byte)0x21;
    private final static byte P1_EMPTY = (byte)0x00;
    private final static byte P2_EMPTY = (byte)0x00;
  

    private PassThruCardService servClient = null;
   
    boolean DISPLAY = true;


    public static void main( String[] args ) throws InterruptedException {
	    new TheClient();
    }


    public TheClient() {
	    try {
		    SmartCard.start();
		    System.out.print( "Smartcard inserted?... " ); 
		    
		    CardRequest cr = new CardRequest (CardRequest.ANYCARD,null,null); 
		    
		    SmartCard sm = SmartCard.waitForCard (cr);
		   
		    if (sm != null) {
			    System.out.println ("got a SmartCard object!\n");
		    } else
			    System.out.println( "did not get a SmartCard object!\n" );
		   
		    this.initNewCard( sm ); 
		    
		    SmartCard.shutdown();
	   
	    } catch( Exception e ) {
		    System.out.println( "TheClient error: " + e.getMessage() );
	    }
	    java.lang.System.exit(0) ;
    }

    private ResponseAPDU sendAPDU(CommandAPDU cmd) {
	    return sendAPDU(cmd, true);
    }

    private ResponseAPDU sendAPDU( CommandAPDU cmd, boolean display ) {
	    ResponseAPDU result = null;
	    try {
		result = this.servClient.sendCommandAPDU( cmd );
		if(display)
			displayAPDU(cmd, result);
	    } catch( Exception e ) {
           	 System.out.println( "Exception caught in sendAPDU: " + e.getMessage() );
           	 java.lang.System.exit( -1 );
            }
	    return result;
    }


    /************************************************
     * *********** BEGINNING OF TOOLS ***************
     * **********************************************/


    private String apdu2string( APDU apdu ) {
	    return removeCR( HexString.hexify( apdu.getBytes() ) );
    }


    public void displayAPDU( APDU apdu ) {
	System.out.println( removeCR( HexString.hexify( apdu.getBytes() ) ) + "\n" );
    }


    public void displayAPDU( CommandAPDU termCmd, ResponseAPDU cardResp ) {
	System.out.println( "--> Term: " + removeCR( HexString.hexify( termCmd.getBytes() ) ) );
	System.out.println( "<-- Card: " + removeCR( HexString.hexify( cardResp.getBytes() ) ) );
    }


    private String removeCR( String string ) {
	    return string.replace( '\n', ' ' );
    }


    /******************************************
     * *********** END OF TOOLS ***************
     * ****************************************/


    private boolean selectApplet() {
	 boolean cardOk = false;
	 try {
	    CommandAPDU cmd = new CommandAPDU( new byte[] {
                (byte)0x00, (byte)0xA4, (byte)0x04, (byte)0x00, (byte)0x0A,
		(byte)0xA0, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x62, 
		(byte)0x03, (byte)0x01, (byte)0x0C, (byte)0x06, (byte)0x01
            } );
            ResponseAPDU resp = this.sendAPDU( cmd );
	    if( this.apdu2string( resp ).equals( "90 00" ) )
		    cardOk = true;
	 } catch(Exception e) {
            System.out.println( "Exception caught in selectApplet: " + e.getMessage() );
            java.lang.System.exit( -1 );
        }
	return cardOk;
    }


    private void initNewCard( SmartCard card ) {
	if( card != null )
		System.out.println( "Smartcard inserted\n" );
	else {
		System.out.println( "Did not get a smartcard" );
		System.exit( -1 );
	}

	System.out.println( "ATR: " + HexString.hexify( card.getCardID().getATR() ) + "\n");


	try {
		this.servClient = (PassThruCardService)card.getCardService( PassThruCardService.class, true );
	} catch( Exception e ) {
		System.out.println( e.getMessage() );
	}

	System.out.println("Applet selecting...");
	if( !this.selectApplet() ) {
		System.out.println( "Wrong card, no applet to select!\n" );
		System.exit( 1 );
		return;
	} else 
		System.out.println( "Applet selected\n" );
       
	foo();
    }


    private void testDES_ECB_NOPAD( boolean displayAPDUs ) { 
	    testCryptoGeneric(INS_TESTDES_ECB_NOPAD_ENC);
	    testCryptoGeneric(INS_TESTDES_ECB_NOPAD_DEC);
    }


    private void testCryptoGeneric( byte typeINS ) {
	    byte[] t = new byte[4];

	    t[0] = CLA_TEST;
	    t[1] = typeINS;
	    t[2] = P1_EMPTY;
	    t[3] = P2_EMPTY;

            this.sendAPDU(new CommandAPDU( t ));
    } 
    
    
    private byte[] cipherDES_ECB_NOPAD( byte[] challenge, boolean display ) {
	    return cipherGeneric( INS_DES_ECB_NOPAD_ENC, challenge );
    } 
    
    
    private byte[] uncipherDES_ECB_NOPAD( byte[] challenge, boolean display ) {
	    return cipherGeneric( INS_DES_ECB_NOPAD_DEC, challenge );
    } 


    private byte[] cipherGeneric( byte typeINS, byte[] challenge ) {
	    byte[] result = new byte[challenge.length];
	    // TO COMPLETE
	    return result;
    }
    
    
    private void foo() {
	    sun.misc.BASE64Encoder encoder = new sun.misc.BASE64Encoder();
	    byte[] response;
	    byte[] unciphered; 
	    long d1, d2, seed=0;
	    java.util.Random r = new java.util.Random( seed );

	    byte[] challengeDES = new byte[16]; 		// size%8==0, coz DES key 64bits

	    r.nextBytes( challengeDES );

	    System.out.println( "**TESTING**");
	    testDES_ECB_NOPAD( true );
	    System.out.println( "**TESTING**");
	   
	    System.out.println("\nchallenge:\n" + encoder.encode(challengeDES) + "\n");
	    response = cipherGeneric(INS_DES_ECB_NOPAD_ENC, challengeDES);
	    System.out.println("\nciphered is:\n" + encoder.encode(response) + "\n");
	    unciphered = cipherGeneric(INS_DES_ECB_NOPAD_DEC, response);
	    System.out.print("\nunciphered is:\n" + encoder.encode(unciphered) + "\n");
    }


}
