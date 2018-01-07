package client;

import java.io.*;
import opencard.core.service.*;
import opencard.core.terminal.*;
import opencard.core.util.*;
import opencard.opt.util.*;




public class TheClient {

    private PassThruCardService servClient = null;
   
    boolean DISPLAY = true;


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
       
	    byte[] cmd_ = {0,0,0,0,0};
            CommandAPDU cmd = new CommandAPDU( cmd_ );
	    System.out.println("Sending blank command APDU, data expected...");
            ResponseAPDU resp = this.sendAPDU( cmd, DISPLAY );
	    byte[] bytes = resp.getBytes();
	    String msg = "";
	    for(int i=0; i<bytes.length-2;i++)
		    msg += new StringBuffer("").append((char)bytes[i]);
	    System.out.println(msg);
    }


    public static void main( String[] args ) throws InterruptedException {
	    new TheClient();
    }


}
