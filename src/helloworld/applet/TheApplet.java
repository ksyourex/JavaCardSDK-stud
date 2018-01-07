package applet;


import javacard.framework.*;




public class TheApplet extends Applet {


    protected byte[] msg={(byte)12,'H','e','l','l','o',' ','w','o','r','l','d','!'};


    protected TheApplet() {
	    this.register();
    }


    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
	    new TheApplet();
    } 
    
    
    public boolean select() {
	    return true;
    } 
    
    
    public void process(APDU apdu) throws ISOException {
        if( selectingApplet() == true )
		return;

        byte[] buffer = apdu.getBuffer();
	Util.arrayCopy(msg, (short)1, buffer, (short)0, msg[0]);
	apdu.setOutgoingAndSend( (short)0, msg[0] );
    }


}
