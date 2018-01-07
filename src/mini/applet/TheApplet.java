package applet;


import javacard.framework.*;




public class TheApplet extends Applet {


    protected TheApplet() {
	    this.register();
    }


    public static void install(byte[] bArray, short bOffset, byte bLength) {
	    new TheApplet();
    } 
    
    
    public void process(APDU apdu) {
        if(selectingApplet() == true)
		return;
    }


}
