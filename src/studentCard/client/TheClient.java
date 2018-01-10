package client;

import java.io.*;
import java.util.*;
import opencard.core.service.*;
import opencard.core.terminal.*;
import opencard.core.util.*;
import opencard.opt.util.*;

public class TheClient {

	private PassThruCardService servClient = null;
	boolean DISPLAY = true;
	boolean loop = true;
	
	static final byte INS_DES_ECB_NOPAD_DEC				= (byte)0x21;
	static final byte INS_DES_ECB_NOPAD_ENC 			= (byte)0x20;
	static final byte TYPEDATA					        = (byte)0x16;
	static final byte TYPEHEADER			       	    = (byte)0x15;
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
	static final byte CLA								= (byte)0x00;
	static final byte P1								= (byte)0x00;
	static final byte P2								= (byte)0x00;
	
	static final int MAX_SIZE 							= 248;
	static final short MAX_FILE_SIZE 					= 4096;
	static final byte BUFSIZE				      		= (byte)0x7F;
    
	
	static byte filename[] = {0x46, 0x6F, 0x6F, 0x2E, 0x74, 0x78, 0x74};
	
	public TheClient() {
		try {
			SmartCard.start();
			System.out.print("Smartcard inserted?... "); 

			CardRequest cr = new CardRequest (CardRequest.ANYCARD,null,null); 

			SmartCard sm = SmartCard.waitForCard (cr);

			if (sm != null) {
				System.out.println ("got a SmartCard object!\n");
			} else
				System.out.println("did not get a SmartCard object!\n");

			this.initNewCard(sm); 
			SmartCard.shutdown();

		} catch(Exception e) {
			System.out.println("TheClient error: " + e.getMessage());
		}
		java.lang.System.exit(0);
	}

	private ResponseAPDU sendAPDU(CommandAPDU cmd) {
		return sendAPDU(cmd, true);
	}

	private ResponseAPDU sendAPDU(CommandAPDU cmd, boolean display) {
		ResponseAPDU result = null;
		try {
			result = this.servClient.sendCommandAPDU(cmd);
			if(display)
				displayAPDU(cmd, result);
		} catch(Exception e) {
			System.out.println("Exception caught in sendAPDU: " + e.getMessage());
			java.lang.System.exit(-1);
		}
		return result;
	}


	/************************************************
	 * *********** BEGINNING OF TOOLS ***************
	 * **********************************************/
	private String apdu2string(APDU apdu) {
		return removeCR(HexString.hexify(apdu.getBytes()));
	}

	public void displayAPDU(APDU apdu) {
		System.out.println(removeCR(HexString.hexify(apdu.getBytes())) + "\n");
	}

	public void displayAPDU(CommandAPDU termCmd, ResponseAPDU cardResp) {
		System.out.println("--> Term: " + removeCR(HexString.hexify(termCmd.getBytes())));
		System.out.println("<-- Card: " + removeCR(HexString.hexify(cardResp.getBytes())));
	}

	private String removeCR(String string) {
		return string.replace('\n', ' ');
	}


	/******************************************
	 * *********** END OF TOOLS ***************
	 * ****************************************/
	private byte[] cipherGeneric(byte typeINS, byte[] challenge) {
	    byte[] result = new byte[challenge.length];
	    byte[] header = {CLA, typeINS, P1, P2, (byte)challenge.length};
	    byte[] apdu = new byte[header.length + result.length + 1];
	    
	    System.arraycopy(header, 0, apdu, 0, header.length);
	    System.arraycopy(challenge, 0, apdu, header.length, result.length);

	    apdu[apdu.length-1] = (byte) challenge.length;

	    CommandAPDU cmd = new CommandAPDU(apdu);
	    ResponseAPDU resp = this.sendAPDU(cmd, DISPLAY);
	    
	    byte[] bytes = resp.getBytes();
	    System.arraycopy(bytes, 0, result,0 , bytes.length-2);

	    return result;
	}

	private boolean selectApplet() {
		boolean cardOk = false;
		try {
			CommandAPDU cmd = new CommandAPDU( new byte[] {
				(byte)0x00, (byte)0xA4, (byte)0x04, (byte)0x00, (byte)0x0A,
				(byte)0xA0, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x62, 
				(byte)0x03, (byte)0x01, (byte)0x0C, (byte)0x06, (byte)0x01
			});
			
			ResponseAPDU resp = this.sendAPDU(cmd);
			
			if( this.apdu2string(resp).equals("90 00"))
				cardOk = true;
		} catch(Exception e) {
			System.out.println("Exception caught in selectApplet: " + e.getMessage());
			java.lang.System.exit(-1);
		}
		return cardOk;
	}

	private void initNewCard(SmartCard card) throws IOException{
		if(card != null)
			System.out.println("Smartcard inserted\n");
		else {
			System.out.println("Did not get a smartcard");
			System.exit(-1);
		}

		System.out.println("ATR: " + HexString.hexify( card.getCardID().getATR() ) + "\n");

		try {
			this.servClient = (PassThruCardService)card.getCardService(PassThruCardService.class, true);
		} catch(Exception e) {
			System.out.println(e.getMessage());
		}

		System.out.println("Applet selecting...");
		if(!this.selectApplet()) {
			System.out.println("Wrong card, no applet to select!\n");
			System.exit(1);
			return;
		} else 
			System.out.println("Applet selected");

		mainLoop();
	}

	byte[] paddingCheck(byte[] buf) {
		int count = buf.length-1;
		byte[] ret;

		while(buf[count] == 0) count--;		  

		// Remove the padding
		if(buf[count] == buf.length-1-count) {
			ret = new byte[count];
			System.arraycopy(buf, 0, ret, 0, count);		
		}
		// Else no padding so we remove 8 bytes of padding
		else{
			ret = new byte[buf.length-8];
			System.arraycopy(buf, 0, ret, 0, buf.length-8);
		}
		return ret;
	}

	void fileWriter(String path,byte[] buffer){
		try{
			FileOutputStream fos = new FileOutputStream(path);
			fos.write(buffer);
			fos.close();
		}catch (Exception e){System.out.println(e.toString());}	
	}

	void updateCardKey() {
		ResponseAPDU resp = null;

		System.out.println("Write the new DES key :");
		String newDESKey = readKeyboard();
		
		if (newDESKey.length() != 8)
			System.out.println("DES KEY LENGTH ERROR !");

		byte [] data = newDESKey.getBytes();
		byte lc = (byte)data.length;
		byte [] cmd = new byte [lc+5];
		byte [] header = {CLA, UPDATECARDKEY, P1, P2, lc};
		System.arraycopy(header, 0, cmd, 0, header.length);
		System.arraycopy(data, 0, cmd, header.length, lc);
		resp = sendAPDU (new CommandAPDU(cmd), DISPLAY);	

		if (this.apdu2string(resp).equals("90 00"))
			System.out.println("Change done !"); 
		else {
			if (this.apdu2string(resp).equals("63 01"))
				System.out.println("DES key needed !");
			else
				System.out.println("ERROR !");
		}
	}

	void uncipherFileByCard() {
		InputStream is = null;
		DataInputStream dataIS = null;
		try{	        
			is = new FileInputStream("cipher"); // Create file input stream
			dataIS = new DataInputStream(is);	// Create new data input stream
			int length = dataIS.available();	// Available stream to be read
			byte[] buf = new byte[length];		// Create main buffer
			byte[] buffer = new byte[length];	// Create buffer for save cipher file
			byte[] tmp = new byte [MAX_SIZE];
			byte[] resp = new byte[MAX_SIZE];

			dataIS.readFully(buf);				// Read the full data into the main buffer
			int i = 0;

			while(i+MAX_SIZE <= length)	{
				tmp = Arrays.copyOfRange(buf, i, i+MAX_SIZE);			
				resp = cipherGeneric(INS_DES_ECB_NOPAD_DEC, tmp);
				System.arraycopy(resp, 0, buffer, i, resp.length);
				i += MAX_SIZE;
			}

			if(i+MAX_SIZE > length){
				tmp = Arrays.copyOfRange(buf, i, length);				
				resp = cipherGeneric(INS_DES_ECB_NOPAD_DEC, tmp);
				System.arraycopy(resp, 0, buffer, i, resp.length);			
				fileWriter("uncipher", paddingCheck(buffer));
			}			
		} catch(Exception e){System.out.println(e.toString());}
	}

	void cipherFileByCard() {
		System.out.println("Write the file name :");
		String file = readKeyboard();
		InputStream is = null;
		DataInputStream dataIS = null;

		try {
			is = new FileInputStream(file); 	// Create file input stream
			dataIS = new DataInputStream(is);	// Create new data input stream
			int length = dataIS.available();	// Available stream to be read
			byte[] buf = new byte[length]; 		// Create main buffer
			byte[] buffer = new byte[(length%8==1)?length+16-length%8 : length+8-length%8]; // Create buffer for save cipher file
			byte[] tmp = new byte[MAX_SIZE];
			byte[] resp = new byte[MAX_SIZE];

			dataIS.readFully(buf); // Read the full data into the main buffer
			int i = 0;
			while(i+MAX_SIZE < length && length >= MAX_SIZE) {
				tmp = Arrays.copyOfRange(buf, i, i+MAX_SIZE);
				resp = cipherGeneric(INS_DES_ECB_NOPAD_ENC, tmp);
				System.arraycopy(resp, 0, buffer, i, resp.length);
				i += MAX_SIZE;
			}

			// Force add padding
			if(i == length) {
				byte[] buffZero = new byte[8];
				buffZero[0] = (byte)7;	
				resp = cipherGeneric(INS_DES_ECB_NOPAD_ENC, buffZero);			
				System.arraycopy(resp, 0, buffer, length, (byte)8);
			}

			if(i < length){
				int size = length-i;
				int padding = 8 - size%8;
				byte[] tmpPadding = new byte [size+padding];
				byte[] buffZero=new byte[padding];
				// Padding
				buffZero[0]=(byte)((padding==1) ? padding-1+8 : padding-1);	

				System.arraycopy(buf, i, tmpPadding, 0, size); // Rest of data
				System.arraycopy(buffZero, 0, tmpPadding, size, padding);// Rest of padding
				resp = cipherGeneric(INS_DES_ECB_NOPAD_ENC, tmpPadding);			
				System.arraycopy(resp, 0, buffer, i, resp.length); // Bug init buffer size				
				if(padding == 1){				
					byte[] zero = new byte[8]; // Padding 8 zero
					resp = cipherGeneric(INS_DES_ECB_NOPAD_ENC, zero);
					System.arraycopy(resp, 0, buffer, i+size+padding, resp.length);
				}
			}
			fileWriter("cipher", buffer);
		}catch(Exception e) {System.out.println(e.toString());}
	}	
	
	void readFileFromCard() {
		CommandAPDU command;
        ResponseAPDU response;
        String strFile = "";
		
        int nb = 0;
        byte bytes[];
        byte header[] = {(byte)CLA, (byte)READFILEFROMCARD, (byte)TYPEHEADER, (byte)P2, (byte)0x0A};
        byte cmd[] = new byte[5];

        System.arraycopy(header, 0, cmd, 0, 5);
        command = new CommandAPDU(cmd);
        this.displayAPDU(command);
        response = this.sendAPDU(command, DISPLAY);
        this.displayAPDU(response);
		
        bytes = response.getBytes();
        String s = new String(Arrays.copyOfRange(bytes, 1, 8));
        int nbMax = bytes[8];
        byte lastblocksize = bytes[9];

        if (s.equals(new String(filename)) == false) {
            System.out.println ("No file to read !");
            return;
        }
		
        FileOutputStream stream;

        try{
            stream = new FileOutputStream("OutputFileRead");
            // Reading file per BUFSIZE block
			while (nbMax > 0) {
                header[2] = (byte)TYPEDATA;
                header[3] = (byte)(nb);
                header[4] = (byte)BUFSIZE;

                System.arraycopy(header, 0, cmd, 0, 5);

                // New commandAPDU with send and get command reponse
                command = new CommandAPDU(cmd);
                this.displayAPDU(command);
                response = this.sendAPDU(command, DISPLAY);
                
                bytes = response.getBytes();
                stream.write(bytes);
				String msg = "";
                msg += new String(Arrays.copyOfRange(bytes, 0, BUFSIZE));
				System.out.println("Block : " + msg);
				strFile += msg;
                nbMax--;
                nb++;
            }

            // Last file packet
            header[2] = (byte)TYPEDATA;
            header[3] = (byte)(nb);
            header[4] = (byte) lastblocksize;
			
            System.arraycopy(header, 0, cmd, 0, 5);
            command = new CommandAPDU(cmd);
            this.displayAPDU(command);
            response = this.sendAPDU(command, DISPLAY);
            
            bytes = response.getBytes();
            stream.write(bytes);
			String msg = "";
            msg += new String(Arrays.copyOfRange(bytes, 0, lastblocksize));
            strFile += msg;
			
			System.out.println("File data : " + strFile);
			stream.close();
        } catch(Exception e){System.out.println(e.toString());}
	}
	
	void writeFileToCard() {
		CommandAPDU command;
        ResponseAPDU response;
        FileInputStream fileStream;
		
        int n, nbMax, filesize = 0;
        byte[] buf = new byte[BUFSIZE];
        byte cmd[];

        // File APDU
        byte headerInfo[] = {(byte)CLA, (byte)WRITEFILETOCARD, (byte)TYPEHEADER, (byte)0x00, (byte)filename.length};

        // Data APDU
        byte apduDataHeader[] = {(byte)CLA, (byte)WRITEFILETOCARD, (byte)TYPEDATA, (byte)0x00, (byte)buf.length};

        try {
            System.out.println("Write the file name (with its path) :");
            String name = readKeyboard();

            File f = new File(name);
            filesize = (int)f.length();

            if (filesize > MAX_FILE_SIZE) {
                System.out.println("Error !");
                System.exit(1);
            }
            nbMax = (int) filesize / BUFSIZE;

            // Sending file data to card
            headerInfo[3] = (byte) nbMax;
            nbMax = 0;
            cmd = new byte[5 + filename.length];
            System.arraycopy(headerInfo, 0, cmd, 0, 5);
            System.arraycopy(filename, 0, cmd, 5, filename.length);
            command = new CommandAPDU(cmd);
            this.displayAPDU(command);
            response = this.sendAPDU(command, DISPLAY);
            fileStream = new FileInputStream(f);

            // Reading the file data
            byte apduDataData[] = new byte[5 + buf.length];

            while ((n = fileStream.read(buf)) >= 0) {
                if (n == buf.length) {
                    apduDataHeader[3] = (byte)nbMax;
                    System.arraycopy(apduDataHeader, 0, apduDataData, 0, 5);
                    System.arraycopy(buf, 0, apduDataData, 5,  buf.length);
                    command = new CommandAPDU(apduDataData);
                    this.displayAPDU(command);
                    response = this.sendAPDU(command, DISPLAY);
                    nbMax ++;
                }
                else {
                    byte apduDataLast[] = new byte [5+n];
                    apduDataHeader[3] = (byte)nbMax;
                    apduDataHeader[4] = (byte)n;
                    System.arraycopy(apduDataHeader, 0,apduDataLast , 0, 5);
                    System.arraycopy(buf, 0, apduDataLast, 5, (byte)n);
                    command = new CommandAPDU(apduDataLast);
                    this.displayAPDU(command);
                    response = this.sendAPDU(command, DISPLAY);
                }
            }
        }
        catch (Exception e){System.out.println(e.toString());}
	}

	void updateWritePIN() {
		ResponseAPDU resp = null;
		String pin = readKeyboard();

		System.out.println("Write the new PIN Code for the reading :");

		if (pin.length() != 4)
			System.out.println("PIN CODE SIZE ERROR !");

		byte [] data = pin.getBytes();
		byte lc = (byte)data.length;
		byte [] cmd = new byte [lc+5];
		byte [] header = {CLA, UPDATEWRITEPIN, P1, P2, lc};
		System.arraycopy(header, 0, cmd, 0, header.length);
		System.arraycopy(data, 0, cmd, header.length, lc);
		resp = sendAPDU (new CommandAPDU(cmd), DISPLAY);	

		if (this.apdu2string(resp).equals("90 00"))
			System.out.println("Correct Code"); 
		else {
			if (this.apdu2string(resp).equals("63 01"))
				System.out.println("PIN Code needed !");
			else
				System.out.println("ERROR !");
		}
	}

	void updateReadPIN() {
		ResponseAPDU resp = null;
		String pin = readKeyboard();

		System.out.println("Write the new PIN Code for writing :");

		if (pin.length() != 4)
			System.out.println("PIN CODE SIZE ERROR !");

		byte [] data = pin.getBytes();
		byte lc = (byte)data.length;
		byte [] cmd = new byte[lc+5];
		byte [] header = {CLA, UPDATEREADPIN, P1, P2, lc};
		System.arraycopy(header, 0, cmd, 0, header.length);
		System.arraycopy(data, 0, cmd, header.length, lc);
		resp = sendAPDU(new CommandAPDU(cmd), DISPLAY);

		if (this.apdu2string(resp).equals("90 00"))
			System.out.println("Correct Code");
		else {
			if(this.apdu2string(resp).equals("63 01"))
				System.out.println("PIN Code needed !");
			else
				System.out.println("ERROR !");
		}
	}

	void displayPINSecurity() {
		ResponseAPDU result = null;
		String msg = "PIN Sec :\n";
		byte [] bytes;
		byte [] header = {CLA, DISPLAYPINSECURITY, P1, P2, (byte)0};

		result = sendAPDU(new CommandAPDU(header), DISPLAY);

		if(this.apdu2string(result).endsWith("90 00"))
			System.out.println("Correct Code");
		else
			System.out.println("Wrong Code !");

		bytes = result.getBytes();
		for(int i=0; i<bytes.length-2; i++)
			msg += new StringBuffer("").append((char)bytes[i]);

		System.out.println(msg);
	}

	void desactivateActivatePINSecurity() {
		ResponseAPDU result = null ;
		byte [] header = {CLA, DESACTIVATEACTIVATEPINSECURITY, P1, P2};
		result = sendAPDU(new CommandAPDU(header), DISPLAY);

		if(this.apdu2string(result).equals("90 00"))
			System.out.println("PIN SEC ACTIVED/DESACTIVED !");
		else
			System.out.println("PIN SEC ACTIVED/DESACTIVED !");
	}

	void enterReadPIN() {
		ResponseAPDU resp = null;

		System.out.println("Write the PIN Code for reading :");
		String pin = readKeyboard();
		if (pin.length()!= 4)
			System.out.println("PIN CODE ERROR !");

		byte [] data = pin.getBytes() ;
		byte lc = (byte) data.length;
		byte [] cmd = new byte [lc+5] ;
		byte [] header = {CLA, ENTERREADPIN, P1, P2, lc};

		System.arraycopy(header, 0, cmd, 0, header.length);
		System.arraycopy(data, 0, cmd, header.length, lc);
		resp = sendAPDU(new CommandAPDU(cmd), DISPLAY);	

		if(this.apdu2string(resp).equals("90 00"))
			System.out.println("Correct Code");
		else
			System.out.println("Wrong Code !");
	}

	void enterWritePIN() {
		ResponseAPDU resp = null;

		System.out.println("Write the PIN Code for writing :");	
		String pin = readKeyboard();
		if (pin.length()!=4)
			System.out.println("PIN CODE ERROR !");

		byte [] data = pin.getBytes();
		byte lc = (byte) data.length;
		byte [] cmd = new byte [lc+5];
		byte [] header = {CLA, ENTERWRITEPIN, P1, P2, lc};

		System.arraycopy(header, 0, cmd, 0, header.length);
		System.arraycopy(data, 0, cmd, header.length, lc);
		resp = sendAPDU(new CommandAPDU(cmd), DISPLAY);	

		if(this.apdu2string(resp).equals("90 00"))
			System.out.println("Correct Code");
		else
			System.out.println("Wrong Code !");
	}

	void readNameFromCard() {
		ResponseAPDU result = null;

		byte [] header = {CLA, READNAMEFROMCARD, P1, P2,(byte)0};
		byte [] cmd    = new byte [header.length];

		System.arraycopy (header, 0, cmd, 0, header.length);
		result = sendAPDU (new CommandAPDU(cmd), DISPLAY);

		if(!this.apdu2string(result).endsWith("90 00"))
			System.out.println("Write the PIN Code for reading :");

		byte[] bytes = result.getBytes();
		String msg = "Card name :\n";

		for(int i=0; i<bytes.length-2; i++)
			msg += new StringBuffer("").append((char)bytes[i]);

		System.out.println(msg);	
	}

	void writeNameToCard() {
		ResponseAPDU result = null;

		System.out.println("Write the card name :");

		String name = readKeyboard();
		byte[] tabName = name.getBytes();
		byte[] tabApdu = new byte[tabName.length+5];
		byte[] header = {CLA, WRITENAMETOCARD, P1, P2, (byte)name.length()};

		System.arraycopy(header, (byte)0, tabApdu, (byte)0, (byte)header.length);
		System.arraycopy(tabName, (byte)0, tabApdu, (byte)header.length, (byte)tabName.length);

		result = sendAPDU(new CommandAPDU(tabApdu), DISPLAY);

		if(!this.apdu2string(result).equals("90 00"))
			System.out.println("Write the PIN Code for writing :");
	}

	void exit() {loop = false;}

	void runAction(int choice) {
		switch( choice ) {
			case 13: updateCardKey(); break;
			case 12: uncipherFileByCard(); break;
			case 11: cipherFileByCard(); break;
			case 10: readFileFromCard(); break;
			case 9: writeFileToCard(); break;
			case 8: updateWritePIN(); break;
			case 7: updateReadPIN(); break;
			case 6: displayPINSecurity(); break;
			case 5: desactivateActivatePINSecurity(); break;
			case 4: enterReadPIN(); break;
			case 3: enterWritePIN(); break;
			case 2: readNameFromCard(); break;
			case 1: writeNameToCard(); break;
			case 0: exit(); break;
			default: System.out.println("Unknown choice !");
		}
	}

	String readKeyboard() {
		String result = null;

		try {
			BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
			result = input.readLine();
		} catch(Exception e) {}

		return result;
	}

	int readMenuChoice() {
		int result = 0;

		try {
			String choice = readKeyboard();
			result = Integer.parseInt(choice);
		} catch(Exception e) {}

		System.out.println("");

		return result;
	}

	void printMenu() {
		System.out.println("");
		System.out.println("13: update the DES key within the card");
		System.out.println("12: uncipher a file by the card");
		System.out.println("11: cipher a file by the card");
		System.out.println("10: read a file from the card");
		System.out.println("9: write a file to the card");
		System.out.println("8: update WRITE_PIN");
		System.out.println("7: update READ_PIN");
		System.out.println("6: display PIN security status");
		System.out.println("5: desactivate/activate PIN security");
		System.out.println("4: enter READ_PIN");
		System.out.println("3: enter WRITE_PIN");
		System.out.println("2: read a name from the card");
		System.out.println("1: write a name to the card");
		System.out.println("0: exit");
		System.out.print(" --> ");
	}

	void mainLoop() {
		while(loop) {
			printMenu();
			int choice = readMenuChoice();
			runAction(choice);
		}
	}

	public static void main(String[] args) {
		new TheClient();
	}
}
