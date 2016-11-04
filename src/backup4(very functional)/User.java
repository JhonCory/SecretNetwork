import java.io.BufferedReader;
import java.io.FileReader;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.UUID;
import javax.xml.bind.DatatypeConverter;

/** Represents the registered operating system or account used by the person trying 
  * to access a secret from the SecretServer */
public class User {
	private final String accountName;
	private final SecretServer server;
	private final boolean simMode;
	private final String secretsfn;
	private final String hashfn;
	private final String pubkeysfn;
	private final String privkeysfn;
	private final String validusersfn;
	private BigInteger my_d; // second half of accountName's private key
	private BigInteger my_n; // first half of accountName's public key
	private int my_e; // second half of accountName's public key
	private BigInteger serv_n; // first half of SecretServer's public key
	private int serv_e; // second half of SecretServer's public key
	private String username;
	private byte[] sessionKey;
	private int counter; // to be included in the next payload User sends

	public User(String accountName, SecretServer server, boolean simMode){
		this.accountName = accountName;
		this.server = server;
		this.simMode = simMode;

		secretsfn = "secrets.txt";
		hashfn = "passwords.txt";
		pubkeysfn = "publickeys.txt";
		privkeysfn = "privatekeys.txt";
		validusersfn = "validusers.txt";

		configureKeys(accountName);
	}


	/** Using a secure Bilateral Authentication Protocol which relies on public
	  * key RSA, attempts to set up a secure session with the SecretServer using
	  * the given username. 
	  * Returns true if successful, false otherwise.
	  * NOTE: Because each User's private key is stored on their own account,
	  * this protocol will FAIL if username doesn't match accountName. */
	public boolean connectAs(String uname) {
		boolean noProblems = true; // no problems have been encountered
 
		// First Message: A->B: Alice || E_kB(Alice || nonce_A)
		byte[] nonce_user = ComMethods.genNonce();
		ComMethods.report(accountName+" has randomly generated a 128-bit nonce_user = "+(new String(nonce_user))+".",simMode);

		byte[] unameBytes = uname.getBytes();
		byte[] pload = ComMethods.concatByteArrs(unameBytes, nonce_user);
		byte[] srvrNameBytes = "SecretServer".getBytes();
//
		System.out.println("uname in bytes: ");
		ComMethods.charByChar(unameBytes,true);
		System.out.println("nonce_user in bytes: ");
		ComMethods.charByChar(nonce_user,true);
		System.out.println("pload concatenation in bytes: ");
		ComMethods.charByChar(pload,true);
//

		pload = ComMethods.encryptRSA(pload, serv_n, BigInteger.valueOf(serv_e));

//
		System.out.println();
		System.out.println("uname, in bytes: ");
		ComMethods.charByChar(unameBytes,true);
		ComMethods.report("pload is now encrypted with RSA", simMode);
		System.out.println("encrypted pload, in bytes: ");
		ComMethods.charByChar(pload,true);
//

		byte[] message1 = ComMethods.concatByteArrs(unameBytes,pload);

//
		ComMethods.report("message1 is now prepared", simMode);
		System.out.println("message1, in bytes: ");
		ComMethods.charByChar(message1,true);
//


		ComMethods.report(accountName+" is sending SecretServer the name "+uname+", concatenated with '"+uname+" || nonce_user' encrypted under RSA with the SecretServer's public key.", simMode);	
		
		byte[] response1 = sendServer(message1,false);

		if (!checkError(response1)) {
			response1 = ComMethods.decryptRSA(response1, my_n, my_d);
			ComMethods.report(accountName+" has decrypted the SecretServer's message using "+accountName+"'s private RSA key.", simMode);
		} else {
			ComMethods.report(accountName+" has received the SecretServer's error message.", simMode);
		}

		// Test for proper formatting of the second message in the protocol
		if (!Arrays.equals(Arrays.copyOf(response1,nonce_user.length), nonce_user) || !Arrays.equals(Arrays.copyOfRange(response1, nonce_user.length, nonce_user.length+srvrNameBytes.length), srvrNameBytes)) {

//
			System.out.println();
			System.out.println("nonce_user = "+nonce_user);
			System.out.println("response1 = "+response1);
			System.out.println("nonce_user in bytes: ");
			ComMethods.charByChar(nonce_user,true);
			System.out.println("\"ServerName\" in bytes: ");
			ComMethods.charByChar(srvrNameBytes,true);
			System.out.println("response1 in bytes: ");
			ComMethods.charByChar(response1,true);
//
			noProblems = false;
			System.out.println("ERROR ~ something went wrong with the second message in the bilateral authentication protocol.");
		} else {
			byte[] nonce_srvr = Arrays.copyOfRange(response1, nonce_user.length + srvrNameBytes.length, response1.length);
			ComMethods.report(accountName+" now has nonce_srvr.", simMode);

			// Third Message: A->B: E_kB(nonce_B || kS)
			sessionKey = ComMethods.genNonce();
			ComMethods.report(accountName+" has generated a random 128-bit session key.", simMode);
			
			byte[] message2 = ComMethods.concatByteArrs(nonce_srvr, sessionKey);
			message2 = ComMethods.encryptRSA(message2, serv_n, BigInteger.valueOf(serv_e));
			ComMethods.report(accountName+" is sending the SecretServer the concatenation of nonce_srvr and the session key, encrypted under RSA using the SecretServer's public key.", simMode);

			byte[] response2 = sendServer(message2, false);
			if (!checkError(response2)) {
				response2 = ComMethods.processPayload(srvrNameBytes, response2, 11, sessionKey, simMode);
				ComMethods.report(accountName+" has decrypted the SecretServer's message using the symmetric session key that "+accountName+" just generated.", simMode);				
			} else {
				ComMethods.report(accountName+" has received the SecretServer's error message.", simMode);
			}

			// Test formatting of the 4th message in the protocol
			byte[] expected = "understood".getBytes();
			if (!Arrays.equals(Arrays.copyOf(response2, expected.length), expected)) {

//
				System.out.println();
				System.out.println("expected (\"understood\" in bytes is): ");
				ComMethods.charByChar(expected, true);
				System.out.println("response 2: ");
				ComMethods.charByChar(response2, true);
//

				noProblems = false;
				ComMethods.report("ERROR ~ something went wrong with the fourth message in the Bilateral Authentication Protocol.", simMode);
			} else {
				counter = 12; // counter to be used in future messages
			}
		}

		if (noProblems) {
			username = uname;
		}

		return noProblems; 
	}


	/** Attempts to "log into" specified account (which SHOULD be this User's 
	  * account, if security is guaranteed) with the SecretServer to gain access
	  * to the secret using the given password.
	  * Returns true if successful, false otherwise. */ 
	public boolean logIn(String password) {
		byte[] message = ComMethods.concatByteArrs("password:".getBytes(), password.getBytes());
		byte[] response = sendServerCoded(message); 

		boolean success;
		switch (new String(response)) {
			case "accepted":
				success = true;
				break;
			case "rejected":
				success = false;
				break;
			default:
				success = false;
				ComMethods.handleBadResp();
				break;
		}
		return success;
	}


	// Asks SecretServer to send secret, which is encrypted using username's key. 
	// Returns the decrypted secret.
	// NOTE: there's no handling for failure to respond
	public String requestView() { 
		byte[] userMessage = "view".getBytes();
		byte[] srvrResponse = sendServerCoded(userMessage);
		
		if (!checkError(srvrResponse)) {
			byte[] encryptedSecret = srvrResponse;
			byte[] decryptedSecret = ComMethods.decryptRSA(encryptedSecret, my_n, my_d);
			return new String(decryptedSecret);
		} else {
			return "error";
		}
	}


	// Tells SecretServer to change secret to newSecret.
	// NOTE: there's no handling for failure to respond
	public boolean updateSecret(String newSecret) {
		byte[] encryptedNewSecret = ComMethods.encryptRSA(newSecret.getBytes(), my_n, BigInteger.valueOf(my_e));
		byte[] userMessage = ComMethods.concatByteArrs("update:".getBytes(), encryptedNewSecret);
		return sendAndCheckResp(userMessage, "secretupdated", "writingfailure");
	}


	// Tells SecretServer to delete the secret.
	// NOTE: there's no handling for failure to respond
	public boolean deleteSecret() {
		byte[] userMessage = "delete".getBytes();
		return sendAndCheckResp(userMessage, "secretdeleted", "writingfailure");
	}

	
	// Sends message coded to the SecretServer, then returns true if server's 
	// response matches trueResp, returns false if falseResp (error otherwise)
	private boolean sendAndCheckResp(byte[] userMessage, String trueResp, String falseResp) {
		byte[] srvrResponse = sendServerCoded(userMessage);
		byte[] expectedResponse = trueResp.getBytes();
		byte[] alternateResponse = falseResp.getBytes();

		boolean truthVal = false;
		if (Arrays.equals(srvrResponse, expectedResponse)) {
			truthVal = true;
		} else if (Arrays.equals(srvrResponse, alternateResponse)) {
			// truthVal = false;
		} else {
			ComMethods.handleBadResp();
		}
		return truthVal;
	}



	// Sends a given message to the SecretServer and returns its response
	private byte[] sendServer(byte[] message, boolean activeSession) { 
		ComMethods.report(accountName+" sending message to SecretServer now...", simMode);
		byte[] response = server.getMessage(message, activeSession);
		ComMethods.report(accountName+" has received SecretServer's response.", simMode);
		return response; 
	}


	/** Sends a given message to the SecretServer and returns its response,
	  * but encodes/decodes messages using sessionKey.
	  * Rejects any "bad" responses. */
	private byte[] sendServerCoded(byte[] message) { 
		byte[] toPayload = ComMethods.preparePayload(username.getBytes(), message, counter, sessionKey, simMode);
		byte[] fromPayload = sendServer(toPayload, true);

		byte[] response = new byte[0];
		if (checkError(fromPayload)) {
			response = "error".getBytes();
		} else {
			response = ComMethods.processPayload("SecretServer".getBytes(), fromPayload, counter+1, sessionKey, simMode);
			counter = counter + 2;
		}
		return response;
	}

	
	// Checks whether SecretServer sent back an error message
	private boolean checkError(byte[] response) {
		return Arrays.equals(response,"error".getBytes());
	}


	/** Sets the private key of this accountName, the public key of this 
	  * accountName, and the public key of the SecretServer, which are found by
	  * parsing the relevant text files for public keys and private keys of 
	  * registered users of this secret server storage service.
	  * NOTE: This is a simulation. In a real setting, the private keys would
	  * be native to individuals' accounts and not stored together in a file. */
	private void configureKeys(String accountName) {
		// accountName's public key
		String line = ComMethods.getValueFor(accountName, pubkeysfn);
		int x = line.indexOf(',');
		my_n = new BigInteger(line.substring(0,x));
		my_e = new Integer(line.substring(x+1,line.length()));

		// accountName's private key
		line = ComMethods.getValueFor(accountName, privkeysfn);
		x = line.indexOf(',');
		my_d = new BigInteger(line.substring(x+1,line.length()));
			
		// SecretServer's public key
		line = ComMethods.getValueFor("SecretServer", pubkeysfn);
		x = line.indexOf(',');
		serv_n = new BigInteger(line.substring(0,x));
		serv_e = new Integer(line.substring(x+1,line.length()));
	}
}