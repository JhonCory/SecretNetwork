import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import javax.xml.bind.DatatypeConverter;

/** Represents the server which handles requests for accessing secrets. */
public class SecretServer {
	private String secretsfn;
	private final String hashfn;
	private final String pubkeysfn;
	private final String privkeysfn;
	private final String validusersfn;

	private final boolean simMode;
	private final String[] validUsers; // registered users of this system
	private BigInteger my_d; // second half of SecretServer's private key
	private BigInteger my_n; // first half of SecretServer's public key
	private int my_e; // second half of SecretServer's public key
	private BigInteger[] usersPubKeys1; // stores n-vals for regist. users
	private int[] usersPubKeys2; // stores e-values for registered users

	private byte[] myNonce; // temporary nonce made by server for auth. protocol
	private String currentUser;
	private int userNum; // index of currentUser for userPubKeys
	private byte[] currentPassword;
	private byte[] currentSessionKey; 
	private boolean userSet; // is there a currentUser?
	private boolean passVerified; // does currentUser have a verified password?
	private boolean activeSession; // is currentSessionKey agreed upon?
	private int counter; // to be included in the next payload SecretServer sends

	public SecretServer(boolean simMode) {
		this.simMode = simMode;

		secretsfn = "secrets.txt";
		hashfn = "hashes.txt";
		pubkeysfn = "publickeys.txt";
		privkeysfn = "privatekeys.txt";
		validusersfn = "validusers.txt";

		validUsers = ComMethods.getValidUsers();
		configureKeys();
		userNum = -1;
		myNonce = null;
		currentUser = null;
		currentPassword = null;
		currentSessionKey = null;
		userSet = false;
		passVerified = false;
		activeSession = false;
		counter = -1;		
	}

	// Interprets input payloads and returns appropriate responses
	public byte[] getMessage(byte[] payload, boolean partOfSession) {
		ComMethods.report("SecretServer received payload and will now process it.", simMode);
		byte[] resp = new byte[0];
		if (partOfSession) {
			if (!activeSession) { // Verify the claimed boolean 
				ComMethods.handleBadResp();
			} else {
				// Extract message from active session payload
				byte[] message = processPayload(payload);

				switch (getSessionCommand(message)) {
					case "password":
						resp = handlePassword(message);
						break;
					case "view":
						resp = handleView();
						break;
					case "update":
						resp = handleUpdate(message);
						break;
					case "delete":
						resp = handleDelete();
						break;
					default:
						ComMethods.handleBadResp();
						break;
				}
				counter = counter + 2;
			}
		} else if (!userSet) {
			resp = handleAuthPt1(payload);
		} else if (!activeSession) {
			resp = handleAuthPt2(payload);
		} else {
			// Something's wrong
			ComMethods.handleBadResp();
		}
		return resp;
	}


	// Determines the type of command in the encrypted payload
	// This method is called during a session, after the authentication protocol
	private String getSessionCommand(byte[] message) {
		// Various accepted options
		byte[] pw = "password:".getBytes();
		byte[] view = "view".getBytes();
		byte[] update = "update:".getBytes();
		byte[] delete = "delete".getBytes();

		String resp;
		if (Arrays.equals(Arrays.copyOf(message, pw.length), pw) && !passVerified) {
			resp = "password";
		} else if (passVerified) {
			if (Arrays.equals(Arrays.copyOf(message, view.length), view)) {
				resp = "view";
			} else if (Arrays.equals(Arrays.copyOf(message, update.length), update)) {
				resp = "update";
			} else if (Arrays.equals(Arrays.copyOf(message, delete.length), delete)) {
				resp = "delete";
			} else {
				resp = "BAD INPUT ERROR";
			}
		} else {
			ComMethods.report("ERROR ~~ password already set.",simMode);
			resp = "BAD INPUT ERROR";
		}
//
		ComMethods.report("SecretServer has understood User's message of \""+resp+"\".", simMode);
//
		return resp; 
	}


	// Handles password verif., returns "accepted" or "rejected"
	private byte[] handlePassword(byte[] message) {
		byte[] password = Arrays.copyOfRange(message, "password:".getBytes().length, message.length);

		// Check hash of password against user's value in the digest text file
		passVerified = checkHash(password, ComMethods.getValueFor(currentUser, hashfn));

		// Respond to user
		if (passVerified) {
			currentPassword = password; // store pw for session
			return preparePayload("accepted".getBytes());
		} else {
			return preparePayload("rejected".getBytes());
		}
	}


	// Handles view requests, returns the deciphered secret
	private byte[] handleView() {
		String secret = ComMethods.getValueFor(currentUser, secretsfn);
		if (secret.equals("")) {
			return "error".getBytes();
		} else {
			byte[] secretInBytes = DatatypeConverter.parseBase64Binary(secret);

			ComMethods.report("SecretServer has retrieved "+currentUser+"'s secret and will now return it.", simMode);
			return preparePayload(secretInBytes);
		}
	}


	// Handles update requests, returns "secretupdated" when done
	private byte[] handleUpdate(byte[] message) {
		byte[] newSecretBytes = Arrays.copyOfRange(message, "update:".getBytes().length, message.length);

/*
		System.out.println("THIS IS A TEST:");
		System.out.println("newSecretBytes:");
		ComMethods.charByChar(newSecretBytes, true);
		System.out.println("newSecretBytes, reversed:");
		String toStr = DatatypeConverter.printBase64Binary(newSecretBytes);
		byte[] fromStr = DatatypeConverter.parseBase64Binary(toStr);
		ComMethods.charByChar(fromStr, true);
*/
		String newSecret = DatatypeConverter.printBase64Binary(newSecretBytes);
		boolean success = replaceSecretWith(currentUser, newSecret);
		
		if (success) {
			ComMethods.report("SecretServer has replaced "+currentUser+"'s secret with "+newSecret+".", simMode);
			return preparePayload("secretupdated".getBytes());
		} else {
			ComMethods.report("SecretServer has FAILED to replace "+currentUser+"'s secret with "+newSecret+".", simMode);
			return preparePayload("writingfailure".getBytes());
		}
	}


	// Handles delete requests, returns "secretdeleted" when done
	private byte[] handleDelete() {
		boolean success = replaceSecretWith(currentUser, "");

		if (success) {
			ComMethods.report("SecretServer has deleted "+currentUser+"'s secret.", simMode);
			return preparePayload("secretdeleted".getBytes());
		} else {
			ComMethods.report("SecretServer has FAILED to delete "+currentUser+"'s secret.", simMode);
			return preparePayload("writingfailure".getBytes());
		}
	}



	// Handles second transaction of Bilateral Auth. Protocol
	// Given encrypted first message, identifies User, verifies proper formatting
	// of message, generates a nonce, and sends the User a payload in response
	private byte[] handleAuthPt1(byte[] payload) {
		boolean userIdentified = false;
		byte[] supposedUser = null;

//
		System.out.println("payload received by SecretServer:");
		ComMethods.charByChar(payload,true);
//

		userNum = -1;
		while (userNum < validUsers.length-1 && !userIdentified) {
			userNum++;
			supposedUser = validUsers[userNum].getBytes();
			userIdentified = Arrays.equals(Arrays.copyOf(payload, supposedUser.length), supposedUser);

//
			System.out.println();
			System.out.println("\""+validUsers[userNum]+"\" in bytes:");
			ComMethods.charByChar(validUsers[userNum].getBytes(),true);
			System.out.println("\"Arrays.copyOf(payload, supposedUser.length\" in bytes:");
			ComMethods.charByChar(Arrays.copyOf(payload, supposedUser.length),true);
			System.out.println();
//
		}

		if (!userIdentified) {
			ComMethods.report("SecretServer doesn't recognize name of valid user.", simMode);
			return "error".getBytes();
		} else {
			// Process second half of message, and verify format
			byte[] secondHalf = Arrays.copyOfRange(payload, supposedUser.length, payload.length);
//
	System.out.println("secondHalf = "+secondHalf);
//
			secondHalf = ComMethods.decryptRSA(secondHalf, my_n, my_d);

//
	System.out.println("secondHalf = "+secondHalf);
//
			ComMethods.report("SecretServer has decrypted the second half of the User's message using SecretServer's private RSA key.", simMode);

			if (!Arrays.equals(Arrays.copyOf(secondHalf, supposedUser.length), supposedUser)) {
				// i.e. plaintext name doesn't match the encrypted bit
				ComMethods.report("ERROR ~ invalid first message in protocol.", simMode);				
				return "error".getBytes();
			} else {
				// confirmed: supposedUser is legit. user
				currentUser = new String(supposedUser); 
				userSet = true;
				byte[] nonce_user = Arrays.copyOfRange(secondHalf, supposedUser.length, secondHalf.length);

				// Second Message: B->A: E_kA(nonce_A || Bob || nonce_B)
				myNonce = ComMethods.genNonce();
				ComMethods.report("SecretServer has randomly generated a 128-bit nonce_srvr = "+myNonce+".", simMode);
			
				byte[] response = ComMethods.concatByteArrs(nonce_user, "SecretServer".getBytes(), myNonce);
				byte[] responsePayload = ComMethods.encryptRSA(response, usersPubKeys1[userNum], BigInteger.valueOf(usersPubKeys2[userNum]));
				return responsePayload;
			}
		}
	}



	// Handles fourth transaction of Bilateral Auth. Protocol
	// Verifies Server's nonce, stores value of sessionKey, and sends a 
	// response to the User
	private byte[] handleAuthPt2(byte[] payload) { 
		byte[] message = ComMethods.decryptRSA(payload, my_n, my_d);
		ComMethods.report("SecretServer has decrypted the User's message using SecretServer's private RSA key.", simMode);
		
		if (!Arrays.equals(Arrays.copyOf(message, myNonce.length), myNonce)) {
			ComMethods.report("ERROR ~ invalid third message in protocol.", simMode);
			return "error".getBytes();
		} else {
			// Authentication done!
			currentSessionKey = Arrays.copyOfRange(message, myNonce.length, message.length);
			activeSession = true;
			counter = 11;

			// use "preparePayload" from now on for all outgoing messages
			byte[] responsePayload = preparePayload("understood".getBytes());
			counter = 13;
			return responsePayload;
		} 
	}




	// Determines whether a password matches up to the hashed value (digest),
	// using knowledge of the hash function and # of times the hash was stretched
	private boolean checkHash(byte[] password, String hashValue) {
		int hashReps = 1000; // stretch the hash this many times
		String hashAlgorithm = "MD5";

		String endValue = new String();
		try {
			MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
			byte[] value = password;
			for (int i=0; i<hashReps; i++) { 
				value = md.digest(value);
			}
			endValue = DatatypeConverter.printBase64Binary(value);
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(0);
		}

		ComMethods.report("Digest calculated is "+endValue+".", simMode);
		ComMethods.report("Actual digest associated with username is "+hashValue+".", simMode);

		return (endValue.equals(hashValue));
	}



	// Writes to file, replacing user's existing secret with newSecret
	// Returns true if new file was created properly with appropriate contents
	private boolean replaceSecretWith(String user, String newSecret) {

//
System.out.println();	
System.out.println();	
System.out.println();		System.out.println("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
System.out.println("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
System.out.println("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
		System.out.println("WRITING TO FILE");
		System.out.println("encryptedSecret = "+newSecret);
		System.out.println("-------------------");
		System.out.println("encryptedSecret in bytes:");		
		ComMethods.charByChar(newSecret.getBytes(), true);
System.out.println("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
System.out.println("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
System.out.println("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
System.out.println();
System.out.println();
System.out.println();
//
		try {
			File oldFile = new File(secretsfn);

			if (!oldFile.isFile()) {
				System.out.println("ERROR ~~ "+secretsfn+" is not the name of an existing file.");
				return false;
			}

			// Build up new secrets file in a temp file, will rename later
			File newFile = File.createTempFile("secretstmp", "");
		
			BufferedReader br = new BufferedReader(new FileReader(oldFile));
			BufferedWriter bw = new BufferedWriter(new FileWriter(newFile));

//
			System.out.println("User is "+user+".");
//
			String l;
			while (null != (l = br.readLine())) {
				bw.write(String.format("%s%n", l));
//
				System.out.println("Wrote line "+l+" to newFile.");
//
				if (l.equals(user)) {
					l = br.readLine();
					bw.write(String.format("%s%n", newSecret));
//					
					System.out.println("Condition Triggered: l.equals(user).");
					System.out.println("Wrote "+newSecret+" to newFile.");
//
				}
			}
			br.close();
			bw.close();

			// Delete original file
			if (!oldFile.delete()) {
				System.out.println("Could not delete file.");
				return false;
			}
			
			// Rename temp file to name of original file
			if (!newFile.renameTo(oldFile)) {
				// Still a success, but change filename temporarily
				System.out.println("WARNING ~ Could not rename file.");
				System.out.println("WARNING ~ Secret file temporarily named: \""+newFile.getName()+"\".");
				secretsfn = newFile.getName(); 
			}
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return true;
	}



	// Takes "regular" payload and spits out enclosed message
	private byte[] processPayload(byte[] message) {
		return ComMethods.processPayload(currentUser.getBytes(), message, counter-1, currentSessionKey, simMode);
	}


	// Takes message and packages it in "regular" payload for active session
	private byte[] preparePayload(byte[] message) {
		return ComMethods.preparePayload("SecretServer".getBytes(), message, counter, currentSessionKey, simMode);
	}




	/** Sets the private and public keys of the SecretServer, which are found by
	  * parsing the relevant text files for public keys and private keys of 
	  * registered users of this secret server storage service. 
	  * Also sets up arrays of public keys for all registered users for efficient 
	  * use and access.
	  * NOTE: This is a simulation. In a real setting, the private keys would
	  * be native to individuals' accounts and not stored together in a file. */
	private final void configureKeys() {
		// SecretServer's public key
		String line = ComMethods.getValueFor("SecretServer", pubkeysfn);
		int x = line.indexOf(',');
		my_n = new BigInteger(line.substring(0,x));
		my_e = new Integer(line.substring(x+1,line.length()));

		// SecretServer's private key
		line = ComMethods.getValueFor("SecretServer", privkeysfn);
		x = line.indexOf(',');
		my_d = new BigInteger(line.substring(x+1,line.length()));

		// Public keys for all registered Users
		usersPubKeys1 = new BigInteger[validUsers.length];
		usersPubKeys2 = new int[validUsers.length];
		for (int i=0; i<validUsers.length; i++) {
			line = ComMethods.getValueFor(validUsers[i], pubkeysfn);
			x = line.indexOf(',');
			usersPubKeys1[i] = new BigInteger(line.substring(0,x));
			usersPubKeys2[i] = new Integer(line.substring(x+1,line.length()));
		}
	}
}