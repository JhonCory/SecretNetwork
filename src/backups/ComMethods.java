import java.io.BufferedReader;
import java.io.FileReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

// Methods common to more than one class 
public class ComMethods {
	// Parses .txt file, finds user's name, and returns line below it
	// (i.e. the value corresponding to that user in the file)
	public static String getValueFor(String user, String fname) {
		String line = new String();
		try (BufferedReader br = new BufferedReader(new FileReader(fname))) {
			line = br.readLine();
    			while (!line.startsWith(user)) {
       				line = br.readLine();
    			} 
			line = br.readLine();

			br.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return line;
	}


	// Reads validusers.txt and outputs array of names of valid users
	public static String[] getValidUsers() {
		String[] resultArr = new String[0];
		try {
			BufferedReader in = new BufferedReader(new FileReader("validusers.txt"));
			String str;
		
			List<String> list = new ArrayList<String>();
			while ((str = in.readLine()) != null) {
				list.add(str);
        		}

        		resultArr = list.toArray(new String[0]);
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(0);
		}
		return resultArr;
	} 


	// In simulationMode, used to state what's currently happening in the process
	public static void report(String str, boolean simulationMode) {
		if (simulationMode) {
			System.out.println(str);
		}
	}


	// If something goes wrong and security may have been breached, end program
	// NOTE: in real-world scenario, would just end comms or reask for password
	public static void handleBadResp() {
		System.out.println("ERROR ~ unexpected message sent. Exiting program for security reasons.");
		System.exit(0);
	}


	// Randomly generates a 128-bit array of bytes
	public static byte[] genNonce() {
		String randoms = UUID.randomUUID().toString();
		byte[] randomBytes = randoms.getBytes();
		byte[] keyInBytes = getFirst16(randomBytes);
		return keyInBytes;
	}


	// Given array of bytes, returns array of first 16 bytes
	private static byte[] getFirst16(byte[] oldArr) {
		byte[] newArr = new byte[16];
		for (int i=0; i<16; i++) {
			newArr[i] = oldArr[i];
		}
		return newArr;
	}


	// Concatenates two arrays of bytes
	public static byte[] concatByteArrs(byte[] a, byte[] b) {
   		int aLen = a.length;
   		int bLen = b.length;
   		byte[] c= new byte[aLen+bLen];
   		System.arraycopy(a, 0, c, 0, aLen);
   		System.arraycopy(b, 0, c, aLen, bLen);
   		return c;
	}

	// Concatenates three arrays of bytes
	public static byte[] concatByteArrs(byte[] a, byte[] b, byte[] c) {
		return concatByteArrs(concatByteArrs(a,b),c);
	}

	// Given array of bytes, prints out each byte, line by line
	// (For debugging only)
	public static void charByChar(byte[] arr, boolean hex) {
		System.out.println("Total # of bytes: "+arr.length);
		for (int i=0; i<arr.length; i++) {
			Byte thisByte = arr[i];
			if (!hex) {
				System.out.print(thisByte.toString());
			} else {
				System.out.print(String.format("%02X ", thisByte));	
			}
			System.out.print(", ");
			if ((i+1) % 16 == 0) {
				System.out.println();
			}
		}
		System.out.println();
	}
}

