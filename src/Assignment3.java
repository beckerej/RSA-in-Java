/** Use java.math.BigInteger 
 * and java.security.SecureRandom as required */
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Scanner;

/** * * * * * * * * * * * * * * * * * * * * **
 * 										     *
 *  RSA Algorithm described by Assignment 3  *
 *  @author Evan Becker - CS 469 - 11/28/17  *
 * 										     *
 ** * * * * * * * * * * * * * * * * * * * * ** 
 * RSA description from Wiki-> "A user of RSA creates and then publishes the product of two large 
 * prime numbers, along with an auxiliary value, as their public key. The prime factors must be kept 
 * secret. Anyone can use the public key to encrypt a message, but with currently published methods, 
 * if the public key is large enough, only someone with knowledge of the prime factors can feasibly 
 * decode the message.
 ** * * * * * * * * * * * * * * * * * * * * **/

public class Assignment3 {
	/** Define Keys and Random Number **/
	private BigInteger private_key;
	private BigInteger public_key;
	private BigInteger mod;
	private static SecureRandom rand;
	private static Scanner scan;
	
	/** 1536 Bit RSA */
	Assignment3(){
		int n = 1536; // using 1536-bit
		rand = new SecureRandom();
		// n = p * q
		BigInteger p = BigInteger.probablePrime(n/2, rand);
		BigInteger q = BigInteger.probablePrime(n/2, rand);
		// phi(n) = (p-1)*(q-1) = o(p) * o(q)
		BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
		// (p-1)*(q-1) = o(p) * o(q)
		mod = p.multiply(q);
		// define public key, 2^16+1=65537 is usually used.
		public_key = new BigInteger("65537"); // 2^16+1, (e,n)
		// calculate private key using (d,n), solving for e*d=1mod
		private_key = public_key.modInverse(phi);
	}
	
	/** 
	 * @param n-bit RSA for p and q
	 */
	Assignment3(int n){
		rand = new SecureRandom();
		// n = p * q
		
		/* 
		 * ATTEMPT AT MAKING P AND Q 2^10000 AWAY FROM EACHOTHER:
		
		BigInteger p,q;
		BigInteger TEN_THOUSAND = new BigInteger("2");
		TEN_THOUSAND.pow(1000);
		do{
			p = BigInteger.probablePrime(n/2, rand);
			q = BigInteger.probablePrime(n/2, rand);
		} while((p.subtract(q)).abs().compareTo(TEN_THOUSAND) == 1);
		
		*/
		
		BigInteger p = BigInteger.probablePrime(n/2, rand);
		BigInteger q = BigInteger.probablePrime(n/2, rand);
		
		// phi(n) = (p-1)*(q-1) = o(p) * o(q)
		BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
		// (p-1)*(q-1) = o(p) * o(q)
		mod = p.multiply(q);
		// define public key, 2^16+1=65537 is usually used.
		public_key = new BigInteger("65537"); // 2^16+1, (e,n)
		// calculate private key using (d,n), solving for e*d=1mod
		private_key = public_key.modInverse(phi);
	}
	
	/** Encryption Algorithm, Passes BigInteger M */
	BigInteger encrypt(BigInteger M){ return M.modPow(public_key, mod); }
	BigInteger decrypt(BigInteger E){ return E.modPow(private_key, mod); }
	public String toString() { return "Public Key: " + public_key + "\nPrivate Key: " + private_key + "\nModulus: " + mod; }
	
	/**
	 * Main method to instantiate logic and pass variables to correct methods.
	 * Simply uses a number for the Message, however a String/Character could 
	 * work if integer parsing is enabled
	 * @param args
	 */
	public static void main(String[] args){
		scan = new Scanner(System.in);
		System.out.print("Enter Bit Length (Use 1536-bit or greater for assignment!): ");
		int n = scan.nextInt();
		
		// CREATE KEY
		Assignment3 key = new Assignment3(n);
		System.out.println("\n== KEY CREATION == \n" + key);
		
		// Create random message number, E & D, simulating a message from a document, string, character, etc.
		BigInteger M = new BigInteger(n-1, rand);
		
		// Encryption and Decryption
		BigInteger E = key.encrypt(M);
		BigInteger D = key.decrypt(E);
		
		// Print Message, E, & D
		System.out.println("== ENTERING MAIN ==");
		System.out.println("Original Message:" + M);
		System.out.println("Encrypted Message: " + E);
		System.out.println("Decrypted Message: " + D);
		
		// END PROGRAM - EXIT 0
		System.out.println("== CLOSING SCANNER ==\n== EXITING MAIN ==");
		scan.close();
	}
}
