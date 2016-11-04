import java.io.BufferedReader;
import java.io.FileReader;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

// Interface for the simulation; uses CLI
public class Interface {
	/** SecretServer is a simulation of the server that would handle access to 
	  * stored secrets; User represents the system of user accessing server */
	private static SecretServer server;
	private static User user;
	private static String accountName; // name of the User account we're using
	private static String username; // User we're CLAIMING to be to the server
	private static boolean simMode; // reports what's happening in process
	private static boolean securelyConnected; // user/server sec. connected atm?
	private static boolean passwordVerified; // password verified atm?
	private static double fishyActivityCounter; // level of suspicious activity
	private static int secureCounter; // # of exchanges made in current session

	/** Takes in two arguments
	  * First argument is name of account you're using
	  * Second argument, "true"/"false", for toggling simulationMode */
	public static void main(String[] args) {
		String[] validUsers = ComMethods.getValidUsers();

		if (args.length < 2) {
			System.out.println("ERROR ~ arguments missing.");
			System.out.println("Please specify as arguments the name of the user from whose account you have access to in the simulations and 'true' or 'false', depending on whether you would like detailed reports on the inner workings of the simulation.");
		} else if (args.length > 2) {
			System.out.println("ERROR ~ too many arguments.");
		} else if (!Arrays.asList(validUsers).contains(args[0])) {
			System.out.println("ERROR ~ first argument is not a valid user of the system. Check validusers.txt for list of valid users.");
		} else if (!args[1].equals("true") && !args[1].equals("false")) {
			System.out.println("ERROR ~ second argument is neither 'true' nor 'false'");
		} else {
			// Instantiate variables
			accountName = args[0];
			simMode = Boolean.valueOf(args[1]);
			server = new SecretServer(simMode); 
			user = new User(accountName, server, simMode);
			securelyConnected = false;
			fishyActivityCounter = 0.0;


			Scanner scanner = new Scanner(System.in);

			System.out.print("Hello! ");
			// Establish secure session
			while (!securelyConnected) {
				checkFishiness();
				establishContact(scanner);
			}
			

			// Mediate access between user and server

			passwordVerified = false;

			/** End session after an amount of exchanges, so as to protect 
			  * the security of the communications afterwards */
			secureCounter = 0; 
			while (secureCounter < 6) {
				// Ask for and verify password
				if (!passwordVerified) {
					checkFishiness();
					askPassword(scanner);
					secureCounter++;
					System.out.println();
				} else {
					// Allow access to secrets
					while (secureCounter < 6) {
						checkFishiness();
						offerSecretOptions(scanner);
						secureCounter++;
						System.out.println();
					}
				}	
			}

			// Inform the user as to why the session is being terminated
			System.out.println("You have made a lot of exchanges in this session.");
			System.out.println("For security reasons, the session will now be terminated.");
			endProgram();
		}
	}


	/** Attempts to establish a secure line of contact between the server and the
	  * user with a user-specified "username"
	  * NOTE: using the username of a different user will result in an inability 
	  * to establish a secure connection with the server, due to your user system 
	  * not having access to the appropriate public key */
	private static void establishContact(Scanner scanner) {
		String uname = getInput("Please enter the username you want to send to the server (but good luck trying to do so from someone else's account): ", scanner);

		ComMethods.report("Attempting to set up connection between "+accountName+" and SecretServer using username "+uname+"...", simMode);

		boolean successful = user.connectAs(uname);
		if (!successful) {
			System.out.println("Connection failed. Please try a different username.");
			System.out.println();
			fishyActivityCounter++;
		} else {
			username = uname;
			System.out.println("Secure connection to SecretServer successful!");
			System.out.println("Welcome, "+username+".");
			System.out.println();
			securelyConnected = true; // toggle the bool to end the loop
		}
	}


	/** Attempts to have the server grant the user access to the specified 
	  * username's secret using a user-specified password */
	private static void askPassword(Scanner scanner) {
		String password = getInput("Please enter the password: ", scanner); 
		ComMethods.report("Attempting to log in to gain access to desired secret using "+password+" as password...", simMode);

		boolean successful = user.logIn(password);
		if (!successful) {
			System.out.println("Password rejected. Please try a different password, "+accountName+".");
			fishyActivityCounter++;
		} else {
			System.out.println("Password accepted!");
			System.out.println("You are now logged in as "+username+".");
			passwordVerified = true;
		}
	}


	// Provides the logged in user with access to the secret
	private static void offerSecretOptions(Scanner scanner) {
		System.out.println("+++++++++++++++++++++++++++++++++++++++++++++");
		System.out.println("You may now view your secret ('view'), replace your existing secret with a new one ('update'), or delete your secret ('delete'). You may also quit at any time ('quit').");
		System.out.println();

		boolean acceptedInput = false;
		while (!acceptedInput) {
			checkFishiness();
			acceptedInput = true; 
			String input = getInput("What would you like to do now? ", scanner);

			switch (input) {
				case "view":
					ComMethods.report("Sending request...", simMode);
					String secret = user.requestView();
					System.out.println("=================================");
					if (secret == "error") {
						System.out.println("We are sorry. There was an error retrieving your secret.");
					} else {
						System.out.print("SECRET: ");
						System.out.println(secret);
					}
					System.out.println("=================================");
					break;
				case "update":
					String newSecret = getInput("Enter the new secret (type \"cancel\" to cancel): ", scanner);
					if (newSecret.equals("cancel")) {
						System.out.println("Action cancelled.");
					} else {
						System.out.println("Sending new secret...");
						boolean success = user.updateSecret(newSecret);
						if (success) {
							System.out.println("Your secret has been changed.");
						} else {
							System.out.println("We are sorry. Something went wrong in the exchange.");
							System.out.println("Your secret has not been changed.");
						}
					}
					break;
				case "delete":
					System.out.println("Deleting secret...");
					boolean success = user.deleteSecret();
					
					if (success) {
						System.out.println("Secret deleted.");
					} else {
						System.out.println("We are sorry. Something went wrong in the exchange.");
						System.out.println("Your secret has not been deleted.");
					}
					break;
				default:
					acceptedInput = false;
					fishyActivityCounter += 0.5;
					System.out.println("ERROR ~ invalid input.");
					break;
			}
			System.out.println();
		}
	}



	/** Gives the user a prompt, receives the input, starts a new line, and 
	  * returns the input as a String (exception: input == 'quit') */
	private static String getInput(String prompt, Scanner scanner) {
		String input = new String();

		System.out.print(prompt);
    		while (true) {
        		if (scanner.hasNext()) {
				input = scanner.nextLine();
            			break;
        		}
    		}
		
		if (input.equals("quit") || input.equals("q")) {
			endProgram();
		}
		System.out.println();
		return input;
	}

	// Method for terminating the program
	private static void endProgram() {
		System.out.println();
		System.out.println("Have a good day!");
		System.out.println();
		System.exit(0);
	}

	/** If User has made 4+ fishy moves, "lock them out of the system".
	  * Bad commands once logged in count for less than using an invalid password 
	  * or username (originally 0.5)
	  * NOTE: This is a simulation, so the user obviously won't actually be 
	  * locked out of any such system. That would be annoying. */
	private static void checkFishiness() {
		if (fishyActivityCounter >= 4.0) {
			System.out.println();
			System.out.println("We are sorry. Your system is temporarily banned from accessing the server, due to suspicious activity.");
			endProgram();
		}
	}

}