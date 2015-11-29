package experimentdh;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class New_Client 
{
	public static void main(String[] args) 
	{
		byte server[],client[];
		BigInteger serverP, serverG;
		int serverL;
		
		//final String encryptionKey = "letstrythisonet1";
		
		int set=0;
		String username = null;
		String password = null;
		String choice=null;
		System.out.println("client running\n");

		Scanner input = new Scanner(System.in);
		Socket smtpSocket = null;
		ObjectOutputStream os = null;
		ObjectInputStream is = null;

		try 
		{
			smtpSocket = new Socket("localhost", 9999);
			os = new ObjectOutputStream(smtpSocket.getOutputStream());
			is = new ObjectInputStream(smtpSocket.getInputStream());
		} 
		catch (UnknownHostException e) 
		{
			System.err.println("Don't know about host: hostname");
		} 
		catch (IOException e) 
		{
			System.err.println("Couldn't get I/O for the connection to: hostname");
		}


		if (smtpSocket != null && os != null && is != null) 
		{
			try {

				String responseLine2;

				serverG=(BigInteger) is.readObject();
				serverP=(BigInteger) is.readObject();
				serverL=(int) is.readObject();
				server=(byte[]) is.readObject();
				
				KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
				DHParameterSpec dhSpec = new DHParameterSpec(
									serverP, serverG, serverL);
				kpg.initialize(dhSpec);
				KeyPair kp = kpg.generateKeyPair();
				client = kp.getPublic().getEncoded();
				
				os.writeObject(client);

				KeyAgreement ka = KeyAgreement.getInstance("DH");
				ka.init(kp.getPrivate());

				KeyFactory kf = KeyFactory.getInstance("DH");
				X509EncodedKeySpec x509Spec =
								new X509EncodedKeySpec(server);
				PublicKey pk = kf.generatePublic(x509Spec);
				ka.doPhase(pk, true);

				byte secret[] = ka.generateSecret();
				
				String temp = AES.CipherToString(secret);
				temp = temp.substring(0, 16);
				
				final String encryptionKey =temp;
				
				while(set==0)
				{
					responseLine2 = (String) is.readObject();
					System.out.println("Server: " + responseLine2);
					choice = input.nextLine();
					os.writeObject(choice);
					os.flush();
					
					while(true)
					{
						responseLine2 = (String) is.readObject();
						System.out.println("Server: " + responseLine2);
						username = input.nextLine();
						byte[] cipher=AES.encrypt(username, encryptionKey);
						
						System.out.println("client side cipher username:"+ AES.CipherToString(cipher)+"\n");
						os.writeObject(cipher);
						os.flush();
		
						responseLine2 = (String) is.readObject();
						System.out.println("Server: " + responseLine2);
						username=input.nextLine();
						cipher=AES.encrypt(username, encryptionKey);
						System.out.println("client side cipher password:"+AES.CipherToString(cipher)+"\n");
						os.writeObject(cipher);
						os.flush();
						
						responseLine2 = (String) is.readObject();
						System.out.println("Server: " + responseLine2);
						System.out.println("");
						
						if(responseLine2.equals("sign up successful") )
						{
							break;
						}
						 if(responseLine2.equals("login successful") )
						{
							 set=1;
							 break;
						}
					}
				}
				os.close();
				is.close();
				smtpSocket.close();
			} 
			catch (UnknownHostException e) 
			{
				System.err.println("Trying to connect to unknown host: " + e);
			} 
			catch (IOException e) 
			{
				System.err.println("IOException:  " + e);
			} 
			catch (Exception e) 
			{
				System.err.println("Exception:  " + e);
			}
		}
	}
}

