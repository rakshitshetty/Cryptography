package experimentdh;

//www.wikipedia.org
//http://www.javaworld.com/article/2077322/core-java/core-java-sockets-programming-in-java-a-tutorial.html?null
//http://www.anyexample.com/programming/java/java_simple_class_to_compute_sha_1_hash.xml
//http://karanbalkar.com/2014/02/tutorial-76-implement-aes-256-encryptiondecryption-using-java/
//http://www.cs.ait.ac.th/~on/O/oreilly/java-ent/security/ch13_07.htm

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.concurrent.TimeUnit;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class New_Server 
{
	public static void main(String args[]) throws Exception 
	{
		
		byte server[],client[];
		BigInteger serverP, serverG;
		int serverL;
		
		//final String encryptionKey = "letstrythisonet1";
		
		String encoded=SimpleSHA1.SHA1("123");

		System.out.println("server running\n");
		int count =0;
		int set=0;
		
		HashMap<String,String> storage=new HashMap<String,String>();
		storage.put("rakshith", encoded);
		storage.put("naveen", encoded);
		storage.put("sid", encoded);
		storage.put("bhargav", encoded);
		storage.put("shwetha", encoded);
				
		ServerSocket echoServer = null;
		String user_name = null,pwd = null,choice;
		ObjectInputStream is;
		ObjectOutputStream os;
		Socket clientSocket = null;

		try 
		{
			echoServer = new ServerSocket(9999);
		}
		catch (IOException e) 
		{
			System.out.println(e);
		}

		try 
		{
			clientSocket = echoServer.accept();
			is = new ObjectInputStream(clientSocket.getInputStream());
			os = new ObjectOutputStream(clientSocket.getOutputStream());
			
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
			kpg.initialize(1024);
			KeyPair kp = kpg.generateKeyPair();
		
			Class dhClass = Class.forName("javax.crypto.spec.DHParameterSpec");
			DHParameterSpec dhSpec = ((DHPublicKey) kp.getPublic()).getParams();
			serverG = dhSpec.getG();
			serverP = dhSpec.getP();
			serverL = dhSpec.getL();
			server = kp.getPublic().getEncoded();
			
			os.writeObject(serverG);
			os.writeObject(serverP);
			os.writeObject(serverL);
			os.writeObject(server);
			
			client=(byte[]) is.readObject();
			
			KeyAgreement ka = KeyAgreement.getInstance("DH");
			ka.init(kp.getPrivate());

			KeyFactory kf = KeyFactory.getInstance("DH");
			X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(client);
			PublicKey pk = kf.generatePublic(x509Spec);
			ka.doPhase(pk, true);
			
			byte secret[] = ka.generateSecret();
			String temp = AES.CipherToString(secret);
			temp = temp.substring(0, 16);

			final String encryptionKey =temp;

			while(set==0)
			{
				os.writeObject("\n \t Enter 1 for signup\n \t Enter 2 for login\n");
				choice=(String) is.readObject();
				System.out.println("choice :"+choice+"\n");
			
				if(choice.equals("1"))
				{
					System.out.println("entered signup\n");
					while(true)
					{
						os.writeObject("enter username");
						byte[] cipher = (byte[])is.readObject();
						System.out.println("server side cipher username:"+AES.CipherToString(cipher)+"\n");
						user_name=AES.decrypt(cipher, encryptionKey);
						System.out.println("client username :"+user_name);

						os.writeObject("enter password");
						cipher = (byte[])is.readObject();
						System.out.println("server side cipher password:"+AES.CipherToString(cipher)+"\n");
						pwd=AES.decrypt(cipher, encryptionKey);
						System.out.println("client password :"+pwd);

						if(storage.containsKey(user_name))
						{
							os.writeObject("username already exists please enter again\n");
						}
						else
						{
							String pwd1=SimpleSHA1.SHA1(pwd);
							storage.put(user_name, pwd1);
							System.out.println("password stored as:"+pwd1);
							os.writeObject("sign up successful");
							break;
						}
					}
				}	
				else if(choice.equals("2"))
				{
					System.out.println("entered login");
					while(true)
					{
						os.writeObject("enter username");
						byte[] cipher =(byte[]) is.readObject();
						System.out.println("server side cipher username:"+AES.CipherToString(cipher)+"\n");
						user_name=AES.decrypt(cipher, encryptionKey);
						System.out.println("client username :"+user_name);
		
						os.writeObject("enter password");
						cipher = (byte[])is.readObject();
						System.out.println("server side cipher password:"+AES.CipherToString(cipher)+"\n");
						pwd=AES.decrypt(cipher, encryptionKey);
						System.out.println("client password :"+pwd);
						
						String pwd1=SimpleSHA1.SHA1(pwd);
						
						if(storage.containsKey(user_name))
						{
							if(storage.get(user_name).equals(pwd1))
							{
								os.writeObject("login successful");
								set=1;
								break;
							}
							else
							{
								count++;
								if(count<4)
								{
									os.writeObject("password incorrect please try again");
								}
								else
								{
									os.writeObject("consecutive logins failed 3 minute lockdown initialised");
									TimeUnit.MINUTES.sleep(3);
								}	
							}
						}
						else
						{
							count++;
							if(count<4)
							{
								os.writeObject("username incorrect please try again");
							}
							else
							{
								os.writeObject("consecutive logins failed 3 min lockdown initialised");
								TimeUnit.MINUTES.sleep(3);
							}
						}
					}
				}
				else
				{
					System.out.println("wrong choice");
				}
			}
		} 
		catch (IOException e) 
		{
			System.out.println(e);
		}
	}
}

