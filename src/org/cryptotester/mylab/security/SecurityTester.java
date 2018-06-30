package org.cryptotester.mylab.security;

import java.text.ParseException;
import java.io.*;

import javax.crypto.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;
import org.owasp.esapi.errors.IntrusionException;
import org.owasp.esapi.errors.ValidationException;


/*
 * Cryptography Test Object.  Test simulation methods for AES, 3DES, and SHA Hash algorithms.
 * Author: Rob Temple
 * Date: 06/26/2014
 * 
 *  * 
 */


public class SecurityTester 
{
	private static final Logger logger = Logger.getLogger(SecurityTester.class);


	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidKeySpecException, ParseException, InvalidAlgorithmParameterException  {
	
		//java.sql.Date sqlDate = java.sql.Date.valueOf("2015-09-10");
		//TestBean tb = new TestBean("lima", "Peru", "bake", sqlDate, 5);
		
		//System.out.println("printing bean: " + tb.toMap());

		SecAlgorithms.preloadESAPI();

		logger.info("Begin CipherScan ********************* ");
		SecAlgorithms.getProviderList();
		SecAlgorithms.demoSymmetric();
		SecAlgorithms.demoSymmetricAES();
		SecAlgorithms.demoSymmetric3DES();
		SecAlgorithms.SHAHash();

		SecAlgorithms.doESAPIEncryption();
		SecAlgorithms.doESAPIValidations();

		String encodedString = SecAlgorithms.stripXSS("badstring <script>alert();</script>");


		//VulnerableSimulator vulnerableSimulator = new VulnerableSimulator();
		//vulnerableSimulator.getVulnerabileSQLInjectionFlaw("alice@bank.com", "alice123");


	
	}
	
}


	

