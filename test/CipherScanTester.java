package org.cryptotester.mylab.security;


import static org.junit.Assert.*;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;



/**
 * Created by req80117 on 04/28/2017.
 */
public class CipherScanTester {


    @Before
    public void setUp() throws Exception {

    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void testGetFirstProviderName() {

        assertEquals("SUN", SecAlgorithms.getFirstProviderName());

    }

    @Test
    public void testGetSymmetricAESName()  {

        assertEquals("AES", SecAlgorithms.getSymmetricAESName());

    }

    @Test
    public void testGetESAPIEncoder()  {

        assertEquals("Hello World", SecAlgorithms.getESAPIEncoder());

    }



}
