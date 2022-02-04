package com.horizen.certnative;

import static org.junit.Assert.assertEquals;

import java.util.Random;

import com.horizen.TestUtils;
import com.horizen.librustsidechains.FieldElement;

import org.junit.Test;

public class WithdrawalCertificateTest {

    static String expectedWCertNoBtNoCFFieldHashHex  = "4c02eb7b6fac2484c743a873e82090b31548ff7e2ac97982be0b72c2785f252e";
    static String expectedWCertWithBtWithCFFieldHashHex  = "2cdc3c6dec6d2f9936af913956f80e6d5e2049d2c9c7b86d4a5388ac7c25501d";
    static String expectedWCertNoBtWithCFFieldHashHex  = "4696e1b178025fa7f826893bbc7b00ac3dba3261677bc0696303d098d639512f";
    static String expectedWCertWithBtNoCFFieldHashHex  = "5caa1419bb3a6f5f8df8948e3f2880c7ff5413b8cf7121d775bb431331a94029";

    static long seed = 1234567890L;
    static int backwardTransferCout = 10;
    static int customFieldsCout = 10;

    @Test
    public void testWCertFieldHash() throws Exception {
        assertEquals(expectedWCertNoBtNoCFFieldHashHex, generateWCertAndGetFieldHashHex(0, 0));
        assertEquals(expectedWCertWithBtWithCFFieldHashHex, generateWCertAndGetFieldHashHex(backwardTransferCout, customFieldsCout));
        assertEquals(expectedWCertNoBtWithCFFieldHashHex, generateWCertAndGetFieldHashHex(0, customFieldsCout));
        assertEquals(expectedWCertWithBtNoCFFieldHashHex, generateWCertAndGetFieldHashHex(backwardTransferCout, 0));
    }

    private String generateWCertAndGetFieldHashHex(int numBt, int numCustomFields) throws Exception {
        
        // Generate random cert
        Random r = new Random(seed);
        WithdrawalCertificate cert = WithdrawalCertificate.getRandom(r, numBt, numCustomFields);

        // Get FieldHash
        FieldElement certHash = cert.getHash();
        byte[] certHashBytes = certHash.serializeFieldElement();

        // Free memory Rust side
        cert.close();
        certHash.close();

        return TestUtils.toHexString(certHashBytes);
    }
}
