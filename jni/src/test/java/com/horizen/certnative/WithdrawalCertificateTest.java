package com.horizen.certnative;

import static org.junit.Assert.assertEquals;

import java.util.Random;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.librustsidechains.Utils;

import org.junit.Test;

public class WithdrawalCertificateTest {

    static String expectedWCertNoBtNoCFFieldHashHex  = "4C02EB7B6FAC2484C743A873E82090B31548FF7E2AC97982BE0B72C2785F252E";
    static String expectedWCertWithBtWithCFFieldHashHex  = "2CDC3C6DEC6D2F9936AF913956F80E6D5E2049D2C9C7B86D4A5388AC7C25501D";
    static String expectedWCertNoBtWithCFFieldHashHex  = "4696E1B178025FA7F826893BBC7B00AC3DBA3261677BC0696303D098D639512F";
    static String expectedWCertWithBtNoCFFieldHashHex  = "5CAA1419BB3A6F5F8DF8948E3F2880C7FF5413B8CF7121D775BB431331A94029";

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

        return Utils.bytesToHex(certHashBytes);
    }
}
