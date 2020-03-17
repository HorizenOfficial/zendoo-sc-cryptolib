package com.horizen.vrf;

import org.junit.Test;

public class VRFLibraryTest {

    @Test
    public void testLoad() {
        System.out.println(VRFLibrary.getOperatingSystem());
        System.out.println(VRFLibrary.getModel());
        System.out.println(System.getProperty("java.io.tmpdir"));
    }
}
