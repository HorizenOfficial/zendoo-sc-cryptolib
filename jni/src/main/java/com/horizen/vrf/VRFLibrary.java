package com.horizen.vrf;

public class VRFLibrary {

    private static boolean loaded = false;

    static {
        if (!loaded) {
            load();
            loaded = true;
        }
    }

    public static String getOperatingSystem() {
        String name = System.getProperty("os.name").toLowerCase().trim();
        if( name.startsWith("linux") ) {
            return "linux";
        }
        if( name.startsWith("mac os x") ) {
            return "osx";
        }
        if( name.startsWith("win") ) {
            return "windows";
        }
        return name;
    }

    public static int getModel() {
        String model = System.getProperty("sun.arch.data.model");
        if (model == null) {
            model = System.getProperty("com.ibm.vm.bitmode");
        }
        if (model!=null) {
            return Integer.parseInt(model);
        }
        return -1;
    }

    public static synchronized void load() {
        System.out.println("Try to load...");
    }

}
