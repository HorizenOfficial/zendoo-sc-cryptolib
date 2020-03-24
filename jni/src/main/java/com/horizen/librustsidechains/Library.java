package com.horizen.librustsidechains;

import java.io.*;
import java.net.URL;

public class Library {

    private static boolean loaded = false;

    private static String commonLibName = "librustsidechains";

    private static String windowsOsName = "windows";
    private static String linuxOsName = "linux";
    private static String osxOsName = "osx";

    private static String windowsLibName = commonLibName + ".dll";
    private static String linuxLibName = commonLibName + ".so";
    private static String osxLibName = commonLibName + ".jnilib";

    static {
        load();
    }

    public static String getOperatingSystem() {
        String name = System.getProperty("os.name").toLowerCase().trim();
        if( name.startsWith("linux") ) {
            return linuxOsName;
        }
        if( name.startsWith("mac os x") ) {
            return osxOsName;
        }
        if( name.startsWith("win") ) {
            return windowsOsName;
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

    public static String getLibName() {
        String osName = getOperatingSystem();
        if (osName.equalsIgnoreCase(windowsOsName)) {
            return windowsLibName;
        }
        if (osName.equalsIgnoreCase(linuxOsName)) {
            return linuxLibName;
        }
        if (osName.equalsIgnoreCase(osxOsName)) {
            return osxLibName;
        }
        return "";
    }

    public static URL getResource() {
        String resourcePath = "native/" + getOperatingSystem() + getModel() + "/" + getLibName();
        return Library.class.getClassLoader().getResource(resourcePath);
    }

    static void close(Closeable f) {
        if (f != null) {
            try {
                f.close();
            } catch (Throwable e) {
            }
        }
    }

    public static void extractLoad() {

        File targetFile = null;
        String libName = getLibName();

        int i = libName.lastIndexOf('.');
        String prefix = libName.substring(0, i)+"-";
        String suffix = libName.substring(i);

        try {
            FileOutputStream os = null;
            InputStream is = null;
            try {
                targetFile = File.createTempFile(prefix, suffix);
                is = getResource().openStream();
                if (is != null) {
                    byte[] buffer = new byte[4096];
                    os = new FileOutputStream(targetFile);
                    int read;
                    while ((read = is.read(buffer)) != -1) {
                        os.write(buffer, 0, read);
                    }
                }
                targetFile.deleteOnExit();
            } finally {
                close(os);
                close(is);
            }
            System.load(targetFile.getAbsolutePath());
        } catch (Throwable e) {
            IOException io;
            if (targetFile != null) {
                targetFile.delete();
                io = new IOException("Unable to extract library to " + targetFile);
            } else {
                io = new IOException("Unable to create temporary file.");
            }
            io.initCause(e);
            throw new RuntimeException(io);
        }
    }

    public static synchronized void load() {
        if (!loaded) {
            extractLoad();
            loaded = true;
        }
    }

}
