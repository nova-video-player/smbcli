package org.courville;

import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbFile;

import jcifs.smb.SmbException;
import jcifs.smb.SmbAuthException;

import java.net.MalformedURLException;

import java.io.File;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

public class smbcli {

    final static Logger logger = Logger.getLogger(smbcli.class);

    private static NtlmPasswordAuthentication auth = null;

    static boolean isRootOrWorkgroup(String path) {
        boolean isRootOrWorkgroup = false;
        try {
            SmbFile smbFile = new SmbFile(path, auth);
            int type = getType(smbFile);
            // Note: TYPE_WORKGROUP is also returned for the root
            if (type == SmbFile.TYPE_WORKGROUP) {
                isRootOrWorkgroup = true;
            }
        } catch (MalformedURLException e) {
            //Log.e(TAG, "MalformedURLException: ", e);
            e.printStackTrace();
        }
        return isRootOrWorkgroup;
    }

    static int getType(SmbFile smbFile) {
        // TODO: Workaround for issue where jcifs-ng throws SmbAuthException when getting type of password protected Share
        int type;
        try {
            type = smbFile.getType();
        } catch (SmbAuthException e) {
            type = SmbFile.TYPE_SHARE;
        } catch (SmbException e) {
            type = SmbFile.TYPE_FILESYSTEM;
        }
        return (type);
    }
    
    public static void main(String[] args) throws Exception {

        String log4jConfigFile = System.getProperty("user.dir") + File.separator + "log4j.properties";
        PropertyConfigurator.configure(log4jConfigFile);

        boolean noAuth = false;
        SmbFile smbFile = null;
        if (args.length == 0 || (args.length > 1 && args.length < 4)) {
            System.out.println("Proper Usage is: smb://server/share/ [domain user password]");
            System.exit(0);
        }
        if (args.length == 1) noAuth = true;

        auth = null;
        if (noAuth)
            auth = new NtlmPasswordAuthentication("", "GUEST", "");
        else
            auth = new NtlmPasswordAuthentication(args[1], args[2], args[3]);
        smbFile = new SmbFile(args[0], auth);

        int type;
        try {
            type = smbFile.getType();
        } catch (SmbAuthException authE) {
            logger.warn("Caught SmbAuthException");
            type = SmbFile.TYPE_SHARE;
        } catch (SmbException smbE) {
            type = SmbFile.TYPE_FILESYSTEM;
        }
        if (type == SmbFile.TYPE_SERVER)
            logger.info("smbFile is a server");
        else if (type == SmbFile.TYPE_FILESYSTEM)
            logger.info("smbFile is a filesystem");
        else if (type == SmbFile.TYPE_WORKGROUP)
            logger.info("smbFile is a root or workgroup");
        else if (type == SmbFile.TYPE_SHARE)
            logger.info("smbFile is a share");

        SmbFile[] smbFilesArray = null;
        try {
            String cur_name = smbFile.getName();
            logger.info("Current smbFile name = " + smbFile.getName());
            smbFilesArray = smbFile.listFiles();
        } catch (SmbAuthException authE) {
            logger.warn("Caught a SmbAuthException on listFiles", authE);
        } catch (SmbException smbE) {
            logger.warn("Caught a SmbException on listFiles", smbE);
        }

        if (smbFilesArray != null) {
            for (SmbFile file : smbFilesArray) {
                if (file.isFile() || file.isDirectory()) {
                    boolean exists = false;
                    String msg = " exists";
                    // TODO: check if file/dir/workgroup/other before
                    try {
                        exists = file.exists();
                    } catch (SmbAuthException authE) {
                        exists = true;
                        msg = " exists but cannot access with provided credentials";
                    } catch (SmbException smbE) {
                        exists = true;
                        msg = " exists but not accessible";
                    }
                    System.out.println(file.getPath() + (exists ? msg : " does not exist"));
                }
            }
        } else {
            logger.info("smbFilesArray is null");
        }
    }
}
