package org.courville;

import jcifs.smb.SmbFile;
import jcifs.context.BaseContext;
import jcifs.smb.NtlmPasswordAuthenticator;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.smb.SmbException;
import jcifs.smb.SmbAuthException;

import java.net.MalformedURLException;

import jcifs.config.PropertyConfiguration;

import java.util.Properties;
import java.io.File;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

public class smbcli {

    final static Logger logger = Logger.getLogger(smbcli.class);

    private static final CIFSContext baseContextSmb1 = createContext(false);
    private static final CIFSContext baseContextSmb2 = createContext(true);

    static boolean isRootOrWorkgroup(String path) {
        boolean isRootOrWorkgroup = false;
        try {
            SmbFile smbFile = new SmbFile(path, getBaseContext(false));
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

    private static CIFSContext createContext(boolean isSmb2) {
        Properties prop = new Properties();
        prop.putAll(System.getProperties());

        prop.put("jcifs.smb.client.enableSMB2", String.valueOf(isSmb2));
        // must remain false to be able to talk to smbV1 only
        prop.put("jcifs.smb.client.disableSMB1", "false");
        prop.put("jcifs.traceResources", "true");
        prop.put("jcifs.resolveOrder", "BCAST,DNS");

        // get around https://github.com/AgNO3/jcifs-ng/issues/40
        prop.put("jcifs.smb.client.ipcSigningEnforced", "false");
        // allow plaintext password fallback
        prop.put("jcifs.smb.client.disablePlainTextPasswords", "false");
        // disable dfs makes win10 shares with ms account work
        prop.put("jcifs.smb.client.dfs.disabled", "true");
        // this is needed to allow connection to MacOS 10.12.5 and higher according to https://github.com/IdentityAutomation/vfs-jcifs-ng/blob/master/src/test/java/net/idauto/oss/jcifsng/vfs2/provider/SmbProviderTestCase.java
        // prop.put("jcifs.smb.client.signingEnforced", "true");
        // makes Guest work on Win10 https://github.com/AgNO3/jcifs-ng/issues/186 --> interferes with WD MyCloud and should not prevent win10 guest
        // prop.put("jcifs.smb.client.disableSpnegoIntegrity", "false");
        // test for Guest on MacOS
        //prop.put("jcifs.netbios.hostname", "imarc");

        PropertyConfiguration propertyConfiguration = null;
        try {
            propertyConfiguration = new PropertyConfiguration(prop);
        } catch (CIFSException e) {
            logger.warn("Caught a CIFSException on PropertyConfiguration", e);
        }
        return new BaseContext(propertyConfiguration);
    }

    public static CIFSContext getBaseContext(boolean isSmb2) {
        return isSmb2 ? baseContextSmb2 : baseContextSmb1;
    }

    public static void main(String[] args) throws Exception {

        String log4jConfigFile = System.getProperty("user.dir") + File.separator + "log4j.properties";
        PropertyConfigurator.configure(log4jConfigFile);

        boolean noAuth = false;
        SmbFile smbFile = null;
        if (args.length == 0 || (args.length > 2 && args.length < 5)) {
            System.out.println("Proper Usage is: 1|2 smb://server/share/ [domain user password]");
            System.exit(0);
        }
        if (args.length == 2) noAuth = true;
        boolean SMB2 = (args[0].equals("2"));
        if (SMB2) logger.info("Enabling SMB2");

        CIFSContext baseContext = getBaseContext(SMB2);
        NtlmPasswordAuthenticator auth = null;
        if (noAuth)
            auth = new NtlmPasswordAuthenticator("", "GUEST", "");
        else
            auth = new NtlmPasswordAuthenticator(args[2], args[3], args[4]);
        CIFSContext ctx = baseContext.withCredentials(auth);
        smbFile = new SmbFile(args[1], ctx);

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
