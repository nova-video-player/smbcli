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

import java.util.HashMap;
import java.util.Properties;
import java.io.File;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

public class smbcli {

    private static String user = "GUEST";
    private static String password = "";
    private static String domain = "";
    private static String url = "";

    final static Logger logger = Logger.getLogger(smbcli.class);

    static boolean isSMBv2Enabled = false;
    // when enabling LIMIT_PROTOCOL_NEGO smbFile will use strict SMBv1 or SMBv2 contexts to avoid SMBv1 negotiations or SMBv2 negotiations
    // this is a hack to get around some issues seen with jcifs-ng
    public final static boolean LIMIT_PROTOCOL_NEGO = true;

    private static Properties prop = null;
    private static CIFSContext baseContextSmb1 = createContext(false);
    private static CIFSContext baseContextSmb2 = createContext(true);

    private static CIFSContext baseContextSmb1Only = createContextOnly(false);
    private static CIFSContext baseContextSmb2Only = createContextOnly(true);

    private static CIFSContext createContext(boolean isSmb2) {
        prop = new Properties();
        prop.putAll(System.getProperties());

        prop.put("jcifs.smb.client.disableSMB1", "false");
        prop.put("jcifs.smb.client.enableSMB2", String.valueOf(isSmb2));
        // must remain false to be able to talk to smbV1 only
        prop.put("jcifs.smb.client.useSMB2Negotiation", "false");
        // resolve in this order to avoid netbios name being also a foreign DNS entry resulting in bad resolution
        // do not change resolveOrder for now
        prop.put("jcifs.resolveOrder", "BCAST,DNS");
        // get around https://github.com/AgNO3/jcifs-ng/issues/40
        prop.put("jcifs.smb.client.ipcSigningEnforced", "false");
        // allow plaintext password fallback
        prop.put("jcifs.smb.client.disablePlainTextPasswords", "false");
        // disable dfs makes win10 shares with ms account work
        prop.put("jcifs.smb.client.dfs.disabled", "true");
        // make Guest work on Win10 https://github.com/AgNO3/jcifs-ng/issues/186
        prop.put("jcifs.smb.client.disableSpnegoIntegrity", "false");

        PropertyConfiguration propertyConfiguration = null;
        try {
            propertyConfiguration = new PropertyConfiguration(prop);
        } catch (CIFSException e) {
            logger.warn("CIFSException caught PropertyConfiguration");
        }
        return new BaseContext(propertyConfiguration);
    }

    private static CIFSContext createContextOnly(boolean isSmb2) {
        prop = new Properties();
        prop.putAll(System.getProperties());

        if (isSmb2) {
            prop.put("jcifs.smb.client.disableSMB1", "true");
            prop.put("jcifs.smb.client.enableSMB2", "true");
            // smbV1 is NOT supported if enabled
            prop.put("jcifs.smb.client.useSMB2Negotiation", "true");
        } else {
            prop.put("jcifs.smb.client.disableSMB1", "false");
            prop.put("jcifs.smb.client.enableSMB2", "false");
            prop.put("jcifs.smb.client.useSMB2Negotiation", "false");
        }

        // resolve in this order to avoid netbios name being also a foreign DNS entry resulting in bad resolution
        // do not change resolveOrder for now
        prop.put("jcifs.resolveOrder", "BCAST,DNS");

        // get around https://github.com/AgNO3/jcifs-ng/issues/40
        prop.put("jcifs.smb.client.ipcSigningEnforced", "false");
        // allow plaintext password fallback
        prop.put("jcifs.smb.client.disablePlainTextPasswords", "false");
        // disable dfs makes win10 shares with ms account work
        prop.put("jcifs.smb.client.dfs.disabled", "true");
        // make Guest work on Win10 https://github.com/AgNO3/jcifs-ng/issues/186
        prop.put("jcifs.smb.client.disableSpnegoIntegrity", "false");

        PropertyConfiguration propertyConfiguration = null;
        try {
            propertyConfiguration = new PropertyConfiguration(prop);
        } catch (CIFSException e) {
            logger.warn("CIFSException caught PropertyConfiguration");
        }
        return new BaseContext(propertyConfiguration);
    }

    public static CIFSContext getBaseContext(boolean isSmb2) {
        logger.warn("getBaseContext: for isSmb2=" + isSmb2);
        return isSmb2 ? baseContextSmb2 : baseContextSmb1;
    }

    public static CIFSContext getBaseContextOnly(boolean isSmb2) {
        logger.warn("getBaseContextOnly: for isSmb2=" + isSmb2);
        return isSmb2 ? baseContextSmb2Only : baseContextSmb1Only;
    }

    private static HashMap<String, Boolean> ListServers = new HashMap<>();

    public static void declareServerSmbV2(String server, boolean isSmbV2) {
        logger.info("declareServerSmbV2 for " + server + " " + isSmbV2);
        ListServers.put(server, isSmbV2);
    }

    // isServerSmbV2 returns true/false/null, null is do not know
    public static Boolean isServerSmbV2(String server) throws MalformedURLException {
        Boolean isSmbV2 = ListServers.get(server);
        logger.info("isServerSmbV2 for " + server + " " + isSmbV2);
        if (isSmbV2 == null) { // let's probe server root
            String uri = "smb://" + server + "/";
            NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("", user, password);
            CIFSContext context = null;
            SmbFile smbFile = null;
            try {
                // TODO MARC: does not work to identify server as smbv2... with getType works with all contexts
                // issue: smbv1 only server identified as smbv2
                // identification should be disabled when only smbv1
                logger.info("isServerSmbV2: probing " + uri + " to check if smbV2");
                context = getBaseContextOnly(true);
                smbFile = new SmbFile(uri, context.withCredentials(auth));
                smbFile.list();
                declareServerSmbV2(server, true);
                return true;
            } catch (SmbAuthException authE) {
                logger.info("isServerSmbV2: caught SmbAutException in probing");
                return null;
            } catch (SmbException smbE) {
                logger.info("isServerSmbV2: caught SmbException " + smbE);
                try {
                    logger.info("isServerSmbV2: it is not smbV2 probing " + uri + " to check if smbV1");
                    context = getBaseContextOnly(false);
                    smbFile = new SmbFile(url, context.withCredentials(auth));
                    smbFile.list(); // should be SmbFile.TYPE_SERVER
                    declareServerSmbV2(server, false);
                    return false;
                } catch (SmbException ce2) {
                    logger.info("isServerSmbV2: caught SmbAutException in probing");
                    return null;
                }
            }
        } else
            return isSmbV2;
    }

    public static SmbFile getSmbFile(String uri) throws MalformedURLException {
        if (isSMBv2Enabled && LIMIT_PROTOCOL_NEGO) {
            logger.info("getSmbFile: using context with strict nego");
            return getSmbFileStrictNego(uri);
        } else {
            logger.info("getSmbFile: using context without strict nego");
            return getSmbFileAllProtocols(uri, isSMBv2Enabled);
        }
    }

    public static SmbFile getSmbFileStrictNego(String uri) throws MalformedURLException {
        NtlmPasswordAuthenticator auth = new NtlmPasswordAuthenticator("", user, password);
        String hostName = uri;
        // remove leading smb://
        if (hostName.startsWith("smb://")) hostName = hostName.substring("smb://".length());
        // extract server name
        hostName = hostName.substring(0, hostName.indexOf("/"));
        logger.info("getSmbFileStrictNego: do we know this server " + hostName + "?");
        Boolean isSmbV2 = isServerSmbV2(hostName);

        CIFSContext context = null;
        if (isSmbV2 == null) { // server type not identified, default to smbV2
            context = getBaseContext(true);
            logger.info("getSmbFile: server NOT identified passing smbv2/smbv1 capable context for uri " + uri);
        } else if (isSmbV2) { // provide smbV2 only
            context = getBaseContextOnly(true);
            logger.info("getSmbFile: server already identified as smbv2 processing uri " + uri);
        } else { // if dont't know (null) or smbV2 provide smbV2 only to try out. Fallback needs to be implemented in each calls
            context = getBaseContextOnly(false);
            logger.info("getSmbFile: server already identified as smbv1 processing uri " + uri);
        }
        return new SmbFile(uri.toString(), context.withCredentials(auth));
    }

    public static SmbFile getSmbFileAllProtocols(String uri, Boolean isSMBv2) throws MalformedURLException {
        NtlmPasswordAuthenticator auth = null;
        auth = new NtlmPasswordAuthenticator("", user, password);
        CIFSContext context = getBaseContext(isSMBv2);
        return new SmbFile(uri, context.withCredentials(auth));
    }

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

    public static void main(String[] args) throws Exception {

        String log4jConfigFile = System.getProperty("user.dir") + File.separator + "log4j.properties";
        PropertyConfigurator.configure(log4jConfigFile);

        if (args.length == 0 || (args.length > 2 && args.length < 5)) {
            System.out.println("Proper Usage is: 1|2 smb://server/share/ [domain user password]");
            System.exit(0);
        }
        boolean noAuth = false;
        if (args.length == 2) noAuth = true;
        isSMBv2Enabled = (args[0].equals("2"));
        if (isSMBv2Enabled) logger.info("Enabling SMB2");
        if (!noAuth) logger.info("Credentials provided");

        if (noAuth) {
            user = "GUEST";
            password = "";
            domain = "";
            url = args[1];
        } else {
            user = args[3];
            password = args[4];
            domain = args[2];
            url = args[1];
        }

        SmbFile smbFile = getSmbFile(args[1]);

        int type;
        try {
            type = smbFile.getType();
        } catch (SmbAuthException authE) {
            logger.info("Caught SmbAuthException");
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
            logger.info("Caught a SmbAuthException on listFiles", authE);
        } catch (SmbException smbE) {
            logger.info("Caught a SmbException on listFiles", smbE);
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
