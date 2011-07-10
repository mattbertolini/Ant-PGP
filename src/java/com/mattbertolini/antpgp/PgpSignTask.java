package com.mattbertolini.antpgp;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SignatureException;
import java.util.Iterator;

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Task;
import org.apache.tools.ant.types.Resource;
import org.apache.tools.ant.types.ResourceCollection;
import org.apache.tools.ant.types.resources.FileResource;
import org.apache.tools.ant.types.resources.Union;
import org.apache.tools.ant.util.FileUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPUtil;

/**
 * Ant task for creating signatures using PGP
 * 
 * @author Matt Bertolini
 */
public class PgpSignTask extends Task {
    private static final int RADIX_BASE_16 = 16;
    private static final long KEY_ID_MASK = 0xFFFFFFFFL;
    private static final String FILE_SEPARATOR = System.getProperty("file.separator");

    private Provider securityProvider;
    private File secretKeyring;
    private String keyId;
    private String passphrase;
    private boolean armor;
    private File outputDir;
    private Union files;

    @Override
    public void init() throws BuildException {
        this.securityProvider = new BouncyCastleProvider();
        this.files = new Union();
        this.armor = true;
    }

    @Override
    public void execute() throws BuildException {
        if (this.secretKeyring == null) {
            throw new BuildException("Secret keyring is null.");
        } else if (this.keyId == null || this.keyId.isEmpty()) {
            throw new BuildException("Key ID is null or empty.");
        } else if (this.passphrase == null || this.passphrase.isEmpty()) {
            throw new BuildException("Passphrase is null or empty.");
        }
        
        if(!this.outputDir.isDirectory()) {
            throw new BuildException("Output dir is not a directory.");
        }
        
        try {
            PGPSecretKey secretKey = this.getSecretKey();
            if(secretKey == null) {
                throw new BuildException("Could not find secret key with key ID " + this.keyId + " in keyring " + this.secretKeyring);
            }
            PGPPrivateKey privateKey = secretKey.extractPrivateKey(this.passphrase.toCharArray(), this.securityProvider);
            PGPSignatureGenerator sigGenerator = new PGPSignatureGenerator(secretKey.getPublicKey().getAlgorithm(), PGPUtil.SHA1, this.securityProvider);
            sigGenerator.initSign(PGPSignature.BINARY_DOCUMENT, privateKey);

            @SuppressWarnings("unchecked")
            Iterator<Resource> fileIter = this.files.iterator();
            while (fileIter.hasNext()) {
                InputStream fileToSignInputStream = null;
                OutputStream signatureFileOutputStream = null;
                try {
                    Resource resource = fileIter.next();
                    if (!(resource instanceof FileResource)) {
                        throw new BuildException(resource.getName() + " is not a file.");
                    }
                    FileResource fileResource = (FileResource) resource;
                    File file = fileResource.getFile();
                    String filePath = file.getAbsolutePath();
                    if (!file.exists()) {
                        throw new BuildException(filePath + " not found.");
                    }
                    log("Signing " + filePath);
                    fileToSignInputStream = new BufferedInputStream(new FileInputStream(file));
                    int valueByte;
                    while ((valueByte = fileToSignInputStream.read()) >= 0) {
                        sigGenerator.update((byte) valueByte);
                    }
                    String outputPath = filePath;
                    if(this.outputDir != null) {
                        outputPath = this.outputDir.getAbsolutePath() + FILE_SEPARATOR + file.getName();
                        log("Saving file to " + outputPath);
                    }
                    if (this.armor) {
                        signatureFileOutputStream = new ArmoredOutputStream(new FileOutputStream(outputPath + ".asc"));
                    } else {
                        signatureFileOutputStream = new BufferedOutputStream(new FileOutputStream(outputPath + ".sig"));
                    }
                    sigGenerator.generate().encode(signatureFileOutputStream);
                } catch (FileNotFoundException e) {
                    throw new BuildException(e);
                } catch (SignatureException e) {
                    throw new BuildException(e);
                } catch (IOException e) {
                    throw new BuildException(e);
                } catch (PGPException e) {
                    throw new BuildException(e);
                } finally {
                    FileUtils.close(fileToSignInputStream);
                    FileUtils.close(signatureFileOutputStream);
                }
            }
        } catch (PGPException e) {
            throw new BuildException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new BuildException(e);
        }
    }
    
    @SuppressWarnings("unchecked")
    private PGPSecretKey getSecretKey() throws BuildException {
        InputStream keyringInputStream = null;
        PGPSecretKey secretKey = null;
        try {
            long keyIdAsLong = Long.parseLong(this.keyId, RADIX_BASE_16);
            keyringInputStream = PGPUtil.getDecoderStream(new FileInputStream(this.secretKeyring));
            PGPSecretKeyRingCollection secretKeyrings = new PGPSecretKeyRingCollection(keyringInputStream);
            for (Iterator<PGPSecretKeyRing> secretKeyringIter = secretKeyrings.getKeyRings(); secretKey == null && secretKeyringIter.hasNext();) {
                PGPSecretKeyRing secretKeyring = secretKeyringIter.next();
                for (Iterator<PGPSecretKey> secretKeyIter = secretKeyring.getSecretKeys(); secretKey == null && secretKeyIter.hasNext();) {
                    PGPSecretKey key = secretKeyIter.next();
                    if(keyIdAsLong == key.getKeyID()) {
                        secretKey = key;
                    } else if(keyIdAsLong == (key.getKeyID() & KEY_ID_MASK)) {
                        secretKey = key;
                    }
                }
            }
        } catch (FileNotFoundException e) {
            throw new BuildException(e);
        } catch (IOException e) {
            throw new BuildException(e);
        } catch (PGPException e) {
            throw new BuildException(e);
        } finally {
            FileUtils.close(keyringInputStream);
        }
        return secretKey;
    }

    /**
     * Required. The secret keyring file to use for creating signatures.
     * 
     * @param secretKeyring
     * @since 1.0.0
     */
    public void setSecretKeyring(File secretKeyring) {
        this.secretKeyring = secretKeyring;
    }

    /**
     * Required. The PGP key ID.
     * 
     * @param keyId
     * @since 1.0.0
     */
    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    /**
     * Required. The passphrase associated with the key ID.
     * 
     * @param passphrase
     * @since 1.0.0
     */
    public void setPassphrase(String passphrase) {
        this.passphrase = passphrase;
    }

    /**
     * Optional. Create ASCII armored output. Default is true.
     * 
     * @param armor
     * @since 1.0.0
     */
    public void setArmor(boolean armor) {
        this.armor = armor;
    }
    
    /**
     * Optional. Changes the directory where the signature files will be saved. 
     * Defaults to the same directory as the files being signed.
     * 
     * @param outputDir
     */
    public void setOutputDir(File outputDir) {
        this.outputDir = outputDir;
    }

    public void add(ResourceCollection rc) {
        this.files.add(rc);
    }
}
