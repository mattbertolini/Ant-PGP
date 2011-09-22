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
 * 
 * @author Matt Bertolini
 */
public class BouncyCastlePgpSignatureGenerator implements PgpSignatureGenerator {
    private static final int RADIX_BASE_16 = 16;
    private static final long KEY_ID_MASK = 0xFFFFFFFFL;
    
    private Provider securityProvider;
    private PGPSignatureGenerator sigGenerator;
    
    public BouncyCastlePgpSignatureGenerator() {
        this.securityProvider = new BouncyCastleProvider();
    }

    @Override
    public void init(File secretKeyring, String keyId, String passphrase) throws FileNotFoundException, IOException, PgpSignatureGeneratorException {
        if(secretKeyring == null) {
            throw new IllegalArgumentException("Secret keyring file is null.");
        }
        if(keyId == null) {
            throw new IllegalArgumentException("Key id is null.");
        }
        if(passphrase == null) {
            throw new IllegalArgumentException("Passphrase is null");
        }
        
        PGPSecretKey secretKey = this.getSecretKey(secretKeyring, keyId);
        try {
            PGPPrivateKey privateKey = secretKey.extractPrivateKey(passphrase.toCharArray(), this.securityProvider);
            this.sigGenerator = new PGPSignatureGenerator(secretKey.getPublicKey().getAlgorithm(), PGPUtil.SHA1, this.securityProvider);
            this.sigGenerator.initSign(PGPSignature.BINARY_DOCUMENT, privateKey);
        } catch(PGPException e) {
            throw new PgpSignatureGeneratorException("Error initializing signature generator", e);
        } catch (NoSuchAlgorithmException e) {
            throw new PgpSignatureGeneratorException("Error initializing signature generator. Public key aglorithm not found.", e);
        }
    }
    
    public void signFile(File fileToSign, File outputFile, boolean armor) throws FileNotFoundException, IOException, PgpSignatureGeneratorException {
        if(fileToSign == null) {
            throw new IllegalArgumentException("File to sign is null.");
        }
        if(outputFile == null) {
            throw new IllegalArgumentException("Output file is null.");
        }
        if(this.sigGenerator == null) {
            throw new IllegalStateException("Signature generator has not been initialized.");
        }
        
        InputStream fileToSignInputStream = null;
        OutputStream signatureFileOutputStream = null;
        try {
            fileToSignInputStream = new BufferedInputStream(new FileInputStream(fileToSign));
            int valueByte;
            while ((valueByte = fileToSignInputStream.read()) >= 0) {
                this.sigGenerator.update((byte) valueByte);
            }
            if (armor) {
                signatureFileOutputStream = new ArmoredOutputStream(new FileOutputStream(outputFile));
            } else {
                signatureFileOutputStream = new BufferedOutputStream(new FileOutputStream(outputFile));
            }
            this.sigGenerator.generate().encode(signatureFileOutputStream);
        } catch (SignatureException e) {
            throw new PgpSignatureGeneratorException("Unable to sign file", e);
        } catch (PGPException e) {
            throw new PgpSignatureGeneratorException("Unable to sign file", e);
        } finally {
            if(fileToSignInputStream != null) {
                try {
                    fileToSignInputStream.close();
                } catch (IOException e) {
                    // Do nothing
                }
            }
            if(signatureFileOutputStream != null) {
                try {
                    signatureFileOutputStream.close();
                } catch(IOException e) {
                    // Do nothing
                }
            }
        }
    }
    
    @SuppressWarnings("unchecked")
    private PGPSecretKey getSecretKey(File secretKeyring, String keyId) throws FileNotFoundException, IOException, PgpSignatureGeneratorException {
        InputStream keyringInputStream = null;
        PGPSecretKey secretKey = null;
        try {
            long keyIdAsLong = Long.parseLong(keyId, RADIX_BASE_16);
            keyringInputStream = PGPUtil.getDecoderStream(new FileInputStream(secretKeyring));
            PGPSecretKeyRingCollection secretKeyrings = new PGPSecretKeyRingCollection(keyringInputStream);
            for (Iterator<PGPSecretKeyRing> secretKeyringIter = secretKeyrings.getKeyRings(); secretKey == null && secretKeyringIter.hasNext();) {
                PGPSecretKeyRing pgpSecretKeyring = secretKeyringIter.next();
                for (Iterator<PGPSecretKey> secretKeyIter = pgpSecretKeyring.getSecretKeys(); secretKey == null && secretKeyIter.hasNext();) {
                    PGPSecretKey key = secretKeyIter.next();
                    if(keyIdAsLong == key.getKeyID()) {
                        secretKey = key;
                    } else if(keyIdAsLong == (key.getKeyID() & KEY_ID_MASK)) {
                        secretKey = key;
                    }
                }
            }
        } catch (PGPException e) {
            throw new PgpSignatureGeneratorException("Unable to get the secret key", e);
        } finally {
            if(keyringInputStream != null) {
                try {
                    keyringInputStream.close();
                } catch(IOException e) {
                    // Do Nothing
                }
            }
        }
        return secretKey;
    }
}
